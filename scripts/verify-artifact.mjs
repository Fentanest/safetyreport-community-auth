#!/usr/bin/env node
// Verifies a built safeauth artifact before it is published.
//   node scripts/verify-artifact.mjs --dir dist [--base /]
//        [--require-config] [--expect-supabase https://<ref>.supabase.co] [--site-origin https://safeauth.worklazy.net] [--allow-origin https://x ...] [--json]
// Checks: file allowlist, no symlinks, per-page security meta (referrer first, CSP
// without inline script), noindex, asset paths under the base, no third-party
// runtime, ads/analytics/service worker, no secrets, no design-demo leftovers, and
// the official Kakao asset hash. Exit 1 on any failure.
import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const KAKAO_ASSET = 'kakao/kakao_login_kr_medium.svg';
// Official "Kakao Login" resource ZIP, SVG/kakao_login_kr_medium.svg (see docs/assets.md).
export const KAKAO_SHA256 = 'ab90ab44616f14a671844cd991b3fbb33277f42c5bb2cc5a9422344a854c9398';
export const PAGES = ['index.html', 'callback.html', 'help.html', 'privacy.html'];

const DEMO_MARKERS = ['DESIGN REFERENCE', '디자인용 버튼', 'Q7MH-4K2P', '우리집 NAS', '디자인 시안', 'demo-bar', 'OFFLINE DESIGN DEMO'];
const FORBIDDEN_RUNTIME = [
  /googletagmanager|google-analytics|gtag\(|adsbygoogle|pagead2|doubleclick|wcslog|naver\.net\/wcs/i,
  /serviceWorker\s*\.\s*register/,
  /dapi\.kakao\.com|developers\.kakao\.com|t1\.kakaocdn/i,
  /cdn\.jsdelivr|unpkg\.com|cdnjs|fonts\.googleapis|fonts\.gstatic/i,
  /localStorage\.clear|sessionStorage\.clear|caches\.delete/,
];
const SECRET_PATTERNS = [
  /sb_secret_[A-Za-z0-9_-]+/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /AUTH_RELAY_(HASH_PEPPER|ENCRYPTION_KEY)/,
  /SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SECRET_KEYS/,
];

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    const st = lstatSync(path);
    if (st.isSymbolicLink()) out.push({ path, symlink: true });
    else if (st.isDirectory()) walk(path, out);
    else out.push({ path, symlink: false });
  }
  return out;
}

function jwtRoles(text) {
  const roles = [];
  for (const m of text.matchAll(/eyJ[A-Za-z0-9_-]{8,}\.(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{16,}/g)) {
    try { roles.push(JSON.parse(Buffer.from(m[1], 'base64url').toString('utf8')).role); } catch { /* not a JWT */ }
  }
  return roles;
}

// Origins a bundle may mention: the site, the configured Supabase project, and any
// operator link compiled in from the same public build variables (privacy policy).
export function configuredOrigins(env = process.env) {
  const out = [];
  const policy = env.SAFEAUTH_PUBLIC_PRIVACY_POLICY_URL;
  if (policy) { try { const u = new URL(policy); if (u.protocol === 'https:') out.push(u.origin); } catch { /* ignored */ } }
  return out;
}

export function verifyArtifact({ dir, base = '/', requireConfig = false, expectSupabase = null, siteOrigin = 'https://safeauth.worklazy.net', allowOrigins = configuredOrigins() }) {
  const errors = [];
  const files = walk(dir);
  const rel = f => relative(dir, f.path).split(sep).join('/');
  const allowed = f => PAGES.includes(f) || f === KAKAO_ASSET || /^assets\/[A-Za-z0-9_.-]+\.(js|css)$/.test(f);
  for (const f of files) {
    const name = rel(f);
    if (f.symlink) errors.push(`symlink not allowed: ${name}`);
    else if (!allowed(name)) errors.push(`file not in allowlist: ${name}`);
  }
  const names = new Set(files.map(rel));
  for (const page of PAGES) if (!names.has(page)) errors.push(`missing page: ${page}`);
  if (!names.has(KAKAO_ASSET)) errors.push('missing official Kakao asset');
  else {
    const hash = createHash('sha256').update(readFileSync(join(dir, KAKAO_ASSET))).digest('hex');
    if (hash !== KAKAO_SHA256) errors.push('Kakao asset hash differs from the recorded official file');
  }

  const connectSources = new Set();
  for (const page of PAGES.filter(p => names.has(p))) {
    const html = readFileSync(join(dir, page), 'utf8');
    const head = html.slice(0, html.indexOf('</head>'));
    const firstResource = head.search(/<(script|link)\b/i);
    const referrer = head.search(/<meta name="referrer" content="no-referrer">/);
    if (referrer < 0 || (firstResource >= 0 && referrer > firstResource)) errors.push(`${page}: no-referrer meta must precede resources`);
    const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(head)?.[1];
    if (!csp) errors.push(`${page}: CSP meta missing`);
    else {
      if (!/script-src 'self'(;|$)/.test(csp) || /unsafe-inline|unsafe-eval/.test(csp)) errors.push(`${page}: CSP must be script-src 'self' only`);
      if (!/default-src 'none'/.test(csp)) errors.push(`${page}: CSP default-src must be 'none'`);
      connectSources.add(/connect-src ([^;]+)/.exec(csp)?.[1]?.trim() ?? '');
    }
    if (!/<meta name="robots" content="noindex, nofollow, noarchive">/.test(head)) errors.push(`${page}: noindex meta missing`);
    if (!new RegExp(`<meta name="safeauth-page" content="${page.replace('.html', '')}">`).test(head)) errors.push(`${page}: page marker missing`);
    if (/<script(?![^>]*\bsrc=)[^>]*>/i.test(html)) errors.push(`${page}: inline script found`);
    if (/\son[a-z]+\s*=/i.test(html)) errors.push(`${page}: inline event handler found`);
    if (/<style\b|style="/i.test(html)) errors.push(`${page}: inline style found`);
    for (const m of html.matchAll(/\b(?:src|href)="([^"]+)"/g)) {
      const ref = m[1];
      if (ref.startsWith('#') || ref.startsWith('./')) continue;
      if (/^[a-z]+:/i.test(ref)) { errors.push(`${page}: absolute URL reference ${ref}`); continue; }
      if (!ref.startsWith(base)) { errors.push(`${page}: reference outside base ${ref}`); continue; }
      if (!names.has(ref.slice(base.length))) errors.push(`${page}: missing referenced file ${ref}`);
    }
  }
  if (connectSources.size !== 1) errors.push('pages disagree on connect-src');
  const connect = [...connectSources][0] ?? '';
  if (requireConfig && (connect === "'none'" || !connect.startsWith('https://'))) errors.push('Supabase URL not configured (connect-src)');
  if (expectSupabase && connect !== expectSupabase) errors.push(`connect-src ${connect} != expected ${expectSupabase}`);

  for (const f of files.filter(x => !x.symlink)) {
    const name = rel(f);
    const text = readFileSync(f.path, 'utf8');
    for (const marker of DEMO_MARKERS) if (text.includes(marker)) errors.push(`${name}: design demo leftover "${marker}"`);
    for (const pattern of FORBIDDEN_RUNTIME) if (pattern.test(text)) errors.push(`${name}: forbidden runtime ${pattern}`);
    for (const pattern of SECRET_PATTERNS) if (pattern.test(text)) errors.push(`${name}: secret-like value ${pattern}`);
    for (const role of jwtRoles(text)) if (role !== 'anon') errors.push(`${name}: JWT with role ${role}`);
    if (name.endsWith('.js') || name.endsWith('.css')) {
      for (const m of text.matchAll(/https?:\/\/[A-Za-z0-9.-]+(?::\d+)?/g)) {
        const origin = m[0];
        const ok = origin === siteOrigin || origin === 'http://www.w3.org' || (connect && origin === connect) || allowOrigins.includes(origin);
        if (!ok) errors.push(`${name}: unexpected URL ${origin}`);
      }
    }
  }
  return { ok: errors.length === 0, errors, files: [...names].sort(), connectSrc: connect };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const get = flag => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : undefined; };
  const result = verifyArtifact({
    dir: get('--dir') ?? 'dist',
    base: get('--base') ?? '/',
    requireConfig: args.includes('--require-config'),
    expectSupabase: get('--expect-supabase') ?? null,
    siteOrigin: get('--site-origin') ?? 'https://safeauth.worklazy.net',
    allowOrigins: [...configuredOrigins(), ...args.flatMap((a, i) => (a === '--allow-origin' ? [args[i + 1]] : []))],
  });
  if (args.includes('--json')) console.log(JSON.stringify(result, null, 2));
  else {
    console.log(`safeauth artifact: ${result.files.length} files, connect-src ${result.connectSrc}`);
    for (const e of result.errors) console.error(`FAIL ${e}`);
    console.log(result.ok ? 'PASS' : 'FAIL');
  }
  process.exit(result.ok ? 0 : 1);
}
