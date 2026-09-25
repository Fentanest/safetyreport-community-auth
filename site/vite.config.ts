// Independent build for the central account-link pages (https://safeauth.worklazy.net/).
//   npm run build                          -> dist/ with base /
//   SAFEAUTH_BASE=/sub/ vite build --mode localtest ...  (local subpath check only)
// Shares no code, ads or analytics with the community map or WorklazyTools.
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, loadEnv, type Plugin } from 'vite';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..');
const PROD_SITE = 'https://safeauth.worklazy.net/';

function fail(message: string): never {
  throw new Error(`[safeauth build] ${message}`);
}

function jwtRole(token: string): string | null {
  const part = token.split('.')[1];
  if (!part) return null;
  try { return JSON.parse(Buffer.from(part, 'base64url').toString('utf8')).role ?? null; } catch { return null; }
}

function checkedEnv(mode: string, base: string, env: Record<string, string>) {
  const local = mode === 'localtest';
  if (!local && base !== '/') fail('production base must be /');
  const site = env.SAFEAUTH_PUBLIC_SITE_URL || PROD_SITE;
  const siteUrl = new URL(site);
  if (siteUrl.pathname !== base) fail('SAFEAUTH_PUBLIC_SITE_URL path must equal the build base');
  if (!local && site !== PROD_SITE) fail(`production site must be ${PROD_SITE}`);
  let supabaseOrigin: string | null = null;
  if (env.SAFEAUTH_PUBLIC_SUPABASE_URL) {
    const url = new URL(env.SAFEAUTH_PUBLIC_SUPABASE_URL);
    const loopback = local && url.protocol === 'http:' && url.hostname === '127.0.0.1';
    if (url.protocol !== 'https:' && !loopback) fail('SAFEAUTH_PUBLIC_SUPABASE_URL must be https');
    if (url.pathname !== '/' || url.search || url.hash) fail('SAFEAUTH_PUBLIC_SUPABASE_URL must be an origin');
    supabaseOrigin = url.origin;
  }
  const key = env.SAFEAUTH_PUBLIC_PUBLISHABLE_KEY ?? '';
  if (key) {
    if (/^sb_secret_/.test(key)) fail('a secret key must never be bundled');
    if (!/^sb_publishable_/.test(key) && jwtRole(key) !== 'anon') fail('only a publishable/anon key may be bundled');
  }
  for (const name of Object.keys(env)) {
    if (/SECRET|SERVICE|PEPPER|PRIVATE|PASSWORD/i.test(name)) fail(`${name} looks secret and cannot be a public build variable`);
  }
  return { supabaseOrigin, local, site };
}

function cspPlugin(supabaseOrigin: string | null, local: boolean, isBuild: boolean): Plugin {
  const policy = [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self'",
    `connect-src ${supabaseOrigin ?? "'none'"}`,
    "base-uri 'none'",
    "form-action 'none'",
    "object-src 'none'",
    "frame-src 'none'",
    "worker-src 'none'",
    "manifest-src 'none'",
    ...(local ? [] : ['upgrade-insecure-requests']),
  ].join('; ');
  return {
    name: 'safeauth-csp',
    transformIndexHtml(html) {
      if (!html.includes('__SAFEAUTH_CSP__')) fail('CSP placeholder missing');
      // The dev server needs inline HMR code; only built files carry the real policy.
      return isBuild ? html.replace('__SAFEAUTH_CSP__', policy) : html.replace(/\s*<meta http-equiv="Content-Security-Policy"[^>]*>/, '');
    },
  };
}

export default defineConfig(({ mode, command }) => {
  const base = process.env.SAFEAUTH_BASE || '/';
  const env = loadEnv(mode, repo, 'SAFEAUTH_PUBLIC_');
  const { supabaseOrigin, local, site } = checkedEnv(mode, base, env);
  return {
    root: here,
    base,
    envDir: repo,
    envPrefix: 'SAFEAUTH_PUBLIC_',
    publicDir: resolve(here, 'public'),
    plugins: [cspPlugin(supabaseOrigin, local, command === 'build')],
    // Exactly one site URL is compiled in; the page refuses to run anywhere else.
    define: { 'import.meta.env.SAFEAUTH_PUBLIC_SITE_URL': JSON.stringify(site) },
    build: {
      outDir: resolve(repo, process.env.SAFEAUTH_OUT_DIR || 'dist'),
      emptyOutDir: true,
      sourcemap: false,
      assetsInlineLimit: 0,
      modulePreload: { polyfill: false },
      rollupOptions: {
        input: {
          index: resolve(here, 'index.html'),
          callback: resolve(here, 'callback.html'),
          help: resolve(here, 'help.html'),
          privacy: resolve(here, 'privacy.html'),
        },
      },
    },
    server: { host: '127.0.0.1' },
  };
});
