// Relay configuration from server-side environment. Fails closed: any missing,
// placeholder or malformed value disables every endpoint with config_missing.

import { base64UrlDecode, type CodeKey, Hasher, importCodeKey } from './crypto.ts';

export interface RelayConfig {
  enabled: boolean;
  siteUrl: string;            // https://safeauth.worklazy.net/
  callbackUrl: string;        // https://safeauth.worklazy.net/callback.html
  browserOrigins: string[];   // https://safeauth.worklazy.net (origin only, never a path)
  publicSupabaseUrl: string;  // origin used in the authorize URL and JWT issuer
  jwtIssuer: string;
  requestTtlSeconds: number;
  codeTtlSeconds: number;
  pollIntervalSeconds: number;
  maxActivePerInstall: number;
  maxActiveTotal: number;
  createLimitPerIp: number;   // per 10 minutes
  hasher: Hasher;
  codeKeys: CodeKey[];        // first key seals; all keys may open
}

export type ConfigResult = { ok: true; config: RelayConfig } | { ok: false; problems: string[] };

type Env = (name: string) => string | undefined;

function intIn(env: Env, name: string, fallback: number, min: number, max: number, problems: string[]): number {
  const raw = env(name);
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) {
    problems.push(`${name} must be an integer in [${min}, ${max}]`);
    return fallback;
  }
  return value;
}

function secretBytes(env: Env, name: string, problems: string[], exact?: number): Uint8Array<ArrayBuffer> | null {
  const raw = env(name)?.trim();
  if (!raw) { problems.push(`${name} missing`); return null; }
  if (/replace|example|changeme|your_/i.test(raw)) { problems.push(`${name} is a placeholder`); return null; }
  let bytes: Uint8Array<ArrayBuffer>;
  try { bytes = base64UrlDecode(raw); } catch { problems.push(`${name} must be base64url`); return null; }
  if (exact !== undefined ? bytes.length !== exact : bytes.length < 32) {
    problems.push(`${name} must decode to ${exact ?? 'at least 32'} bytes`);
    return null;
  }
  if (new Set(bytes).size < 16) { problems.push(`${name} has too little entropy`); return null; }
  return bytes;
}

function httpsUrl(value: string | undefined, allowLoopbackHttp: boolean): URL | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (url.username || url.password || url.search || url.hash) return null;
    if (url.protocol === 'https:') return url;
    if (allowLoopbackHttp && url.protocol === 'http:' && url.hostname === '127.0.0.1') return url;
    return null;
  } catch {
    return null;
  }
}

export async function loadRelayConfig(env: Env): Promise<ConfigResult> {
  const problems: string[] = [];
  // Loopback http is accepted only when explicitly marked as a local verification stack.
  const loopback = env('AUTH_RELAY_LOCAL_STACK') === 'loopback-only';

  const site = httpsUrl(env('AUTH_SITE_URL'), loopback);
  if (!site || !site.pathname.endsWith('/')) problems.push('AUTH_SITE_URL must be an https URL ending in /');
  const callbackUrl = site ? new URL('callback.html', site).toString() : '';
  const declaredCallback = env('AUTH_CALLBACK_URL');
  if (declaredCallback && declaredCallback !== callbackUrl) problems.push('AUTH_CALLBACK_URL must equal AUTH_SITE_URL + callback.html');

  const origins = (env('AUTH_BROWSER_ORIGIN') ?? '').split(',').map(v => v.trim()).filter(Boolean);
  if (origins.length === 0) problems.push('AUTH_BROWSER_ORIGIN missing');
  for (const origin of origins) {
    const url = httpsUrl(origin, loopback);
    if (!url || url.origin !== origin) problems.push('AUTH_BROWSER_ORIGIN entries must be bare origins (no path)');
  }
  if (site && !origins.includes(site.origin)) problems.push('AUTH_BROWSER_ORIGIN must include the AUTH_SITE_URL origin');

  const supabase = httpsUrl(env('AUTH_PUBLIC_SUPABASE_URL') || env('SUPABASE_URL'), loopback);
  if (!supabase) problems.push('SUPABASE_URL / AUTH_PUBLIC_SUPABASE_URL invalid');
  const publicSupabaseUrl = supabase ? supabase.origin : '';

  const requestTtlSeconds = intIn(env, 'AUTH_RELAY_REQUEST_TTL_SECONDS', 600, 120, 1800, problems);
  // Supabase Auth flow state lasts 300 s from /authorize; the relay copy must be shorter.
  const codeTtlSeconds = intIn(env, 'AUTH_RELAY_CODE_TTL_SECONDS', 120, 30, 240, problems);
  const pollIntervalSeconds = intIn(env, 'AUTH_RELAY_POLL_INTERVAL_SECONDS', 5, 2, 30, problems);
  const maxActivePerInstall = intIn(env, 'AUTH_RELAY_MAX_ACTIVE_PER_INSTALL', 3, 1, 20, problems);
  const maxActiveTotal = intIn(env, 'AUTH_RELAY_MAX_ACTIVE_TOTAL', 5000, 10, 100000, problems);
  const createLimitPerIp = intIn(env, 'AUTH_RELAY_CREATE_LIMIT_PER_IP', 10, 1, 1000, problems);

  const pepper = secretBytes(env, 'AUTH_RELAY_HASH_PEPPER', problems);
  const codeKeyRaw = secretBytes(env, 'AUTH_RELAY_ENCRYPTION_KEY', problems, 32);
  const previousRaw = env('AUTH_RELAY_ENCRYPTION_KEY_PREVIOUS') ? secretBytes(env, 'AUTH_RELAY_ENCRYPTION_KEY_PREVIOUS', problems, 32) : null;
  if (pepper && codeKeyRaw && pepper.length === codeKeyRaw.length && pepper.every((b, i) => b === codeKeyRaw[i])) {
    problems.push('AUTH_RELAY_HASH_PEPPER and AUTH_RELAY_ENCRYPTION_KEY must differ');
  }

  if (problems.length > 0 || !site || !pepper || !codeKeyRaw) return { ok: false, problems };

  const codeKeys = [await importCodeKey(codeKeyRaw)];
  if (previousRaw) codeKeys.push(await importCodeKey(previousRaw));
  return {
    ok: true,
    config: {
      enabled: env('AUTH_RELAY_ENABLED') === 'true',
      siteUrl: site.toString(),
      callbackUrl,
      browserOrigins: origins,
      publicSupabaseUrl,
      jwtIssuer: env('AUTH_JWT_ISSUER') || `${publicSupabaseUrl}/auth/v1`,
      requestTtlSeconds,
      codeTtlSeconds,
      pollIntervalSeconds,
      maxActivePerInstall,
      maxActiveTotal,
      createLimitPerIp,
      hasher: await Hasher.create(pepper),
      codeKeys,
    },
  };
}
