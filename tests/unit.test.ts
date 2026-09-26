// Fast checks that need no containers: wire parsing, URL guards, crypto envelopes,
// fail-closed configuration and handler validation with a stub repository.
import { describe, expect, it } from 'vitest';
import { loadRelayConfig } from '../server/config.ts';
import { Hasher, importCodeKey, openCode, randomDisplayCode, randomSecret, s256Challenge, sealCode } from '../server/crypto.ts';
import {
  buildAuthorizeUrl, DISPLAY_CODE_PATTERN, normalizeDeviceLabel, parseBootstrapFragment, parseCallback, verifyAuthorizeUrl,
} from '../server/protocol.ts';
import { createRelayHandler } from '../server/relay.ts';

const SUPA = 'https://abcdefghijklmnop.supabase.co';
const CALLBACK = 'https://safeauth.worklazy.net/callback.html';
const ID = '6f37df54-911b-4c37-8020-a0b45a84591d';

function env(overrides: Record<string, string | undefined> = {}) {
  const base: Record<string, string | undefined> = {
    SUPABASE_URL: SUPA, AUTH_SITE_URL: 'https://safeauth.worklazy.net/', AUTH_BROWSER_ORIGIN: 'https://safeauth.worklazy.net',
    AUTH_RELAY_ENABLED: 'true', AUTH_RELAY_HASH_PEPPER: randomSecret(), AUTH_RELAY_ENCRYPTION_KEY: randomSecret(),
  };
  const merged = { ...base, ...overrides };
  return (name: string) => merged[name];
}

describe('protocol helpers', () => {
  it('RFC 7636 appendix B S256 vector', async () => {
    expect(await s256Challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('bootstrap fragment accepts only r and t with strict formats', () => {
    const t = randomSecret();
    expect(parseBootstrapFragment(`#r=${ID}&t=${t}`)).toEqual({ requestId: ID, ticket: t });
    for (const bad of ['', '#', `#r=${ID}`, `#r=${ID}&t=${t}&next=https://evil.invalid`, `#r=x&t=${t}`, `#r=${ID}&t=short`, `#r=${ID}&t=${t}&t=${t}`]) {
      expect(parseBootstrapFragment(bad), bad).toBeNull();
    }
  });

  it('authorize URL guard rejects foreign hosts, extra params, other callbacks and providers', () => {
    const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
    const good = buildAuthorizeUrl(SUPA, CALLBACK, challenge);
    expect(verifyAuthorizeUrl(good, SUPA, CALLBACK)).toBe(good);
    const variants = [
      good.replace(SUPA, 'https://evil.supabase.co'),
      `${good}&redirect_to=https://evil.invalid`,
      `${good}&scopes=email`,
      good.replace('provider=kakao', 'provider=google'),
      good.replace(encodeURIComponent(CALLBACK), encodeURIComponent('https://worklazy.net/other.html')),
      good.replace('code_challenge_method=s256', 'code_challenge_method=plain'),
      `${good}#x`,
      'javascript:alert(1)',
    ];
    for (const v of variants) expect(verifyAuthorizeUrl(v, SUPA, CALLBACK), v).toBeNull();
  });

  it('callback parsing never exposes provider error text', () => {
    expect(parseCallback('?code=11111111-2222-4333-8444-555555555555', '')).toEqual({ kind: 'code', code: '11111111-2222-4333-8444-555555555555' });
    expect(parseCallback('?error=access_denied&error_description=<script>', '')).toEqual({ kind: 'denied' });
    expect(parseCallback('', '#error=server_error&error_description=boom&sb=')).toEqual({ kind: 'error' });
    expect(parseCallback('?code=a&code=b', '')).toEqual({ kind: 'error' });
    expect(parseCallback('?code=<bad>', '')).toEqual({ kind: 'error' }); // tampered code fails the request
    expect(parseCallback('', '')).toEqual({ kind: 'missing' });
  });

  it('device labels are display text only', () => {
    expect(normalizeDeviceLabel('  우리집   NAS ')).toBe('우리집 NAS');
    for (const bad of ['', ' ', '<b>x</b>', 'javascript:alert(1)', 'https://evil', 'a‮b', 'x'.repeat(41), 'quote"', 12]) {
      expect(normalizeDeviceLabel(bad), String(bad)).toBeNull();
    }
    expect(normalizeDeviceLabel('가'.repeat(40))).toBe('가'.repeat(40));
  });

  it('display codes use the unambiguous alphabet', () => {
    for (let i = 0; i < 200; i += 1) expect(randomDisplayCode()).toMatch(DISPLAY_CODE_PATTERN);
  });
});

describe('crypto envelopes', () => {
  it('sealed codes open only for the same request and key', async () => {
    const raw = crypto.getRandomValues(new Uint8Array(new ArrayBuffer(32)));
    const key = await importCodeKey(raw);
    const other = await importCodeKey(crypto.getRandomValues(new Uint8Array(new ArrayBuffer(32))));
    const sealed = await sealCode(key, ID, 'code-123');
    expect(sealed).not.toContain('code-123');
    expect(await openCode([key], ID, sealed)).toBe('code-123');
    await expect(openCode([key], '00000000-0000-4000-8000-000000000000', sealed)).rejects.toThrow();
    await expect(openCode([other], ID, sealed)).rejects.toThrow();
    await expect(openCode([other, key], ID, sealed)).resolves.toBe('code-123'); // rotation: previous key still opens
  });

  it('digests are purpose bound', async () => {
    const h = await Hasher.create(crypto.getRandomValues(new Uint8Array(new ArrayBuffer(32))));
    const s = randomSecret();
    expect(await h.digest('device', ID, s)).not.toBe(await h.digest('browser', ID, s));
    expect(await h.digest('device', ID, s)).not.toBe(await h.digest('device', '00000000-0000-4000-8000-000000000000', s));
  });
});

describe('relay configuration fails closed', () => {
  it.each([
    ['missing pepper', { AUTH_RELAY_HASH_PEPPER: undefined }],
    ['placeholder key', { AUTH_RELAY_ENCRYPTION_KEY: 'REPLACE_WITH_SERVER_SECRET' }],
    ['short key', { AUTH_RELAY_ENCRYPTION_KEY: randomSecret(16) }],
    ['low entropy', { AUTH_RELAY_HASH_PEPPER: 'A'.repeat(43) }],
    ['origin with path', { AUTH_BROWSER_ORIGIN: 'https://safeauth.worklazy.net/callback' }],
    ['http site', { AUTH_SITE_URL: 'http://safeauth.worklazy.net/' }],
    ['site origin not allowed', { AUTH_BROWSER_ORIGIN: 'https://worklazy.net' }],
    ['callback mismatch', { AUTH_CALLBACK_URL: 'https://worklazy.net/other.html' }],
    ['code ttl above auth flow', { AUTH_RELAY_CODE_TTL_SECONDS: '300' }],
    ['loopback without local flag', { AUTH_SITE_URL: 'http://127.0.0.1:8480/', AUTH_BROWSER_ORIGIN: 'http://127.0.0.1:8480' }],
  ])('%s', async (_name, overrides) => {
    const result = await loadRelayConfig(env(overrides));
    expect(result.ok).toBe(false);
  });

  it('the production values load and derive the exact callback', async () => {
    const result = await loadRelayConfig(env({ AUTH_CALLBACK_URL: CALLBACK }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.config.callbackUrl).toBe(CALLBACK);
      expect(result.config.browserOrigins).toEqual(['https://safeauth.worklazy.net']);
      expect(result.config.jwtIssuer).toBe(`${SUPA}/auth/v1`);
      expect(result.config.enabled).toBe(true);
    }
  });
});

describe('relay handler validation (stub repository)', () => {
  async function handler(overrides: Record<string, string | undefined> = {}, rpcImpl?: (name: string) => unknown) {
    const calls: string[] = [];
    const logs: unknown[] = [];
    const h = createRelayHandler({
      config: await loadRelayConfig(env(overrides)),
      rpc: async name => { calls.push(name); return rpcImpl ? rpcImpl(name) : { allowed: true, retry_after: 1 }; },
      getUserId: async () => null,
      clientAddress: () => '203.0.113.9',
      log: e => logs.push(e),
      cleanupSampleRate: 0,
    });
    return { h, calls, logs };
  }
  const req = (action: string, body: unknown, headers: Record<string, string> = {}, method = 'POST') =>
    new Request(`${SUPA}/functions/v1/community-auth-relay/${action}`, {
      method, headers: { 'content-type': 'application/json', ...headers }, body: method === 'POST' ? JSON.stringify(body) : undefined,
    });

  it('refuses an oversized streamed body while reading it (SOL-10)', async () => {
    const { h, calls } = await handler();
    let pulled = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(c) { pulled++; c.enqueue(new Uint8Array(1024).fill(0x20)); },
    }, { highWaterMark: 0 });
    const res = await h(new Request(`${SUPA}/functions/v1/community-auth-relay/requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: stream, duplex: 'half',
    } as RequestInit));
    expect(res.status).toBe(400);
    expect((await res.json()).error.code).toBe('invalid_request');
    expect(pulled).toBeLessThanOrEqual(10); // 8 KiB 상한
    expect(calls.filter(n => n !== 'internal_safeauth_rate_limit')).toEqual([]);
  });

  it('preflight and origin policy', async () => {
    const { h } = await handler();
    const pre = await h(new Request(`${SUPA}/functions/v1/community-auth-relay/claim`, { method: 'OPTIONS', headers: { origin: 'https://safeauth.worklazy.net' } }));
    expect(pre.status).toBe(204);
    expect(pre.headers.get('access-control-allow-origin')).toBe('https://safeauth.worklazy.net');
    const evil = await h(req('claim', {}, { origin: 'https://safeauth.worklazy.net.evil.invalid' }));
    expect(evil.status).toBe(403);
    expect((await h(req('claim', {}, {}, 'GET'))).status).toBe(405);
  });

  it('disabled and misconfigured relays answer 503 without touching the database', async () => {
    const off = await handler({ AUTH_RELAY_ENABLED: 'false' });
    const r = await off.h(req('requests', { protocol: 1 }));
    expect(r.status).toBe(503);
    expect(((await r.json()) as { error: { code: string } }).error.code).toBe('service_disabled');
    expect(off.calls).toEqual([]);
    const bad = await handler({ AUTH_RELAY_HASH_PEPPER: undefined });
    expect((await bad.h(req('requests', { protocol: 1 }))).status).toBe(503);
  });

  it('strict bodies: unknown fields, wrong protocol, wrong content type, oversize', async () => {
    const { h } = await handler();
    const base = { protocol: 1, request_id: ID, ticket: randomSecret(), browser_secret: randomSecret() };
    expect((await h(req('claim', { ...base, returnTo: 'https://evil.invalid' }))).status).toBe(400);
    expect((await h(req('claim', { ...base, protocol: 2 }))).status).toBe(400);
    expect((await h(new Request(`${SUPA}/functions/v1/community-auth-relay/claim`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: JSON.stringify(base) }))).status).toBe(400);
    expect((await h(req('claim', { ...base, pad: 'x'.repeat(9000) }))).status).toBe(400);
    expect((await h(req('unknown-action', base))).status).toBe(404);
  });

  it('rate limit answers 429 with Retry-After', async () => {
    const { h } = await handler({}, name => (name === 'internal_safeauth_rate_limit' ? { allowed: false, retry_after: 42 } : {}));
    const r = await h(req('claim', { protocol: 1, request_id: ID, ticket: randomSecret(), browser_secret: randomSecret() }));
    expect(r.status).toBe(429);
    expect(r.headers.get('retry-after')).toBe('42');
  });

  it('complete requires a bearer token that Supabase Auth accepts', async () => {
    const { h, calls } = await handler();
    const body = { protocol: 1, request_id: ID, device_secret: randomSecret() };
    expect((await h(req('complete', body))).status).toBe(401);
    expect((await h(req('complete', body, { authorization: 'Bearer a.b.c' }))).status).toBe(401);
    expect(calls.filter(c => c === 'internal_safeauth_complete')).toEqual([]);
  });

  it('repository failures are 500 with a trace id and never echo input', async () => {
    const secret = randomSecret();
    const { h, logs } = await handler({}, name => { if (name === 'internal_safeauth_claim') throw new Error(`db said ${secret}`); return { allowed: true }; });
    const r = await h(req('claim', { protocol: 1, request_id: ID, ticket: secret, browser_secret: randomSecret() }));
    const text = await r.text();
    expect(r.status).toBe(500);
    expect(text).not.toContain(secret);
    expect(JSON.stringify(logs)).not.toContain(secret);
    expect(r.headers.get('cache-control')).toBe('no-store');
  });
});
