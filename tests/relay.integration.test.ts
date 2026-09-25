// Integration tests against the LOCAL stack: real Supabase Postgres + real Supabase
// Auth (GoTrue v2.197.0) + PostgREST, mock Kakao. Run:
//   node tests/stack/stack.mjs up
//   SAFEAUTH_STACK=1 npx vitest run tests/relay.integration.test.ts
// These prove protocol behaviour with the real Auth server; they are NOT a hosted
// Kakao E2E (see docs/acceptance.md for the manual hosted procedure).
import { createHmac, randomUUID } from 'node:crypto';
import type { Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomSecret } from '../server/crypto.ts';
import { Browser, Device, expectOk, flowToCode, post } from './support/actors.ts';
import { startMockKakao } from './stack/mock-kakao.mjs';
import { loadStackEnv, PORTS, psql } from './stack/stack.mjs';
import { startGateway } from './stack/gateway.ts';

const enabled = process.env.SAFEAUTH_STACK === '1';
const ORIGIN = `http://127.0.0.1:${PORTS.site}`;
const BASE = `http://127.0.0.1:${PORTS.gateway}`;

function sign(payload: Record<string, unknown>, secret: string) {
  const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
  const head = enc({ alg: 'HS256', typ: 'JWT' });
  const body = enc(payload);
  return `${head}.${body}.${createHmac('sha256', secret).update(`${head}.${body}`).digest('base64url')}`;
}

function payloadOf(jwt: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'));
}

describe.skipIf(!enabled)('safeauth relay on the local Supabase stack', () => {
  let stack: Record<string, string>;
  let kakao: Server;
  let gateway: Awaited<ReturnType<typeof startGateway>>;

  beforeAll(async () => {
    stack = loadStackEnv();
    // Shared local stack: reset only rate-limit windows, never other runs' requests.
    psql("delete from private.community_auth_rate_limits;", { env: stack });
    kakao = await startMockKakao({ clientSecret: stack.SAFEAUTH_KAKAO_SECRET }) as Server;
    gateway = await startGateway();
    expect(gateway.config.ok).toBe(true);
  });

  afterAll(async () => {
    await new Promise(r => gateway?.server.close(r));
    await new Promise(r => kakao?.close(r));
  });

  describe('PKCE principle (P01-P05)', () => {
    it('P01: only the originating device exchanges the code with its own verifier and gets a session', async () => {
      const { device, browser } = await flowToCode(BASE, stack.SAFEAUTH_ANON_KEY, ORIGIN);
      expect((await browser.status()).json.phase).toBe('code_ready');
      const polled = expectOk(await device.poll());
      expect(polled.json.status).toBe('code');
      expect((await browser.status()).json.phase).toBe('code_delivered');
      const exchanged = await device.exchange(String(polled.json.auth_code));
      expect(exchanged.status).toBe(200);
      const user = exchanged.json.user as Record<string, unknown>;
      expect(user.email ?? '').toBe(''); // mock account A has no e-mail
      // Still not success in the browser until the device confirms.
      expect((await browser.status()).json.phase).toBe('code_delivered');
      const completed = expectOk(await device.complete());
      expect(completed.json.phase).toBe('device_confirmed');
      expect((await browser.status()).json.phase).toBe('device_confirmed');
      const row = psql(`select user_id::text, encrypted_auth_code is null from private.community_auth_requests where id='${device.requestId}'`, { env: stack, tuplesOnly: true }).trim();
      expect(row).toBe(`${user.id}|t`);
    });

    it('P03: a code cannot be exchanged with another verifier or another request verifier', async () => {
      const a = await flowToCode(BASE, stack.SAFEAUTH_ANON_KEY, ORIGIN);
      const b = new Device(BASE, stack.SAFEAUTH_ANON_KEY);
      const code = String((await a.device.poll()).json.auth_code);
      const wrong = await a.device.exchange(code, randomSecret());
      expect(wrong.status).toBe(400);
      expect(wrong.json.error_code ?? wrong.json.code).toBe('bad_code_verifier');
      const other = await a.device.exchange(code, b.verifier);
      expect(other.status).toBe(400);
      // The right verifier still works afterwards (a failed PKCE check does not burn the code).
      expect((await a.device.exchange(code)).status).toBe(200);
    });

    it('P04: an auth code is exchangeable once', async () => {
      const { device } = await flowToCode(BASE, stack.SAFEAUTH_ANON_KEY, ORIGIN);
      const code = String((await device.poll()).json.auth_code);
      expect((await device.exchange(code)).status).toBe(200);
      const again = await device.exchange(code);
      expect(again.status).toBe(404);
      expect(again.json.error_code ?? again.json.code).toBe('flow_state_not_found');
    });

    it('P05: the callback carries only the code on the fixed callback URL, and publish requires the claimed browser', async () => {
      const device = new Device(BASE, stack.SAFEAUTH_ANON_KEY);
      expectOk(await device.create());
      const browser = new Browser(BASE, ORIGIN);
      browser.open(device.bootstrapUrl);
      expectOk(await browser.claim());
      const prepared = expectOk(await browser.prepare());
      const { landed, outcome } = await browser.login(String(prepared.json.authorize_url));
      expect(`${landed.origin}${landed.pathname}`).toBe(`${ORIGIN}/callback.html`);
      expect([...landed.searchParams.keys()]).toEqual(['code']);
      const stranger = new Browser(BASE, ORIGIN);
      stranger.requestId = browser.requestId;
      const r = await stranger.publish({ outcome: 'code', code: (outcome as { code: string }).code });
      expect(r.status).toBe(404);
      expect(r.json.error).toMatchObject({ code: 'not_found' });
    });

    it('P05b: a callback URL that is not allow-listed is silently replaced by the Site URL (preflight must verify allowlisting)', async () => {
      const device = new Device(BASE, stack.SAFEAUTH_ANON_KEY);
      expectOk(await device.create());
      const url = new URL(`${BASE}/auth/v1/authorize`);
      url.search = new URLSearchParams({ provider: 'kakao', redirect_to: 'https://attacker.invalid/cb', code_challenge: 'x'.repeat(43), code_challenge_method: 's256' }).toString();
      const { landed } = await new Browser(BASE, ORIGIN).login(url.toString());
      expect(landed.origin).toBe('http://127.0.0.1:8490'); // GOTRUE_SITE_URL, not the attacker
      expect(landed.pathname).toBe('/');
    });

    it('OAuth denial at Kakao becomes cancelled, never success', async () => {
      const device = new Device(BASE, stack.SAFEAUTH_ANON_KEY);
      expectOk(await device.create());
      const browser = new Browser(BASE, ORIGIN);
      browser.open(device.bootstrapUrl);
      expectOk(await browser.claim());
      const prepared = expectOk(await browser.prepare());
      const { outcome } = await browser.login(String(prepared.json.authorize_url), 'deny');
      expect(outcome.kind).toBe('denied');
      expect(expectOk(await browser.publish({ outcome: 'denied' })).json.phase).toBe('cancelled');
      expect((await device.poll()).json).toMatchObject({ status: 'cancelled', reason: 'oauth' });
    });
  });

  describe('capabilities and state (S01-S18)', () => {
    it('S01/S02: request_id or display code alone grant nothing', async () => {
      const device = new Device(BASE, stack.SAFEAUTH_ANON_KEY);
      expectOk(await device.create());
      const b = new Browser(BASE, ORIGIN);
      b.requestId = device.requestId;
      b.ticket = randomSecret();
      expect((await b.claim()).status).toBe(404);
      const intruder = new Device(BASE, stack.SAFEAUTH_ANON_KEY);
      intruder.requestId = device.requestId;
      expect((await intruder.poll()).status).toBe(404);
      expect((await intruder.cancel()).status).toBe(404);
      const byCode = await post(BASE, 'claim', { protocol: 1, request_id: device.requestId, ticket: device.displayCode, browser_secret: randomSecret() }, { origin: ORIGIN });
      expect(byCode.status).toBe(400);
      // Unknown and existing ids with wrong secrets are indistinguishable.
      const unknown = new Browser(BASE, ORIGIN);
      unknown.requestId = randomUUID();
      unknown.ticket = randomSecret();
      const u = await unknown.claim();
      expect(u.status).toBe(404);
      expect((u.json.error as Record<string, unknown>).code).toBe('not_found');
    });

    it('S03/S13: anon and authenticated roles cannot read the relay table or call relay RPCs', async () => {
      const { device } = await flowToCode(BASE, stack.SAFEAUTH_ANON_KEY, ORIGIN);
      const session = await device.exchange(String((await device.poll()).json.auth_code));
      const userJwt = String(session.json.access_token);
      for (const key of [stack.SAFEAUTH_ANON_KEY, userJwt]) {
        const headers = { apikey: stack.SAFEAUTH_ANON_KEY, authorization: `Bearer ${key}`, 'content-type': 'application/json' };
        const rpc = await fetch(`${BASE}/rest/v1/rpc/internal_safeauth_poll`, {
          method: 'POST', headers,
          body: JSON.stringify({ p_id: device.requestId, p_device_secret_hash: '0'.repeat(64), p_delivery_key_hash: '0'.repeat(64) }),
        });
        expect([401, 403, 404]).toContain(rpc.status);
        const table = await fetch(`${BASE}/rest/v1/community_auth_requests?select=*`, { headers: { ...headers, 'accept-profile': 'private' } });
        expect(table.status).toBeGreaterThanOrEqual(400);
      }
      const grants = psql(`select
          has_table_privilege('anon','private.community_auth_requests','select'),
          has_table_privilege('authenticated','private.community_auth_requests','select'),
          has_function_privilege('anon','public.internal_safeauth_poll(uuid,text,text)','execute'),
          has_function_privilege('authenticated','public.internal_safeauth_complete(uuid,text,uuid,uuid,timestamptz)','execute'),
          has_function_privilege('service_role','public.internal_safeauth_poll(uuid,text,text)','execute')`, { env: stack, tuplesOnly: true }).trim();
      expect(grants).toBe('f|f|f|f|t');
      const definers = psql(`select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace
          where p.proname like 'internal_safeauth_%' and p.prosecdef and array_to_string(p.proconfig, ',') = 'search_path=""'`,
        { env: stack, tuplesOnly: true }).trim();
      expect(Number(definers)).toBe(11);
    });

    it('S04: first claim wins; same secret is idempotent; another secret is rejected', async () => {
      const device = new Device(BASE, stack.SAFEAUTH_ANON_KEY);
      expectOk(await device.create());
      const b = new Browser(BASE, ORIGIN);
      b.open(device.bootstrapUrl);
      expect((await b.claim()).json.phase).toBe('claimed');
      expect((await b.claim()).json.phase).toBe('claimed');
      const other = await b.claim(randomSecret());
      expect(other.status).toBe(409);
      expect((other.json.error as Record<string, unknown>).code).toBe('already_claimed');
    });

    it('S05: browser and device capabilities are not interchangeable', async () => {
      const { device, browser } = await flowToCode(BASE, stack.SAFEAUTH_ANON_KEY, ORIGIN);
      const swapped = await post(BASE, 'poll', { protocol: 1, request_id: device.requestId, device_secret: browser.browserSecret, delivery_key: randomSecret() });
      expect(swapped.status).toBe(404);
      const other = new Device(BASE, stack.SAFEAUTH_ANON_KEY);
      expectOk(await other.create());
      const cross = await post(BASE, 'poll', { protocol: 1, request_id: other.requestId, device_secret: device.deviceSecret, delivery_key: device.deliveryKey });
      expect(cross.status).toBe(404);
    });

    it('S06: complete rejects forged, expired, wrong-issuer and wrong-user tokens', async () => {
      const { device } = await flowToCode(BASE, stack.SAFEAUTH_ANON_KEY, ORIGIN);
      const real = await device.exchange(String((await device.poll()).json.auth_code));
      const jwt = String(real.json.access_token);
      const claims = payloadOf(jwt);
      const now = Math.floor(Date.now() / 1000);
      const cases = {
        garbage: 'aaa.bbb.ccc',
        badSignature: sign(claims, 'not-the-secret-not-the-secret-000000'),
        expired: sign({ ...claims, iat: now - 7200, exp: now - 3600 }, stack.SAFEAUTH_JWT_SECRET),
        wrongIssuer: sign({ ...claims, iss: 'https://evil.invalid/auth/v1' }, stack.SAFEAUTH_JWT_SECRET),
        unknownUser: sign({ ...claims, sub: randomUUID() }, stack.SAFEAUTH_JWT_SECRET),
      };
      for (const [name, token] of Object.entries(cases)) {
        const r = await device.complete(token);
        expect(r.status, name).toBe(401);
      }
      const missing = await post(BASE, 'complete', { protocol: 1, request_id: device.requestId, device_secret: device.deviceSecret });
      expect(missing.status).toBe(401);
      const withBodyUser = await post(BASE, 'complete', { protocol: 1, request_id: device.requestId, device_secret: device.deviceSecret, user_id: randomUUID() }, { authorization: `Bearer ${jwt}` });
      expect(withBodyUser.status).toBe(400);
      expect((await device.complete(jwt)).json.phase).toBe('device_confirmed');
    });

    it('S06b: a session older than the request cannot complete it', async () => {
      const first = await flowToCode(BASE, stack.SAFEAUTH_ANON_KEY, ORIGIN);
      const old = await first.device.exchange(String((await first.device.poll()).json.auth_code));
      psql(`update private.community_auth_requests set created_at = now() - interval '5 minutes', expires_at = now() + interval '5 minutes'`, { env: stack });
      const second = await flowToCode(BASE, stack.SAFEAUTH_ANON_KEY, ORIGIN);
      await second.device.poll();
      const staleToken = sign({ ...payloadOf(String(old.json.access_token)), iat: Math.floor(Date.now() / 1000) - 3000 }, stack.SAFEAUTH_JWT_SECRET);
      const r = await second.device.complete(staleToken);
      expect([401, 409]).toContain(r.status);
    });

    it('S07: identical publish is idempotent; a different code cannot overwrite', async () => {
      const { browser, code } = await flowToCode(BASE, stack.SAFEAUTH_ANON_KEY, ORIGIN);
      expect((await browser.publish({ outcome: 'code', code })).status).toBe(200);
      const other = await browser.publish({ outcome: 'code', code: randomUUID() });
      expect(other.status).toBe(409);
      expect((other.json.error as Record<string, unknown>).code).toBe('code_conflict');
      const deny = await browser.publish({ outcome: 'denied' });
      expect(deny.status).toBe(409);
    });

    it('S08: concurrent claims and polls keep one winner', async () => {
      const device = new Device(BASE, stack.SAFEAUTH_ANON_KEY);
      expectOk(await device.create());
      const browsers = Array.from({ length: 8 }, (_, i) => { const b = new Browser(BASE, ORIGIN, `198.51.100.${40 + i}`); b.open(device.bootstrapUrl); return b; });
      const claims = await Promise.all(browsers.map(b => b.claim()));
      expect(claims.filter(r => r.status === 200)).toHaveLength(1);
      const { device: d2 } = await flowToCode(BASE, stack.SAFEAUTH_ANON_KEY, ORIGIN);
      const keys = Array.from({ length: 6 }, () => randomSecret());
      const polls = await Promise.all(keys.map(k => d2.poll(k)));
      expect(polls.filter(r => r.json.status === 'code')).toHaveLength(1);
      expect(polls.filter(r => r.status === 409)).toHaveLength(5);
    });

    it('S09: lost poll response is recoverable only with the pinned delivery key', async () => {
      const { device, code } = await flowToCode(BASE, stack.SAFEAUTH_ANON_KEY, ORIGIN);
      expect((await device.poll()).json.auth_code).toBe(code);
      expect((await device.poll()).json.auth_code).toBe(code);
      expect((await device.poll(randomSecret())).status).toBe(409);
    });

    it('S10: expiry is enforced from the DB clock and never reactivated', async () => {
      const { device, browser } = await flowToCode(BASE, stack.SAFEAUTH_ANON_KEY, ORIGIN);
      psql(`update private.community_auth_requests set expires_at = now() - interval '1 second', code_expires_at = now() - interval '2 seconds', created_at = now() - interval '11 minutes' where id='${device.requestId}'`, { env: stack });
      expect((await device.poll()).json.status).toBe('expired');
      expect((await browser.status()).json.phase).toBe('expired');
      expect((await browser.publish({ outcome: 'denied' })).status).toBe(410);
      expect((await browser.prepare()).status).toBe(410);
      expect((await device.cancel()).json.phase).toBe('expired');
      const wiped = psql(`select encrypted_auth_code is null, status from private.community_auth_requests where id='${device.requestId}'`, { env: stack, tuplesOnly: true }).trim();
      expect(wiped).toBe('t|expired');
    });

    it('S11/S12: creation is rate limited with Retry-After, and state survives a new relay instance', async () => {
      const ip = '192.0.2.77';
      const results = [];
      for (let i = 0; i < 11; i += 1) results.push(await new Device(BASE, stack.SAFEAUTH_ANON_KEY, 'rl', 'pc', ip).create());
      const limited = results.at(-1)!;
      expect(limited.status).toBe(429);
      expect(Number(limited.headers.get('retry-after'))).toBeGreaterThan(0);
      expect((limited.json.error as Record<string, unknown>).retryAfterSeconds).toBeGreaterThan(0);
      // A second relay instance on another port shares the DB-backed limit and state.
      const second = await startGateway({ port: PORTS.gateway + 7 });
      try {
        const base2 = `http://127.0.0.1:${PORTS.gateway + 7}`;
        const again = await new Device(base2, stack.SAFEAUTH_ANON_KEY, 'rl', 'pc', ip).create();
        expect(again.status).toBe(429);
        const device = new Device(BASE, stack.SAFEAUTH_ANON_KEY);
        expectOk(await device.create());
        const b = new Browser(base2, ORIGIN);
        b.open(device.bootstrapUrl);
        expect((await b.claim()).json.phase).toBe('claimed');
      } finally {
        await new Promise(r => second.server.close(r));
      }
    });

    it('S14: relay logs and gateway error bodies never contain secrets or codes', async () => {
      const { device, browser, code } = await flowToCode(BASE, stack.SAFEAUTH_ANON_KEY, ORIGIN);
      await device.poll();
      await post(BASE, 'poll', { protocol: 1, request_id: device.requestId, device_secret: 'x', delivery_key: 'y' });
      const dump = JSON.stringify(gateway.logs);
      for (const secret of [code, device.deviceSecret, device.verifier, browser.browserSecret, browser.ticket]) {
        expect(dump).not.toContain(secret);
      }
      const stored = psql('select row_to_json(r)::text from private.community_auth_requests r', { env: stack });
      for (const secret of [code, device.deviceSecret, device.verifier, browser.browserSecret, browser.ticket, device.deliveryKey]) {
        expect(stored).not.toContain(secret);
      }
    });

    it('S15: missing, placeholder or wrong encryption keys fail closed', async () => {
      const broken = await startGateway({ port: PORTS.gateway + 8, overrides: { AUTH_RELAY_ENCRYPTION_KEY: 'REPLACE_WITH_SERVER_SECRET' } });
      try {
        const r = await new Device(`http://127.0.0.1:${PORTS.gateway + 8}`, stack.SAFEAUTH_ANON_KEY).create();
        expect(r.status).toBe(503);
        expect((r.json.error as Record<string, unknown>).code).toBe('config_missing');
      } finally { await new Promise(r => broken.server.close(r)); }
      const { device } = await flowToCode(BASE, stack.SAFEAUTH_ANON_KEY, ORIGIN);
      const rotated = await startGateway({ port: PORTS.gateway + 9, overrides: { AUTH_RELAY_ENCRYPTION_KEY: randomSecret() } });
      try {
        const other = new Device(`http://127.0.0.1:${PORTS.gateway + 9}`, stack.SAFEAUTH_ANON_KEY);
        Object.assign(other, { requestId: device.requestId, deviceSecret: device.deviceSecret, deliveryKey: device.deliveryKey });
        const r = await other.poll();
        expect(r.status).toBe(500);
        expect(JSON.stringify(r.json)).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-/); // no code leaked
      } finally { await new Promise(r => rotated.server.close(r)); }
      const tamper = await flowToCode(BASE, stack.SAFEAUTH_ANON_KEY, ORIGIN);
      psql(`update private.community_auth_requests set encrypted_auth_code = overlay(encrypted_auth_code placing case when substr(encrypted_auth_code, length(encrypted_auth_code) - 6, 1) = 'A' then 'B' else 'A' end from length(encrypted_auth_code) - 6 for 1) where id='${tamper.device.requestId}'`, { env: stack });
      expect((await tamper.device.poll()).status).toBe(500);
    });

    it('S16: markup/URL labels, unknown fields and caller-supplied URLs are rejected', async () => {
      for (const label of ['<img src=x onerror=alert(1)>', 'javascript:alert(1)', 'a‮b', '', 'x'.repeat(41)]) {
        expect((await new Device(BASE, stack.SAFEAUTH_ANON_KEY, label, 'pc', '192.0.2.90').create()).status, label).toBe(400);
      }
      const extra = await new Device(BASE, stack.SAFEAUTH_ANON_KEY, 'ok', 'pc', '192.0.2.91').create({ redirect_to: 'https://evil.invalid' });
      expect(extra.status).toBe(400);
      const device = new Device(BASE, stack.SAFEAUTH_ANON_KEY, 'ok', 'pc', '192.0.2.92');
      expectOk(await device.create());
      expect(device.bootstrapUrl.startsWith(`${ORIGIN}/#r=`)).toBe(true);
      const b = new Browser(BASE, ORIGIN);
      b.open(device.bootstrapUrl);
      await b.claim();
      const withUrl = await post(BASE, 'prepare', { protocol: 1, request_id: b.requestId, browser_secret: b.browserSecret, confirmed_started_by_me: true, authorize_url: 'https://evil.invalid' }, { origin: ORIGIN });
      expect(withUrl.status).toBe(400);
      const unconfirmed = await post(BASE, 'prepare', { protocol: 1, request_id: b.requestId, browser_secret: b.browserSecret, confirmed_started_by_me: false }, { origin: ORIGIN });
      expect(unconfirmed.status).toBe(400);
      const prepared = expectOk(await b.prepare());
      const url = new URL(String(prepared.json.authorize_url));
      expect(url.origin + url.pathname).toBe(`${BASE}/auth/v1/authorize`);
      expect(url.searchParams.get('redirect_to')).toBe(`${ORIGIN}/callback.html`);
    });

    it('S17: CORS allows only the exact central origin; native callers without Origin still need capabilities', async () => {
      const pre = await fetch(`${BASE}/functions/v1/community-auth-relay/claim`, { method: 'OPTIONS', headers: { origin: ORIGIN, 'access-control-request-method': 'POST' } });
      expect(pre.status).toBe(204);
      expect(pre.headers.get('access-control-allow-origin')).toBe(ORIGIN);
      const evil = await post(BASE, 'claim', { protocol: 1 }, { origin: 'https://evil.invalid' });
      expect(evil.status).toBe(403);
      expect(evil.headers.get('access-control-allow-origin')).toBeNull();
      const withPath = await post(BASE, 'claim', { protocol: 1 }, { origin: `${ORIGIN}/safeauth` });
      expect(withPath.status).toBe(403);
      const native = await post(BASE, 'claim', { protocol: 1, request_id: randomUUID(), ticket: randomSecret(), browser_secret: randomSecret() });
      expect(native.status).toBe(404);
      const get = await fetch(`${BASE}/functions/v1/community-auth-relay/claim`);
      expect(get.status).toBe(405);
      for (const response of [evil, native]) expect(response.headers.get('cache-control')).toBe('no-store');
    });

    it('cancel is idempotent, blocked after completion, and a cancelled request cannot restart', async () => {
      const device = new Device(BASE, stack.SAFEAUTH_ANON_KEY);
      expectOk(await device.create());
      const b = new Browser(BASE, ORIGIN);
      b.open(device.bootstrapUrl);
      await b.claim();
      const byBrowser = await post(BASE, 'cancel', { protocol: 1, request_id: b.requestId, actor: 'browser', secret: b.browserSecret }, { origin: ORIGIN });
      expect(byBrowser.json.phase).toBe('cancelled');
      expect((await device.cancel()).json.phase).toBe('cancelled');
      expect((await b.prepare()).status).toBe(409);
      expect((await device.poll()).json).toMatchObject({ status: 'cancelled', reason: 'browser' });
      const done = await flowToCode(BASE, stack.SAFEAUTH_ANON_KEY, ORIGIN);
      await done.device.exchange(String((await done.device.poll()).json.auth_code));
      await done.device.complete();
      expect((await done.device.cancel()).status).toBe(409);
    });

    it('create is idempotent per device secret and rotates the unseen ticket', async () => {
      const device = new Device(BASE, stack.SAFEAUTH_ANON_KEY, 'retry', 'docker', '192.0.2.120');
      expectOk(await device.create({ installation_id: randomSecret(18) }));
      const firstUrl = device.bootstrapUrl;
      const firstId = device.requestId;
      const retry = expectOk(await device.create());
      expect(retry.status).toBe(200);
      expect(device.requestId).toBe(firstId);
      expect(device.bootstrapUrl).not.toBe(firstUrl);
      const stale = new Browser(BASE, ORIGIN);
      stale.open(firstUrl);
      expect((await stale.claim()).status).toBe(404);
      const fresh = new Browser(BASE, ORIGIN);
      fresh.open(device.bootstrapUrl);
      expect((await fresh.claim()).status).toBe(200);
      expect((await device.create()).status).toBe(409); // claimed: not reusable
    });

    it('per-installation pending cap', async () => {
      const installation_id = randomSecret(18);
      const statuses = [];
      for (let i = 0; i < 4; i += 1) statuses.push((await new Device(BASE, stack.SAFEAUTH_ANON_KEY, 'cap', 'pc', `192.0.2.${130 + i}`).create({ installation_id })).status);
      expect(statuses).toEqual([201, 201, 201, 429]);
    });
  });
});
