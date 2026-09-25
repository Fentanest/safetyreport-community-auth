// community-account handler without containers: auth, claims, rate limit, strict bodies, RPC arguments, error mapping.
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createAccountHandler } from '../server/account.ts';

const UID = '6f37df54-911b-4c37-8020-a0b45a84591d';
const SID = '0b1c2d3e-4f50-4a61-8b72-9c8d7e6f5a4b';
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (claims: Record<string, unknown>) => `${b64({ alg: 'ES256' })}.${b64(claims)}.sig`;
const good = { sub: UID, role: 'authenticated', aud: 'authenticated', iss: 'https://p.supabase.co/auth/v1', session_id: SID, is_anonymous: false };

type Call = { name: string; args: Record<string, unknown> };
function setup(opts: { user?: unknown; userThrows?: boolean; rpc?: (n: string, a: Record<string, unknown>) => unknown; issuer?: string | null } = {}) {
  const calls: Call[] = [];
  const handler = createAccountHandler({
    enabled: true, jwtIssuer: opts.issuer === undefined ? 'https://p.supabase.co/auth/v1' : opts.issuer,
    getUser: async () => { if (opts.userThrows) throw new Error('down'); return (opts.user === undefined ? { id: UID, isAnonymous: false, displayName: '민지' } : opts.user) as never; },
    rpc: async (name, args) => {
      calls.push({ name, args });
      if (name === 'internal_safeauth_rate_limit') return { allowed: true, retry_after: 1 };
      return opts.rpc ? opts.rpc(name, args) : { ok: true };
    },
  });
  return { calls, handler };
}
const req = (action: string, body: unknown, token: string | null = jwt(good), extra: Record<string, string> = {}) =>
  new Request(`https://p.supabase.co/functions/v1/community-account/${action}`, { method: 'POST',
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...extra },
    body: typeof body === 'string' ? body : JSON.stringify(body) });
const errorCode = async (r: Response) => (await r.json()).error.code;

describe('community-account handler', () => {
  it('requires POST, a bearer JWT and protocol 1', async () => {
    const { handler } = setup();
    expect((await handler(new Request('https://x/functions/v1/community-account/status'))).status).toBe(405);
    expect(await errorCode(await handler(req('status', { protocol: 1 }, null)))).toBe('auth_required');
    expect(await errorCode(await handler(req('status', { protocol: 1 }, 'sb_publishable_abc')))).toBe('auth_required');
    expect(await errorCode(await handler(req('status', { protocol: 2 })))).toBe('unsupported_protocol');
    expect(await errorCode(await handler(req('nope', { protocol: 1 })))).toBe('not_found');
  });

  it('rejects tokens Auth refuses, claim mismatches, other issuers and anonymous users', async () => {
    expect(await errorCode(await setup({ user: null }).handler(req('status', { protocol: 1 })))).toBe('auth_required');
    expect((await setup({ userThrows: true }).handler(req('status', { protocol: 1 }))).status).toBe(503);
    expect(await errorCode(await setup().handler(req('status', { protocol: 1 }, jwt({ ...good, sub: 'someone-else' }))))).toBe('auth_required');
    expect(await errorCode(await setup().handler(req('status', { protocol: 1 }, jwt({ ...good, role: 'service_role' }))))).toBe('auth_required');
    expect(await errorCode(await setup().handler(req('status', { protocol: 1 }, jwt({ ...good, iss: 'https://other.supabase.co/auth/v1' }))))).toBe('auth_required');
    expect(await errorCode(await setup().handler(req('status', { protocol: 1 }, jwt({ ...good, session_id: undefined }))))).toBe('auth_required');
    expect(await errorCode(await setup().handler(req('status', { protocol: 1 }, jwt({ ...good, is_anonymous: true }))))).toBe('kakao_required');
    expect(await errorCode(await setup({ user: { id: UID, isAnonymous: true, displayName: null } }).handler(req('status', { protocol: 1 })))).toBe('kakao_required');
  });

  it('never takes the user from the body and returns a fingerprint instead of the user id', async () => {
    const { handler, calls } = setup({ rpc: () => ({ gate: { can_enter: true } }) });
    expect(await errorCode(await handler(req('status', { protocol: 1, user_id: 'x' })))).toBe('invalid_request');
    const res = await handler(req('status', { protocol: 1 }));
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
    const call = calls.find(c => c.name === 'internal_account_status')!;
    expect(call.args).toEqual({ p_user: UID, p_session: SID, p_connection: null });
    expect(body.account.fingerprint).toBe(createHash('sha256').update(`sr-community-account|v1|${UID}`).digest('hex').slice(0, 32));
    expect(JSON.stringify(body)).not.toContain(UID);
  });

  it('rate limits per user with Retry-After', async () => {
    const handler = createAccountHandler({ enabled: true, jwtIssuer: null, getUser: async () => ({ id: UID, isAnonymous: false, displayName: null }),
      rpc: async name => (name === 'internal_safeauth_rate_limit' ? { allowed: false, retry_after: 42 } : {}) });
    const res = await handler(req('status', { protocol: 1 }));
    expect(res.status).toBe(429);
    expect(res.headers.get('retry-after')).toBe('42');
  });

  it('consent needs an explicit accepted:true and a known channel', async () => {
    const { handler, calls } = setup({ rpc: () => ({ grant_id: 'g', created: true }) });
    const base = { protocol: 1, policy_version: '2026-09-26.1', consent_text_sha256: 'a'.repeat(64), via: 'mobile_standalone' };
    expect(await errorCode(await handler(req('consent', { ...base, accepted: false })))).toBe('invalid_request');
    expect(await errorCode(await handler(req('consent', { ...base, via: 'web', accepted: true })))).toBe('invalid_request');
    expect((await handler(req('consent', { ...base, accepted: true }))).status).toBe(200);
    expect(calls.find(c => c.name === 'internal_account_grant_consent')!.args.p_via).toBe('mobile_standalone');
  });

  it('stores only the hash of the connection secret and validates the writer shape', async () => {
    const { handler, calls } = setup({ rpc: () => ({ connection_id: 'c', writer_epoch: 7 }) });
    const secret = 'A'.repeat(43);
    const body = { protocol: 1, source_app: 'safetyreport', source_mode: 'server', platform: 'docker', device_label: '우리집 NAS',
      dataset_key: 'b'.repeat(64), connection_secret: secret, takeover: false };
    expect(await errorCode(await handler(req('connections', { ...body, source_mode: 'standalone' })))).toBe('invalid_request');
    expect(await errorCode(await handler(req('connections', { ...body, device_label: '<script>' })))).toBe('invalid_request');
    expect((await handler(req('connections', body))).status).toBe(200);
    const args = calls.find(c => c.name === 'internal_account_register_connection')!.args;
    expect(args.p_secret_sha256).toBe(createHash('sha256').update(secret).digest('hex'));
    expect(JSON.stringify(args)).not.toContain(secret);
  });

  it('maps SQL outcomes to contract errors', async () => {
    const conflict = setup({ rpc: n => (n === 'internal_account_register_connection' ? { error: 'writer_conflict', active_writer: { device_label: 'PC', platform: 'windows' } } : {}) });
    const res = await conflict.handler(req('connections', { protocol: 1, source_app: 'safetyreport-mobile', source_mode: 'standalone', platform: 'android',
      device_label: 'phone', dataset_key: 'c'.repeat(64), connection_secret: 'B'.repeat(43), takeover: false }));
    expect(res.status).toBe(409);
    expect((await res.json()).error.active_writer.device_label).toBe('PC');
    const stale = setup({ rpc: () => ({ error: 'stale_grant' }) });
    const r2 = await stale.handler(req('consent-revoke', { protocol: 1, grant_id: '11111111-2222-3333-4444-555555555555' }));
    expect(r2.status).toBe(409); expect((await r2.json()).error.code).toBe('stale_grant');
    const weird = setup({ rpc: () => ({ error: 'something_internal' }) });
    const r3 = await weird.handler(req('consent-revoke', { protocol: 1, grant_id: '11111111-2222-3333-4444-555555555555' }));
    expect(r3.status).toBe(500); expect(JSON.stringify(await r3.json())).not.toContain('something_internal');
    const busy = setup({ rpc: () => { throw new Error('40P01 deadlock detected'); } });
    expect((await busy.handler(req('consent-revoke', { protocol: 1, grant_id: '11111111-2222-3333-4444-555555555555' }))).status).toBe(503);
  });

  it('deletion needs the typed confirmation', async () => {
    const { handler, calls } = setup({ rpc: () => ({ deletion_id: 'd', deleted_facts: 2 }) });
    expect(await errorCode(await handler(req('contributions-delete', { protocol: 1, confirm: 'yes' })))).toBe('invalid_request');
    expect((await handler(req('contributions-delete', { protocol: 1, confirm: 'DELETE_MY_SHARED_REPORTS' }))).status).toBe(200);
    expect(calls.find(c => c.name === 'internal_community_delete_contributions')!.args).toEqual({ p_user: UID, p_session: SID });
  });
});
