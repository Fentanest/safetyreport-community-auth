// Regressions for the 2026-10-04 review (safetyreport tech log D1-03, D1-04, D1-06, D1-08, D1-09, D1-10, D1-11, F-04).
// No containers: site text against the policy migrations, adapter error codes, label validation parity and the
// central page flow controller with a stub view and a stub relay.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RepositoryError, rpcFrom } from '../server/adapters.ts';
import { createAccountHandler } from '../server/account.ts';
import { normalizeDeviceLabel } from '../server/protocol.ts';

const root = join(__dirname, '..');
const read = (p: string) => readFileSync(join(root, p), 'utf8');

describe('central pages state the current policy (D1-04, D1-10)', () => {
  const policyVersions = () => readdirSync(join(root, 'supabase/migrations'))
    .filter(f => /_policy_\d{4}_\d{2}_\d{2}_\d+\.sql$/.test(f)).sort()
    .map(f => /정책 버전: (\d{4}-\d{2}-\d{2}\.\d+)/.exec(read(`supabase/migrations/${f}`))?.[1])
    .filter((v): v is string => !!v);

  it('privacy page names the policy version that the newest migration makes current, and no older one', () => {
    const versions = policyVersions();
    expect(versions.length).toBeGreaterThan(0);
    const privacy = read('site/privacy.html');
    expect(privacy).toContain(`정책 버전 ${versions[versions.length - 1]}`);
    for (const old of versions.slice(0, -1)) expect(privacy).not.toContain(`정책 버전 ${old})`);
  });

  it('privacy and help describe the shared items and the 10-report viewer rule of the current policy', () => {
    for (const page of ['site/privacy.html', 'site/help.html']) {
      const text = read(page);
      expect(text, page).toContain('10건 이상');
      expect(text, page).not.toContain('한 건 이상');
      expect(text, page).toContain('위반 법률 이름과 조항');
      expect(text, page).toContain('별점사유');
    }
  });

  it('privacy page describes the real code lifetime instead of a fixed two-minute delete', () => {
    const privacy = read('site/privacy.html');
    expect(privacy).not.toContain('최대 2분 동안만 보관');
    expect(privacy).toContain('30초~4분');
    expect(privacy).not.toContain('인증 코드는 기기가 가져가거나 만료되면 즉시 지웁니다');
  });
});

describe('relay-only local stack skips every migration that needs the account registry (D1-06)', () => {
  it('lists each registry-dependent file', () => {
    const stack = read('tests/stack/stack.mjs');
    for (const f of readdirSync(join(root, 'supabase/migrations'))) {
      const sql = read(`supabase/migrations/${f}`);
      const usesRegistry = /private\.community_(policies|policy_current|policy_texts|consent_grants|current_policy)\b/.test(sql)
        && !/create table private\.community_policies\b/.test(sql);
      if (usesRegistry) expect(stack, f).toContain(`'${f}'`);
    }
  });
});

describe('repository errors keep only a safe SQLSTATE (D1-08)', () => {
  it('maps a deadlock from the real adapter to 503 busy', async () => {
    const rpc = rpcFrom({
      rpc: async () => ({ data: null, error: { code: '40P01', message: 'deadlock detected: secret table names' } }),
      auth: { getUser: async () => ({ data: { user: null }, error: null }) },
    });
    const error = await rpc('x', {}).catch(e => e);
    expect(error).toBeInstanceOf(RepositoryError);
    expect(String(error)).not.toContain('secret');
    expect((error as RepositoryError).retryable).toBe(true);

    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const token = `${b64({ alg: 'ES256' })}.${b64({ sub: '6f37df54-911b-4c37-8020-a0b45a84591d', role: 'authenticated',
      aud: 'authenticated', iss: 'https://p.supabase.co/auth/v1', session_id: '0b1c2d3e-4f50-4a61-8b72-9c8d7e6f5a4b', is_anonymous: false })}.sig`;
    const handler = createAccountHandler({
      enabled: true, jwtIssuer: 'https://p.supabase.co/auth/v1',
      getUser: async () => ({ id: '6f37df54-911b-4c37-8020-a0b45a84591d', isAnonymous: false, displayName: 'x' }),
      rpc: async name => {
        if (name === 'internal_safeauth_rate_limit') return { allowed: true, retry_after: 1 };
        throw new RepositoryError('40P01');
      },
    });
    const res = await handler(new Request('https://p.supabase.co/functions/v1/community-account/status', {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ protocol: 1 }),
    }));
    expect(res.status).toBe(503);
    expect((await res.json()).error.code).toBe('busy');
  });

  it('other repository errors stay a generic 500', async () => {
    const error = new RepositoryError('23505');
    expect(error.retryable).toBe(false);
    expect(error.message).toBe('relay repository unavailable');
  });
});

describe('one device-label rule for relay and account (D1-11)', () => {
  it('account rejects what the relay rejects', async () => {
    for (const label of ['기기\u0085이름', 'a​b', 'x<y', 'javascript:x', '']) {
      expect(normalizeDeviceLabel(label), JSON.stringify(label)).toBeNull();
    }
    const account = read('server/account.ts');
    expect(account).toContain('normalizeDeviceLabel(v)');
    expect(account).not.toMatch(/u007f‪-‮/);
  });
});

describe('central page flow (D1-03, D1-07, D1-09, F-04)', () => {
  type Rendered = { kind: string };
  let rendered: Rendered[];
  let saved: unknown[];
  let cleared: number;

  beforeEach(() => {
    rendered = []; saved = []; cleared = 0;
    vi.useFakeTimers();
    vi.stubGlobal('document', { visibilityState: 'visible', baseURI: 'https://safeauth.worklazy.net/' });
    vi.stubGlobal('window', { setTimeout, clearTimeout, location: { assign: () => {} } });
    vi.stubGlobal('sessionStorage', {
      setItem: (_k: string, v: string) => { saved.push(v); }, getItem: () => null, removeItem: () => { cleared += 1; },
    });
  });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.resetModules(); vi.doUnmock('../site/src/api.ts'); });

  async function controller(responses: Array<() => Promise<unknown>>) {
    vi.doMock('../site/src/api.ts', () => ({ call: vi.fn(() => (responses.shift() ?? (() => new Promise(() => {})))()) }));
    const { FlowController } = await import('../site/src/flow.ts');
    const view = { render: (s: Rendered) => { rendered.push(s); }, stopCountdown: () => {}, onExpire: null as null | (() => void) };
    const flow = { requestId: 'r', browserSecret: 's', phase: 'code_ready', deviceLabel: '이 PC', clientKind: 'pc', displayCode: 'ABCD-EFGH',
      expiresAt: new Date(Date.now() + 60000).toISOString() };
    return new FlowController({ supabaseUrl: 'https://p', callbackUrl: 'https://c', relayBase: 'https://p/r' } as never, view as never, flow as never);
  }

  it('a poll that answers after the flow finished does not bring back the waiting screen or the secret', async () => {
    let answer: (v: unknown) => void = () => {};
    const ctrl = await controller([() => new Promise(resolve => { answer = resolve; })]);
    ctrl.route('code_ready');
    const savesBefore = saved.length;
    await vi.advanceTimersByTimeAsync(4000); // poll in flight
    ctrl.finish('expired');
    answer({ ok: true, data: { phase: 'code_delivered' } });
    await vi.runOnlyPendingTimersAsync();
    expect(rendered[rendered.length - 1].kind).toBe('expired');
    expect(saved.length).toBe(savesBefore);
  });

  it('returning in oauth_started keeps checking so expiry is noticed', async () => {
    const ctrl = await controller([async () => ({ ok: true, data: { phase: 'expired' } })]);
    ctrl.route('oauth_started');
    await vi.advanceTimersByTimeAsync(4000);
    expect(rendered[rendered.length - 1].kind).toBe('expired');
  });

  it('honours a Retry-After longer than its own backoff cap', async () => {
    let calls = 0;
    const ctrl = await controller([]);
    ctrl.handleError({ ok: false, kind: 'relay', code: 'rate_limited', retryAfterSeconds: 42, traceId: null } as never, () => { calls += 1; });
    await vi.advanceTimersByTimeAsync(30000);
    expect(calls).toBe(0);
    await vi.advanceTimersByTimeAsync(12500);
    expect(calls).toBe(1);
  });

  it('does not print the device name twice when it equals the kind label', () => {
    const view = read('site/src/view.ts');
    expect(view).toContain("pc: ['PC 프로그램', 'LOCAL']");
    expect(view).toContain('if (kindText !== device.label)');
  });
});
