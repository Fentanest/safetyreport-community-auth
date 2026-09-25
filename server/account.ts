// Runtime-agnostic handler for the user-only `community-account` function: gate status, share consent,
// writer connection registry and deletion of shared reports. Contract: safetyreport-community-map
// contracts/community-ingest/account-api.md. Every action requires a user JWT that Supabase Auth accepts
// (getUser: signature, expiry, session existence) plus claims checks; the SQL RPCs re-check identity,
// session and consent inside their transactions. Never logs bodies, tokens or user ids.

import { decodeJwtPayload } from './crypto.ts';

export type Rpc = (name: string, args: Record<string, unknown>) => Promise<unknown>;

export interface AccountUser { id: string; isAnonymous: boolean; displayName: string | null }

export interface AccountDeps {
  rpc: Rpc;
  // Supabase Auth /user for the token: the user when accepted, null when rejected (401/403/404), throws when down.
  getUser(accessToken: string): Promise<AccountUser | null>;
  jwtIssuer: string | null;   // enforced when set (hosted: https://<ref>.supabase.co/auth/v1)
  enabled: boolean;
  log?(entry: Record<string, string | number>): void;
}

export const ACCOUNT_ACTIONS = ['status', 'consent', 'consent-revoke', 'connections', 'connections-rebind',
  'connections-revoke', 'contributions-delete'] as const;
type Action = typeof ACCOUNT_ACTIONS[number];

type Code = 'invalid_request' | 'unsupported_protocol' | 'method_not_allowed' | 'not_found' | 'auth_required' |
  'kakao_required' | 'policy_mismatch' | 'contributor_suspended' | 'writer_conflict' | 'connection_revoked' |
  'connection_superseded' | 'connection_suspended' | 'stale_grant' | 'rate_limited' | 'busy' | 'service_disabled' | 'server_error';

const STATUS: Record<Code, number> = {
  invalid_request: 400, unsupported_protocol: 400, method_not_allowed: 405, not_found: 404, auth_required: 401,
  kakao_required: 403, policy_mismatch: 409, contributor_suspended: 403, writer_conflict: 409,
  connection_revoked: 409, connection_superseded: 409, connection_suspended: 409, stale_grant: 409, rate_limited: 429, busy: 503,
  service_disabled: 503, server_error: 500,
};
const RETRYABLE = new Set<Code>(['rate_limited', 'busy', 'server_error']);
const MESSAGES: Record<Code, string> = {
  invalid_request: 'Request body is not valid for this action.', unsupported_protocol: 'Unsupported protocol version.',
  method_not_allowed: 'Only POST is supported.', not_found: 'Not found.',
  auth_required: 'A valid community sign-in is required.', kakao_required: 'A Kakao-linked community account is required.',
  policy_mismatch: 'The share-consent policy version does not match the current policy.',
  contributor_suspended: 'This community account is suspended.', writer_conflict: 'Another device is the active uploader.',
  connection_revoked: 'This device link was revoked.', connection_superseded: 'Another device took over uploading.',
  connection_suspended: 'This device link is suspended.',
  stale_grant: 'That consent was already closed; reload the current consent status.', rate_limited: 'Too many requests.',
  busy: 'Service is busy, retry shortly.', service_disabled: 'Community account service is not enabled.',
  server_error: 'Unexpected error.',
};

class Failure extends Error {
  constructor(readonly code: Code, readonly extra: Record<string, unknown> = {}, readonly retryAfter?: number) { super(code); }
}
const fail = (code: Code, extra: Record<string, unknown> = {}, retryAfter?: number): never => { throw new Failure(code, extra, retryAfter); };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SECRET = /^[A-Za-z0-9_-]{43}$/;
const MAX_BODY = 8192;

function traceId(): string {
  const b = new Uint8Array(12); crypto.getRandomValues(b);
  return [...b].map(x => x.toString(16).padStart(2, '0')).join('');
}

function json(status: number, body: unknown, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: {
    'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
    ...extraHeaders } });
}

async function sha256Hex(text: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}

type Body = Record<string, unknown>;
function keys(body: Body, required: string[], optional: string[] = []): void {
  const allowed = new Set(['protocol', ...required, ...optional]);
  for (const k of Object.keys(body)) if (!allowed.has(k)) fail('invalid_request');
  for (const k of required) if (!(k in body)) fail('invalid_request');
}
const str = (v: unknown, re: RegExp): string => (typeof v === 'string' && re.test(v) ? v : fail('invalid_request'));

function normalizeLabel(v: unknown): string {
  if (typeof v !== 'string') return fail('invalid_request');
  const s = v.normalize('NFC').replace(/\s+/g, ' ').trim();
  if (s.length < 1 || [...s].length > 40 || /[\u0000-\u001f\u007f‪-‮⁦-⁩<>"'`\\]/.test(s) || /^[a-z][a-z0-9+.-]*:/i.test(s)) {
    return fail('invalid_request');
  }
  return s;
}

function rpcError(result: Record<string, unknown>): never {
  const code = String(result.error ?? 'server_error');
  const known: Record<string, Code> = {
    kakao_required: 'kakao_required', policy_mismatch: 'policy_mismatch', contributor_suspended: 'contributor_suspended',
    writer_conflict: 'writer_conflict', not_found: 'not_found', connection_revoked: 'connection_revoked',
    connection_superseded: 'connection_superseded', connection_suspended: 'connection_suspended', invalid_request: 'invalid_request',
    stale_grant: 'stale_grant',
  };
  const extra: Record<string, unknown> = {};
  if (result.active_writer) extra.active_writer = result.active_writer;
  if (result.required_version) extra.required_version = result.required_version;
  return fail(known[code] ?? 'server_error', extra);
}

export function createAccountHandler(deps: AccountDeps): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    const trace = traceId();
    let action = 'unknown';
    try {
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
      if (request.method !== 'POST') fail('method_not_allowed');
      if (!deps.enabled) fail('service_disabled');
      const path = new URL(request.url).pathname.replace(/\/+$/, '');
      const name = path.slice(path.lastIndexOf('/') + 1);
      if (!(ACCOUNT_ACTIONS as readonly string[]).includes(name)) fail('not_found');
      action = name;
      if (!(request.headers.get('content-type') || '').toLowerCase().startsWith('application/json')) fail('invalid_request');
      const auth = request.headers.get('authorization') || '';
      const m = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/.exec(auth);
      if (!m) fail('auth_required');
      const token = m![1];
      const raw = await request.text();
      if (new TextEncoder().encode(raw).length > MAX_BODY) fail('invalid_request');
      let body: Body;
      try { body = JSON.parse(raw); } catch { return fail('invalid_request'); }
      if (!body || typeof body !== 'object' || Array.isArray(body)) fail('invalid_request');
      if (body.protocol !== 1) fail('unsupported_protocol');

      let user: AccountUser | null;
      try { user = await deps.getUser(token); } catch { return fail('busy'); }
      if (!user) fail('auth_required');
      const claims = decodeJwtPayload(token) as Record<string, unknown> | null;
      if (!claims || claims.sub !== user!.id || claims.role !== 'authenticated' || claims.aud !== 'authenticated') fail('auth_required');
      if (deps.jwtIssuer && claims!.iss !== deps.jwtIssuer) fail('auth_required');
      if (claims!.is_anonymous === true || user!.isAnonymous) fail('kakao_required');
      const session = typeof claims!.session_id === 'string' && UUID.test(claims!.session_id) ? claims!.session_id : fail('auth_required');
      const uid = user!.id;

      const limit = await deps.rpc('internal_safeauth_rate_limit', {
        p_bucket: `sa:account:${await sha256Hex(`account|${uid}`)}`, p_limit: 30, p_window_seconds: 60 }) as Record<string, unknown>;
      if (limit?.allowed !== true) fail('rate_limited', {}, Number(limit?.retry_after) || 60);

      const call = async (fn: string, args: Record<string, unknown>) => {
        const result = await deps.rpc(fn, args) as Record<string, unknown>;
        if (result && typeof result === 'object' && 'error' in result) rpcError(result);
        return result;
      };
      let out: Record<string, unknown>;
      switch (action as Action) {
        case 'status': {
          keys(body, [], ['connection_id']);
          const connection = body.connection_id === undefined ? null : str(body.connection_id, UUID);
          const s = await call('internal_account_status', { p_user: uid, p_session: session, p_connection: connection });
          out = { ...s, account: { fingerprint: (await sha256Hex(`sr-community-account|v1|${uid}`)).slice(0, 32),
            display_name: user!.displayName }, server_time: new Date().toISOString() };
          break;
        }
        case 'consent': {
          keys(body, ['policy_version', 'consent_text_sha256', 'via', 'accepted']);
          if (body.accepted !== true) fail('invalid_request');
          const via = body.via;
          if (via !== 'safetyreport_server' && via !== 'mobile_standalone' && via !== 'mobile_client') fail('invalid_request');
          out = await call('internal_account_grant_consent', { p_user: uid, p_session: session,
            p_policy_version: str(body.policy_version, /^[0-9]{4}-[0-9]{2}-[0-9]{2}\.[0-9]{1,3}$/),
            p_text_sha256: str(body.consent_text_sha256, HEX64), p_via: via });
          break;
        }
        case 'consent-revoke':
          keys(body, ['grant_id']);
          out = await call('internal_account_revoke_consent', { p_user: uid, p_session: session, p_grant: str(body.grant_id, UUID) });
          break;
        case 'connections': {
          keys(body, ['source_app', 'source_mode', 'platform', 'device_label', 'dataset_key', 'connection_secret', 'takeover']);
          const pair = `${body.source_app}/${body.source_mode}`;
          if (pair !== 'safetyreport/server' && pair !== 'safetyreport-mobile/standalone') fail('invalid_request');
          if (!['windows', 'linux', 'macos', 'docker', 'android', 'ios', 'other'].includes(String(body.platform))) fail('invalid_request');
          if (typeof body.takeover !== 'boolean') fail('invalid_request');
          out = await call('internal_account_register_connection', { p_user: uid, p_session: session,
            p_source_app: body.source_app, p_source_mode: body.source_mode, p_platform: body.platform,
            p_device_label: normalizeLabel(body.device_label), p_dataset_key: str(body.dataset_key, HEX64),
            p_secret_sha256: await sha256Hex(str(body.connection_secret, SECRET)), p_takeover: body.takeover });
          break;
        }
        case 'connections-rebind':
          keys(body, ['connection_id', 'connection_secret']);
          out = await call('internal_account_rebind_connection', { p_user: uid, p_session: session,
            p_connection: str(body.connection_id, UUID), p_secret_sha256: await sha256Hex(str(body.connection_secret, SECRET)) });
          break;
        case 'connections-revoke':
          keys(body, ['connection_id']);
          out = await call('internal_account_revoke_connection', { p_user: uid, p_connection: str(body.connection_id, UUID) });
          break;
        case 'contributions-delete':
          keys(body, ['confirm']);
          if (body.confirm !== 'DELETE_MY_SHARED_REPORTS') fail('invalid_request');
          out = await call('internal_community_delete_contributions', { p_user: uid, p_session: session });
          break;
        default:
          return fail('not_found');
      }
      deps.log?.({ event: 'community_account', action, outcome: 'ok', trace });
      return json(200, { protocol: 1, ...out });
    } catch (error) {
      const f = error instanceof Failure ? error : new Failure(/40P01|40001|deadlock|serializ/i.test(String(error)) ? 'busy' : 'server_error');
      deps.log?.({ event: 'community_account', action, outcome: f.code, trace });
      const headers: Record<string, string> = f.retryAfter ? { 'Retry-After': String(f.retryAfter) } : {};
      return json(STATUS[f.code], { error: { code: f.code, message: MESSAGES[f.code], requestTraceId: trace,
        retryable: RETRYABLE.has(f.code), ...(f.retryAfter ? { retryAfterSeconds: f.retryAfter } : {}), ...f.extra } }, headers);
    }
  };
}
