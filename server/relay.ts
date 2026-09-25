// Runtime-agnostic request handler for the safeauth device-link relay.
// All state and every transition live in Postgres (internal_safeauth_* functions);
// this layer validates input, derives purpose-bound digests, seals the auth code and
// maps results. It never logs request bodies, secrets, codes or tokens.

import type { ConfigResult, RelayConfig } from './config.ts';
import { decodeJwtPayload, openCode, randomDisplayCode, randomSecret, sealCode } from './crypto.ts';
import {
  ACTIONS, type Action, AUTH_CODE_PATTERN, buildAuthorizeUrl, buildBootstrapUrl, CHALLENGE_PATTERN,
  type ErrorCode, INSTALL_ID_PATTERN, isClientKind, isPhase, normalizeDeviceLabel, PROTOCOL_VERSION,
  RELAY_FUNCTION_NAME, SECRET_PATTERN, UUID_PATTERN,
} from './protocol.ts';

export type Rpc = (name: string, args: Record<string, unknown>) => Promise<unknown>;

export interface RelayDeps {
  config: ConfigResult;
  rpc: Rpc;
  // Returns the user id for a token Supabase Auth accepts, null when Auth rejects it,
  // and throws when Auth is unreachable.
  getUserId(accessToken: string): Promise<string | null>;
  clientAddress(request: Request): string | null;
  log?(entry: Record<string, string | number>): void;
  cleanupSampleRate?: number;
}

const MAX_BODY_BYTES = 8192;

const STATUS_BY_CODE: Record<ErrorCode, number> = {
  invalid_request: 400, unsupported_protocol: 400, method_not_allowed: 405, origin_not_allowed: 403,
  not_found: 404, already_claimed: 409, invalid_state: 409, prepare_limit: 409, code_conflict: 409,
  delivery_conflict: 409, already_completed: 409, request_not_reusable: 409, session_mismatch: 409,
  auth_invalid: 401, expired: 410, cancelled: 409, failed: 409, rate_limited: 429,
  too_many_pending: 429, capacity: 503, service_disabled: 503, config_missing: 503, server_error: 500,
};

const MESSAGES: Record<ErrorCode, string> = {
  invalid_request: 'Request body is not valid for this action.',
  unsupported_protocol: 'Unsupported protocol version.',
  method_not_allowed: 'Only POST is supported.',
  origin_not_allowed: 'Origin is not allowed.',
  not_found: 'Request not found or capability mismatch.',
  already_claimed: 'This link was already opened in another browser.',
  invalid_state: 'Request is not in a state that allows this action.',
  prepare_limit: 'Too many sign-in attempts for this request.',
  code_conflict: 'A different result was already recorded.',
  delivery_conflict: 'The result was already delivered to another recipient.',
  already_completed: 'Request already completed.',
  request_not_reusable: 'Start a new request with a new device secret.',
  session_mismatch: 'Session does not belong to this request.',
  auth_invalid: 'Access token rejected by Supabase Auth.',
  expired: 'Request expired.',
  cancelled: 'Request cancelled.',
  failed: 'Request failed.',
  rate_limited: 'Too many requests.',
  too_many_pending: 'Too many pending requests for this installation.',
  capacity: 'Service is busy.',
  service_disabled: 'Community account linking is not enabled.',
  config_missing: 'Relay is not configured.',
  server_error: 'Unexpected relay error.',
};

class RelayFailure extends Error {
  readonly code: ErrorCode;
  readonly retryAfterSeconds?: number;
  constructor(code: ErrorCode, retryAfterSeconds?: number) {
    super(code);
    this.code = code;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

const fail = (code: ErrorCode, retryAfterSeconds?: number): never => { throw new RelayFailure(code, retryAfterSeconds); };

type Body = Record<string, unknown>;

function expectKeys(body: Body, required: string[], optional: string[] = []): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(body)) if (!allowed.has(key)) fail('invalid_request');
  for (const key of required) if (!(key in body)) fail('invalid_request');
  if (body.protocol !== PROTOCOL_VERSION) fail('unsupported_protocol');
}

function str(body: Body, key: string, pattern: RegExp): string {
  const value = body[key];
  if (typeof value !== 'string' || !pattern.test(value)) fail('invalid_request');
  return value as string;
}

function rpcError(result: unknown): ErrorCode | null {
  if (!result || typeof result !== 'object') return 'server_error';
  const code = (result as Record<string, unknown>).error;
  if (code === undefined) return null;
  return typeof code === 'string' && code in STATUS_BY_CODE ? code as ErrorCode : 'server_error';
}

function record(result: unknown): Record<string, unknown> {
  const code = rpcError(result);
  if (code) fail(code);
  return result as Record<string, unknown>;
}

function phaseOf(value: unknown): string {
  if (!isPhase(value)) fail('server_error');
  return value as string;
}

function baseHeaders(): Headers {
  return new Headers({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  });
}

export function createRelayHandler(deps: RelayDeps): (request: Request) => Promise<Response> {
  const log = deps.log ?? (() => {});
  const cleanupRate = deps.cleanupSampleRate ?? 0.05;

  function corsHeaders(origin: string | null, config: RelayConfig | null): Headers {
    const headers = baseHeaders();
    headers.set('Vary', 'Origin');
    if (origin && config?.browserOrigins.includes(origin)) {
      headers.set('Access-Control-Allow-Origin', origin);
      headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
      headers.set('Access-Control-Allow-Headers', 'content-type, apikey, x-client-info');
      headers.set('Access-Control-Max-Age', '600');
    }
    return headers;
  }

  function errorResponse(code: ErrorCode, traceId: string, headers: Headers, retryAfterSeconds?: number): Response {
    const error: Record<string, unknown> = { code, message: MESSAGES[code], requestTraceId: traceId };
    if (retryAfterSeconds !== undefined) {
      error.retryAfterSeconds = retryAfterSeconds;
      headers.set('Retry-After', String(retryAfterSeconds));
    }
    return new Response(JSON.stringify({ error }), { status: STATUS_BY_CODE[code], headers });
  }

  async function limit(config: RelayConfig, purpose: string, key: string, max: number, windowSeconds: number): Promise<void> {
    const digest = await config.hasher.digest('rate', purpose, key);
    const result = record(await deps.rpc('internal_safeauth_rate_limit', {
      p_bucket: `sa:${purpose}:${digest}`, p_limit: max, p_window_seconds: windowSeconds,
    }));
    if (result.allowed !== true) fail('rate_limited', Number(result.retry_after) || windowSeconds);
  }

  async function readBody(request: Request): Promise<Body> {
    const type = request.headers.get('content-type') ?? '';
    if (!/^application\/json(\s*;|$)/i.test(type)) fail('invalid_request');
    const declared = Number(request.headers.get('content-length') ?? '0');
    if (declared > MAX_BODY_BYTES) fail('invalid_request');
    const text = await request.text();
    if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) fail('invalid_request');
    let value: unknown;
    try { value = JSON.parse(text); } catch { fail('invalid_request'); }
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid_request');
    return value as Body;
  }

  const handlers: Record<Action, (config: RelayConfig, body: Body, request: Request) => Promise<[number, Record<string, unknown>]>> = {
    async requests(config, body, request) {
      expectKeys(body, ['protocol', 'client_kind', 'device_label', 'code_challenge', 'code_challenge_method', 'device_secret'], ['installation_id']);
      if (!isClientKind(body.client_kind)) fail('invalid_request');
      const label = normalizeDeviceLabel(body.device_label);
      if (!label) fail('invalid_request');
      const challenge = str(body, 'code_challenge', CHALLENGE_PATTERN);
      if (body.code_challenge_method !== 's256') fail('invalid_request');
      const deviceSecret = str(body, 'device_secret', SECRET_PATTERN);
      const installId = body.installation_id === undefined ? null : str(body, 'installation_id', INSTALL_ID_PATTERN);
      await limit(config, 'create_ip', deps.clientAddress(request) ?? 'unknown', config.createLimitPerIp, 600);

      if (Math.random() < cleanupRate) {
        deps.rpc('internal_safeauth_cleanup', {}).catch(() => log({ event: 'cleanup_failed' }));
      }

      const hasher = config.hasher;
      let requestId: string = crypto.randomUUID();
      const ticket = randomSecret();
      const created = record(await deps.rpc('internal_safeauth_create', {
        p_id: requestId,
        p_protocol: PROTOCOL_VERSION,
        p_client_kind: body.client_kind,
        p_device_label: label,
        p_display_code: randomDisplayCode(),
        p_code_challenge: challenge,
        p_create_idem_hash: await hasher.digest('create', '-', deviceSecret),
        p_device_secret_hash: await hasher.digest('device', requestId, deviceSecret),
        p_install_hash: installId ? await hasher.digest('install', '-', installId) : null,
        p_ticket_hash: await hasher.digest('ticket', requestId, ticket),
        p_ttl_seconds: config.requestTtlSeconds,
        p_max_active_per_install: config.maxActivePerInstall,
        p_max_active_total: config.maxActiveTotal,
      }));
      let view = created;
      if (created.existing === true) {
        requestId = String(created.request_id);
        if (!UUID_PATTERN.test(requestId)) fail('server_error');
        view = record(await deps.rpc('internal_safeauth_rotate_ticket', {
          p_id: requestId,
          p_device_secret_hash: await hasher.digest('device', requestId, deviceSecret),
          p_ticket_hash: await hasher.digest('ticket', requestId, ticket),
        }));
      }
      return [created.existing === true ? 200 : 201, {
        protocol: PROTOCOL_VERSION,
        request_id: requestId,
        bootstrap_url: buildBootstrapUrl(config.siteUrl, requestId, ticket),
        display_code: view.display_code,
        expires_at: view.expires_at,
        poll_interval_seconds: config.pollIntervalSeconds,
        code_ttl_seconds: config.codeTtlSeconds,
      }];
    },

    async claim(config, body, request) {
      expectKeys(body, ['protocol', 'request_id', 'ticket', 'browser_secret']);
      const id = str(body, 'request_id', UUID_PATTERN);
      const ticket = str(body, 'ticket', SECRET_PATTERN);
      const browserSecret = str(body, 'browser_secret', SECRET_PATTERN);
      await limit(config, 'claim_ip', deps.clientAddress(request) ?? 'unknown', 30, 60);
      await limit(config, 'claim_req', id, 10, 60);
      const result = record(await deps.rpc('internal_safeauth_claim', {
        p_id: id,
        p_ticket_hash: await config.hasher.digest('ticket', id, ticket),
        p_browser_secret_hash: await config.hasher.digest('browser', id, browserSecret),
      }));
      return [200, {
        protocol: PROTOCOL_VERSION, request_id: id, phase: phaseOf(result.phase),
        client_kind: result.client_kind, device_label: result.device_label,
        display_code: result.display_code, expires_at: result.expires_at,
      }];
    },

    async prepare(config, body) {
      expectKeys(body, ['protocol', 'request_id', 'browser_secret', 'confirmed_started_by_me']);
      if (body.confirmed_started_by_me !== true) fail('invalid_request');
      const id = str(body, 'request_id', UUID_PATTERN);
      const browserSecret = str(body, 'browser_secret', SECRET_PATTERN);
      await limit(config, 'prepare_req', id, 6, 60);
      const result = record(await deps.rpc('internal_safeauth_prepare', {
        p_id: id, p_browser_secret_hash: await config.hasher.digest('browser', id, browserSecret),
      }));
      const challenge = typeof result.code_challenge === 'string' ? result.code_challenge : '';
      if (!CHALLENGE_PATTERN.test(challenge)) fail('server_error');
      return [200, {
        protocol: PROTOCOL_VERSION, phase: 'oauth_started', expires_at: result.expires_at,
        authorize_url: buildAuthorizeUrl(config.publicSupabaseUrl, config.callbackUrl, challenge),
      }];
    },

    async publish(config, body) {
      expectKeys(body, ['protocol', 'request_id', 'browser_secret', 'outcome'], ['code']);
      const id = str(body, 'request_id', UUID_PATTERN);
      const browserSecret = str(body, 'browser_secret', SECRET_PATTERN);
      const outcome = body.outcome;
      if (outcome !== 'code' && outcome !== 'denied' && outcome !== 'error') fail('invalid_request');
      if ((outcome === 'code') !== ('code' in body)) fail('invalid_request');
      await limit(config, 'publish_req', id, 10, 60);
      let digest: string | null = null;
      let sealed: string | null = null;
      if (outcome === 'code') {
        const code = str(body, 'code', AUTH_CODE_PATTERN);
        digest = await config.hasher.digest('code', id, code);
        sealed = await sealCode(config.codeKeys[0], id, code);
      }
      const result = record(await deps.rpc('internal_safeauth_publish', {
        p_id: id,
        p_browser_secret_hash: await config.hasher.digest('browser', id, browserSecret),
        p_kind: outcome,
        p_code_digest: digest,
        p_encrypted_code: sealed,
        p_code_ttl_seconds: config.codeTtlSeconds,
        p_error_reason: outcome === 'code' ? null : outcome,
      }));
      return [200, { protocol: PROTOCOL_VERSION, phase: phaseOf(result.phase) }];
    },

    async poll(config, body) {
      expectKeys(body, ['protocol', 'request_id', 'device_secret', 'delivery_key']);
      const id = str(body, 'request_id', UUID_PATTERN);
      const deviceSecret = str(body, 'device_secret', SECRET_PATTERN);
      const deliveryKey = str(body, 'delivery_key', SECRET_PATTERN);
      await limit(config, 'poll_req', id, 30, 60);
      const result = record(await deps.rpc('internal_safeauth_poll', {
        p_id: id,
        p_device_secret_hash: await config.hasher.digest('device', id, deviceSecret),
        p_delivery_key_hash: await config.hasher.digest('delivery', id, deliveryKey),
      }));
      const status = result.status;
      if (status === 'pending') {
        return [200, {
          protocol: PROTOCOL_VERSION, status, phase: phaseOf(result.phase),
          expires_at: result.expires_at, poll_after_seconds: config.pollIntervalSeconds,
        }];
      }
      if (status === 'code') {
        let code: string;
        try {
          code = await openCode(config.codeKeys, id, String(result.encrypted_auth_code));
        } catch {
          fail('server_error'); // fail closed on a wrong/rotated key or a damaged envelope
        }
        return [200, { protocol: PROTOCOL_VERSION, status, auth_code: code!, code_expires_at: result.code_expires_at }];
      }
      if (['completed', 'expired', 'cancelled', 'failed', 'code_expired'].includes(String(status))) {
        const out: Record<string, unknown> = { protocol: PROTOCOL_VERSION, status };
        if (typeof result.reason === 'string') out.reason = result.reason;
        return [200, out];
      }
      return fail('server_error');
    },

    async 'browser-status'(config, body) {
      expectKeys(body, ['protocol', 'request_id', 'browser_secret']);
      const id = str(body, 'request_id', UUID_PATTERN);
      const browserSecret = str(body, 'browser_secret', SECRET_PATTERN);
      await limit(config, 'bstatus_req', id, 40, 60);
      const result = record(await deps.rpc('internal_safeauth_browser_status', {
        p_id: id, p_browser_secret_hash: await config.hasher.digest('browser', id, browserSecret),
      }));
      return [200, { protocol: PROTOCOL_VERSION, phase: phaseOf(result.phase), expires_at: result.expires_at }];
    },

    async complete(config, body, request) {
      expectKeys(body, ['protocol', 'request_id', 'device_secret']);
      const id = str(body, 'request_id', UUID_PATTERN);
      const deviceSecret = str(body, 'device_secret', SECRET_PATTERN);
      const bearer = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/.exec(request.headers.get('authorization') ?? '');
      if (!bearer || bearer[1].length > 8192) fail('auth_invalid');
      await limit(config, 'complete_req', id, 10, 60);
      // Supabase Auth validates signature, expiry and session existence. Claims are
      // read only after that succeeds, and never from the request body.
      const userId = await deps.getUserId(bearer![1]);
      if (!userId) fail('auth_invalid');
      const claims = decodeJwtPayload(bearer![1]);
      const aud = claims?.aud;
      const audiences = Array.isArray(aud) ? aud : [aud];
      if (!claims || claims.sub !== userId || claims.iss !== config.jwtIssuer
        || !audiences.includes('authenticated') || claims.role !== 'authenticated'
        || typeof claims.session_id !== 'string' || !UUID_PATTERN.test(claims.session_id)
        || typeof claims.iat !== 'number') {
        fail('auth_invalid');
      }
      const result = record(await deps.rpc('internal_safeauth_complete', {
        p_id: id,
        p_device_secret_hash: await config.hasher.digest('device', id, deviceSecret),
        p_user_id: userId,
        p_session_id: claims!.session_id,
        p_token_issued_at: new Date((claims!.iat as number) * 1000).toISOString(),
      }));
      return [200, { protocol: PROTOCOL_VERSION, phase: phaseOf(result.phase) }];
    },

    async cancel(config, body) {
      expectKeys(body, ['protocol', 'request_id', 'actor', 'secret']);
      const id = str(body, 'request_id', UUID_PATTERN);
      const secret = str(body, 'secret', SECRET_PATTERN);
      if (body.actor !== 'device' && body.actor !== 'browser') fail('invalid_request');
      await limit(config, 'cancel_req', id, 10, 60);
      const result = record(await deps.rpc('internal_safeauth_cancel', {
        p_id: id,
        p_actor: body.actor,
        p_secret_hash: await config.hasher.digest(body.actor === 'device' ? 'device' : 'browser', id, secret),
      }));
      return [200, { protocol: PROTOCOL_VERSION, phase: phaseOf(result.phase) }];
    },
  };

  const actionPattern = new RegExp(`(?:^|/)${RELAY_FUNCTION_NAME}/([a-z-]+)/?$`);

  return async function handle(request: Request): Promise<Response> {
    const traceId = randomSecret(9);
    const config = deps.config.ok ? deps.config.config : null;
    const origin = request.headers.get('origin');
    const headers = corsHeaders(origin, config);

    if (!config) {
      log({ event: 'config_missing', trace: traceId });
      return errorResponse('config_missing', traceId, headers);
    }
    // Origin is not authentication; it only keeps foreign pages from driving the API.
    // Server/native callers send no Origin and are authorised by capabilities alone.
    if (origin !== null && !config.browserOrigins.includes(origin)) {
      return errorResponse('origin_not_allowed', traceId, headers);
    }
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers });
    if (request.method !== 'POST') return errorResponse('method_not_allowed', traceId, headers);
    if (!config.enabled) return errorResponse('service_disabled', traceId, headers);

    const match = actionPattern.exec(new URL(request.url).pathname);
    const action = match?.[1] as Action | undefined;
    if (!action || !(ACTIONS as readonly string[]).includes(action)) return errorResponse('not_found', traceId, headers);

    try {
      await limit(config, 'ip', deps.clientAddress(request) ?? 'unknown', 120, 60);
      const body = await readBody(request);
      const [status, payload] = await handlers[action](config, body, request);
      return new Response(JSON.stringify(payload), { status, headers });
    } catch (error) {
      if (error instanceof RelayFailure) {
        if (STATUS_BY_CODE[error.code] >= 500) log({ event: 'relay_error', action, code: error.code, trace: traceId });
        return errorResponse(error.code, traceId, headers, error.retryAfterSeconds);
      }
      log({ event: 'relay_exception', action, trace: traceId });
      return errorResponse('server_error', traceId, headers);
    }
  };
}
