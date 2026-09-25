// Shared wire contract for the safeauth device-link relay (protocol 1).
// Imported by the Edge function, the central browser app and tests. Pure data and
// validators only: no runtime-specific APIs here. Normative prose: docs/protocol.md.

export const PROTOCOL_VERSION = 1 as const;
export const RELAY_FUNCTION_NAME = 'community-auth-relay';

export const CLIENT_KINDS = ['pc', 'docker', 'mobile_client_server'] as const;
export type ClientKind = (typeof CLIENT_KINDS)[number];

// Phases visible to the browser. `code_ready`/`code_delivered` are NOT success.
export const PHASES = [
  'created', 'claimed', 'oauth_started', 'code_ready', 'code_delivered',
  'device_confirmed', 'cancelled', 'expired', 'failed',
] as const;
export type Phase = (typeof PHASES)[number];
export const TERMINAL_PHASES: readonly Phase[] = ['device_confirmed', 'cancelled', 'expired', 'failed'];

export const ACTIONS = [
  'requests', 'claim', 'prepare', 'publish', 'poll', 'browser-status', 'complete', 'cancel',
] as const;
export type Action = (typeof ACTIONS)[number];

export const ERROR_CODES = [
  'invalid_request', 'unsupported_protocol', 'method_not_allowed', 'origin_not_allowed',
  'not_found', 'already_claimed', 'invalid_state', 'prepare_limit', 'code_conflict',
  'delivery_conflict', 'already_completed', 'request_not_reusable', 'session_mismatch',
  'auth_invalid', 'expired', 'cancelled', 'failed', 'rate_limited', 'too_many_pending',
  'capacity', 'service_disabled', 'config_missing', 'server_error',
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];

export interface RelayError {
  error: { code: ErrorCode; message: string; requestTraceId: string; retryAfterSeconds?: number };
}

// 32 random bytes, base64url without padding.
export const SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/;
// RFC 7636 S256 challenge: base64url(SHA-256(verifier)) is always 43 characters.
export const CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
export const INSTALL_ID_PATTERN = /^[A-Za-z0-9_-]{22,64}$/;
export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
// Supabase Auth currently issues UUID codes; accept a conservative URL-safe superset.
export const AUTH_CODE_PATTERN = /^[A-Za-z0-9._~-]{8,512}$/;
export const DISPLAY_CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
export const DISPLAY_CODE_PATTERN = /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/;
export const DEVICE_LABEL_MAX = 40;

// Device labels are user-supplied display text. Reject controls, bidi overrides and
// markup-significant characters instead of trying to sanitise them.
const LABEL_FORBIDDEN = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩<>"'`\\]/;

export function normalizeDeviceLabel(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const label = value.normalize('NFC').replace(/\s+/g, ' ').trim();
  if (label.length < 1 || [...label].length > DEVICE_LABEL_MAX) return null;
  if (LABEL_FORBIDDEN.test(label)) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(label)) return null; // looks like a URL scheme
  return label;
}

export function isPhase(value: unknown): value is Phase {
  return typeof value === 'string' && (PHASES as readonly string[]).includes(value);
}

export function isClientKind(value: unknown): value is ClientKind {
  return typeof value === 'string' && (CLIENT_KINDS as readonly string[]).includes(value);
}

// Central browser entry: https://safeauth.worklazy.net/#r=<request_id>&t=<ticket>
// The fragment never reaches an HTTP server or Referer header.
export function buildBootstrapUrl(siteUrl: string, requestId: string, ticket: string): string {
  const fragment = new URLSearchParams({ r: requestId, t: ticket }).toString();
  return `${siteUrl}#${fragment}`;
}

export function parseBootstrapFragment(hash: string): { requestId: string; ticket: string } | null {
  const raw = hash.startsWith('#') ? hash.slice(1) : hash;
  if (!raw || raw.length > 256) return null;
  const params = new URLSearchParams(raw);
  const keys = [...params.keys()];
  if (keys.length !== 2 || !params.has('r') || !params.has('t')) return null;
  const requestId = params.get('r') ?? '';
  const ticket = params.get('t') ?? '';
  if (!UUID_PATTERN.test(requestId) || !SECRET_PATTERN.test(ticket)) return null;
  return { requestId, ticket };
}

// The only authorize URL shape the relay may produce and the browser may follow.
export function buildAuthorizeUrl(supabaseUrl: string, callbackUrl: string, challenge: string): string {
  const url = new URL('/auth/v1/authorize', supabaseUrl);
  url.searchParams.set('provider', 'kakao');
  url.searchParams.set('redirect_to', callbackUrl);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 's256');
  return url.toString();
}

export function verifyAuthorizeUrl(candidate: unknown, supabaseUrl: string, callbackUrl: string): string | null {
  if (typeof candidate !== 'string' || candidate.length > 2048) return null;
  let url: URL;
  try { url = new URL(candidate); } catch { return null; }
  const expected = new URL('/auth/v1/authorize', supabaseUrl);
  if (url.origin !== expected.origin || url.pathname !== expected.pathname) return null;
  if (url.username || url.password || url.hash) return null;
  const allowed = ['provider', 'redirect_to', 'code_challenge', 'code_challenge_method'];
  const keys = [...url.searchParams.keys()];
  if (keys.length !== allowed.length || !allowed.every(k => url.searchParams.getAll(k).length === 1)) return null;
  if (url.searchParams.get('provider') !== 'kakao') return null;
  if (url.searchParams.get('redirect_to') !== callbackUrl) return null;
  if (url.searchParams.get('code_challenge_method') !== 's256') return null;
  if (!CHALLENGE_PATTERN.test(url.searchParams.get('code_challenge') ?? '')) return null;
  return url.toString();
}

// Normalised OAuth callback outcome. Provider error text is never rendered or relayed.
export type CallbackOutcome =
  | { kind: 'code'; code: string }
  | { kind: 'denied' }
  | { kind: 'error' }
  | { kind: 'missing' };

export function parseCallback(search: string, hash: string): CallbackOutcome {
  const query = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search);
  const frag = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
  const error = query.get('error') ?? frag.get('error');
  if (error) {
    const code = query.get('error_code') ?? frag.get('error_code') ?? '';
    return error === 'access_denied' || code === 'access_denied' ? { kind: 'denied' } : { kind: 'error' };
  }
  const codes = query.getAll('code');
  if (codes.length === 1 && AUTH_CODE_PATTERN.test(codes[0])) return { kind: 'code', code: codes[0] };
  if (codes.length > 0) return { kind: 'error' };
  return { kind: 'missing' };
}
