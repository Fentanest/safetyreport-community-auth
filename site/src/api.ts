// Relay client for the central page. Fixed endpoint from build config; no credentials,
// no referrer, no caching. Network failures are reported as "unknown", never as
// success or definitive failure.
import { type ErrorCode, PROTOCOL_VERSION } from '../../server/protocol.ts';
import type { PublicConfig } from './config.ts';

export type ApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; kind: 'relay'; code: ErrorCode; traceId: string | null; retryAfterSeconds: number | null }
  | { ok: false; kind: 'network' };

const TIMEOUT_MS = 15000;

export async function call<T>(config: PublicConfig, action: string, body: Record<string, unknown>): Promise<ApiResult<T>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (config.publishableKey) headers.apikey = config.publishableKey;
  try {
    const response = await fetch(`${config.relayBase}/${action}`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ protocol: PROTOCOL_VERSION, ...body }),
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      redirect: 'error',
      signal: controller.signal,
    });
    let json: unknown = null;
    try { json = await response.json(); } catch { json = null; }
    if (response.ok && json && typeof json === 'object') return { ok: true, data: json as T };
    const error = (json as { error?: { code?: string; requestTraceId?: string; retryAfterSeconds?: number } } | null)?.error;
    if (error?.code) {
      return {
        ok: false, kind: 'relay', code: error.code as ErrorCode,
        traceId: typeof error.requestTraceId === 'string' ? error.requestTraceId.slice(0, 32) : null,
        retryAfterSeconds: typeof error.retryAfterSeconds === 'number' ? error.retryAfterSeconds : null,
      };
    }
    return { ok: false, kind: 'network' };
  } catch {
    return { ok: false, kind: 'network' };
  } finally {
    clearTimeout(timer);
  }
}

export interface ClaimData { phase: string; client_kind: string; device_label: string; display_code: string; expires_at: string }
export interface PrepareData { phase: string; authorize_url: string; expires_at: string }
export interface PhaseData { phase: string; expires_at?: string }
