// Binds the relay to a supabase-js client. Used by the Deno Edge entry and by the
// Node local verification gateway so both exercise the same client code path.

import type { Rpc } from './relay.ts';

export interface MinimalSupabase {
  rpc(name: string, args: Record<string, unknown>): PromiseLike<{ data: unknown; error: unknown }>;
  auth: {
    getUser(jwt: string): Promise<{
      data: { user: { id: string; is_anonymous?: boolean; user_metadata?: Record<string, unknown> } | null };
      error: { status?: number } | null;
    }>;
  };
}

export function rpcFrom(client: MinimalSupabase): Rpc {
  return async (name, args) => {
    const { data, error } = await client.rpc(name, args);
    if (error) throw new Error('relay repository unavailable'); // details stay server-side
    return data;
  };
}

export function getUserIdFrom(client: MinimalSupabase): (token: string) => Promise<string | null> {
  return async token => {
    const { data, error } = await client.auth.getUser(token);
    if (error) {
      const status = error.status ?? 0;
      if (status === 401 || status === 403 || status === 400 || status === 404) return null;
      throw new Error('auth unavailable');
    }
    return data.user?.id ?? null;
  };
}

// For user-only functions (community-account): the user Supabase Auth accepts for the token, null when Auth
// rejects it (expired, bad signature, session revoked), throws when Auth is unreachable. display_name is only for
// display; nickname/name come from user-editable metadata and never decide anything.
export function getAccountUserFrom(client: MinimalSupabase):
  (token: string) => Promise<{ id: string; isAnonymous: boolean; displayName: string | null } | null> {
  return async token => {
    const { data, error } = await client.auth.getUser(token);
    if (error) {
      const status = error.status ?? 0;
      if (status === 401 || status === 403 || status === 400 || status === 404) return null;
      throw new Error('auth unavailable');
    }
    const user = data.user;
    if (!user) return null;
    const meta = user.user_metadata ?? {};
    const name = [meta.nickname, meta.name, meta.full_name].find(v => typeof v === 'string' && v.trim());
    return { id: user.id, isAnonymous: user.is_anonymous === true,
      displayName: typeof name === 'string' ? name.trim().slice(0, 40) : null };
  };
}

// Gateway-supplied address; used only inside HMAC rate-limit buckets, never stored raw.
export function clientAddressFrom(request: Request): string | null {
  const direct = request.headers.get('cf-connecting-ip');
  if (direct) return direct.trim();
  const forwarded = request.headers.get('x-forwarded-for');
  return forwarded ? forwarded.split(',')[0].trim() : null;
}

/** 요청 본문을 최대 max 바이트까지만 읽는다(감사 SOL-10). 선언된 Content-Length 가 max 를 넘거나 숫자가 아니면 읽지 않고,
 *  선언이 없거나 거짓이어도 읽는 도중 max 를 넘는 순간 스트림을 취소한다. 넘으면 null. */
export async function readBodyLimited(request: Request, max: number): Promise<Uint8Array | null> {
  const declared = request.headers.get('content-length');
  if (declared !== null && declared.trim() !== '' && !(Number(declared) <= max)) return null;
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      try { await reader.cancel(); } catch { /* 이미 닫힘 */ }
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { out.set(c, offset); offset += c.byteLength; }
  return out;
}
