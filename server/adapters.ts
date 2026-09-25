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
