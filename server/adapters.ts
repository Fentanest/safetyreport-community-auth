// Binds the relay to a supabase-js client. Used by the Deno Edge entry and by the
// Node local verification gateway so both exercise the same client code path.

import type { Rpc } from './relay.ts';

export interface MinimalSupabase {
  rpc(name: string, args: Record<string, unknown>): PromiseLike<{ data: unknown; error: unknown }>;
  auth: {
    getUser(jwt: string): Promise<{ data: { user: { id: string } | null }; error: { status?: number } | null }>;
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

// Gateway-supplied address; used only inside HMAC rate-limit buckets, never stored raw.
export function clientAddressFrom(request: Request): string | null {
  const direct = request.headers.get('cf-connecting-ip');
  if (direct) return direct.trim();
  const forwarded = request.headers.get('x-forwarded-for');
  return forwarded ? forwarded.split(',')[0].trim() : null;
}
