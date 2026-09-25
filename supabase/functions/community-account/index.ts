import { createClient } from 'npm:@supabase/supabase-js@2.117.1';
import { getAccountUserFrom, type MinimalSupabase, rpcFrom } from '../../../server/adapters.ts';
import { createAccountHandler } from '../../../server/account.ts';

// User-only endpoint (verify_jwt = true in config.toml AND getUser + claims in the handler). Status, share consent,
// writer connections and deletion of shared reports. The server key never leaves this runtime; the handler never
// accepts a user id from the body.
const supabaseUrl = Deno.env.get('SUPABASE_URL');
const secretMap = JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS') || '{}') as Record<string, string>;
const serverKey = secretMap.default || Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
const enabled = Deno.env.get('COMMUNITY_ACCOUNT_ENABLED') !== 'false' && !!supabaseUrl && !!serverKey;
if (!enabled) console.error(JSON.stringify({ event: 'community_account_config_invalid' }));

const client = createClient(supabaseUrl ?? 'http://invalid.local', serverKey ?? 'missing', {
  auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
}) as unknown as MinimalSupabase;

Deno.serve(createAccountHandler({
  rpc: rpcFrom(client),
  getUser: getAccountUserFrom(client),
  jwtIssuer: Deno.env.get('AUTH_JWT_ISSUER') || null,
  enabled,
  log: entry => console.log(JSON.stringify(entry)),
}));
