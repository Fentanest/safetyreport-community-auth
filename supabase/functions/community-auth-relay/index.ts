import { createClient } from 'npm:@supabase/supabase-js@2.117.1';
import { clientAddressFrom, getUserIdFrom, type MinimalSupabase, rpcFrom } from '../../../server/adapters.ts';
import { type ConfigResult, loadRelayConfig } from '../../../server/config.ts';
import { createRelayHandler } from '../../../server/relay.ts';

// Pre-login endpoint: verify_jwt is off in config.toml for this function only, because
// devices and the central page have no user JWT yet. Every action is authorised by its
// own capability (device secret, bootstrap ticket, browser secret, or a user JWT that
// Supabase Auth validates for /complete). The server key never leaves this runtime.
const supabaseUrl = Deno.env.get('SUPABASE_URL');
const secretMap = JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS') || '{}') as Record<string, string>;
const serverKey = secretMap.default || Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');

let config: ConfigResult = await loadRelayConfig(name => Deno.env.get(name));
if (!supabaseUrl || !serverKey) config = { ok: false, problems: ['platform credentials missing'] };
if (!config.ok) console.error(JSON.stringify({ event: 'safeauth_config_invalid', problems: config.problems }));

const client = createClient(supabaseUrl ?? 'http://invalid.local', serverKey ?? 'missing', {
  auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
}) as unknown as MinimalSupabase;

const handle = createRelayHandler({
  config,
  rpc: rpcFrom(client),
  getUserId: getUserIdFrom(client),
  clientAddress: clientAddressFrom,
  log: entry => console.log(JSON.stringify(entry)),
});

Deno.serve(handle);
