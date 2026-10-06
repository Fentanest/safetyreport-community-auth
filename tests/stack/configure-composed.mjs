#!/usr/bin/env node
// Read ONLY the already running local ci0926-int stack. Never alter its containers or credentials.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--map') throw new Error('usage: configure-composed.mjs --map /path/to/map-checkout');
const map = resolve(args[1]);
const stack = join(map, '.integration-stack');
const status = JSON.parse(execFileSync(join(map, 'node_modules/.bin/supabase'), ['status', '-o', 'json', '--workdir', stack],
  { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
const db = new URL(status.DB_URL);
if (db.hostname !== '127.0.0.1' || db.port !== '56322') throw new Error('only the local composed stack on 127.0.0.1:56322 is supported');
const container = JSON.parse(execFileSync('docker', ['inspect', 'supabase_auth_ci0926-int'],
  { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }))[0];
const auth = Object.fromEntries(container.Config.Env.map(line => { const at = line.indexOf('='); return [line.slice(0, at), line.slice(at + 1)]; }));
const local = JSON.parse(readFileSync(join(stack, '.stack-secrets.json'), 'utf8'));
const env = {
  SAFEAUTH_SERVICE_KEY: status.SERVICE_ROLE_KEY, SAFEAUTH_ANON_KEY: status.ANON_KEY,
  SAFEAUTH_JWT_SECRET: auth.GOTRUE_JWT_SECRET, SAFEAUTH_KAKAO_SECRET: auth.GOTRUE_EXTERNAL_KAKAO_SECRET,
  AUTH_RELAY_HASH_PEPPER: local.AUTH_RELAY_HASH_PEPPER, AUTH_RELAY_ENCRYPTION_KEY: local.AUTH_RELAY_ENCRYPTION_KEY,
};
if (Object.values(env).some(value => typeof value !== 'string' || !value || /[\r\n]/.test(value))) throw new Error('missing or malformed local test configuration');
const out = resolve(dirname(fileURLToPath(import.meta.url)), '../../.safeauth-stack');
mkdirSync(out, { recursive: true, mode: 0o700 });
const file = join(out, 'composed.env');
writeFileSync(file, Object.entries(env).map(([key, value]) => `${key}=${value}`).join('\n') + '\n', { mode: 0o600 });
chmodSync(file, 0o600);
console.log('Local composed test configuration written (ignored, mode 0600). No credentials printed or changed.');
