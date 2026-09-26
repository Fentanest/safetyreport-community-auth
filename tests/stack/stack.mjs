#!/usr/bin/env node
// Local safeauth verification stack orchestrator. Loopback only, never production.
//   node tests/stack/stack.mjs up        start containers + apply repo migrations
//   node tests/stack/stack.mjs migrate   re-apply only (fresh db required for create table)
//   node tests/stack/stack.mjs down      stop and delete containers + volumes
//   node tests/stack/stack.mjs env       print non-secret connection info
// Secrets are generated per checkout into .safeauth-stack/ (gitignored) and are
// never printed. Service/anon keys are HS256 JWTs signed with the local secret.
import { execFileSync, spawnSync } from 'node:child_process';
import { createHmac, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync, chmodSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '../..');
const runtimeDir = join(repo, '.safeauth-stack');
const envFile = join(runtimeDir, 'stack.env');
const composeFile = join(here, 'compose.yml');
const project = 'safeauth-local';

export const PORTS = { pg: 54432, auth: 54499, rest: 54498, gateway: 54400, kakao: 54410, site: 8480 };

const b64url = buf => Buffer.from(buf).toString('base64url');

function signJwt(payload, secret) {
  const head = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  const sig = createHmac('sha256', secret).update(`${head}.${body}`).digest('base64url');
  return `${head}.${body}.${sig}`;
}

export function loadStackEnv() {
  if (!existsSync(envFile)) throw new Error('stack env missing: run `node tests/stack/stack.mjs up`');
  const out = {};
  for (const line of readFileSync(envFile, 'utf8').split('\n')) {
    const m = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (m) out[m[1]] = m[2];
  }
  return out;
}

function ensureEnv() {
  if (existsSync(envFile)) return loadStackEnv();
  mkdirSync(runtimeDir, { recursive: true });
  const jwtSecret = b64url(randomBytes(48));
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 60 * 60 * 24 * 365;
  const env = {
    SAFEAUTH_PG_PASSWORD: b64url(randomBytes(24)),
    SAFEAUTH_JWT_SECRET: jwtSecret,
    SAFEAUTH_KAKAO_SECRET: b64url(randomBytes(24)),
    SAFEAUTH_SERVICE_KEY: signJwt({ role: 'service_role', iss: 'safeauth-local', iat: now, exp }, jwtSecret),
    SAFEAUTH_ANON_KEY: signJwt({ role: 'anon', iss: 'safeauth-local', iat: now, exp }, jwtSecret),
    AUTH_RELAY_HASH_PEPPER: b64url(randomBytes(32)),
    AUTH_RELAY_ENCRYPTION_KEY: b64url(randomBytes(32)),
  };
  writeFileSync(envFile, Object.entries(env).map(([k, v]) => `${k}=${v}`).join('\n') + '\n', { mode: 0o600 });
  chmodSync(envFile, 0o600);
  return env;
}

function compose(args, env) {
  const r = spawnSync('docker', ['compose', '-p', project, '-f', composeFile, ...args], {
    stdio: ['ignore', 'inherit', 'inherit'], env: { ...process.env, ...env },
  });
  if (r.status !== 0) throw new Error(`docker compose ${args.join(' ')} failed`);
}

function dbContainer(env) {
  return execFileSync('docker', ['compose', '-p', project, '-f', composeFile, 'ps', '-q', 'db'],
    { encoding: 'utf8', env: { ...process.env, ...env } }).trim();
}

export function psql(sql, { user = 'supabase_admin', env = loadStackEnv(), tuplesOnly = false } = {}) {
  const args = ['exec', '-i', '-e', `PGPASSWORD=${env.SAFEAUTH_PG_PASSWORD}`, dbContainer(env),
    'psql', '-h', '127.0.0.1', '-p', String(PORTS.pg), '-U', user, '-d', 'postgres',
    '-v', 'ON_ERROR_STOP=1', '--no-psqlrc', '-q'];
  if (tuplesOnly) args.push('-At');
  return execFileSync('docker', args, { input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
}

async function waitFor(label, check, timeoutMs = 120000) {
  const until = Date.now() + timeoutMs;
  for (;;) {
    try { if (await check()) return; } catch { /* retry */ }
    if (Date.now() > until) throw new Error(`${label} not ready`);
    await new Promise(r => setTimeout(r, 1000));
  }
}

async function up() {
  const env = ensureEnv();
  compose(['up', '-d', 'db'], env);
  await waitFor('postgres', () => psql('select 1', { env, tuplesOnly: true }).trim() === '1');
  // Same role wiring as the Supabase self-host roles.sql, with the runtime password.
  psql(`alter role authenticator with login password '${env.SAFEAUTH_PG_PASSWORD}';
        alter role supabase_auth_admin with login password '${env.SAFEAUTH_PG_PASSWORD}';
        alter role postgres with login password '${env.SAFEAUTH_PG_PASSWORD}';`, { env });
  compose(['up', '-d', 'auth', 'rest'], env);
  await waitFor('gotrue', async () => (await fetch(`http://127.0.0.1:${PORTS.auth}/health`)).ok);
  await waitFor('auth.users', () => psql("select to_regclass('auth.users') is not null", { env, tuplesOnly: true }).trim() === 't');
  migrate(env);
  await waitFor('postgrest', async () => (await fetch(`http://127.0.0.1:${PORTS.rest}/`)).status < 500);
  console.log('safeauth local stack ready');
}

// The account registry (202609260100) builds on the map repository's schema (one shared Supabase project, see
// safetyreport-community-map docs/integration/community-ingest/migration-manifest.json). Set SR_MAP_REPO to a map
// checkout to apply its prerequisite migrations first, in version order with this repository's; without it, files
// that declare "-- Depends on map" are skipped (relay-only stack) and reported.
const MAP_PREREQUISITES = ['202608150001_initial_schema.sql', '202609240001_analytics_v2.sql'];

function migrate(env = loadStackEnv()) {
  const dir = join(repo, 'supabase/migrations');
  const mapRepo = process.env.SR_MAP_REPO ? resolve(process.env.SR_MAP_REPO) : null;
  const files = readdirSync(dir).filter(f => f.endsWith('.sql')).map(f => ({ name: f, path: join(dir, f) }));
  if (mapRepo) for (const f of MAP_PREREQUISITES) files.push({ name: f, path: join(mapRepo, 'supabase/migrations', f) });
  for (const { name, path } of files.sort((a, b) => a.name.localeCompare(b.name))) {
    const text = readFileSync(path, 'utf8');
    if (!mapRepo && /^-- Depends on map /m.test(text)) {
      console.log(`skipped ${name} (needs the map schema: set SR_MAP_REPO)`);
      continue;
    }
    // Hosted migrations run as the postgres role; do the same here.
    psql(text, { env, user: 'postgres' });
    console.log(`applied ${name}`);
  }
  psql("notify pgrst, 'reload schema';", { env });
}

const cmd = process.argv[2];
if (import.meta.url === `file://${process.argv[1]}`) {
  if (cmd === 'up') await up();
  else if (cmd === 'migrate') migrate();
  else if (cmd === 'down') compose(['down', '-v'], existsSync(envFile) ? loadStackEnv() : ensureEnv());
  else if (cmd === 'env') console.log(JSON.stringify({ ports: PORTS, supabaseUrl: `http://127.0.0.1:${PORTS.gateway}` }, null, 2));
  else { console.error('usage: stack.mjs up|migrate|down|env'); process.exit(2); }
}
