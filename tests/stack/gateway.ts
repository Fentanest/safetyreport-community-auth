// LOCAL verification gateway that mimics a Supabase project URL layout:
//   /auth/v1/*                          -> GoTrue container
//   /rest/v1/*                          -> PostgREST container
//   /functions/v1/community-auth-relay/* -> the real relay handler (server/safeauth)
// Run with: node --experimental-strip-types tests/stack/gateway.ts
// It exists so browser and device tests can use one "Supabase URL" on loopback.
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createClient } from '@supabase/supabase-js';
import { clientAddressFrom, getUserIdFrom, type MinimalSupabase, rpcFrom } from '../../server/adapters.ts';
import { loadRelayConfig } from '../../server/config.ts';
import { createRelayHandler } from '../../server/relay.ts';
import { loadStackEnv, PORTS } from './stack.mjs';

export interface GatewayOptions {
  port?: number;
  siteUrl?: string;
  browserOrigins?: string;
  overrides?: Record<string, string>;
  // Proxy relay calls to another runtime (e.g. the Deno Edge entry) instead of in-process.
  relayUpstream?: string;
}

async function readAll(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks);
}

async function relay(res: ServerResponse, response: Response): Promise<void> {
  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => { if (!['content-encoding', 'content-length', 'transfer-encoding'].includes(key)) headers[key] = value; });
  res.writeHead(response.status, headers);
  res.end(Buffer.from(await response.arrayBuffer()));
}

export async function startGateway(options: GatewayOptions = {}) {
  const stack = loadStackEnv();
  const port = options.port ?? PORTS.gateway;
  const relayUpstream = options.relayUpstream ?? (port === PORTS.gateway ? process.env.SAFEAUTH_RELAY_UPSTREAM : undefined);
  const self = `http://127.0.0.1:${port}`;
  const env: Record<string, string> = {
    SUPABASE_URL: self,
    AUTH_RELAY_LOCAL_STACK: 'loopback-only',
    AUTH_RELAY_ENABLED: 'true',
    AUTH_SITE_URL: options.siteUrl ?? `http://127.0.0.1:${PORTS.site}/`,
    AUTH_BROWSER_ORIGIN: options.browserOrigins ?? `http://127.0.0.1:${PORTS.site}`,
    AUTH_JWT_ISSUER: `http://127.0.0.1:${PORTS.gateway}/auth/v1`,
    AUTH_RELAY_HASH_PEPPER: stack.AUTH_RELAY_HASH_PEPPER,
    AUTH_RELAY_ENCRYPTION_KEY: stack.AUTH_RELAY_ENCRYPTION_KEY,
    ...options.overrides,
  };
  const config = await loadRelayConfig(name => env[name]);
  const client = createClient(self, stack.SAFEAUTH_SERVICE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  }) as unknown as MinimalSupabase;
  const logs: Record<string, string | number>[] = [];
  const handler = createRelayHandler({
    config, rpc: rpcFrom(client), getUserId: getUserIdFrom(client), clientAddress: clientAddressFrom,
    log: entry => { logs.push(entry); }, cleanupSampleRate: 0,
  });

  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', self);
      const raw = req.method === 'GET' || req.method === 'HEAD' ? undefined : await readAll(req);
      const body = raw && raw.length ? new Uint8Array(raw) : undefined;
      const headers = new Headers();
      for (const [key, value] of Object.entries(req.headers)) {
        if (typeof value === 'string' && key !== 'host' && key !== 'connection' && key !== 'content-length') headers.set(key, value);
      }
      if (!headers.has('x-forwarded-for')) headers.set('x-forwarded-for', req.socket.remoteAddress ?? '127.0.0.1');
      let upstream: string | null = null;
      if (url.pathname.startsWith('/auth/v1/')) upstream = `http://127.0.0.1:${PORTS.auth}${url.pathname.slice('/auth/v1'.length)}${url.search}`;
      else if (url.pathname.startsWith('/rest/v1/')) upstream = `http://127.0.0.1:${PORTS.rest}${url.pathname.slice('/rest/v1'.length)}${url.search}`;
      if (upstream) {
        return relay(res, await fetch(upstream, { method: req.method, headers, body, redirect: 'manual' }));
      }
      if (url.pathname.startsWith('/functions/v1/community-auth-relay/') && relayUpstream) {
        return relay(res, await fetch(`${relayUpstream}${url.pathname.slice('/functions/v1'.length)}${url.search}`,
          { method: req.method, headers, body, redirect: 'manual' }));
      }
      if (url.pathname.startsWith('/functions/v1/community-auth-relay/')) {
        const request = new Request(url, { method: req.method, headers, body });
        return relay(res, await handler(request));
      }
      res.writeHead(404, { 'Content-Type': 'text/plain' }).end('not found');
    } catch {
      res.writeHead(502, { 'Content-Type': 'text/plain' }).end('gateway error');
    }
  });
  await new Promise<void>(resolve => server.listen(port, '127.0.0.1', resolve));
  return { server, url: self, logs, config };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const gw = await startGateway({
    port: Number(process.env.GATEWAY_PORT) || undefined,
    siteUrl: process.env.AUTH_SITE_URL,
    browserOrigins: process.env.AUTH_BROWSER_ORIGIN,
  });
  if (!gw.config.ok) console.error('relay config problems:', gw.config.problems);
  console.log(`gateway listening on ${gw.url}`);
}
