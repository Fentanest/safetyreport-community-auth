// Starts the LOCAL node-side services for manual/browser/app verification:
//   mock Kakao :54410, Supabase-like gateway :54400 (relay in-process),
//   static site :8480 serving a built safeauth dir at the root (like safeauth.worklazy.net).
// Usage: node --experimental-strip-types tests/stack/serve-local.ts <site-dir>
// Containers must already be up (node tests/stack/stack.mjs up).
import { startGateway } from './gateway.ts';
import { startMockKakao } from './mock-kakao.mjs';
import { loadStackEnv, PORTS } from './stack.mjs';
import { startStaticServer } from './static-server.mjs';

const siteDir = process.argv[2];
if (!siteDir) {
  console.error('usage: serve-local.ts <site-dir>');
  process.exit(2);
}
const stack = loadStackEnv();
await startMockKakao({ clientSecret: stack.SAFEAUTH_KAKAO_SECRET });
const gateway = await startGateway({
  relayUpstream: process.env.SAFEAUTH_RELAY_UPSTREAM,
  overrides: {
    // Every local app test calls from 127.0.0.1; production keeps the default of 10.
    AUTH_RELAY_CREATE_LIMIT_PER_IP: '300',
    ...(process.env.SAFEAUTH_REQUEST_TTL ? { AUTH_RELAY_REQUEST_TTL_SECONDS: process.env.SAFEAUTH_REQUEST_TTL } : {}),
  },
});
if (!gateway.config.ok) console.error('relay config problems', gateway.config.problems);
await startStaticServer({ root: siteDir, port: PORTS.site });
console.log(JSON.stringify({
  supabaseUrl: gateway.url,
  site: `http://127.0.0.1:${PORTS.site}/`,
  mockKakao: `http://127.0.0.1:${PORTS.kakao}/`,
}));
