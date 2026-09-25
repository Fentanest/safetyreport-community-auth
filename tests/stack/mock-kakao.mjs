// Mock Kakao OAuth for the LOCAL verification stack only. GoTrue's Kakao provider is
// pointed here with GOTRUE_EXTERNAL_KAKAO_URL; it calls /oauth/authorize (browser),
// /oauth/token and /v2/user/me exactly like kauth/kapi.kakao.com. This is not a
// Kakao E2E: real Kakao login must be verified manually against the hosted project.
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';

const ACCOUNTS = {
  A: { id: 910001, nickname: '로컬테스트A', email: null },
  B: { id: 910002, nickname: '로컬테스트B', email: 'local-b@example.invalid' },
};

export function startMockKakao({ port = 54410, clientSecret, clientId = 'mock-kakao-client',
  redirectUri = 'http://127.0.0.1:54400/auth/v1/callback' } = {}) {
  const codes = new Map();
  const tokens = new Map();
  const html = body => `<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>MOCK Kakao</title>
<meta name="viewport" content="width=device-width,initial-scale=1"><style>body{font:15px sans-serif;max-width:420px;margin:40px auto;padding:0 16px}
a{display:block;margin:10px 0;padding:14px;border:1px solid #999;border-radius:10px;text-decoration:none;color:#111}</style></head>
<body><p><strong>MOCK Kakao · 로컬 검증 전용</strong></p><p>실제 카카오가 아닙니다.</p>${body}</body></html>`;

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, `http://127.0.0.1:${port}`);
    const send = (status, type, body, headers = {}) => { res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', ...headers }); res.end(body); };
    if (url.pathname === '/oauth/authorize') {
      if (url.searchParams.get('client_id') !== clientId || url.searchParams.get('redirect_uri') !== redirectUri) {
        return send(400, 'text/plain', 'mock kakao: client or redirect mismatch');
      }
      const state = url.searchParams.get('state') ?? '';
      const link = choice => `/oauth/decide?${new URLSearchParams({ state, choice })}`;
      return send(200, 'text/html; charset=utf-8', html(
        `<a id="mock-account-a" href="${link('A')}">테스트 계정 A로 계속 (이메일 없음)</a>
         <a id="mock-account-b" href="${link('B')}">테스트 계정 B로 계속</a>
         <a id="mock-deny" href="${link('deny')}">동의하지 않고 취소</a>`));
    }
    if (url.pathname === '/oauth/decide') {
      const state = url.searchParams.get('state') ?? '';
      const choice = url.searchParams.get('choice');
      const target = new URL(redirectUri);
      target.searchParams.set('state', state);
      if (choice === 'deny') {
        target.searchParams.set('error', 'access_denied');
        target.searchParams.set('error_description', 'User denied access');
      } else if (ACCOUNTS[choice]) {
        const code = randomBytes(16).toString('hex');
        codes.set(code, choice);
        target.searchParams.set('code', code);
      } else {
        return send(400, 'text/plain', 'unknown choice');
      }
      return send(302, 'text/plain', '', { Location: target.toString() });
    }
    if (url.pathname === '/oauth/token' && req.method === 'POST') {
      let raw = '';
      for await (const chunk of req) raw += chunk;
      const form = new URLSearchParams(raw);
      const account = codes.get(form.get('code') ?? '');
      if (form.get('client_secret') !== clientSecret || form.get('client_id') !== clientId || !account) {
        return send(400, 'application/json', JSON.stringify({ error: 'invalid_grant' }));
      }
      codes.delete(form.get('code'));
      const accessToken = randomBytes(24).toString('hex');
      tokens.set(accessToken, account);
      return send(200, 'application/json', JSON.stringify({
        access_token: accessToken, token_type: 'bearer', refresh_token: randomBytes(24).toString('hex'), expires_in: 21599,
      }));
    }
    if (url.pathname === '/v2/user/me') {
      const token = /^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1];
      const account = ACCOUNTS[tokens.get(token)];
      if (!account) return send(401, 'application/json', '{"msg":"invalid token"}');
      const body = { id: account.id, kakao_account: { profile: { nickname: account.nickname } } };
      if (account.email) Object.assign(body.kakao_account, { email: account.email, is_email_valid: true, is_email_verified: true });
      return send(200, 'application/json', JSON.stringify(body));
    }
    return send(404, 'text/plain', 'not found');
  });
  return new Promise(resolve => server.listen(port, '127.0.0.1', () => resolve(server)));
}

// Drives the mock provider without a browser: follows GoTrue -> mock Kakao -> GoTrue
// and returns the final redirect URL that a browser would have loaded.
export async function followOAuth(authorizeUrl, choice = 'A') {
  const step1 = await fetch(authorizeUrl, { redirect: 'manual' });
  const kakaoAuthorize = new URL(step1.headers.get('location'));
  const state = kakaoAuthorize.searchParams.get('state');
  const decide = new URL('/oauth/decide', kakaoAuthorize);
  decide.search = new URLSearchParams({ state, choice }).toString();
  const step2 = await fetch(decide, { redirect: 'manual' });
  const step3 = await fetch(step2.headers.get('location'), { redirect: 'manual' });
  return new URL(step3.headers.get('location'));
}
