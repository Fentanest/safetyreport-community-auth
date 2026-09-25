// Test actors for the local stack. The device mirrors what safetyreport's Python
// server does (it owns the verifier and the session); the browser mirrors the
// central page (it only relays). Neither is used in production.
import { randomSecret, s256Challenge } from '../../server/crypto.ts';
import { parseBootstrapFragment, parseCallback } from '../../server/protocol.ts';
import { followOAuth } from '../stack/mock-kakao.mjs';

export interface Json { [key: string]: unknown }

// Each simulated installation gets its own documentation-range address so the
// per-IP create limit is exercised only where a test intends it.
export function randomTestIp(): string {
  return `2001:db8::${Math.floor(Math.random() * 0xffff).toString(16)}:${Math.floor(Math.random() * 0xffff).toString(16)}`;
}

export async function post(base: string, action: string, body: Json, headers: Record<string, string> = {}) {
  const response = await fetch(`${base}/functions/v1/community-auth-relay/${action}`, {
    method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body),
  });
  const json = await response.json().catch(() => ({})) as Json;
  return { status: response.status, json, headers: response.headers };
}

export class Device {
  readonly verifier = randomSecret();
  readonly deviceSecret = randomSecret();
  readonly deliveryKey = randomSecret();
  requestId = '';
  bootstrapUrl = '';
  displayCode = '';
  session: Json | null = null;

  constructor(readonly base: string, readonly anonKey: string, readonly label = '테스트 PC', readonly kind = 'pc', readonly ip = randomTestIp()) {}

  async create(extra: Json = {}) {
    const r = await post(this.base, 'requests', {
      protocol: 1, client_kind: this.kind, device_label: this.label,
      code_challenge: await s256Challenge(this.verifier), code_challenge_method: 's256',
      device_secret: this.deviceSecret, ...extra,
    }, { 'x-forwarded-for': this.ip });
    if (r.status === 201 || r.status === 200) {
      this.requestId = String(r.json.request_id);
      this.bootstrapUrl = String(r.json.bootstrap_url);
      this.displayCode = String(r.json.display_code);
    }
    return r;
  }

  poll(deliveryKey = this.deliveryKey) {
    return post(this.base, 'poll', { protocol: 1, request_id: this.requestId, device_secret: this.deviceSecret, delivery_key: deliveryKey });
  }

  async exchange(code: string, verifier = this.verifier) {
    const response = await fetch(`${this.base}/auth/v1/token?grant_type=pkce`, {
      method: 'POST', headers: { 'content-type': 'application/json', apikey: this.anonKey },
      body: JSON.stringify({ auth_code: code, code_verifier: verifier }),
    });
    const json = await response.json() as Json;
    if (response.ok) this.session = json;
    return { status: response.status, json };
  }

  complete(accessToken = String(this.session?.access_token)) {
    return post(this.base, 'complete', { protocol: 1, request_id: this.requestId, device_secret: this.deviceSecret },
      { authorization: `Bearer ${accessToken}` });
  }

  cancel() {
    return post(this.base, 'cancel', { protocol: 1, request_id: this.requestId, actor: 'device', secret: this.deviceSecret });
  }
}

export class Browser {
  readonly browserSecret = randomSecret();
  requestId = '';
  ticket = '';

  constructor(readonly base: string, readonly origin: string, readonly ip = '198.51.100.20') {}

  private headers() { return { origin: this.origin, 'x-forwarded-for': this.ip }; }

  open(bootstrapUrl: string) {
    const parsed = parseBootstrapFragment(new URL(bootstrapUrl).hash);
    if (!parsed) throw new Error('bad bootstrap url');
    this.requestId = parsed.requestId;
    this.ticket = parsed.ticket;
  }

  claim(secret = this.browserSecret) {
    return post(this.base, 'claim', { protocol: 1, request_id: this.requestId, ticket: this.ticket, browser_secret: secret }, this.headers());
  }

  prepare() {
    return post(this.base, 'prepare', { protocol: 1, request_id: this.requestId, browser_secret: this.browserSecret, confirmed_started_by_me: true }, this.headers());
  }

  async login(authorizeUrl: string, choice: 'A' | 'B' | 'deny' = 'A') {
    const landed = await followOAuth(authorizeUrl, choice);
    return { landed, outcome: parseCallback(landed.search, landed.hash) };
  }

  publish(body: Json) {
    return post(this.base, 'publish', { protocol: 1, request_id: this.requestId, browser_secret: this.browserSecret, ...body }, this.headers());
  }

  status() {
    return post(this.base, 'browser-status', { protocol: 1, request_id: this.requestId, browser_secret: this.browserSecret }, this.headers());
  }
}

// Runs the relay part of the flow up to the moment the device holds the auth code.
export async function flowToCode(base: string, anonKey: string, origin: string, choice: 'A' | 'B' = 'A') {
  const device = new Device(base, anonKey);
  expectOk(await device.create());
  const browser = new Browser(base, origin);
  browser.open(device.bootstrapUrl);
  expectOk(await browser.claim());
  const prepared = await browser.prepare();
  expectOk(prepared);
  const { outcome, landed } = await browser.login(String(prepared.json.authorize_url), choice);
  if (outcome.kind !== 'code') throw new Error(`oauth outcome ${outcome.kind}`);
  expectOk(await browser.publish({ outcome: 'code', code: outcome.code }));
  return { device, browser, code: outcome.code, landed };
}

export function expectOk(r: { status: number; json: Json }) {
  if (r.status >= 300) throw new Error(`unexpected ${r.status}: ${JSON.stringify(r.json)}`);
  return r;
}
