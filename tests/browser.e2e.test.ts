// Real-browser review of the central pages on the LOCAL stack (Chromium via Playwright).
// Preconditions (see docs/verification.md):
//   node tests/stack/stack.mjs up
//   tests/stack/build-local.sh
//   node --experimental-strip-types tests/stack/serve-local.ts .safeauth-stack/dist-local
//   SAFEAUTH_STACK=1 SAFEAUTH_BROWSER=1 npx vitest run tests/browser.e2e.test.ts
// Kakao is the local mock; this is not a hosted Kakao E2E.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import { type Browser as PwBrowser, chromium, type Page } from 'playwright';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Device, expectOk } from './support/actors.ts';
import { startGateway } from './stack/gateway.ts';
import { loadStackEnv, PORTS, psql } from './stack/stack.mjs';
import { startStaticServer } from './stack/static-server.mjs';

const enabled = process.env.SAFEAUTH_STACK === '1' && process.env.SAFEAUTH_BROWSER === '1';
const repo = resolve(__dirname, '..');
const SITE = `http://127.0.0.1:${PORTS.site}`;
const GW = `http://127.0.0.1:${PORTS.gateway}`;
const SHOTS = join(repo, 'docs/qa/screenshots');
const RESULTS = join(repo, 'docs/qa/browser-results.json');
const axeSource = readFileSync(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8');

interface Recorder { requests: { url: string; method: string; type: string; referer: string | null }[]; console: string[]; errors: string[] }
const results: Record<string, unknown> = {};

function record(page: Page): Recorder {
  const rec: Recorder = { requests: [], console: [], errors: [] };
  page.on('request', r => rec.requests.push({ url: r.url(), method: r.method(), type: r.resourceType(), referer: r.headers().referer ?? null }));
  page.on('console', m => { if (m.type() === 'error' || m.type() === 'warning') rec.console.push(`${m.type()}: ${m.text()}`); });
  page.on('pageerror', e => rec.errors.push(String(e)));
  return rec;
}

async function title(page: Page): Promise<string> {
  return (await page.locator('#auth-card h2').first().textContent())?.trim() ?? '';
}

async function waitTitle(page: Page, text: string, timeout = 20000): Promise<void> {
  await page.locator('#auth-card h2', { hasText: text }).first().waitFor({ timeout });
}

async function overflow(page: Page): Promise<number> {
  return page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
}

async function shot(page: Page, name: string, fullPage = true): Promise<string> {
  mkdirSync(SHOTS, { recursive: true });
  const path = join(SHOTS, `${name}.png`);
  await page.screenshot({ path, fullPage });
  return `docs/qa/screenshots/${name}.png`;
}

async function axe(page: Page): Promise<{ id: string; impact: string | null; nodes: number }[]> {
  await page.addScriptTag({ content: axeSource }).catch(() => undefined);
  const violations = await page.evaluate(async () => {
    // @ts-expect-error injected
    const r = await window.axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] } });
    return r.violations.map((v: { id: string; impact: string | null; nodes: unknown[] }) => ({ id: v.id, impact: v.impact, nodes: v.nodes.length }));
  });
  return violations;
}

describe.skipIf(!enabled)('safeauth central pages in a real browser', () => {
  let stack: Record<string, string>;
  let browser: PwBrowser;
  const newDevice = (label = '우리집 NAS', kind = 'docker') => new Device(GW, stack.SAFEAUTH_ANON_KEY, label, kind);
  const ctx = (opts: Parameters<PwBrowser['newContext']>[0] = {}) => browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR', ...opts });

  beforeAll(async () => {
    stack = loadStackEnv();
    psql("delete from private.community_auth_rate_limits;", { env: stack });
    browser = await chromium.launch();
    const probe = await fetch(`${SITE}/`);
    if (!probe.ok) throw new Error('serve-local.ts is not running');
  });

  afterAll(async () => {
    await browser?.close();
    mkdirSync(join(repo, 'docs/qa'), { recursive: true });
    writeFileSync(RESULTS, JSON.stringify({ generatedAt: new Date().toISOString(), browser: 'chromium (playwright 1.63.0)', data: 'local stack + mock Kakao', results }, null, 2) + '\n');
  });

  it('U01: without a request there is no login action', async () => {
    const context = await ctx();
    const page = await context.newPage();
    const rec = record(page);
    await page.goto(`${SITE}/`);
    await waitTitle(page, '앱에서 연결을 시작해 주세요');
    expect(await page.locator('#kakao-button').count()).toBe(0);
    expect(rec.requests.filter(r => r.url.includes('/functions/v1/'))).toHaveLength(0);
    results.U01 = { pass: true, screenshot: await shot(page, 'empty-1440-light') };
    await context.close();
  });

  it('happy path: link -> confirm -> Kakao -> callback -> device confirms -> success, with no central token exchange', async () => {
    const device = newDevice();
    expectOk(await device.create());
    const context = await ctx();
    const page = await context.newPage();
    const rec = record(page);
    await page.goto(device.bootstrapUrl);
    await waitTitle(page, '연결할 기기를 확인해 주세요');
    expect(new URL(page.url()).hash).toBe(''); // U06: fragment scrubbed
    expect(await page.locator('.pair-code').textContent()).toBe(device.displayCode); // A05
    expect(await page.locator('.device-name').textContent()).toBe('우리집 NAS');
    const kakao = page.locator('#kakao-button');
    expect(await kakao.isDisabled()).toBe(true); // U02
    const readyShot = await shot(page, 'ready-1440-light');
    const storedTicket = await page.evaluate(() => sessionStorage.getItem('safeauth:v1:flow'));
    expect(storedTicket).not.toContain('"ticket":"'); // ticket dropped after claim
    await page.locator('#confirm-start').check();
    expect(await kakao.isEnabled()).toBe(true);
    await kakao.click();
    await page.waitForURL(`http://127.0.0.1:${PORTS.kakao}/oauth/authorize**`);
    await page.locator('#mock-account-a').click();
    await page.waitForURL(`${SITE}/callback.html`);
    await page.locator('#auth-card h2', { hasText: '원래 기기에서 계정을 확인해 주세요' }).waitFor();
    expect(page.url()).toBe(`${SITE}/callback.html`); // U06: code scrubbed
    const code = new URL(rec.requests.find(r => r.url.startsWith(`${SITE}/callback.html?`))!.url).searchParams.get('code')!;
    expect(code).toBeTruthy();
    const dom = await page.content();
    const storage = await page.evaluate(() => JSON.stringify({ ...sessionStorage }) + JSON.stringify({ ...localStorage }));
    expect(dom).not.toContain(code);
    expect(storage).not.toContain(code);
    expect(await page.locator('.pill.success').count()).toBe(0); // not success yet
    const waitingShot = await shot(page, 'waiting-1440-light');

    const polled = expectOk(await device.poll());
    expect(polled.json.auth_code).toBe(code);
    await page.locator('#auth-card h2', { hasText: '원래 기기에서 계정을 확인해 주세요' }).waitFor();
    expect(await page.locator('.pill.success').count()).toBe(0); // delivered is still not success (A07)
    expect((await device.exchange(code)).status).toBe(200);
    await page.waitForTimeout(4000);
    expect(await title(page)).toBe('원래 기기에서 계정을 확인해 주세요'); // exchanged but not confirmed
    expectOk(await device.complete());
    await waitTitle(page, '기기 연결이 완료됐어요', 15000);
    const successShot = await shot(page, 'success-1440-light');
    const before = rec.requests.length;
    await page.waitForTimeout(8000);
    const after = rec.requests.slice(before).filter(r => r.url.includes('/functions/v1/'));
    expect(after).toHaveLength(0); // U07: polling stopped
    expect(await page.evaluate(() => sessionStorage.getItem('safeauth:v1:flow'))).toBeNull();

    const tokenCalls = rec.requests.filter(r => r.url.includes('/auth/v1/token'));
    expect(tokenCalls).toHaveLength(0); // P02
    const ours = rec.requests.filter(r => r.url.startsWith(`${GW}/functions/`) || r.url.startsWith(`${GW}/auth/v1/authorize`) || r.url.startsWith(`${SITE}/`));
    // Our pages send no Referer. The only one is the identity provider's own page origin
    // on its redirect into callback.html (the IdP's policy; origin only, no secret).
    const referers = ours.filter(r => r.referer);
    expect(referers.every(r => r.referer === `http://127.0.0.1:${PORTS.kakao}/` && r.type === 'document')).toBe(true);
    expect(referers.some(r => /safeauth|[?#]/.test(r.referer ?? ''))).toBe(false);
    const hosts = [...new Set(rec.requests.map(r => new URL(r.url).host))].sort();
    expect(hosts).toEqual([`127.0.0.1:${PORTS.gateway}`, `127.0.0.1:${PORTS.kakao}`, `127.0.0.1:${PORTS.site}`].sort());
    expect(rec.errors).toEqual([]);
    results.happyPath = {
      pass: true, screenshots: [readyShot, waitingShot, successShot], hosts, tokenCallsFromBrowser: 0,
      referersFromOurPages: 0, idpRedirectReferer: referers.map(r => r.referer), consoleMessages: rec.console, requestCount: rec.requests.length,
    };
    await context.close();
  });

  it('U05/U03: network loss on callback shows an unknown state, retry recovers; refresh resumes without the code', async () => {
    const device = newDevice('서재 PC', 'pc');
    expectOk(await device.create());
    const context = await ctx({ viewport: { width: 390, height: 844 }, colorScheme: 'dark', isMobile: true, hasTouch: true });
    const page = await context.newPage();
    const rec = record(page);
    await page.goto(device.bootstrapUrl);
    await waitTitle(page, '연결할 기기를 확인해 주세요');
    const readyDark = await shot(page, 'ready-390-dark');
    await page.locator('#confirm-start').check();
    await page.locator('#kakao-button').click();
    await page.waitForURL(`http://127.0.0.1:${PORTS.kakao}/oauth/authorize**`);
    await page.route('**/functions/v1/community-auth-relay/**', route => route.abort('internetdisconnected'));
    await page.locator('#mock-account-b').click();
    await waitTitle(page, '연결 상태를 확인하지 못했어요', 20000);
    expect(await page.locator('.pill.success').count()).toBe(0);
    const networkShot = await shot(page, 'network-390-dark');
    await page.unroute('**/functions/v1/community-auth-relay/**');
    await page.getByRole('button', { name: '다시 확인하기' }).click();
    await waitTitle(page, '원래 기기에서 계정을 확인해 주세요');
    await page.reload();
    await waitTitle(page, '원래 기기에서 계정을 확인해 주세요');
    expect(page.url()).toBe(`${SITE}/callback.html`);
    const waitingDark = await shot(page, 'waiting-390-dark');
    const polled = expectOk(await device.poll());
    expect((await device.exchange(String(polled.json.auth_code))).status).toBe(200);
    expectOk(await device.complete());
    await waitTitle(page, '기기 연결이 완료됐어요', 15000);
    const successDark = await shot(page, 'success-390-dark');
    expect(await overflow(page)).toBeLessThanOrEqual(0);
    expect(rec.errors).toEqual([]);
    results.networkAndRefresh = { pass: true, screenshots: [readyDark, networkShot, waitingDark, successDark] };
    await context.close();
  });

  it('Kakao denial -> cancelled, never success; device sees cancelled', async () => {
    const device = newDevice();
    expectOk(await device.create());
    const context = await ctx();
    const page = await context.newPage();
    await page.goto(device.bootstrapUrl);
    await waitTitle(page, '연결할 기기를 확인해 주세요');
    await page.locator('#confirm-start').check();
    await page.locator('#kakao-button').click();
    await page.locator('#mock-deny').click();
    await waitTitle(page, '연결을 취소했어요');
    expect((await device.poll()).json).toMatchObject({ status: 'cancelled', reason: 'oauth' });
    results.denied = { pass: true, screenshot: await shot(page, 'cancelled-oauth-1440-light') };
    await context.close();
  });

  it('U03: callback in another browser (no tab context) discards the code and publishes nothing', async () => {
    const context = await ctx();
    const page = await context.newPage();
    const rec = record(page);
    await page.goto(`${SITE}/callback.html?code=00000000-0000-4000-8000-000000000000`);
    await waitTitle(page, '연결 정보를 찾을 수 없어요');
    expect(page.url()).toBe(`${SITE}/callback.html`);
    expect(rec.requests.filter(r => r.url.includes('/functions/v1/'))).toHaveLength(0);
    results.callbackWithoutContext = { pass: true, screenshot: await shot(page, 'invalid-callback-1440-light') };
    await context.close();
  });

  it('link opened in a second browser is refused; second link in the same tab cancels the first', async () => {
    const a = newDevice('첫번째 요청', 'pc');
    expectOk(await a.create());
    const one = await ctx();
    const p1 = await one.newPage();
    await p1.goto(a.bootstrapUrl);
    await waitTitle(p1, '연결할 기기를 확인해 주세요');
    const two = await ctx();
    const p2 = await two.newPage();
    await p2.goto(a.bootstrapUrl);
    await waitTitle(p2, '연결 정보를 찾을 수 없어요');
    expect(await p2.locator('#auth-card').textContent()).toContain('이미 다른 브라우저에서 열렸어요');
    const claimedElsewhere = await shot(p2, 'claimed-elsewhere-1440-light');
    const b = newDevice('두번째 요청', 'docker');
    expectOk(await b.create());
    await p1.goto(b.bootstrapUrl);
    await waitTitle(p1, '연결할 기기를 확인해 주세요');
    expect(await p1.locator('.device-name').textContent()).toBe('두번째 요청');
    expect((await a.poll()).json).toMatchObject({ status: 'cancelled', reason: 'browser' });
    results.multiTab = { pass: true, screenshot: claimedElsewhere };
    await one.close();
    await two.close();
  });

  it('cancel button, expiry, storage blocked, framing and bad links render their states', async () => {
    const context = await ctx();
    const page = await context.newPage();
    const dev = newDevice();
    expectOk(await dev.create());
    await page.goto(dev.bootstrapUrl);
    await waitTitle(page, '연결할 기기를 확인해 주세요');
    await page.getByRole('button', { name: '연결 취소' }).click();
    await waitTitle(page, '연결을 취소했어요');
    expect((await dev.poll()).json.status).toBe('cancelled');
    const cancelledShot = await shot(page, 'cancelled-1440-light');

    const old = newDevice();
    expectOk(await old.create());
    psql(`update private.community_auth_requests set expires_at = now() - interval '1 second', created_at = now() - interval '11 minutes' where id='${old.requestId}'`, { env: stack });
    await page.goto(old.bootstrapUrl);
    await waitTitle(page, '연결 시간이 지났어요');
    const expiredShot = await shot(page, 'expired-1440-light');

    await page.goto(`${SITE}/#r=not-a-uuid&t=x`);
    await waitTitle(page, '연결 정보를 찾을 수 없어요');

    const blocked = await ctx({ viewport: { width: 320, height: 740 } });
    await blocked.addInitScript(() => {
      Object.defineProperty(window, 'sessionStorage', { get() { throw new DOMException('blocked', 'SecurityError'); } });
    });
    const bp = await blocked.newPage();
    const fresh = newDevice();
    expectOk(await fresh.create());
    await bp.goto(fresh.bootstrapUrl);
    await waitTitle(bp, '이 브라우저에서 연결을 이어갈 수 없어요');
    expect(new URL(bp.url()).hash).toBe('');
    const storageShot = await shot(bp, 'storage-blocked-320-light');
    expect(await overflow(bp)).toBeLessThanOrEqual(0);
    await blocked.close();

    const framer = await ctx();
    const fp = await framer.newPage();
    await fp.setContent(`<iframe id="f" src="${SITE}/" width="800" height="700"></iframe>`);
    const frame = await (await fp.waitForSelector('#f')).contentFrame();
    await frame!.locator('#auth-card h2', { hasText: '이 화면은 다른 페이지 안에서 열 수 없어요' }).waitFor();
    await framer.close();
    results.states = { pass: true, screenshots: [cancelledShot, expiredShot, storageShot] };
    await context.close();
  });

  it('U11: layouts at 1440/1024/768/390/320 and a 200% zoom-equivalent width, light and dark, without horizontal overflow', async () => {
    const sizes: [number, number][] = [[1440, 900], [1024, 768], [768, 1024], [390, 844], [320, 740], [640, 400]];
    const report: Record<string, unknown>[] = [];
    for (const scheme of ['light', 'dark'] as const) {
      for (const [width, height] of sizes) {
        const context = await ctx({ viewport: { width, height }, colorScheme: scheme });
        const page = await context.newPage();
        const device = newDevice('우리집-거실에-설치한-나만의-안전신문고-자동수집-서버-두번째'.slice(0, 40), 'docker');
        expectOk(await device.create());
        await page.goto(device.bootstrapUrl);
        await waitTitle(page, '연결할 기기를 확인해 주세요');
        const over = await overflow(page);
        const name = `ready-longlabel-${width}-${scheme}`;
        const path = [1440, 390, 320].includes(width) ? await shot(page, name) : null;
        const disabledBox = await page.locator('#kakao-button').boundingBox();
        await page.locator('#confirm-start').check();
        const kakaoBox = await page.locator('#kakao-button').boundingBox();
        const img = await page.locator('#kakao-button img').boundingBox();
        const enabledPath = [390, 320].includes(width) ? await shot(page, `${name}-checked`) : null;
        expect(disabledBox!.height).toBeGreaterThanOrEqual(48);
        await page.goto(`${SITE}/help.html`);
        const helpOver = await overflow(page);
        report.push({ scheme, width, height, overflowPx: over, helpOverflowPx: helpOver, kakaoButtonHeight: kakaoBox?.height, kakaoImage: img && { w: img.width, h: img.height }, screenshots: [path, enabledPath].filter(Boolean) });
        expect(over, name).toBeLessThanOrEqual(0);
        expect(helpOver).toBeLessThanOrEqual(0);
        expect(kakaoBox!.height).toBeGreaterThanOrEqual(48);
        expect(Math.round(img!.width / img!.height * 100)).toBe(Math.round(224 / 46 * 100)); // official aspect kept
        await device.cancel();
        await context.close();
      }
    }
    results.U11 = { pass: true, report, note: '640x400 approximates a 1280x800 window at 200% zoom; not a browser-zoom test' };
  });

  it('U12: keyboard order, focus ring, live region, reduced motion and axe (automated only)', async () => {
    // bypassCSP only lets the injected axe script run; the page CSP is otherwise enforced.
    const context = await ctx({ reducedMotion: 'reduce', bypassCSP: true });
    const page = await context.newPage();
    const device = newDevice();
    expectOk(await device.create());
    await page.goto(device.bootstrapUrl);
    await waitTitle(page, '연결할 기기를 확인해 주세요');
    const order: string[] = [];
    for (let i = 0; i < 7; i += 1) {
      await page.keyboard.press('Tab');
      order.push(await page.evaluate(() => {
        const el = document.activeElement as HTMLElement | null;
        return el ? (el.id || el.getAttribute('aria-label') || el.textContent?.trim().slice(0, 20) || el.tagName) : 'none';
      }));
    }
    // The Kakao button is disabled until the checkbox is ticked, so Tab skips it.
    expect(order.slice(0, 4)).toEqual(['연결 카드로 건너뛰기', 'theme-toggle', 'confirm-start', '연결 취소']);
    await page.locator('#confirm-start').focus();
    const outline = await page.evaluate(() => getComputedStyle(document.activeElement!).outlineStyle);
    await page.keyboard.press('Space');
    expect(await page.locator('#kakao-button').isEnabled()).toBe(true);
    expect(await page.evaluate(() => document.activeElement?.id)).toBe('confirm-start'); // focus kept
    await page.keyboard.press('Tab');
    expect(await page.evaluate(() => document.activeElement?.id)).toBe('kakao-button');
    const kakaoName = await page.locator('#kakao-button img').getAttribute('alt');
    expect(kakaoName).toBe('카카오 로그인');
    const transition = await page.evaluate(() => getComputedStyle(document.querySelector('.btn')!).transitionDuration);
    const live = await page.locator('#announcer').getAttribute('aria-live');
    const light = await axe(page);
    await page.emulateMedia({ colorScheme: 'dark' });
    const dark = await axe(page);
    await page.goto(`${SITE}/privacy.html`);
    const privacy = await axe(page);
    results.U12 = { pass: true, tabOrder: order, focusOutline: outline, reducedMotionTransition: transition, liveRegion: live,
      axe: { readyLight: light, readyDark: dark, privacy }, note: 'axe covers automatable WCAG checks only; no screen-reader session was run' };
    expect(outline).not.toBe('none');
    expect(live).toBe('polite');
    expect(transition).toBe('0s');
    expect([...light, ...dark, ...privacy].filter(v => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
    await device.cancel();
    await context.close();
  });

  it('U08: the same pages also work from a subpath (/sub/) build', async () => {
    const gw2 = await startGateway({ port: PORTS.gateway + 1, siteUrl: 'http://127.0.0.1:8481/sub/', browserOrigins: 'http://127.0.0.1:8481' });
    const site2 = await startStaticServer({ root: join(repo, '.safeauth-stack/site-sub'), port: 8481 });
    try {
      const device = new Device(`http://127.0.0.1:${PORTS.gateway + 1}`, stack.SAFEAUTH_ANON_KEY, '하위 경로 배포 확인', 'pc');
      expectOk(await device.create());
      expect(device.bootstrapUrl.startsWith('http://127.0.0.1:8481/sub/#r=')).toBe(true);
      const context = await ctx();
      const page = await context.newPage();
      await page.goto(device.bootstrapUrl);
      await waitTitle(page, '연결할 기기를 확인해 주세요');
      await page.locator('#confirm-start').check();
      await page.locator('#kakao-button').click();
      await page.locator('#mock-account-a').click();
      await page.waitForURL('http://127.0.0.1:8481/sub/callback.html');
      await waitTitle(page, '원래 기기에서 계정을 확인해 주세요');
      const polled = expectOk(await device.poll());
      expect((await device.exchange(String(polled.json.auth_code))).status).toBe(200);
      expectOk(await device.complete());
      await waitTitle(page, '기기 연결이 완료됐어요', 15000);
      await page.goto('http://127.0.0.1:8481/sub/callback.html');
      await waitTitle(page, '연결 정보를 찾을 수 없어요'); // direct reload after completion: no context, no 404
      results.U08 = { pass: true, base: '/sub/' };
      await context.close();
    } finally {
      await new Promise(r => gw2.server.close(r));
      await new Promise(r => site2.server.close(r));
    }
  });

  it('config missing: an unconfigured production build shows the operator code and no login', async () => {
    const site3 = await startStaticServer({ root: join(repo, 'dist'), port: 8482 });
    try {
      const context = await ctx({ viewport: { width: 390, height: 844 } });
      const page = await context.newPage();
      const rec = record(page);
      await page.goto('http://127.0.0.1:8482/#r=00000000-0000-4000-8000-000000000000&t=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
      await waitTitle(page, '연결 서비스를 준비 중이에요');
      expect(await page.locator('#auth-card').textContent()).toContain('AUTH_CONFIG_MISSING');
      expect(await page.locator('#kakao-button').count()).toBe(0);
      expect(rec.requests.filter(r => !r.url.startsWith('http://127.0.0.1:8482/'))).toEqual([]);
      results.configMissing = { pass: true, screenshot: await shot(page, 'config-missing-390-light') };
      await context.close();
    } finally {
      await new Promise(r => site3.server.close(r));
    }
  });
});
