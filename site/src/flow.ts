// Flow controller shared by index.html and callback.html: phase routing, status
// polling with jitter/backoff/Retry-After, cancel. Success is shown only for the
// relay phase device_confirmed, which requires the original device's confirmation.
import { isPhase, type Phase, TERMINAL_PHASES } from '../../server/protocol.ts';
import { type ApiResult, call, type PhaseData, type PrepareData } from './api.ts';
import type { PublicConfig } from './config.ts';
import { clearFlow, type FlowContext, saveFlow } from './storage.ts';
import { verifyAuthorizeUrl } from '../../server/protocol.ts';
import type { DeviceInfo, View } from './view.ts';

const POLL_MS = 3000;
const HIDDEN_POLL_MS = 10000;
const MAX_BACKOFF_MS = 30000;

export class FlowController {
  private pollTimer: number | null = null;
  private failures = 0;
  private checked = false;
  private busy = false;
  private stopped = false;

  constructor(readonly config: PublicConfig, readonly view: View, public flow: FlowContext) {
    view.onExpire = () => { void this.refresh(); };
  }

  device(): DeviceInfo {
    return { label: this.flow.deviceLabel, kind: this.flow.clientKind, displayCode: this.flow.displayCode, expiresAt: this.flow.expiresAt };
  }

  persist(): void {
    try { saveFlow(this.flow); } catch { /* storage became unavailable; in-memory flow continues */ }
  }

  stop(): void {
    this.stopped = true;
    if (this.pollTimer !== null) window.clearTimeout(this.pollTimer);
    this.pollTimer = null;
    this.view.stopCountdown();
  }

  // Maps relay error codes to screens. Returns true when the error was terminal.
  handleError(result: Exclude<ApiResult<unknown>, { ok: true }>, retry: () => void): void {
    if (result.kind === 'network') {
      this.view.render({ kind: 'network', busy: false, onRetry: retry });
      return;
    }
    switch (result.code) {
      case 'expired': this.finish('expired'); return;
      case 'cancelled': this.finish('cancelled'); return;
      case 'failed': this.finish('failed'); return;
      case 'not_found': this.stop(); clearFlow(); this.view.render({ kind: 'invalid', reason: 'bad_link' }); return;
      case 'already_claimed': this.stop(); this.view.render({ kind: 'invalid', reason: 'claimed_elsewhere' }); return;
      case 'service_disabled':
      case 'config_missing':
        this.stop();
        this.view.render({ kind: 'config', code: `RELAY_${result.code.toUpperCase()}` });
        return;
      case 'rate_limited':
        this.view.render({ kind: 'network', busy: true, onRetry: retry });
        window.setTimeout(retry, Math.min(MAX_BACKOFF_MS, (result.retryAfterSeconds ?? 5) * 1000));
        return;
      case 'invalid_state':
        void this.refresh();
        return;
      default:
        this.stop();
        clearFlow();
        this.view.render({ kind: 'failed', traceId: result.traceId });
    }
  }

  finish(phase: 'device_confirmed' | 'cancelled' | 'expired' | 'failed'): void {
    this.stop();
    this.flow.phase = phase;
    clearFlow();
    if (phase === 'device_confirmed') this.view.render({ kind: 'success', device: this.device() });
    else if (phase === 'cancelled') this.view.render({ kind: 'cancelled' });
    else if (phase === 'expired') this.view.render({ kind: 'expired' });
    else this.view.render({ kind: 'oauth_failed' });
  }

  route(phase: Phase): void {
    this.flow.phase = phase;
    if ((TERMINAL_PHASES as readonly string[]).includes(phase)) {
      this.finish(phase as 'device_confirmed' | 'cancelled' | 'expired' | 'failed');
      return;
    }
    this.persist();
    if (phase === 'claimed') this.renderReady();
    else if (phase === 'oauth_started') this.view.render({ kind: 'redirecting', onRetry: () => { void this.startOAuth(); }, onCancel: () => { void this.cancel(); }, retried: true });
    else if (phase === 'code_ready' || phase === 'code_delivered') {
      this.view.render({ kind: 'waiting', device: this.device(), delivered: phase === 'code_delivered' });
      this.schedulePoll(POLL_MS);
    } else {
      this.view.render({ kind: 'invalid', reason: 'bad_link' }); // 'created' is never visible to a claimed browser
    }
  }

  renderReady(message?: string): void {
    this.view.render({
      kind: 'ready', device: this.device(), busy: this.busy, checked: this.checked, message,
      onCheck: v => { this.checked = v; this.renderReady(); },
      onKakao: () => { void this.startOAuth(); },
      onCancel: () => { void this.cancel(); },
    });
  }

  async refresh(): Promise<void> {
    if (this.stopped) return;
    const result = await call<PhaseData>(this.config, 'browser-status', { request_id: this.flow.requestId, browser_secret: this.flow.browserSecret });
    if (!result.ok) { this.handleError(result, () => { void this.refresh(); }); return; }
    if (!isPhase(result.data.phase)) { this.view.render({ kind: 'failed', traceId: null }); return; }
    if (typeof result.data.expires_at === 'string') this.flow.expiresAt = result.data.expires_at;
    this.failures = 0;
    this.route(result.data.phase);
  }

  private schedulePoll(delay: number): void {
    if (this.stopped) return;
    if (this.pollTimer !== null) window.clearTimeout(this.pollTimer);
    const jitter = delay * (0.8 + Math.random() * 0.4);
    const wait = document.visibilityState === 'hidden' ? Math.max(jitter, HIDDEN_POLL_MS) : jitter;
    this.pollTimer = window.setTimeout(() => { void this.pollOnce(); }, wait);
  }

  private async pollOnce(): Promise<void> {
    if (this.stopped) return;
    const before = this.flow.phase;
    const result = await call<PhaseData>(this.config, 'browser-status', { request_id: this.flow.requestId, browser_secret: this.flow.browserSecret });
    if (!result.ok) {
      if (result.kind === 'network') {
        this.failures += 1;
        if (this.failures >= 3) {
          this.view.render({ kind: 'network', busy: false, onRetry: () => { this.failures = 0; void this.refresh(); } });
          return;
        }
        this.schedulePoll(Math.min(MAX_BACKOFF_MS, POLL_MS * 2 ** this.failures));
        return;
      }
      if (result.code === 'rate_limited') { this.schedulePoll((result.retryAfterSeconds ?? 10) * 1000); return; }
      this.handleError(result, () => { void this.refresh(); });
      return;
    }
    this.failures = 0;
    if (!isPhase(result.data.phase)) return;
    if (result.data.phase === before) { this.schedulePoll(POLL_MS); return; }
    this.route(result.data.phase);
  }

  async startOAuth(): Promise<void> {
    if (this.busy) return;
    this.busy = true;
    if (this.flow.phase === 'claimed') this.renderReady();
    const result = await call<PrepareData>(this.config, 'prepare', {
      request_id: this.flow.requestId, browser_secret: this.flow.browserSecret, confirmed_started_by_me: true,
    });
    this.busy = false;
    if (!result.ok) {
      if (result.kind === 'relay' && result.code === 'prepare_limit') {
        this.stop();
        this.view.render({ kind: 'failed', traceId: result.traceId });
        return;
      }
      this.handleError(result, () => { void this.startOAuth(); });
      return;
    }
    // Follow only an authorize URL for our own Supabase project and fixed callback.
    const url = verifyAuthorizeUrl(result.data.authorize_url, this.config.supabaseUrl, this.config.callbackUrl);
    if (!url) { this.stop(); clearFlow(); this.view.render({ kind: 'failed', traceId: null }); return; }
    this.flow.phase = 'oauth_started';
    this.persist();
    this.view.render({ kind: 'redirecting', onRetry: null, onCancel: () => { void this.cancel(); }, retried: false });
    let retried = false;
    window.location.assign(url);
    window.setTimeout(() => {
      if (this.stopped) return;
      this.view.render({
        kind: 'redirecting', retried,
        onRetry: retried ? null : () => { retried = true; window.location.assign(url); },
        onCancel: () => { void this.cancel(); },
      });
    }, 4000);
  }

  async cancel(): Promise<void> {
    const result = await call<PhaseData>(this.config, 'cancel', { request_id: this.flow.requestId, actor: 'browser', secret: this.flow.browserSecret });
    if (result.ok && isPhase(result.data.phase)) { this.route(result.data.phase); return; }
    if (!result.ok && result.kind === 'relay' && result.code === 'already_completed') { this.finish('device_confirmed'); return; }
    if (!result.ok) this.handleError(result, () => { void this.cancel(); });
  }
}
