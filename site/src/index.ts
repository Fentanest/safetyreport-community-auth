// Entry for /safeauth/ (index.html). Reads the one-time bootstrap fragment, moves it
// into this tab's sessionStorage, scrubs the address bar, then claims the request.
import './styles/tokens.css';
import './styles/ui.css';
import { randomSecret } from '../../server/crypto.ts';
import { isClientKind, isPhase, parseBootstrapFragment, TERMINAL_PHASES } from '../../server/protocol.ts';
import { call, type ClaimData } from './api.ts';
import { initTheme, isFramed } from './common.ts';
import { readConfig } from './config.ts';
import { FlowController } from './flow.ts';
import { clearFlow, type FlowContext, loadFlow, saveFlow, StorageUnavailable } from './storage.ts';
import { View } from './view.ts';

const rawHash = window.location.hash;
const hadQuery = window.location.search.length > 0;
if (rawHash || hadQuery) window.history.replaceState(null, '', window.location.pathname);

const view = new View();
initTheme();

// A new link pasted into this tab changes only the fragment (no page load). Reload so
// the new request goes through the same read-scrub-claim path as a fresh open.
window.addEventListener('hashchange', () => {
  if (window.location.hash.length > 1) window.location.reload();
});

async function claim(controller: FlowController): Promise<void> {
  const flow = controller.flow;
  if (!flow.ticket) { await controller.refresh(); return; }
  view.render({ kind: 'verifying' });
  const result = await call<ClaimData>(controller.config, 'claim', {
    request_id: flow.requestId, ticket: flow.ticket, browser_secret: flow.browserSecret,
  });
  if (!result.ok) { controller.handleError(result, () => { void claim(controller); }); return; }
  const data = result.data;
  if (!isPhase(data.phase)) { view.render({ kind: 'failed', traceId: null }); return; }
  flow.ticket = null; // claim is bound to this tab's browser secret from now on
  flow.deviceLabel = typeof data.device_label === 'string' ? data.device_label : null;
  flow.clientKind = isClientKind(data.client_kind) ? data.client_kind : null;
  flow.displayCode = typeof data.display_code === 'string' ? data.display_code : null;
  flow.expiresAt = typeof data.expires_at === 'string' ? data.expires_at : null;
  controller.route(data.phase);
}

async function main(): Promise<void> {
  if (isFramed()) { view.render({ kind: 'framed' }); return; }
  const cfg = readConfig();
  if (!cfg.ok) { view.render({ kind: 'config', code: cfg.code }); return; }
  const config = cfg.config;

  let existing: FlowContext | null;
  try { existing = loadFlow(); } catch (error) {
    if (error instanceof StorageUnavailable) { view.render({ kind: 'storage' }); return; }
    throw error;
  }

  if (rawHash) {
    const parsed = parseBootstrapFragment(rawHash);
    if (!parsed) { view.render({ kind: 'invalid', reason: 'bad_link' }); return; }
    let flow: FlowContext;
    if (existing && existing.requestId === parsed.requestId) {
      flow = { ...existing, ticket: existing.phase === 'created' ? parsed.ticket : existing.ticket };
    } else {
      if (existing && !(TERMINAL_PHASES as readonly string[]).includes(existing.phase)) {
        // One flow per tab: the previous unfinished request is cancelled, not silently merged.
        await call(config, 'cancel', { request_id: existing.requestId, actor: 'browser', secret: existing.browserSecret });
      }
      flow = {
        v: 1, requestId: parsed.requestId, browserSecret: randomSecret(), ticket: parsed.ticket, phase: 'created',
        expiresAt: null, deviceLabel: null, clientKind: null, displayCode: null,
      };
    }
    try { saveFlow(flow); } catch { view.render({ kind: 'storage' }); return; }
    await claim(new FlowController(config, view, flow));
    return;
  }

  if (!existing) { view.render({ kind: 'empty' }); return; }
  const controller = new FlowController(config, view, existing);
  if (existing.phase === 'created' && existing.ticket) await claim(controller);
  else { view.render({ kind: 'verifying' }); await controller.refresh(); }
}

main().catch(() => { clearFlow(); view.render({ kind: 'failed', traceId: null }); });
