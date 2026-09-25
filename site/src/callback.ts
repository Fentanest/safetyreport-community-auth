// Entry for /callback.html. The auth code is read into memory and the
// address bar is scrubbed before anything else runs; the code is never stored,
// logged, rendered, or sent anywhere except the relay publish call for the request
// that this same tab started. Without that tab context the code is discarded.
import './styles/tokens.css';
import './styles/ui.css';
import { type CallbackOutcome, isPhase, parseCallback } from '../../server/protocol.ts';
import { call, type PhaseData } from './api.ts';
import { initTheme, isFramed } from './common.ts';
import { readConfig } from './config.ts';
import { FlowController } from './flow.ts';
import { clearFlow, type FlowContext, loadFlow, StorageUnavailable } from './storage.ts';
import { View } from './view.ts';

let outcome: CallbackOutcome = parseCallback(window.location.search, window.location.hash);
window.history.replaceState(null, '', window.location.pathname);

const view = new View();
initTheme();

async function publish(controller: FlowController, attempt = 0): Promise<void> {
  view.render({ kind: 'callback' });
  const body = outcome.kind === 'code'
    ? { request_id: controller.flow.requestId, browser_secret: controller.flow.browserSecret, outcome: 'code', code: outcome.code }
    : { request_id: controller.flow.requestId, browser_secret: controller.flow.browserSecret, outcome: outcome.kind === 'denied' ? 'denied' : 'error' };
  const result = await call<PhaseData>(controller.config, 'publish', body);
  if (!result.ok && result.kind === 'network' && attempt < 2) {
    // Same code again is idempotent on the relay; retry briefly before asking the user.
    window.setTimeout(() => { void publish(controller, attempt + 1); }, 1500 * (attempt + 1));
    return;
  }
  if (!result.ok) {
    controller.handleError(result, () => { void publish(controller, 0); });
    return;
  }
  outcome = { kind: 'missing' }; // drop the code from memory once the relay has it
  if (!isPhase(result.data.phase)) { view.render({ kind: 'failed', traceId: null }); return; }
  controller.route(result.data.phase);
}

async function main(): Promise<void> {
  if (isFramed()) { outcome = { kind: 'missing' }; view.render({ kind: 'framed' }); return; }
  const cfg = readConfig();
  if (!cfg.ok) { outcome = { kind: 'missing' }; view.render({ kind: 'config', code: cfg.code }); return; }

  let flow: FlowContext | null;
  try { flow = loadFlow(); } catch (error) {
    if (error instanceof StorageUnavailable) { outcome = { kind: 'missing' }; view.render({ kind: 'storage' }); return; }
    throw error;
  }
  if (!flow) {
    outcome = { kind: 'missing' };
    view.render({ kind: 'invalid', reason: 'no_context' });
    return;
  }

  const controller = new FlowController(cfg.config, view, flow);
  if (outcome.kind === 'missing') {
    // Refresh after the scrub, back navigation, or a direct visit: show server state only.
    view.render({ kind: 'callback' });
    await controller.refresh();
    return;
  }
  if (flow.phase !== 'oauth_started' && flow.phase !== 'code_ready' && flow.phase !== 'code_delivered') {
    outcome = { kind: 'missing' };
    await controller.refresh();
    return;
  }
  await publish(controller);
}

main().catch(() => { outcome = { kind: 'missing' }; clearFlow(); view.render({ kind: 'failed', traceId: null }); });
