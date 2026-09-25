// Per-tab flow context in sessionStorage. The key prefix only avoids collisions with
// other apps on https://worklazy.net; it is NOT isolation (same origin, same storage).
// Stored: request id, this tab's browser secret, the unclaimed ticket (until claim
// succeeds), phase and display metadata. Never: auth codes, tokens, verifiers.
import { isClientKind, isPhase, type ClientKind, type Phase, SECRET_PATTERN, UUID_PATTERN } from '../../server/protocol.ts';

const KEY = 'safeauth:v1:flow';

export interface FlowContext {
  v: 1;
  requestId: string;
  browserSecret: string;
  ticket: string | null;
  phase: Phase;
  expiresAt: string | null;
  deviceLabel: string | null;
  clientKind: ClientKind | null;
  displayCode: string | null;
}

export class StorageUnavailable extends Error {}

function store(): Storage {
  try {
    const s = window.sessionStorage;
    const probe = `${KEY}:probe`;
    s.setItem(probe, '1');
    s.removeItem(probe);
    return s;
  } catch {
    throw new StorageUnavailable('sessionStorage unavailable');
  }
}

export function loadFlow(): FlowContext | null {
  const raw = store().getItem(KEY);
  if (!raw) return null;
  try {
    const v = JSON.parse(raw) as Partial<FlowContext>;
    if (v.v !== 1 || !UUID_PATTERN.test(String(v.requestId)) || !SECRET_PATTERN.test(String(v.browserSecret)) || !isPhase(v.phase)) {
      clearFlow();
      return null;
    }
    return {
      v: 1,
      requestId: String(v.requestId),
      browserSecret: String(v.browserSecret),
      ticket: typeof v.ticket === 'string' && SECRET_PATTERN.test(v.ticket) ? v.ticket : null,
      phase: v.phase,
      expiresAt: typeof v.expiresAt === 'string' ? v.expiresAt : null,
      deviceLabel: typeof v.deviceLabel === 'string' ? v.deviceLabel.slice(0, 40) : null,
      clientKind: isClientKind(v.clientKind) ? v.clientKind : null,
      displayCode: typeof v.displayCode === 'string' ? v.displayCode.slice(0, 9) : null,
    };
  } catch {
    clearFlow();
    return null;
  }
}

export function saveFlow(flow: FlowContext): void {
  store().setItem(KEY, JSON.stringify(flow));
}

export function clearFlow(): void {
  try { window.sessionStorage.removeItem(KEY); } catch { /* storage blocked: nothing to clear */ }
}

// Theme preference only; never stored with flow data.
const THEME_KEY = 'safeauth:theme';
export function loadTheme(): 'light' | 'dark' | null {
  try {
    const v = window.localStorage.getItem(THEME_KEY);
    return v === 'light' || v === 'dark' ? v : null;
  } catch { return null; }
}
export function saveTheme(value: 'light' | 'dark'): void {
  try { window.localStorage.setItem(THEME_KEY, value); } catch { /* preference not persisted */ }
}
