// Renders the transaction card for every flow state. All text is local constant copy
// or server-provided display fields inserted with textContent (never innerHTML).
import type { ClientKind } from '../../server/protocol.ts';

export interface DeviceInfo {
  label: string | null;
  kind: ClientKind | null;
  displayCode: string | null;
  expiresAt: string | null;
}

export type ViewState =
  | { kind: 'verifying' }
  | { kind: 'empty' }
  | { kind: 'ready'; device: DeviceInfo; busy: boolean; checked: boolean; onCheck(v: boolean): void; onKakao(): void; onCancel(): void; message?: string }
  | { kind: 'redirecting'; onRetry: (() => void) | null; onCancel(): void; retried: boolean }
  | { kind: 'callback' }
  | { kind: 'waiting'; device: DeviceInfo; delivered: boolean }
  | { kind: 'success'; device: DeviceInfo }
  | { kind: 'expired' }
  | { kind: 'cancelled' }
  | { kind: 'oauth_failed' }
  | { kind: 'network'; onRetry(): void; busy: boolean }
  | { kind: 'invalid'; reason: 'no_context' | 'claimed_elsewhere' | 'bad_link' }
  | { kind: 'config'; code: string }
  | { kind: 'storage' }
  | { kind: 'framed' }
  | { kind: 'failed'; traceId: string | null };

const KIND_LABEL: Record<ClientKind, [string, string]> = {
  pc: ['이 PC', 'LOCAL'],
  docker: ['Docker / NAS 서버', 'SERVER'],
  mobile_client_server: ['연결된 서버', 'SERVER'],
};

const helpHref = () => new URL('help.html', document.baseURI).pathname;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

function button(text: string, cls: string, onClick: () => void, busy = false): HTMLButtonElement {
  const b = el('button', cls, text);
  b.type = 'button';
  b.disabled = busy;
  if (busy) b.setAttribute('aria-busy', 'true');
  b.addEventListener('click', onClick);
  return b;
}

function linkButton(text: string, href: string, cls = 'btn secondary'): HTMLAnchorElement {
  const a = el('a', cls, text);
  a.href = href;
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  return a;
}

function remaining(expiresAt: string | null): number | null {
  if (!expiresAt) return null;
  const ms = Date.parse(expiresAt) - Date.now();
  return Number.isFinite(ms) ? Math.max(0, Math.floor(ms / 1000)) : null;
}

function mmss(seconds: number): string {
  return `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
}

export class View {
  private readonly card: HTMLElement;
  private readonly announcer: HTMLElement;
  private readonly steps: NodeListOf<HTMLElement>;
  private timer: number | null = null;
  private lastKind: string | null = null;
  private announcedThresholds = new Set<number>();
  onExpire: (() => void) | null = null;

  constructor() {
    this.card = document.getElementById('auth-card') as HTMLElement;
    this.announcer = document.getElementById('announcer') as HTMLElement;
    this.steps = document.querySelectorAll<HTMLElement>('.step');
  }

  announce(text: string): void {
    this.announcer.textContent = '';
    window.setTimeout(() => { this.announcer.textContent = text; }, 30);
  }

  private setStep(step: 1 | 2 | 3, done = false): void {
    this.steps.forEach(node => {
      const n = Number(node.dataset.step);
      node.classList.toggle('active', n === step && !done);
      node.classList.toggle('done', n < step || (done && n === step));
      if (n === step) node.setAttribute('aria-current', 'step'); else node.removeAttribute('aria-current');
    });
  }

  private meta(pill: string, step: 1 | 2 | 3, tone: '' | 'success' | 'error' = ''): HTMLElement {
    const meta = el('div', 'card-meta');
    meta.append(el('span', `pill ${tone}`.trim(), pill), el('span', 'progress-label', `0${step} / 03`));
    return meta;
  }

  private devicePanel(device: DeviceInfo, completed: boolean): HTMLElement {
    const panel = el('div', 'device-panel');
    const top = el('div', 'device-top');
    const info = el('div');
    const [kindText, tag] = device.kind ? KIND_LABEL[device.kind] : ['연결 요청 기기', 'DEVICE'];
    info.append(
      el('span', 'meta-label', completed ? '연결한 기기' : '연결할 기기'),
      el('div', 'device-name', device.label ?? '이름 없는 기기'),
      el('div', 'device-kind', kindText),
    );
    top.append(info, el('span', 'device-label', tag));
    panel.append(top);
    const bottom = el('div', 'device-bottom');
    if (completed) {
      bottom.append(el('span', '', '원래 기기의 계정 확인'), el('strong', '', '완료'));
    } else {
      const left = remaining(device.expiresAt);
      const value = el('strong', '', left === null ? '—' : mmss(left));
      value.dataset.countdown = device.expiresAt ?? '';
      value.setAttribute('aria-hidden', 'true');
      const label = el('span', '', '남은 시간');
      const sr = el('span', 'visually-hidden', left === null ? '' : `약 ${Math.ceil(left / 60)}분 남음`);
      bottom.append(label, value, sr);
    }
    panel.append(bottom);
    return panel;
  }

  private stateArea(marker: string, title: string, text: string, tone: '' | 'success' | 'error' = ''): HTMLElement {
    const area = el('div', 'state-area');
    const m = el('div', `state-marker ${tone}`.trim(), marker);
    m.setAttribute('aria-hidden', 'true');
    const h = el('h2', '', title);
    h.id = 'card-title';
    h.tabIndex = -1;
    area.append(m, h, el('p', 'card-description', text));
    return area;
  }

  private note(): HTMLElement {
    return el('p', 'card-note', '계정 연결만으로 신고 데이터가 업로드되지는 않습니다. 이 페이지에서는 안전신문고·카카오 비밀번호를 입력받지 않습니다.');
  }

  private startCountdown(): void {
    this.stopCountdown();
    this.timer = window.setInterval(() => {
      const node = this.card.querySelector<HTMLElement>('[data-countdown]');
      if (!node) return;
      const left = remaining(node.dataset.countdown || null);
      if (left === null) return;
      node.textContent = mmss(left);
      for (const threshold of [120, 30]) {
        if (left <= threshold && left > 0 && !this.announcedThresholds.has(threshold)) {
          this.announcedThresholds.add(threshold);
          this.announce(threshold === 120 ? '연결 요청 시간이 2분 남았어요.' : '연결 요청 시간이 30초 남았어요.');
        }
      }
      if (left === 0) { this.stopCountdown(); this.onExpire?.(); }
    }, 1000);
  }

  stopCountdown(): void {
    if (this.timer !== null) window.clearInterval(this.timer);
    this.timer = null;
  }

  render(state: ViewState): void {
    const changed = state.kind !== this.lastKind;
    this.lastKind = state.kind;
    this.stopCountdown();
    const card = this.card;
    // Re-rendering the same state (e.g. ticking the checkbox) must not drop keyboard focus.
    const focusedId = card.contains(document.activeElement) ? (document.activeElement as HTMLElement).id : '';
    card.replaceChildren();
    let announceText = '';

    switch (state.kind) {
      case 'verifying': {
        this.setStep(1);
        card.append(this.meta('요청 확인 중', 1), this.stateArea('···', '연결 요청을 확인하고 있어요', '어떤 기기에서 보낸 요청인지 확인하고 있습니다.'));
        const sk = el('div', 'skeleton');
        sk.setAttribute('aria-hidden', 'true');
        sk.append(el('span'), el('span'), el('span'));
        card.append(sk);
        announceText = '연결 요청을 확인하고 있어요';
        break;
      }
      case 'empty': {
        this.setStep(1);
        card.append(this.meta('앱에서 시작', 1), this.stateArea('01', '앱에서 연결을 시작해 주세요',
          '나만의 안전신문고의 설정에서 ‘커뮤니티 계정 연결’을 선택하세요. 이 화면만으로는 새 연결을 시작할 수 없습니다.'));
        card.append(linkButton('연결 방법 보기', helpHref()));
        announceText = '앱에서 연결을 시작해 주세요';
        break;
      }
      case 'ready': {
        this.setStep(1);
        const h = el('h2', '', '연결할 기기를 확인해 주세요');
        h.id = 'card-title';
        h.tabIndex = -1;
        card.append(this.meta('연결 요청 확인', 1), h,
          el('p', 'card-description', '원래 앱과 기기 정보가 같은지 확인하세요. 다른 사람이 보낸 요청은 승인하지 마세요.'),
          this.devicePanel(state.device, false));
        const code = el('div', 'code-panel');
        code.append(el('p', 'code-label', '기기 비교코드'), el('p', 'pair-code', state.device.displayCode ?? '—'),
          el('p', 'code-hint', '원래 앱의 코드와 같은지 확인하세요.'));
        card.append(code);
        const consent = el('label', 'consent');
        const input = el('input');
        input.type = 'checkbox';
        input.id = 'confirm-start';
        input.checked = state.checked;
        input.disabled = state.busy;
        consent.append(input, el('span', '', '내가 이 기기에서 시작한 요청입니다.'));
        // The official Kakao asset is shown only when the button is actionable. While
        // disabled, a neutral text button stands in so the brand colour is never altered.
        const actionable = state.checked && !state.busy;
        const kakao = el('button', actionable ? 'btn kakao' : 'btn kakao-disabled');
        kakao.type = 'button';
        kakao.id = 'kakao-button';
        kakao.disabled = !actionable;
        if (state.busy) kakao.setAttribute('aria-busy', 'true');
        if (actionable) {
          const img = el('img');
          img.src = new URL('kakao/kakao_login_kr_medium.svg', document.baseURI).pathname;
          img.alt = '카카오 로그인';
          img.width = 224;
          img.height = 46;
          kakao.append(img);
        } else {
          kakao.textContent = state.busy ? '카카오 로그인 준비 중…' : '카카오 로그인';
        }
        kakao.setAttribute('aria-describedby', 'kakao-hint');
        const hint = el('p', 'kakao-hint', state.message ?? (state.checked ? '카카오 화면에서 계정을 선택합니다.' : '위 확인란을 선택하면 카카오 로그인을 진행할 수 있어요.'));
        hint.id = 'kakao-hint';
        if (state.message) hint.setAttribute('role', 'alert');
        input.addEventListener('change', () => state.onCheck(input.checked));
        kakao.addEventListener('click', () => { if (input.checked) state.onKakao(); });
        card.append(consent, kakao, hint, button('연결 취소', 'cancel-btn', state.onCancel, state.busy));
        this.startCountdown();
        announceText = '연결할 기기를 확인해 주세요';
        break;
      }
      case 'redirecting': {
        this.setStep(2);
        card.append(this.meta('카카오 로그인', 2), this.stateArea('02', '카카오 로그인으로 이동해요',
          state.onRetry ? '카카오 화면이 열리지 않았다면 아래 버튼을 눌러 주세요.' : '카카오 화면으로 이동하고 있습니다.'));
        const actions = el('div', 'actions');
        if (state.onRetry) actions.append(button(state.retried ? '카카오 로그인 다시 열기' : '카카오 로그인 열기', 'btn secondary', state.onRetry));
        actions.append(button('연결 취소', 'cancel-btn', state.onCancel));
        card.append(actions);
        announceText = '카카오 로그인으로 이동해요';
        break;
      }
      case 'callback': {
        this.setStep(2);
        card.append(this.meta('인증 결과 확인 중', 2), this.stateArea('···', '로그인 결과를 확인하고 있어요',
          '이 창을 잠시 열어 두세요. 아직 기기 연결이 완료된 것은 아닙니다.'));
        announceText = '로그인 결과를 확인하고 있어요';
        break;
      }
      case 'waiting': {
        this.setStep(3);
        card.append(this.meta('원래 기기 확인 대기', 3), this.stateArea('03', '원래 기기에서 계정을 확인해 주세요',
          state.delivered
            ? '로그인 결과를 전달했어요. 원래 앱에서 연결할 계정을 확인하면 연결이 완료됩니다.'
            : '로그인 결과를 받았어요. 원래 기기가 결과를 가져가면 앱에서 계정을 확인할 수 있어요.'),
          this.devicePanel(state.device, false));
        const wait = el('p', 'wait-note');
        wait.append(el('strong', '', '중앙 화면에서 할 일은 끝났어요. '), document.createTextNode('원래 앱의 계정 확인 화면으로 돌아가세요. 이 창은 열어 두면 완료 여부를 보여 드려요.'));
        card.append(wait);
        this.startCountdown();
        announceText = '원래 기기에서 계정을 확인해 주세요';
        break;
      }
      case 'success': {
        this.setStep(3, true);
        card.append(this.meta('연결 완료', 3, 'success'), this.stateArea('✓', '기기 연결이 완료됐어요',
          '원래 앱으로 돌아가세요. 커뮤니티 업로드는 앱에서 별도로 설정할 수 있어요.', 'success'),
          this.devicePanel(state.device, true));
        const close = button('이 탭 닫기', 'btn primary', () => {
          window.close();
          window.setTimeout(() => {
            if (!card.querySelector('.inline-message')) {
              const msg = el('p', 'inline-message', '브라우저가 자동으로 닫지 못했어요. 이 탭을 직접 닫아도 됩니다.');
              msg.setAttribute('role', 'status');
              card.append(msg);
            }
          }, 300);
        });
        card.append(close);
        announceText = '기기 연결이 완료됐어요';
        break;
      }
      case 'expired':
        this.setStep(1);
        card.append(this.meta('요청 만료', 1, 'error'), this.stateArea('—', '연결 시간이 지났어요',
          '원래 앱에서 새로운 연결 요청을 시작해 주세요. 만료된 요청으로는 로그인을 계속할 수 없습니다.', 'error'),
          linkButton('다시 연결하는 방법', helpHref()));
        announceText = '연결 시간이 지났어요';
        break;
      case 'cancelled':
        this.setStep(1);
        card.append(this.meta('연결 취소', 1), this.stateArea('—', '연결을 취소했어요',
          '새 계정 연결은 적용되지 않았습니다. 다시 연결하려면 원래 앱에서 시작해 주세요.'),
          el('p', 'inline-message', '이 탭은 닫아도 됩니다.'));
        announceText = '연결을 취소했어요';
        break;
      case 'oauth_failed':
        this.setStep(2);
        card.append(this.meta('로그인 실패', 2, 'error'), this.stateArea('!', '카카오 로그인을 완료하지 못했어요',
          '새 계정 연결은 적용되지 않았습니다. 원래 앱에서 연결을 다시 시작해 주세요.', 'error'),
          linkButton('연결 도움말', helpHref()));
        announceText = '카카오 로그인을 완료하지 못했어요';
        break;
      case 'network':
        card.append(this.meta('상태 확인 필요', 2, 'error'), this.stateArea('!', '연결 상태를 확인하지 못했어요',
          '네트워크 연결을 확인하고 다시 시도해 주세요. 연결이 완료되었는지는 원래 앱에서도 확인할 수 있습니다.', 'error'),
          button(state.busy ? '확인하는 중…' : '다시 확인하기', 'btn secondary', state.onRetry, state.busy));
        announceText = '연결 상태를 확인하지 못했어요';
        break;
      case 'invalid': {
        this.setStep(1);
        const text = state.reason === 'claimed_elsewhere'
          ? '이 연결 링크는 이미 다른 브라우저에서 열렸어요. 링크를 공유하지 말고 원래 앱에서 새로 시작해 주세요.'
          : state.reason === 'bad_link'
            ? '연결 링크가 올바르지 않아요. 원래 앱에서 연결을 다시 시작해 주세요.'
            : '로그인을 시작한 브라우저로 돌아가거나 원래 앱에서 다시 시작해 주세요.';
        card.append(this.meta('연결 정보 없음', 1, 'error'), this.stateArea('!', '연결 정보를 찾을 수 없어요', text, 'error'),
          linkButton('연결 방법 보기', helpHref()));
        announceText = '연결 정보를 찾을 수 없어요';
        break;
      }
      case 'config':
        this.setStep(1);
        card.append(this.meta('서비스 준비 중', 1), this.stateArea('—', '연결 서비스를 준비 중이에요',
          '지금은 로그인할 수 없습니다. 잠시 후 원래 앱에서 다시 시도해 주세요.'),
          el('p', 'wait-note', `운영자 확인 코드 · ${state.code}`), linkButton('도움말 보기', helpHref()));
        announceText = '연결 서비스를 준비 중이에요';
        break;
      case 'storage':
        this.setStep(1);
        card.append(this.meta('브라우저 설정 필요', 1, 'error'), this.stateArea('!', '이 브라우저에서 연결을 이어갈 수 없어요',
          '브라우저의 사이트 데이터 저장이 막혀 있어요. 저장을 허용하거나 다른 브라우저로 원래 앱에서 다시 시작해 주세요.', 'error'),
          linkButton('도움말 보기', helpHref()));
        announceText = '이 브라우저에서 연결을 이어갈 수 없어요';
        break;
      case 'framed':
        card.append(this.meta('열 수 없음', 1, 'error'), this.stateArea('!', '이 화면은 다른 페이지 안에서 열 수 없어요',
          '주소창에 직접 연 창에서만 계정 연결을 진행할 수 있습니다.', 'error'));
        announceText = '이 화면은 다른 페이지 안에서 열 수 없어요';
        break;
      case 'failed':
        card.append(this.meta('연결 실패', 1, 'error'), this.stateArea('!', '연결을 완료하지 못했어요',
          '새 계정 연결은 적용되지 않았을 수 있어요. 원래 앱에서 상태를 확인하고 다시 시작해 주세요.', 'error'));
        if (state.traceId) card.append(el('p', 'wait-note', `진단 ID · ${state.traceId}`));
        card.append(linkButton('연결 도움말', helpHref()));
        announceText = '연결을 완료하지 못했어요';
        break;
    }
    card.append(this.note());
    if (!changed && focusedId) document.getElementById(focusedId)?.focus({ preventScroll: true });
    if (changed && announceText) {
      this.announce(announceText);
      this.announcedThresholds.clear();
      const title = card.querySelector<HTMLElement>('#card-title');
      if (title && document.activeElement && document.activeElement !== document.body) title.focus({ preventScroll: true });
    }
  }
}
