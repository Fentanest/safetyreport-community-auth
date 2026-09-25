// Shared page bootstrap: theme toggle and frame guard. No analytics, ads, service
// workers or third-party code are loaded on any safeauth page.
import { loadTheme, saveTheme } from './storage.ts';

export function isFramed(): boolean {
  try { return window.top !== window.self; } catch { return true; }
}

export function initTheme(): void {
  const button = document.getElementById('theme-toggle') as HTMLButtonElement | null;
  const media = window.matchMedia?.('(prefers-color-scheme: dark)');
  const apply = (theme: 'light' | 'dark' | null) => {
    if (theme) document.documentElement.dataset.theme = theme;
    else delete document.documentElement.dataset.theme;
    const dark = theme ? theme === 'dark' : Boolean(media?.matches);
    if (button) {
      button.textContent = dark ? '라이트 모드' : '다크 모드';
      button.setAttribute('aria-pressed', String(dark));
    }
  };
  apply(loadTheme());
  media?.addEventListener?.('change', () => apply(loadTheme()));
  button?.addEventListener('click', () => {
    const current = document.documentElement.dataset.theme;
    const dark = current ? current === 'dark' : Boolean(media?.matches);
    const next = dark ? 'light' : 'dark';
    saveTheme(next);
    apply(next);
  });
}
