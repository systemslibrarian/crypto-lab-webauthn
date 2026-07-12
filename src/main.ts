import './style.css';
import './extra.css';
import { mountApp } from './ui';
import { mountLiveDemo } from './live';

const THEME_KEY = 'crypto-lab-theme';

function applyTheme(theme: 'dark' | 'light'): void {
  document.documentElement.setAttribute('data-theme', theme);
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* storage may be disabled — ignore */
  }
  const toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.textContent = theme === 'dark' ? '🌙' : '☀️';
    toggle.setAttribute(
      'aria-label',
      theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme',
    );
  }
}

function currentTheme(): 'dark' | 'light' {
  const attr = document.documentElement.getAttribute('data-theme');
  return attr === 'light' ? 'light' : 'dark';
}

function wireThemeToggle(): void {
  applyTheme(currentTheme());
  const toggle = document.getElementById('theme-toggle');
  if (!toggle) return;
  toggle.addEventListener('click', () => {
    applyTheme(currentTheme() === 'dark' ? 'light' : 'dark');
  });
}

function boot(): void {
  const root = document.getElementById('app');
  if (!(root instanceof HTMLDivElement)) {
    throw new Error('#app root not found');
  }
  mountApp(root);
  wireThemeToggle();

  // The ceremony/attack logic that this file used to `selfTest()` on every page
  // load now lives in fast, isolated unit tests (test/engine.test.ts, run via
  // `npm test`) — no debug harness ships in the boot path.

  // Path C — wire the real WebAuthn live demo. RP id falls back to the
  // current hostname so the demo works on both localhost preview and the
  // deployed Pages origin.
  const liveHost = document.getElementById('live-demo-host');
  if (liveHost) {
    const rpId = window.location.hostname || 'localhost';
    void mountLiveDemo(liveHost, rpId, 'crypto-lab WebAuthn');
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot, { once: true });
} else {
  boot();
}
