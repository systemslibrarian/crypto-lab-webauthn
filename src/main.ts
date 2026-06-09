import './style.css';
import './extra.css';
import { mountApp } from './ui';
import {
  Authenticator,
  RelyingParty,
  randomChallenge,
} from './engine';

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

async function selfTest(): Promise<void> {
  // console.group works in any browser. Keep this lightweight.
  // eslint-disable-next-line no-console
  console.group('crypto-lab-webauthn · self-test');
  try {
    const auth = new Authenticator();
    const rp = new RelyingParty();
    const cred = await auth.makeCredential('example.com');
    rp.register(cred);

    const challenge = randomChallenge();
    const legit = await auth.getAssertion(
      cred.credentialId,
      challenge,
      'https://example.com',
      'example.com',
    );
    if ('error' in legit) throw new Error(`legit assertion errored: ${legit.error}`);
    const legitResult = await rp.verifyAssertion(legit, {
      expectedChallenge: challenge,
      expectedOrigin: 'https://example.com',
      expectedRpId: 'example.com',
    });
    console.log('legit ok ===', legitResult.ok, '— expect true');
    if (!legitResult.ok) console.error('SELF-TEST FAIL: legit should pass', legitResult);

    const challenge2 = randomChallenge();
    const phish = await auth.getAssertion(
      cred.credentialId,
      challenge2,
      'https://examp1e-login.com',
      'example.com',
    );
    if ('error' in phish) throw new Error(`phish assertion errored: ${phish.error}`);
    const phishResult = await rp.verifyAssertion(phish, {
      expectedChallenge: challenge2,
      expectedOrigin: 'https://example.com',
      expectedRpId: 'example.com',
    });
    console.log('wrong-origin ok ===', phishResult.ok, '— expect false');
    if (phishResult.ok) console.error('SELF-TEST FAIL: phish should fail', phishResult);
  } catch (err) {
    console.error('Self-test threw:', err);
  } finally {
    console.groupEnd();
  }
}

function boot(): void {
  const root = document.getElementById('app');
  if (!(root instanceof HTMLDivElement)) {
    throw new Error('#app root not found');
  }
  mountApp(root);
  wireThemeToggle();
  void selfTest();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot, { once: true });
} else {
  boot();
}
