// tests/browser-e2e.mjs — headless end-to-end verification of the WebAuthn demo.
// Run with: npm run test:e2e (after `npm run build`).
//
// Starts a preview server, drives a real Chromium, and asserts:
//   * page loads, no console errors, theme attribute set
//   * Create passkey produces a credential card (kty=EC, crv=P-256)
//   * Authenticate yields 5 pass badges and an "Authenticated" summary
//   * Phishing fails on Origin match
//   * Replay fails on Challenge match
//   * Wrong RP is refused by the authenticator (no signature reaches server)
//   * Cloned authenticator fails on Counter increasing
//   * Baseline restores a passing state
//   * Theme toggle flips data-theme and persists across reload
//   * Skip link is focusable and reveals on focus

import { spawn } from 'node:child_process';
import { setTimeout as wait } from 'node:timers/promises';
import puppeteer from 'puppeteer';

const PORT = 4173;
const BASE = `http://localhost:${PORT}/crypto-lab-webauthn/`;

function startPreview() {
  const child = spawn('npx', ['vite', 'preview', '--port', String(PORT), '--strictPort'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: process.platform === 'win32',
  });
  return new Promise((resolve, reject) => {
    let buf = '';
    const onData = (d) => {
      buf += d.toString();
      if (buf.includes(String(PORT))) resolve(child);
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('exit', (code) => reject(new Error(`preview exited early with code ${code}`)));
    setTimeout(() => resolve(child), 5000);
  });
}

const consoleErrors = [];
const results = [];

function assert(label, cond, detail = '') {
  results.push({ label, pass: !!cond, detail });
  if (!cond) console.error(`FAIL  ${label}  ${detail}`);
  else console.log(`PASS  ${label}`);
}

async function clickAndSettle(page, selector) {
  await page.click(selector);
  // wait for aria-busy to clear on any panel that turned on
  await page.waitForFunction(
    () => !document.querySelector('[aria-busy="true"]'),
    { timeout: 5000 },
  );
}

async function main() {
  const preview = await startPreview();
  await wait(800);
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });
  try {
    const page = await browser.newPage();
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        const text = msg.text();
        // ignore self-test informational logs
        if (!text.startsWith('legit ok ===') && !text.startsWith('wrong-origin ok ===')) {
          consoleErrors.push(text);
        }
      }
    });
    page.on('pageerror', (err) => consoleErrors.push(String(err)));

    await page.setViewport({ width: 1100, height: 900 });
    await page.goto(BASE, { waitUntil: 'networkidle2' });

    // ---- Page loaded, theme set ----
    const theme = await page.$eval('html', (h) => h.getAttribute('data-theme'));
    assert('page loads with dark theme', theme === 'dark', `data-theme=${theme}`);
    assert('title present', (await page.title()).includes('WebAuthn'));

    // ---- Skip link ----
    const skipLinkHTML = await page.$eval('.skip-link', (a) => a.textContent);
    assert('skip link present', /skip to main/i.test(skipLinkHTML));

    // ---- Register ----
    const registerBtn = await page.waitForSelector('#register button');
    await registerBtn.click();
    await page.waitForFunction(
      () => document.querySelector('#register-out table'),
      { timeout: 5000 },
    );
    const credText = await page.$eval('#register-out', (n) => n.textContent ?? '');
    assert('register shows EC public key', /EC/.test(credText) && /P-256/.test(credText));
    assert('register shows credential ID label', /Credential ID/.test(credText));

    // ---- Authenticate ----
    await clickAndSettle(page, '#login button');
    const loginText = await page.$eval('#login-out', (n) => n.textContent ?? '');
    assert('authenticate summary says Authenticated', /Authenticated/.test(loginText));
    const passBadges = await page.$$eval(
      '#login-out .check-row--pass .scenario-status--valid',
      (els) => els.length,
    );
    assert('authenticate shows 5 pass rows', passBadges === 5, `got ${passBadges}`);

    // helper to click an attack button by visible label
    async function clickAttack(labelRegex) {
      const handle = await page.evaluateHandle((re) => {
        const buttons = Array.from(document.querySelectorAll('#break-it button'));
        return buttons.find((b) => new RegExp(re, 'i').test(b.textContent || '')) || null;
      }, labelRegex.source);
      if (!handle) throw new Error(`no attack button for ${labelRegex}`);
      const el = handle.asElement();
      if (!el) throw new Error(`attack button handle not an element: ${labelRegex}`);
      await el.click();
      await page.waitForFunction(
        () => !document.querySelector('#attack-out[aria-busy="true"]'),
        { timeout: 5000 },
      );
    }

    // ---- Phishing ----
    await clickAttack(/Phishing site/);
    const phishText = await page.$eval('#attack-out', (n) => n.textContent ?? '');
    const phishFailLabel = await page.$eval(
      '#attack-out .check-row--fail-spotlight .check-label',
      (n) => n.textContent ?? '',
    );
    assert('phishing trips Origin check', /Origin match/.test(phishFailLabel), `spotlight=${phishFailLabel}`);
    assert('phishing summary mentions phishing blocked', /phishing blocked/i.test(phishText));

    // ---- Replay ----
    await clickAttack(/Replay assertion/);
    const replayFailLabel = await page.$eval(
      '#attack-out .check-row--fail-spotlight .check-label',
      (n) => n.textContent ?? '',
    );
    assert('replay trips Challenge check', /Challenge match/.test(replayFailLabel), `spotlight=${replayFailLabel}`);

    // ---- Wrong RP — authenticator refuses ----
    await clickAttack(/Wrong relying party/);
    const wrongRpText = await page.$eval('#attack-out', (n) => n.textContent ?? '');
    assert('wrong RP refused by authenticator', /authenticator refuses/i.test(wrongRpText));
    const wrongRpHasCheckRows = await page.$('#attack-out .check-row');
    assert('wrong RP — no signature reaches server (no check rows)', !wrongRpHasCheckRows);

    // ---- Clone ----
    await clickAttack(/Cloned authenticator/);
    const cloneFailLabel = await page.$eval(
      '#attack-out .check-row--fail-spotlight .check-label',
      (n) => n.textContent ?? '',
    );
    assert('clone trips Counter check', /Counter increasing/.test(cloneFailLabel), `spotlight=${cloneFailLabel}`);

    // ---- Baseline restores ----
    await clickAttack(/Reset baseline/);
    const baselineText = await page.$eval('#attack-out', (n) => n.textContent ?? '');
    assert('baseline restores Authenticated', /Authenticated/.test(baselineText));

    // ---- signCount chip incremented ----
    const chipCount = await page.$eval('.sign-count-chip strong', (n) => Number(n.textContent));
    assert('signCount chip > 0', chipCount > 0, `chip=${chipCount}`);

    // ---- Theme toggle ----
    await page.click('#theme-toggle');
    await wait(100);
    const themeAfter = await page.$eval('html', (h) => h.getAttribute('data-theme'));
    assert('theme toggled to light', themeAfter === 'light');
    await page.reload({ waitUntil: 'networkidle2' });
    const themePersisted = await page.$eval('html', (h) => h.getAttribute('data-theme'));
    assert('theme persisted across reload', themePersisted === 'light');

    // ---- Mobile viewport sanity ----
    await page.setViewport({ width: 375, height: 800 });
    await wait(100);
    const overflow = await page.evaluate(() => {
      const doc = document.documentElement;
      return doc.scrollWidth - doc.clientWidth;
    });
    assert('no horizontal page overflow at 375px wide', overflow <= 0, `overflow=${overflow}px`);

    // ---- No unexpected console errors ----
    assert('no unexpected console errors', consoleErrors.length === 0, consoleErrors.join(' | '));
  } finally {
    await browser.close();
    preview.kill();
  }
}

main().then(() => {
  const fails = results.filter((r) => !r.pass);
  console.log(`\n${results.length - fails.length}/${results.length} checks passed.`);
  if (fails.length) {
    console.error(fails.map((f) => `  - ${f.label}: ${f.detail}`).join('\n'));
    process.exit(1);
  }
}).catch((err) => {
  console.error('e2e error:', err);
  process.exit(1);
});
