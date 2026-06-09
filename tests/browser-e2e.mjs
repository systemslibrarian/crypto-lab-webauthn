// tests/browser-e2e.mjs — headless end-to-end verification of the WebAuthn demo.
// Run with: npm run test:e2e (after `npm run build`).
//
// Starts a preview server, drives a real Chromium, and asserts:
//   * Page loads, no console errors, dark theme set, skip link present
//   * Ceremony diagram renders both actors and the highlighted origin
//   * Create passkey produces a credential card (kty=EC, crv=P-256)
//   * Authenticate yields 5 pass badges, an "Authenticated" summary,
//     and the signed-bytes panel showing clientDataJSON + signature
//   * Phishing fails on Origin match (side-by-side with baseline)
//   * Replay fails on Challenge match (side-by-side)
//   * Wrong RP is refused by the authenticator (refused col + baseline col)
//   * Cloned authenticator fails on Counter (side-by-side)
//   * Baseline restores a passing state
//   * Tamper: flip-sig, forge-origin, bump-counter — all fail Signature
//   * Theme toggle flips data-theme and persists across reload
//   * Mobile viewport: no horizontal page overflow at 375px
//   * axe-core: zero critical or serious WCAG violations

import { spawn } from 'node:child_process';
import { setTimeout as wait } from 'node:timers/promises';
import puppeteer from 'puppeteer';
import { AxePuppeteer } from '@axe-core/puppeteer';

const PORT = 4173;
const BASE = `http://localhost:${PORT}/crypto-lab-webauthn/`;

function startPreview() {
  const child = spawn('npx', ['vite', 'preview', '--port', String(PORT), '--strictPort'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: process.platform === 'win32',
  });
  return new Promise((resolve) => {
    let buf = '';
    const onData = (d) => {
      buf += d.toString();
      if (buf.includes(String(PORT))) resolve(child);
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
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

async function waitIdle(page) {
  await page.waitForFunction(
    () => !document.querySelector('[aria-busy="true"]'),
    { timeout: 5000 },
  );
}

async function clickAttack(page, labelRegex) {
  const handle = await page.evaluateHandle(
    (re, scope) => {
      const buttons = Array.from(document.querySelectorAll(`${scope} button`));
      return buttons.find((b) => new RegExp(re, 'i').test(b.textContent || '')) || null;
    },
    labelRegex.source,
    '#break-it',
  );
  const elHandle = handle.asElement();
  if (!elHandle) throw new Error(`no attack button for ${labelRegex}`);
  await elHandle.click();
  await waitIdle(page);
}

async function clickTamper(page, labelRegex) {
  const handle = await page.evaluateHandle(
    (re, scope) => {
      const buttons = Array.from(document.querySelectorAll(`${scope} button`));
      return buttons.find((b) => new RegExp(re, 'i').test(b.textContent || '')) || null;
    },
    labelRegex.source,
    '#tamper',
  );
  const elHandle = handle.asElement();
  if (!elHandle) throw new Error(`no tamper button for ${labelRegex}`);
  await elHandle.click();
  await waitIdle(page);
}

async function runAxe(page, contextLabel) {
  const axe = await new AxePuppeteer(page)
    .options({ resultTypes: ['violations'] })
    .analyze();
  const serious = axe.violations.filter((v) => v.impact === 'critical' || v.impact === 'serious');
  if (serious.length) {
    const summary = serious
      .map((v) => `${v.impact}: ${v.id} (${v.nodes.length} nodes) — ${v.description}`)
      .join(' | ');
    assert(`axe — no critical/serious violations [${contextLabel}]`, false, summary);
  } else {
    assert(`axe — no critical/serious violations [${contextLabel}]`, true);
  }
  const minor = axe.violations.filter((v) => v.impact === 'moderate' || v.impact === 'minor');
  if (minor.length) {
    console.log(`  (informational) ${minor.length} moderate/minor axe findings in ${contextLabel}`);
    for (const v of minor) console.log(`    ${v.impact}: ${v.id} — ${v.nodes.length} nodes`);
  }
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
        if (!text.startsWith('legit ok ===') && !text.startsWith('wrong-origin ok ===')) {
          consoleErrors.push(text);
        }
      }
    });
    page.on('pageerror', (err) => consoleErrors.push(String(err)));

    await page.setViewport({ width: 1100, height: 1000 });
    await page.goto(BASE, { waitUntil: 'networkidle2' });

    // ---- Page basics ----
    const theme = await page.$eval('html', (h) => h.getAttribute('data-theme'));
    assert('page loads with dark theme', theme === 'dark', `data-theme=${theme}`);
    assert('title present', (await page.title()).includes('WebAuthn'));
    const skipText = await page.$eval('.skip-link', (a) => a.textContent ?? '');
    assert('skip link present', /skip to main/i.test(skipText));

    // ---- Ceremony diagram ----
    const diagramAuth = await page.$('#ceremony-diagram .ceremony-actor--auth h3');
    const diagramServer = await page.$('#ceremony-diagram .ceremony-actor--server h3');
    assert('diagram has authenticator card', !!diagramAuth);
    assert('diagram has server card', !!diagramServer);
    const highlighted = await page.$eval(
      '#ceremony-diagram .signed-field.highlight-origin',
      (n) => n.textContent ?? '',
    );
    assert('diagram highlights origin in signed fields', /origin/i.test(highlighted));

    // ---- axe scan: initial page ----
    await runAxe(page, 'initial page');

    // ---- Register ----
    const registerBtn = await page.waitForSelector('#register button');
    await registerBtn.click();
    await page.waitForFunction(() => document.querySelector('#register-out table'), { timeout: 5000 });
    const credText = await page.$eval('#register-out', (n) => n.textContent ?? '');
    assert('register shows EC public key', /EC/.test(credText) && /P-256/.test(credText));

    // ---- Authenticate ----
    await page.click('#login button');
    await waitIdle(page);
    const loginText = await page.$eval('#login-out', (n) => n.textContent ?? '');
    assert('authenticate summary says Authenticated', /Authenticated/.test(loginText));
    const passBadges = await page.$$eval(
      '#login-out .check-row--pass .scenario-status--valid',
      (els) => els.length,
    );
    assert('authenticate shows 5 pass rows', passBadges === 5, `got ${passBadges}`);

    // Signed-bytes panel must show clientDataJSON + signature
    const signedBytes = await page.$eval('#login-out .signed-bytes', (n) => n.textContent ?? '');
    assert('signed-bytes panel shows clientDataJSON', /clientDataJSON/.test(signedBytes));
    assert('signed-bytes panel shows authData', /authData/.test(signedBytes));
    assert('signed-bytes panel shows ECDSA signature', /ECDSA signature/i.test(signedBytes));
    const originHighlight = await page.$(
      '#login-out .signed-bytes .highlight-origin--match',
    );
    assert('signed-bytes highlights matching origin in green', !!originHighlight);

    // ---- axe scan: after authenticate ----
    await runAxe(page, 'after authenticate');

    // ---- Phishing → side-by-side ----
    await clickAttack(page, /Phishing site/);
    const compareCols = await page.$$('#attack-out .compare-col');
    assert('phishing renders 2 compare columns', compareCols.length === 2, `cols=${compareCols.length}`);
    const phishFailLabel = await page.$eval(
      '#attack-out .compare-col--attack .check-row--fail-spotlight .check-label',
      (n) => n.textContent ?? '',
    );
    assert('phishing trips Origin check', /Origin match/.test(phishFailLabel));
    const phishOriginMismatch = await page.$('#attack-out .compare-col--attack .highlight-origin--mismatch');
    assert('phishing shows mismatched origin in red', !!phishOriginMismatch);

    // ---- Replay → side-by-side ----
    await clickAttack(page, /Replay assertion/);
    const replayFailLabel = await page.$eval(
      '#attack-out .compare-col--attack .check-row--fail-spotlight .check-label',
      (n) => n.textContent ?? '',
    );
    assert('replay trips Challenge check', /Challenge match/.test(replayFailLabel));

    // ---- Wrong RP — authenticator refuses (baseline col + refused col) ----
    await clickAttack(page, /Wrong relying party/);
    const wrongRpText = await page.$eval('#attack-out', (n) => n.textContent ?? '');
    assert('wrong RP refused by authenticator', /authenticator refuses/i.test(wrongRpText));
    const wrongRpCols = await page.$$('#attack-out .compare-col');
    assert('wrong RP still shows baseline + refused side by side', wrongRpCols.length === 2);

    // ---- Clone → side-by-side ----
    await clickAttack(page, /Cloned authenticator/);
    const cloneFailLabel = await page.$eval(
      '#attack-out .compare-col--attack .check-row--fail-spotlight .check-label',
      (n) => n.textContent ?? '',
    );
    assert('clone trips Counter check', /Counter increasing/.test(cloneFailLabel));

    // ---- Baseline restores ----
    await clickAttack(page, /Reset baseline/);
    const baselineText = await page.$eval('#attack-out', (n) => n.textContent ?? '');
    assert('baseline restores Authenticated', /Authenticated/.test(baselineText));

    // ---- axe scan: after compare grids rendered ----
    await runAxe(page, 'after attack scenarios');

    // ---- Tamper interactive ----
    await clickTamper(page, /Flip 1 bit of signature/);
    const tamperSigFail = await page.$eval(
      '#tamper-out .compare-col--attack .check-row--fail-spotlight .check-label',
      (n) => n.textContent ?? '',
    );
    assert('flip-sig tamper trips Signature valid', /Signature valid/.test(tamperSigFail));

    await clickTamper(page, /Forge origin/);
    // Either Origin match or Signature valid is the first failing — both should be red.
    const forgeSpotlightLabel = await page.$eval(
      '#tamper-out .compare-col--attack .check-row--fail-spotlight .check-label',
      (n) => n.textContent ?? '',
    );
    assert(
      'forge-origin tamper fails Origin or Signature',
      /Origin match|Signature valid/.test(forgeSpotlightLabel),
      `spotlight=${forgeSpotlightLabel}`,
    );
    const forgeFails = await page.$$eval(
      '#tamper-out .compare-col--attack .check-row--fail .check-label',
      (els) => els.map((e) => e.textContent ?? ''),
    );
    assert(
      'forge-origin fails BOTH Origin and Signature',
      forgeFails.some((l) => /Origin match/.test(l)) && forgeFails.some((l) => /Signature valid/.test(l)),
      `fails=${forgeFails.join(' | ')}`,
    );

    await clickTamper(page, /Bump signCount/);
    const bumpSpotlight = await page.$eval(
      '#tamper-out .compare-col--attack .check-row--fail-spotlight .check-label',
      (n) => n.textContent ?? '',
    );
    assert('bump-counter tamper fails Signature valid', /Signature valid/.test(bumpSpotlight));

    // ---- signCount chip incremented ----
    const chipCount = await page.$eval('.sign-count-chip strong', (n) => Number(n.textContent));
    assert('signCount chip > 0', chipCount > 0, `chip=${chipCount}`);

    // ---- Theme toggle ----
    await page.click('#theme-toggle');
    await wait(120);
    const themeAfter = await page.$eval('html', (h) => h.getAttribute('data-theme'));
    assert('theme toggled to light', themeAfter === 'light');
    await page.reload({ waitUntil: 'networkidle2' });
    const themePersisted = await page.$eval('html', (h) => h.getAttribute('data-theme'));
    assert('theme persisted across reload', themePersisted === 'light');

    // ---- axe scan: light theme ----
    await runAxe(page, 'light theme');

    // ---- Mobile viewport sanity ----
    await page.setViewport({ width: 375, height: 800 });
    await wait(150);
    const overflow = await page.evaluate(() => {
      const doc = document.documentElement;
      return doc.scrollWidth - doc.clientWidth;
    });
    assert('no horizontal page overflow at 375px wide', overflow <= 0, `overflow=${overflow}px`);

    // ---- axe scan: mobile viewport ----
    await runAxe(page, 'mobile viewport');

    // ---- Path A: production-gaps section ----
    const gapCardCount = await page.$$eval('#production-gaps .gap-card', (els) => els.length);
    assert('production-gaps shows 6 cards', gapCardCount === 6, `got ${gapCardCount}`);

    // ---- Path B: discoverable + UV section ----
    // Reset viewport so the buttons are clickable (we shrank to 375 earlier).
    await page.setViewport({ width: 1100, height: 1000 });
    await wait(150);
    // After the reload, state was reset. Re-register so the discoverable
    // section has a credential to work with.
    await page.click('#register button');
    await page.waitForFunction(() => document.querySelector('#register-out table'), { timeout: 5000 });
    async function clickDiscoverable(labelRegex) {
      const handle = await page.evaluateHandle(
        (re) => {
          const buttons = Array.from(document.querySelectorAll('#discoverable button'));
          return buttons.find((b) => new RegExp(re, 'i').test(b.textContent || '')) || null;
        },
        labelRegex.source,
      );
      const elHandle = handle.asElement();
      if (!elHandle) throw new Error(`no discoverable button for ${labelRegex}`);
      await elHandle.click();
      await waitIdle(page);
    }

    await clickDiscoverable(/Discoverable login/);
    const discChecks = await page.$$eval('#discoverable-out .check-row', (els) => els.length);
    assert('discoverable login yields 7 check rows (incl. UP+UV)', discChecks === 7, `got ${discChecks}`);
    const discAllPass = await page.$$eval(
      '#discoverable-out .check-row--pass',
      (els) => els.length,
    );
    assert('discoverable login: all 7 rows pass', discAllPass === 7, `passes=${discAllPass}`);

    await clickDiscoverable(/RP demands UV/);
    const uvFailLabel = await page.$eval(
      '#discoverable-out .check-row--fail-spotlight .check-label',
      (n) => n.textContent ?? '',
    );
    assert('UV-required + UV-not-performed trips UV check', /User verified/.test(uvFailLabel));

    await clickDiscoverable(/RP demands UP/);
    const upFailLabel = await page.$eval(
      '#discoverable-out .check-row--fail-spotlight .check-label',
      (n) => n.textContent ?? '',
    );
    assert('UP-required + UP-not-performed trips UP check', /User present/.test(upFailLabel));

    // ---- Path C: live demo with virtual authenticator ----
    const client = await page.createCDPSession();
    await client.send('WebAuthn.enable', { enableUI: false });
    const virtAuth = await client.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });
    assert('virtual authenticator created', !!virtAuth.authenticatorId);

    // Make sure the live-demo host actually rendered.
    const liveSupported = await page.$eval('#live-demo-host .live-status', (n) => n.textContent ?? '');
    assert('live demo reports WebAuthn supported', /supported/i.test(liveSupported));

    // Click "Register a real passkey" and wait for the panel to render the AAGUID line.
    const liveRegisterBtn = await page.evaluateHandle(() => {
      const btns = Array.from(document.querySelectorAll('#live-demo-host button'));
      return btns.find((b) => /Register a real passkey/i.test(b.textContent || '')) || null;
    });
    const liveRegEl = liveRegisterBtn.asElement();
    if (!liveRegEl) throw new Error('live register button not found');
    await liveRegEl.click();
    await page.waitForFunction(
      () => {
        const out = document.querySelector('#live-out');
        return out && /AAGUID/i.test(out.textContent || '');
      },
      { timeout: 8000 },
    );
    const liveRegText = await page.$eval('#live-out', (n) => n.textContent ?? '');
    assert('live register shows credentialId', /credentialId/.test(liveRegText));
    assert('live register shows AAGUID', /AAGUID/.test(liveRegText));
    assert('live register shows public key JWK', /EC \/ P-256/.test(liveRegText));
    assert('live register shows UP flag set', /UP: 1/.test(liveRegText));

    // Click "Authenticate" and verify locally-verified=true.
    const liveAuthBtn = await page.evaluateHandle(() => {
      const btns = Array.from(document.querySelectorAll('#live-demo-host button'));
      return btns.find((b) => /Authenticate with the real passkey/i.test(b.textContent || '')) || null;
    });
    const liveAuthEl = liveAuthBtn.asElement();
    if (!liveAuthEl) throw new Error('live authenticate button not found');
    await liveAuthEl.click();
    await page.waitForFunction(
      () => {
        const out = document.querySelector('#live-out');
        return out && /(Verified|Signature failed)/i.test(out.textContent || '');
      },
      { timeout: 8000 },
    );
    const liveAuthText = await page.$eval('#live-out', (n) => n.textContent ?? '');
    assert('live authenticate verifies signature locally', /Verified/i.test(liveAuthText) && !/Signature failed/.test(liveAuthText));
    assert('live authenticate shows DER + raw signature', /DER, base64/.test(liveAuthText) && /raw r/.test(liveAuthText));
    assert('live authenticate shows BE\/BS flags', /BE:/.test(liveAuthText) && /BS:/.test(liveAuthText));

    await client.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: virtAuth.authenticatorId });

    // ---- No console errors ----
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
