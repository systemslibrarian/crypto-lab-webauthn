import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG regression gate for the WebAuthn / passkeys demo.
 *
 * The app is a single-scroll page (main.ts renders every section at once — no
 * tabs). Each interactive section injects its result region only after a button
 * is clicked: Register mints a credential, Log in captures a baseline assertion,
 * and the attack / tamper / discoverable exhibits then render pass/fail output.
 * So we DRIVE the whole flow (register -> authenticate -> every attack) and open
 * all <details> before scanning, in both themes, with WCAG 2.0/2.1 A + AA rules.
 * Asserts zero violations.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Neutralize animation/transition/opacity so mid-flight states can't hide text
// from the contrast checker.
async function killMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation-duration:0s!important;animation-delay:0s!important;
      transition-duration:0s!important;transition-delay:0s!important;
      opacity:1!important;scroll-behavior:auto!important;
    }`,
  });
}

// Expand every <details> and reveal any [hidden]/collapsible so axe scans the
// whole page in one pass.
async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const d of document.querySelectorAll('details')) (d as HTMLDetailsElement).open = true;
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) el.removeAttribute('hidden');
  });
}

async function clickInSection(page: Page, sectionId: string, name: string): Promise<void> {
  const btn = page.locator(`#${sectionId}`).getByRole('button', { name });
  await btn.click();
}

// Drive every live demo so the injected output regions exist during the scan.
async function driveDemos(page: Page): Promise<void> {
  // Register a passkey (mints the credential every other section needs).
  await clickInSection(page, 'register', 'Create passkey');
  await expect(page.locator('#register-out table')).toBeVisible({ timeout: 15_000 });

  // Log in — captures the baseline assertion used by the attack exhibits.
  await clickInSection(page, 'login', 'Authenticate');
  await expect(page.locator('#login-out')).toContainText(/verif|ok|pass|signature/i, {
    timeout: 15_000,
  });

  // Break it — every attack scenario injects a pass/fail result-box.
  for (const name of ['Phishing site', 'Replay assertion', 'Wrong relying party', 'Cloned authenticator']) {
    await clickInSection(page, 'break-it', name);
  }
  await expect(page.locator('#attack-out')).not.toContainText('No attack run yet', {
    timeout: 15_000,
  });

  // Tamper — each button mutates one field; drive all so red-check output renders.
  for (const name of [/flip/i, /forge/i, /bump/i, /counter/i]) {
    const b = page.locator('#tamper').getByRole('button', { name });
    if (await b.count()) await b.first().click();
  }

  // Discoverable / UV scenarios.
  const disc = page.locator('#discoverable').getByRole('button');
  const n = await disc.count();
  for (let i = 0; i < n; i++) await disc.nth(i).click();
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#cl-theme-toggle')).toBeVisible();
  await expect(page.locator('#register')).toBeVisible();
  await killMotion(page);
});

test('no WCAG A/AA violations in dark theme (all demos driven)', async ({ page }) => {
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await driveDemos(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme (all demos driven)', async ({ page }) => {
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveDemos(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});
