import { expect, test } from '@playwright/test';

test('the hero distinguishes the simulator from the real browser ceremony below', async ({ page }) => {
  await page.goto('.');

  const hero = page.locator('.cl-hero');
  await expect(hero.locator('.cl-hero-sub')).toHaveText(
    'Readable simulator first · real browser API below',
  );
  await expect(hero.locator('.cl-hero-desc')).toContainText(
    'WebAuthn security-logic simulation using real ECDSA P-256 signatures but simplified JSON encoding',
  );
  await expect(hero.locator('.cl-hero-desc')).toContainText(
    'The real navigator.credentials ceremony is a separate section below',
  );
  await expect(hero.locator('.cl-hero-desc')).not.toContainText('Run a real WebAuthn ceremony');

  await expect(page.locator('#live-demo')).toContainText('Everything above uses a simulated authenticator');
  await expect(page.locator('#live-demo')).toContainText('calls the actual browser WebAuthn API');
});

for (const width of [1280, 380]) {
  test(`clone signs its stale counter and preserves authenticated policy at width ${width}`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('.');
    await page.getByRole('button', { name: 'Create passkey', exact: true }).click();
    await expect(page.locator('#register-out')).toContainText('Stored credential');
    await page.getByRole('button', { name: 'Authenticate', exact: true }).click();
    await expect(page.locator('#login-out .verify-header .scenario-status')).toHaveText('Authenticated');
    await page.getByRole('button', { name: /Cloned authenticator/ }).click();

    const attempt = page.locator('.compare-col--attack');
    await expect(attempt.locator('.verify-header .scenario-status')).toHaveText('Rejected');
    await expect(attempt.locator('.check-row--pass').filter({ hasText: 'Signature valid' })).toHaveCount(1);
    await expect(attempt.locator('.check-row--fail')).toHaveCount(1);
    await expect(attempt.locator('.check-row--fail .check-label')).toHaveText('Counter increasing');
    await expect(attempt.locator('.check-detail').filter({ hasText: 'Signed counter' })).toHaveText(
      'Signed counter 1 <= 1 — possible cloned authenticator.',
    );
    const signedCounter = attempt.locator('.signed-bytes dt').filter({ hasText: 'authData (' }).locator('xpath=following-sibling::dd[1]');
    await expect(signedCounter).toHaveText(/^[0-9a-f]{64}\|5\|1$/);
    await expect(signedCounter).toBeVisible();
    await expect(page.locator('.verify-note').filter({ hasText: 'Assume a copy' })).toContainText('not extraction of a hardware passkey');
    const overflowing = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
    expect(overflowing).toBe(false);
  });
}
