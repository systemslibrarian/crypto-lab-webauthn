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
