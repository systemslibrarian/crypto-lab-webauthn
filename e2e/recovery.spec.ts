import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
for (const width of [1280, 380]) test(`synthetic recovery closes separate routes at ${width}px`, async ({ page }) => {
  await page.setViewportSize({ width, height: 900 }); await page.goto('.');
  const panel = page.locator('#account-recovery'), result = panel.locator('#recovery-result');
  await panel.getByRole('button', { name: 'Record inventory snapshot' }).click();
  await panel.getByRole('button', { name: 'Reset password', exact: true }).click();
  await panel.getByRole('button', { name: 'Log out all sessions' }).click();
  await panel.getByRole('button', { name: 'Try intruder access' }).click();
  await expect(result).toContainText('Intruder has a session again');
  for (const label of ['Revoke unrecognized passkey', 'Remove intruder recovery email', 'Log out all sessions', 'Try intruder access']) await panel.getByRole('button', { name: label }).click();
  await expect(result).toContainText('Intruder cannot re-enter');
  await expect(result).toContainText('Recorded routes (preserved): unrecognized passkey, existing session, recovery email, known password');
  expect((await new AxeBuilder({ page }).include('#account-recovery').analyze()).violations).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1)).toBe(false);
  await panel.getByRole('button', { name: 'Reset fictional account' }).click();
  await expect(result).toContainText('Inventory has not been recorded');
});
