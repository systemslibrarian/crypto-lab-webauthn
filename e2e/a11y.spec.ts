import { test } from '@playwright/test';
import { NARROW, WIDE, boot, driveAllStates } from './gate';

/**
 * WCAG A/AA gate for the WebAuthn / passkeys lab.
 *
 * Four configurations — {dark, light} × {desktop 1280, phone 380} — and inside
 * each one the lab is driven through every state it can reach and scanned after
 * every single step. The machinery, and what each oracle is for, is documented
 * in `gate.ts`; the drive itself is `driveAllStates` there.
 *
 * The two axes are not redundant. Theme changes which ink lands on which
 * surface — the accents are re-authored for light mode and the status tints are
 * translucent, so the same badge composites differently in each. Width changes
 * the layout entirely: the compare grid collapses to one column at 760px, the
 * check rows drop a track at 640px, and only at 380px do the tables actually
 * begin to scroll inside their wrappers.
 */
for (const theme of ['dark', 'light'] as const) {
  for (const [size, viewport] of [
    ['desktop 1280', WIDE],
    ['phone 380', NARROW],
  ] as const) {
    test(`no WCAG A/AA failures — ${theme}, ${size}`, async ({ page }) => {
      test.setTimeout(300_000);
      await boot(page, theme, viewport);
      await driveAllStates(page, theme, size);
    });
  }
}
