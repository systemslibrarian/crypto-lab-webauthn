import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright config for the WCAG gate.
 *
 * `vite preview` serves `dist/`, so without a build in front of it the gate
 * measures whatever bundle happened to be on disk — nothing on a clean
 * checkout, and the previous build on a working tree. A gate that certifies a
 * stale bundle is worse than no gate, so the webServer command builds first.
 *
 * Theme and viewport are deliberately NOT pinned in `use`. The spec runs four
 * configurations — {dark, light} × {1280, 380} — from this one project, seeding
 * each through `localStorage` and `setViewportSize` before the first paint;
 * fixing either here would silently override one of them.
 */
const PORT = 4333;
const BASE = '/crypto-lab-webauthn/';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: 'line',
  use: {
    baseURL: `http://localhost:${PORT}${BASE}`,
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}${BASE}`,
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
