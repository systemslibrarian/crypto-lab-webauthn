import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright config for the strict axe-core WCAG gate.
 * Serves the built app via `vite preview` on a unique port and drives a single
 * Chromium project in the dark (default) theme; the spec also exercises light.
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
    colorScheme: 'dark',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: `npm run preview -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}${BASE}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
