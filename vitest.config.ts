import { defineConfig } from 'vitest/config';

// Unit tests run in Node against the pure engine (real Web Crypto is available
// as a global in Node 20+). The browser e2e (tests/) and the axe-core a11y
// suite (e2e/) are driven separately and must NOT be collected here.
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['e2e/**', 'tests/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
