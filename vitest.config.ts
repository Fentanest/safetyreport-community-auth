import { defineConfig } from 'vitest/config';

// Tests needing the local stack or a browser skip themselves unless
// SAFEAUTH_STACK=1 (and SAFEAUTH_BROWSER=1) are set; see docs/verification.md.
export default defineConfig({
  test: { environment: 'node', include: ['tests/**/*.test.ts'], testTimeout: 30000 },
});
