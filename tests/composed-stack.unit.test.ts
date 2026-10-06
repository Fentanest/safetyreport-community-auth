import { spawnSync } from 'node:child_process';
import { expect, it } from 'vitest';

it('refuses to manage externally owned Docker services in composed-stack mode', () => {
  const run = spawnSync(process.execPath, ['tests/stack/stack.mjs', 'up'], {
    env: { ...process.env, SAFEAUTH_COMPOSED_STACK: '1' }, encoding: 'utf8',
  });
  expect(run.status).not.toBe(0);
  expect(run.stderr).toContain('composed stack is externally owned');
});
