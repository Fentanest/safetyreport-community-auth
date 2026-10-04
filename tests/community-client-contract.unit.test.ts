// D2-10: client rules shared with the PC server and the mobile app (tests/contracts/community-client is a byte copy of
// safetyreport contracts/community-client). The central side checks what it produces: the error code → HTTP status and
// retryable table, and the device-label validator.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { RETRYABLE, STATUS } from '../server/account.ts';
import { normalizeDeviceLabel } from '../server/protocol.ts';

const dir = join(__dirname, 'contracts', 'community-client');
const vectors = (name: string) => JSON.parse(readFileSync(join(dir, 'vectors', name), 'utf8'));

describe('community-client contract copy', () => {
  it('matches its MANIFEST', () => {
    for (const line of readFileSync(join(dir, 'MANIFEST.sha256'), 'utf8').trim().split('\n')) {
      const [digest, name] = line.split(/\s+/);
      expect(createHash('sha256').update(readFileSync(join(dir, name))).digest('hex'), name).toBe(digest);
    }
  });

  it('central error codes use the HTTP status and retryable flag that clients classify', () => {
    const central = vectors('account-errors.json').central_codes as Record<string, { http_status: number; retryable: boolean }>;
    expect(Object.keys(STATUS).sort()).toEqual(Object.keys(central).sort());
    for (const [code, want] of Object.entries(central)) {
      expect({ http: STATUS[code as keyof typeof STATUS], retryable: RETRYABLE.has(code as keyof typeof STATUS) }, code)
        .toEqual({ http: want.http_status, retryable: want.retryable });
    }
  });

  it('device label validation matches the vectors, and mobile-sanitized names are accepted', () => {
    for (const c of vectors('device-label.json').cases as { input: unknown; valid: string | null; sanitized: string | null }[]) {
      expect(normalizeDeviceLabel(c.input), JSON.stringify(c.input)).toBe(c.valid);
      if (c.sanitized !== null) expect(normalizeDeviceLabel(c.sanitized), `sanitized ${JSON.stringify(c.sanitized)}`).not.toBeNull();
    }
  });
});
