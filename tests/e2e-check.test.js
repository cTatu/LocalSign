import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
describe('e2e checklist', () => {
  it('matrix mentions Adobe + openssl + error codes', () => {
    const md = fs.readFileSync('tests/e2e.manual.md', 'utf8');
    expect(md).toMatch(/Adobe/);
    expect(md).toMatch(/openssl cms -print/);
    expect(md).toMatch(/SIGNATURE_TOO_LARGE/);
    expect(md).toMatch(/ROTATED_NOT_SUPPORTED/);
  });
});
