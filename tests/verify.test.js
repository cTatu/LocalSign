// tests/verify.test.js
import { describe, it, expect } from 'vitest';
import { sanitizeBase, validateByteRangeFourth } from '../js/verify.js';
describe('sanitizeBase', () => {
  it('strips stacked extensions and accents', () => {
    expect(sanitizeBase('invöice.pdf.exe')).toBe('invoice');
    expect(sanitizeBase('/tmp/a.pdf')).toBe('a');
    expect(sanitizeBase('a.docx')).toBe('a');
  });
});
describe('validateByteRangeFourth', () => {
  it('checks 4th == Z-Y', () => {
    expect(validateByteRangeFourth('[0000000000 0000000100 0000000200 0000000800]', 1000)).toBe(true);
    expect(validateByteRangeFourth('[0000000000 0000000100 0000000200 0000000300]', 1000)).toBe(false);
  });
});
