// tests/cert.test.js
import { describe, it, expect } from 'vitest';
import { detectEC, u8ToBinaryStr } from '../js/cert.js';
describe('detectEC', () => {
  it('allows RSA oid with n/e/d', () => {
    expect(detectEC('1.2.840.113549.1.1.1', { n: {}, e: {}, d: {} })).toBe(false);
  });
  it('flags EC oid', () => {
    expect(detectEC('1.2.840.10045.4.3.2', { n: {}, e: {}, d: {} })).toBe(true);
  });
  it('flags Ed25519 oid', () => {
    expect(detectEC('1.3.101.112', { n: {}, e: {}, d: {} })).toBe(true);
  });
  it('flags missing d', () => {
    expect(detectEC('1.2.840.113549.1.1.1', { n: {}, e: {} })).toBe(true);
  });
  it('flags unknown oid as EC (fail-closed)', () => {
    expect(detectEC('1.9.9.9.9', { n: {}, e: {}, d: {} })).toBe(true);
  });
});
describe('u8ToBinaryStr', () => {
  it('converts bytes', () => {
    expect(u8ToBinaryStr(new Uint8Array([65, 66]))).toBe('AB');
  });
});
