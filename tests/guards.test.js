// tests/guards.test.js
import { describe, it, expect } from 'vitest';
import { checkFileGuards } from '../js/guards.js';
describe('checkFileGuards', () => {
  it('rejects oversized', () => {
    expect(checkFileGuards(new Uint8Array(25_000_001), 'a.pdf')).toEqual({ ok: false, code: 'FILE_TOO_LARGE' });
  });
  it('rejects docx', () => {
    expect(checkFileGuards(new Uint8Array([1]), 'a.docx')).toEqual({ ok: false, code: 'DOCX_DEFERRED' });
  });
  it('rejects encrypted at EOF tail', () => {
    const tail = new TextEncoder().encode('%PDF-1.7\n' + 'x'.repeat(100) + 'trailer << /Encrypt 5 0 R >>\n%%EOF');
    expect(checkFileGuards(tail, 'e.pdf').code).toBe('ENCRYPTED_NOT_SUPPORTED');
  });
  it('rejects signed at EOF tail', () => {
    const t = new TextEncoder().encode('aa\ntrailer << /Root 1 0 R >>\n/ByteRange [0 100 200 800]');
    expect(checkFileGuards(t, 's.pdf').code).toBe('ALREADY_SIGNED');
  });
  it('rejects certified DocMDP/FieldMDP', () => {
    const t = new TextEncoder().encode('/Perms << /DocMDP 10 0 R >>');
    expect(checkFileGuards(t, 'c.pdf').code).toBe('CERTIFIED_NOT_SUPPORTED');
    const f = new TextEncoder().encode('/Perms << /FieldMDP 11 0 R >>');
    expect(checkFileGuards(f, 'c2.pdf').code).toBe('CERTIFIED_NOT_SUPPORTED');
  });
  it('accepts clean pdf', () => {
    const t = new TextEncoder().encode('%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj');
    expect(checkFileGuards(t, 'ok.pdf')).toEqual({ ok: true });
  });
});
