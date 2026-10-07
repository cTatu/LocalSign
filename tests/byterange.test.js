// tests/byterange.test.js
import { describe, it, expect } from 'vitest';
import { buildByteRangeString, findAscii, appendPlaceholder, patchRevision, validateSplice } from '../js/byterange.js';
describe('buildByteRangeString', () => {
  it('emits [0 X Y Z-Y] padded', () => {
    expect(buildByteRangeString(100, 200, 1000)).toBe('[0000000000 0000000100 0000000200 0000000800]');
  });
});
describe('findAscii', () => {
  it('finds marker and last occurrence', () => {
    const b = new TextEncoder().encode('ab /Contents <00> cd /Contents <11>');
    expect(findAscii(b, '/Contents <')).toBe(3);
    expect(findAscii(b, '/Contents <', true)).toBe(21);
  });
});
describe('append+patch', () => {
  it('4th == Z-Y on real file, preserves Prev/Size/ID, splice idempotent, rejects oversize', () => {
    const base = new TextEncoder().encode('%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer << /Size 2 /Root 1 0 R /ID [<AABB> <AABB>] >>\nstartxref\n50\n%%EOF');
    const meta = appendPlaceholder(base, { widgetObjNum: 5, rect: [400, 36, 550, 86], pageObjNum: 3, apObjNum: 7 });
    expect(meta.Z - meta.Y).toBeGreaterThan(0);
    expect(meta.withGap.length).toBe(meta.Z);
    const text = new TextDecoder('latin1').decode(meta.withGap);
    expect(text).toMatch(/\/Prev\s+\d+/);
    expect(text).toMatch(/\/Size\s+\d+/);
    expect(text).toMatch(/\/ID\s*\[<AABB>\s*<AABB>\]/);
    const cms = new Uint8Array([1, 2, 3, 4]);
    const once = patchRevision(meta.withGap, cms, meta);
    const twice = patchRevision(once, cms, { ...meta, withGap: once });
    expect(validateSplice(once, meta)).toBe(true);
    expect(() => patchRevision(meta.withGap, new Uint8Array(16385), meta)).toThrow('SIGNATURE_TOO_LARGE');
  });
});
