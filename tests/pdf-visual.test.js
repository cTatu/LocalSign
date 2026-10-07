// tests/pdf-visual.test.js
import { describe, it, expect } from 'vitest';
import { DEFAULT_RECT_W, DEFAULT_RECT_H, MARGIN, buildRectBottomRight, cssToPdfRect, escapePdfText } from '../js/pdf-visual.js';
describe('visual rect', () => {
  it('bottom-right with margins', () => {
    expect(buildRectBottomRight(612, 792)).toEqual([426, 36, 576, 86]);
    expect(DEFAULT_RECT_W).toBe(150);
    expect(DEFAULT_RECT_H).toBe(50);
    expect(MARGIN).toBe(36);
  });
  it('css to pdf flips y', () => {
    expect(cssToPdfRect(0, 0, 96, 48, 1, { x: 0, y: 0, h: 792 })).toEqual([0, 792 - 36, 72, 792]);
  });
  it('escapes parens', () => {
    expect(escapePdfText('a(b)\\c')).toBe('a\\(b\\)\\\\c');
  });
  it('rejects rotated pages', async () => {
    const { PDFDocument } = await import('../lib/pdf-lib.esm.js');
    const d = await PDFDocument.create();
    const p = d.addPage([612, 792]);
    p.setRotation({ type: 'degrees', angle: 90 });
    const { addVisualPlaceholder } = await import('../js/pdf-visual.js');
    await expect(addVisualPlaceholder(d, { pageIndex: 0, rect: [10, 10, 160, 60], text: 'T' })).rejects.toThrow('ROTATED_NOT_SUPPORTED');
  });
});
