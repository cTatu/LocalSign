// tests/pdf-visual.test.js
import { describe, it, expect } from 'vitest';
import { DEFAULT_RECT_W, DEFAULT_RECT_H, MARGIN, buildRectBottomRight, cssToPdfRect, escapePdfText, normalizeDrag, logoOps, moveBox, resizeBox, clampBox, addVisualPlaceholder } from '../js/pdf-visual.js';
describe('visual rect', () => {
  it('bottom-right with margins', () => {
    expect(buildRectBottomRight(612, 792)).toEqual([426, 36, 576, 86]);
    expect(DEFAULT_RECT_W).toBe(150);
    expect(DEFAULT_RECT_H).toBe(50);
    expect(MARGIN).toBe(36);
  });
  it('css to pdf flips y', () => {
    expect(cssToPdfRect(0, 0, 96, 48, 1, { x: 0, y: 0, h: 792 })).toEqual([0, 744, 96, 792]);
  });
  it('maps preview px to points by 1/scale (no 96dpi factor)', () => {
    // 612x792pt page previewed at 0.5 -> 306x396px canvas. Drag (50,300,150,50)
    // must land at [100,92,400,192]pt, not shrunk toward the origin.
    expect(cssToPdfRect(50, 300, 150, 50, 0.5, { x: 0, y: 0, h: 792 })).toEqual([100, 92, 400, 192]);
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
  it('merges into a pre-existing AcroForm (no instanceof crash)', async () => {    const { PDFDocument } = await import('../lib/pdf-lib.esm.js');
    const d = await PDFDocument.create();
    const p = d.addPage([612, 792]);
    const form = d.getForm();
    const tf = form.createTextField('existing.field');
    tf.addToPage(p, { x: 50, y: 700, width: 200, height: 24 });
    const bytes = await d.save({ useObjectStreams: false });
    const d2 = await PDFDocument.load(bytes);
    const { widgetObjNum } = await addVisualPlaceholder(d2, { pageIndex: 0, rect: [426, 36, 576, 86], text: 'T' });
    expect(widgetObjNum).toBeGreaterThan(0);
    const out = await d2.save({ useObjectStreams: false });
    const text = new TextDecoder('latin1').decode(out);
    expect(text).toMatch(/\/FT\s*\/Sig/);
    expect(text).toMatch(/\/FT\s*\/Tx/);
    expect(text).toMatch(/\/SigFlags\s+3/);
  });
  it('normalizeDrag normalizes any direction, rejects tiny drags', () => {
    expect(normalizeDrag(10, 10, 100, 60)).toEqual({ x: 10, y: 10, w: 90, h: 50 });
    expect(normalizeDrag(100, 60, 10, 10)).toEqual({ x: 10, y: 10, w: 90, h: 50 });
    expect(normalizeDrag(10, 10, 15, 12)).toBe(null);
    expect(normalizeDrag(10, 10, 10, 10)).toBe(null);
  });
  it('logoOps draws shield then check with brand colors', () => {    const ops = logoOps(0, 0, 1).split('\n');
    expect(ops[0]).toBe('0.118 0.227 0.541 RG');
    expect(ops).toContain('16 30 m');
    expect(ops).toContain('h S');
    expect(ops).toContain('0.706 0.325 0.035 RG');
    expect(ops[ops.length - 1]).toBe('S');
    expect(ops.join('\n')).toContain('11 16 m');
  });
  it('moveBox translates and clamps to the page', () => {
    expect(moveBox({ x: 10, y: 10, w: 50, h: 30 }, 400, 400, 20, 30))
      .toEqual({ x: 30, y: 40, w: 50, h: 30 });
    expect(moveBox({ x: 370, y: 380, w: 50, h: 30 }, 400, 400, 20, 30))
      .toEqual({ x: 350, y: 370, w: 50, h: 30 });
    expect(moveBox({ x: 10, y: 10, w: 50, h: 30 }, 400, 400, -50, -50))
      .toEqual({ x: 0, y: 0, w: 50, h: 30 });
  });
  it('resizeBox grows/shrinks with minimum size', () => {
    expect(resizeBox({ x: 10, y: 10, w: 50, h: 30 }, 400, 400, 20, 10))
      .toEqual({ x: 10, y: 10, w: 70, h: 40 });
    expect(resizeBox({ x: 10, y: 10, w: 50, h: 30 }, 400, 400, -100, -100))
      .toEqual({ x: 10, y: 10, w: 24, h: 16 });
    expect(resizeBox({ x: 360, y: 10, w: 50, h: 30 }, 400, 400, 100, 0))
      .toEqual({ x: 250, y: 10, w: 150, h: 30 });
  });
});
