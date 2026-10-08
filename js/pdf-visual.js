// js/pdf-visual.js
import { PDFName, PDFNumber, PDFHexString, PDFString, PDFDict, PDFArray, StandardFonts } from '../lib/pdf-lib.esm.js';
export const DEFAULT_RECT_W = 150;
export const DEFAULT_RECT_H = 50;
export const MARGIN = 36;
export function buildRectBottomRight(pageW, pageH) {
  const x1 = Math.max(0, pageW - DEFAULT_RECT_W - MARGIN);
  const y1 = MARGIN;
  return [x1, y1, x1 + DEFAULT_RECT_W, y1 + DEFAULT_RECT_H];
}
export function cssToPdfRect(cssX, cssY, cssW, cssH, scale, crop) {
  // pdf.js maps points -> pixels linearly by `scale` (612pt * 0.5 = 306px),
  // so points = canvasPx / scale. (A previous 72/(96*scale) factor wrongly
  // mixed in 96-DPI CSS sizing and shrank every rect 0.75x toward the origin.)
  const k = 1 / scale;
  const pdfX = crop.x + cssX * k;
  const pdfW = cssW * k;
  const pdfH = cssH * k;
  const pdfY = crop.y + crop.h - (cssY + cssH) * k;
  return [pdfX, pdfY, pdfX + pdfW, pdfY + pdfH];
}
export function escapePdfText(s) {
  return s.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}
function num(n) {
  return String(Math.round(n * 100) / 100);
}
// Brand mark as PDF vector ops (shield + check), drawn in an AP content
// stream. SVG 32-grid mapped with y-flip: X = x0 + x*s, Y = y0 + (32-y)*s.
export function logoOps(x0, y0, s) {
  const X = (x) => num(x0 + x * s);
  const Y = (y) => num(y0 + (32 - y) * s);
  return [
    '0.118 0.227 0.541 RG',
    `${num(3 * s)} w`,
    `${X(16)} ${Y(2)} m`,
    `${X(28)} ${Y(7)} l`,
    `${X(28)} ${Y(16)} l`,
    `${X(28)} ${Y(24)} ${X(22)} ${Y(29)} ${X(16)} ${Y(30)} c`,
    `${X(10)} ${Y(29)} ${X(4)} ${Y(24)} ${X(4)} ${Y(16)} c`,
    `${X(4)} ${Y(7)} l`,
    'h S',
    '0.706 0.325 0.035 RG',
    `${X(11)} ${Y(16)} m`,
    `${X(15)} ${Y(20)} l`,
    `${X(22)} ${Y(12)} l`,
    'S',
  ].join('\n');
}
export function normalizeDrag(x0, y0, x1, y1, minPx = 8) {
  const w = Math.abs(x1 - x0);
  const h = Math.abs(y1 - y0);
  if (w < minPx || h < minPx) return null;
  return { x: Math.min(x0, x1), y: Math.min(y0, y1), w, h };
}
// Pure selection-box math (canvas px): move/resize a box, clamped to the
// page with a minimum size. Overlay handlers are thin glue over this.
export function moveBox(box, W, H, dx, dy, minW = 24, minH = 16) {
  return clampBox({ ...box, x: box.x + dx, y: box.y + dy }, W, H, minW, minH);
}
export function resizeBox(box, W, H, dw, dh, minW = 24, minH = 16) {
  return clampBox({ ...box, w: box.w + dw, h: box.h + dh }, W, H, minW, minH);
}
export function clampBox(box, W, H, minW = 24, minH = 16) {
  const w = Math.max(minW, Math.min(box.w, W));
  const h = Math.max(minH, Math.min(box.h, H));
  return {
    x: Math.max(0, Math.min(box.x, W - w)),
    y: Math.max(0, Math.min(box.y, H - h)),
    w,
    h,
  };
}
export async function addVisualPlaceholder(pdfDoc, { pageIndex, rect, text, imageBytes }) {
  const page = pdfDoc.getPage(pageIndex);
  if (page.getRotation().angle !== 0) throw new Error('ROTATED_NOT_SUPPORTED');
  const context = pdfDoc.context;
  const [x1, y1, x2, y2] = rect;
  const w = x2 - x1; const h = y2 - y1;
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const safe = escapePdfText(text);
  let resourcesExtra = '';
  let drawImage = '';
  let fontDict = `Font: context.obj({ F1: font.ref })`;
  void fontDict;
  if (imageBytes) {
    const img = await pdfDoc.embedPng(imageBytes);
    resourcesExtra = ` /XObject: context.obj({ Im0: img.ref })`;
    drawImage = `q ${w - 4} 0 0 ${h - 18} 2 2 cm /Im0 Do Q\n`;
  }
  // Brand mark left of the text when no uploaded image fills the box (pure
  // vector ops, no XObject needed). Skipped for narrow boxes and image mode.
  const logoSize = Math.min(36, h - 12);
  const withLogo = !imageBytes && w >= logoSize + 56 && logoSize > 12;
  const textX = withLogo ? 4 + logoSize + 8 : 6;
  const logo = withLogo ? logoOps(4, (h - logoSize) / 2, logoSize / 32) + '\n' : '';
  const content = `q\n0.5 w\n0 0 ${w} ${h} re S\n${drawImage}${logo}BT /F1 10 Tf ${textX} 22 Td (${safe}) Tj ET\nQ`;
  const stream = context.flateStream(content);
  stream.dict.set(PDFName.of('Type'), PDFName.of('XObject'));
  stream.dict.set(PDFName.of('Subtype'), PDFName.of('Form'));
  stream.dict.set(PDFName.of('BBox'), context.obj([PDFNumber.of(0), PDFNumber.of(0), PDFNumber.of(w), PDFNumber.of(h)]));
  stream.dict.set(PDFName.of('Matrix'), context.obj([PDFNumber.of(1), PDFNumber.of(0), PDFNumber.of(0), PDFNumber.of(1), PDFNumber.of(0), PDFNumber.of(0)]));
  const resObj = imageBytes ? context.obj({ Font: context.obj({ F1: font.ref }), XObject: context.obj({ Im0: (await pdfDoc.embedPng(imageBytes)).ref }) }) : context.obj({ Font: context.obj({ F1: font.ref }) });
  void resourcesExtra;
  stream.dict.set(PDFName.of('Resources'), resObj);
  const formRef = context.register(stream);
  const widget = context.obj({ Type: PDFName.of('Annot'), Subtype: PDFName.of('Widget'), FT: PDFName.of('Sig'), T: PDFString.of('Signature1'), Rect: context.obj([PDFNumber.of(x1), PDFNumber.of(y1), PDFNumber.of(x2), PDFNumber.of(y2)]), P: page.ref, F: PDFNumber.of(4), AP: context.obj({ N: formRef }) });
  const widgetRef = context.register(widget);
  page.node.addAnnot(widgetRef);
  const acroKey = PDFName.of('AcroForm');
  // NOTE: lookupMaybe requires a real class (it does `value instanceof Type`);
  // passing undefined only works when the key is absent. cancelar-2.pdf has a
  // pre-existing AcroForm, which crashed with "Right-hand side of
  // 'instanceof' is not an object".
  const acro = pdfDoc.catalog.lookupMaybe(acroKey, PDFDict);
  if (!acro) {
    pdfDoc.catalog.set(acroKey, context.obj({ Fields: [widgetRef], SigFlags: PDFNumber.of(3) }));
  } else {
    const fields = acro.lookupMaybe(PDFName.of('Fields'), PDFArray);
    if (fields) fields.push(widgetRef);
    else acro.set(PDFName.of('Fields'), context.obj([widgetRef]));
    acro.set(PDFName.of('SigFlags'), PDFNumber.of(3));
  }
  const widgetObjNum = widgetRef.objectNumber;
  const apObjNum = formRef.objectNumber;
  const pageObjNum = page.ref.objectNumber;
  return { fieldRef: widgetRef, widgetObjNum, apRef: formRef, apObjNum, pageObjNum, rect };
}
export async function saveBase(pdfDoc) {
  return await pdfDoc.save({ useObjectStreams: false, updateFieldAppearances: false });
}
