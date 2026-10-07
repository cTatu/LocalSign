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
  const k = 72 / (96 * scale);
  const pdfX = crop.x + cssX * k;
  const pdfW = cssW * k;
  const pdfH = cssH * k;
  const pdfY = crop.y + crop.h - (cssY + cssH) * k;
  return [pdfX, pdfY, pdfX + pdfW, pdfY + pdfH];
}
export function escapePdfText(s) {
  return s.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}
export async function addVisualPlaceholder(pdfDoc, { pageIndex, rect, text, imageBytes }) {
  const page = pdfDoc.getPage(pageIndex);
  if (page.getRotation().angle !== 0) throw new Error('ROTATED_NOT_SUPPORTED');
  const context = pdfDoc.context;
  const [x1, y1, x2, y2] = rect;
  const w = x2 - x1; const h = y2 - y1;
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const safe = escapePdfText(`Signed by ${text} (client clock, unverified)`);
  let resourcesExtra = '';
  let drawImage = '';
  let fontDict = `Font: context.obj({ F1: font.ref })`;
  void fontDict;
  if (imageBytes) {
    const img = await pdfDoc.embedPng(imageBytes);
    resourcesExtra = ` /XObject: context.obj({ Im0: img.ref })`;
    drawImage = `q ${w - 4} 0 0 ${h - 18} 2 2 cm /Im0 Do Q\n`;
  }
  const content = `q\n0.5 w\n0 0 ${w} ${h} re S\n${drawImage}BT /F1 10 Tf 6 22 Td (${safe}) Tj ET\nQ`;
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
