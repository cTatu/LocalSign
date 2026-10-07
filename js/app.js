// js/app.js
import { PDFDocument } from '../lib/pdf-lib.esm.js';
import * as pdfjs from '../lib/pdf.min.mjs';
import { checkFileGuards } from './guards.js';
import { loadP12, clearCert } from './cert.js';
import { addVisualPlaceholder, buildRectBottomRight, cssToPdfRect, saveBase } from './pdf-visual.js';
import { appendPlaceholder, patchByteRange, patchContents } from './byterange.js';
import { hashByteRange, buildCmsDer } from './cms.js';
import { preCheck, sanitizeBase } from './verify.js';
import { ERRORS } from './errors.js';
const $ = (id) => document.getElementById(id);
// Preview render scale (CSS px per PDF point = PREVIEW_SCALE * 96 / 72).
// Kept small so the page fits without scrolling; click mapping stays exact
// because placement rects are derived from this same constant.
const PREVIEW_SCALE = 0.5;
const PLACED_W_PT = 150;
const PLACED_H_PT = 50;
$('statusEl').textContent = 'Ready — select a PDF and your .p12 to begin.';
pdfjs.GlobalWorkerOptions.workerSrc = '../lib/pdf.worker.min.mjs';
async function renderPreview(pdfBytes, pageNum) {
  // NOTE: pdf.js transfers (neuters) the buffer handed to getDocument, so it
  // must receive a copy — the caller's bytes are needed downstream for signing.
  const doc = await pdfjs.getDocument({ data: pdfBytes.slice() }).promise;
  const page = await doc.getPage(pageNum);
  const viewport = page.getViewport({ scale: PREVIEW_SCALE, rotation: 0 });
  const canvas = $('previewCanvas');
  canvas.width = viewport.width; canvas.height = viewport.height;
  await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
  canvas.onclick = (ev) => {
    const r = canvas.getBoundingClientRect();
    const cssPerPt = PREVIEW_SCALE * 96 / 72;
    window.__previewClick = { x: ev.clientX - r.left, y: ev.clientY - r.top, w: PLACED_W_PT * cssPerPt, h: PLACED_H_PT * cssPerPt, scale: PREVIEW_SCALE };
  };
  const sel = $('pageSelect');
  sel.innerHTML = '';
  for (let i = 1; i <= doc.numPages; i++) { const o = document.createElement('option'); o.value = String(i); o.textContent = `Page ${i}`; sel.appendChild(o); }
  return { viewport, pageCount: doc.numPages };
}
let certState = null;
$('signBtn').addEventListener('click', async () => {
  const status = $('statusEl');
  // Stage tracker: on failure the status shows WHERE it broke (step + error
  // name), so raw browser errors like NotFoundError can be traced to a step.
  let stage = 'starting';
  const at = (s) => { stage = s; status.textContent = s + '…'; };
  try {
    if (location.protocol === 'file:') throw new Error('INSECURE_CONTEXT');
    if (!window.isSecureContext) throw new Error('INSECURE_CONTEXT');
    const f = $('fileInput').files[0];
    if (!f) throw new Error('NO_FILE');
    at('Reading PDF');
    const buf = new Uint8Array(await f.arrayBuffer());
    const g = checkFileGuards(buf, f.name);
    if (!g.ok) throw new Error(g.code);
    at('Rendering preview');
    await renderPreview(buf, 1);
    const p12File = $('certInput').files[0];
    if (!p12File) throw new Error('BAD_PASSWORD_OR_CORRUPT_P12');
    at('Reading certificate');
    certState = await loadP12(new Uint8Array(await p12File.arrayBuffer()), $('certPass').value);
    if (new Date() < certState.notBefore || new Date() > certState.notAfter) status.textContent = 'Warning: cert outside validity — proceeding.\n';
    at('Preparing signature appearance');
    const pdfDoc = await PDFDocument.load(buf);
    const pages = pdfDoc.getPages();
    const selIdx = Math.max(0, (parseInt(($('pageSelect').value || '1'), 10) - 1));
    const pageIdx = Math.min(selIdx, pages.length - 1);
    const page = pages[pageIdx];
    let cropBox;
    try { cropBox = page.getCropBox(); } catch { cropBox = { x: 0, y: 0, width: page.getSize().width, height: page.getSize().height }; }
    const { width, height } = page.getSize();
    const crop = { x: cropBox.x, y: cropBox.y, h: cropBox.height };
    let rect = buildRectBottomRight(cropBox.width, cropBox.height);
    rect = [crop.x + rect[0], crop.y + rect[1], crop.x + rect[2], crop.y + rect[3]];
    if (cropBox.width < 222 || cropBox.height < 122) {
      const s = Math.min(cropBox.width / 222, cropBox.height / 122, 1);
      const w = 150 * s; const h = 50 * s;
      rect = [crop.x + cropBox.width - w - 12, crop.y + 12, crop.x + cropBox.width - 12, crop.y + 12 + h];
    }
    const previewPos = window.__previewClick;
    if (previewPos) {
      rect = cssToPdfRect(previewPos.x, previewPos.y, previewPos.w, previewPos.h, previewPos.scale, crop);
    }
    const { widgetObjNum, apObjNum, pageObjNum } = await addVisualPlaceholder(pdfDoc, { pageIndex: pageIdx, rect, text: certState.subjectCN || 'Signer' });
    at('Building signature');
    const baseBytes = await saveBase(pdfDoc);
    const meta = appendPlaceholder(baseBytes, { widgetObjNum, rect, pageObjNum, apObjNum });
    // PAdES order: ByteRange values are part of the hashed [0,X) segment, so
    // the FINAL values must be written BEFORE hashing (same-width, in place).
    const gapFinal = patchByteRange(meta.withGap, meta);
    at('Hashing document');
    const hash = await hashByteRange(gapFinal, meta.X, meta.Y, meta.Z);
    at('Signing');
    const cms = buildCmsDer(hash, certState);
    const signed = patchContents(gapFinal, cms, meta);
    at('Verifying and downloading');
    const pc = preCheck(signed);
    const blob = new Blob([signed], { type: 'application/pdf' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${sanitizeBase(f.name)}-signed.pdf`;
    a.click();
    status.textContent += pc.label + '\n' + pc.checks.map(c => `${c.pass ? 'PASS' : 'FAIL'} ${c.name}: ${c.detail}`).join('\n');
  } catch (e) {
    const known = ERRORS[e.message];
    status.textContent = known || `Failed at step "${stage}": ${e.name || 'Error'}: ${e.message || e}`;
  } finally {
    clearCert(certState); certState = null;
    const pw = $('certPass'); if (pw) pw.value = '';
  }
});
