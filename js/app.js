// js/app.js
import { PDFDocument } from '../lib/pdf-lib.esm.js';
import * as pdfjs from '../lib/pdf.min.mjs';
import { checkFileGuards } from './guards.js';
import { loadP12, clearCert } from './cert.js';
import { addVisualPlaceholder, buildRectBottomRight, cssToPdfRect, normalizeDrag, saveBase } from './pdf-visual.js';
import { appendPlaceholder, patchByteRange, patchContents } from './byterange.js';
import { hashByteRange, buildCmsDer } from './cms.js';
import { preCheck, sanitizeBase } from './verify.js';
import { ERRORS } from './errors.js';
const $ = (id) => document.getElementById(id);
// Preview render scale: canvas px per PDF point. Click/drag mapping divides
// by this same constant (see cssToPdfRect), so placement stays exact.
// Kept small so the page fits without scrolling.
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
  const overlay = $('selOverlay');
  canvas.width = viewport.width; canvas.height = viewport.height;
  await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
  // Selection is measured in displayed CSS px, then mapped back to canvas px
  // (canvas.width / rect.width) so CSS scaling never skews placement.
  const toCanvas = (ev) => {
    const r = canvas.getBoundingClientRect();
    const k = canvas.width / r.width;
    return { x: (ev.clientX - r.left) * k, y: (ev.clientY - r.top) * k };
  };
  let dragStart = null;
  canvas.onpointerdown = (ev) => {
    const p = toCanvas(ev);
    dragStart = p;
    canvas.setPointerCapture(ev.pointerId);
    overlay.hidden = false;
    overlay.style.left = `${ev.clientX - canvas.getBoundingClientRect().left}px`;
    overlay.style.top = `${ev.clientY - canvas.getBoundingClientRect().top}px`;
    overlay.style.width = '0px';
    overlay.style.height = '0px';
  };
  canvas.onpointermove = (ev) => {
    if (!dragStart) return;
    const p = toCanvas(ev);
    const r = canvas.getBoundingClientRect();
    const x0 = dragStart.x * (r.width / canvas.width);
    const x1 = p.x * (r.width / canvas.width);
    const y0 = dragStart.y * (r.width / canvas.width);
    const y1 = p.y * (r.width / canvas.width);
    overlay.style.left = `${Math.min(x0, x1)}px`;
    overlay.style.top = `${Math.min(y0, y1)}px`;
    overlay.style.width = `${Math.abs(x1 - x0)}px`;
    overlay.style.height = `${Math.abs(y1 - y0)}px`;
  };
  canvas.onpointerup = (ev) => {
    if (!dragStart) return;
    const p = toCanvas(ev);
    const box = normalizeDrag(dragStart.x, dragStart.y, p.x, p.y);
    dragStart = null;
    const cssPerPt = PREVIEW_SCALE;
    if (!box) {
      // Simple click → default-size box centered on the point.
      window.__previewClick = { x: p.x - (PLACED_W_PT * cssPerPt) / 2, y: p.y - (PLACED_H_PT * cssPerPt) / 2, w: PLACED_W_PT * cssPerPt, h: PLACED_H_PT * cssPerPt, scale: PREVIEW_SCALE };
    } else {
      window.__previewClick = { x: box.x, y: box.y, w: box.w, h: box.h, scale: PREVIEW_SCALE };
    }
  };
  const sel = $('pageSelect');
  sel.innerHTML = '';
  for (let i = 1; i <= doc.numPages; i++) { const o = document.createElement('option'); o.value = String(i); o.textContent = `Page ${i}`; sel.appendChild(o); }
  return { viewport, pageCount: doc.numPages };
}
function clearSelection() {
  // Called only when the file or page changes — never during signing, so a
  // drag selection made on the preview survives until Sign is pressed.
  window.__previewClick = null;
  const overlay = $('selOverlay');
  if (overlay) overlay.hidden = true;
}
async function previewFile(pageNum) {
  const status = $('statusEl');
  const f = $('fileInput').files[0];
  if (!f) return;
  try {
    const buf = new Uint8Array(await f.arrayBuffer());
    const g = checkFileGuards(buf, f.name);
    if (!g.ok) throw new Error(g.code);
    clearSelection();
    await renderPreview(buf, pageNum);
  } catch (e) {
    status.textContent = ERRORS[e.message] || `${e.name || 'Error'}: ${e.message || e}`;
  }
}
$('fileInput').addEventListener('change', () => { previewFile(1); });
$('pageSelect').addEventListener('change', () => {
  const n = Math.max(1, parseInt(($('pageSelect').value || '1'), 10));
  previewFile(n);
});
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
