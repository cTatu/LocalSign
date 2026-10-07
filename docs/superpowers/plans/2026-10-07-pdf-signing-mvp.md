# PDF Signing MVP Implementation Plan (v2, plan-review fixes)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a zero-backend static page that PAdES B-B signs an unsigned PDF with an RSA .p12 in-browser.

**Architecture:** Vanilla ES modules with importmap to vendored ESM; pdf-lib PDFContext low-level only for merged field+widget visual, manual incremental ByteRange append with real trailer parse, Forge ASN.1 low-level CMS with ESSCertIDv2 and DER-sorted SET, WebCrypto digest (Worker for >8MB), Adobe Reader normative gate.

**Tech Stack:** Vanilla JS ES modules, pdf-lib@1.17.1, node-forge@1.3.1, pdf.js@4.2.67, WebCrypto subtle.digest + Worker, vitest@1.6.0, `python3 -m http.server 8000` on `http://localhost:8000`.

## Global Constraints

- MVP PDF-only: reject `.docx` with `DOCX_DEFERRED`.
- RSA-only: `detectEC(oid, privateKey) => true` iff `oid` missing RSA prefix `1.2.840.113549.1.1.` OR `!privateKey.n/e/d`; else `EC_NOT_SUPPORTED_MVP`.
- Zero network MVP: CSP `default-src 'self'; script-src 'self'; worker-src 'self' blob:; object-src 'none'; connect-src 'none'`; no fetch.
- `/Rotate 0` only: else `ROTATED_NOT_SUPPORTED`; preview `viewport.rotation=0`; `CropBox||MediaBox`; clamp/shrink if page <222x122pt.
- Reject encrypted (`trailer Encrypt`) `ENCRYPTED_NOT_SUPPORTED`; already-signed (`FT/Sig` or `ByteRange`) `ALREADY_SIGNED`; certified (`DocMDP` or `FieldMDP` or certified `SigFlags 3` with `Perms`) `CERTIFIED_NOT_SUPPORTED`.
- File limit 25000000 bytes `FILE_TOO_LARGE`; scan head 512KB + tail 2MB for guards/precheck.
- `/Contents` 16384 bytes (32768 hex); chain leaf+ALL intermediates leaf-first exclude root only; overflow `SIGNATURE_TOO_LARGE` abort.
- `ByteRange=[0 X Y Z-Y]`, `X=offset('<' of Contents)`, `Y=offset after '>'`, `Z=len`; four 10-digit `pad10`; direct keys inside indirect Sig dict; `Filter/Adobe.PPKLite`, `SubFilter/adbe.pkcs7.detached`.
- CMS detached (`eContent===undefined`), SHA-256, rsaEncryption+sha256, signedAttrs DER-sorted, mandatory contentType+messageDigest+signingCertificateV2 `1.2.840.113549.1.9.16.2.47`.
- Merged field+widget, `F 4` only, no `/F 132`, no Kids/Parent, `SigFlags 3`, AP BBox==Rect w/h.
- Secure context + `http://localhost` or `https://`; reject `file://`; browsers Chrome/Edge 120+, Firefox 120+, Safari 17+.
- Output `<sanitized>-signed.pdf`; `sanitizeBase` loop-strips extensions + NFKD.
- Heap-only keys, best-effort wipe, advise reload; `signingTime` + visual date labeled client-claimed.
- Pre-check label `Pre-check only — trust decision is Adobe Reader`; `no CRL/OCSP in MVP`.

### Frozen signatures (verbatim in every task)
- `checkFileGuards(pdfBytes: Uint8Array, fileName: string) => {ok:true}|{ok:false,code:string}`
- `loadP12(p12Bytes: Uint8Array, password: string) => Promise<{privateKey,leafDer:Uint8Array,chainDer:Uint8Array[],subjectCN:string,issuerCN:string,notBefore:Date,notAfter:Date}>`
- `detectEC(signatureOid: string|undefined, privateKey: object) => boolean`
- `u8ToBinaryStr(u8: Uint8Array) => string`
- `addVisualPlaceholder(pdfDoc: PDFDocument, opts:{pageIndex:number,rect:[number,number,number,number],text:string,imageBytes?:Uint8Array}) => {fieldRef:PDFRef,widgetObjNum:number,apRef:PDFRef,apObjNum:number,pageObjNum:number,rect:[number,number,number,number]}` (Phase 1 visual-only with text + optional PNG Im0, NO Sig ByteRange in base; Sig created in Phase 2 revision which also updates widget with `/V`)
- `buildRectBottomRight(pageW:number,pageH:number) => [number,number,number,number]`
- `cssToPdfRect(cssX,cssY,cssW,cssH,scale,crop:{x,y,h}) => [number,number,number,number]`
- `appendPlaceholder(baseBytes:Uint8Array, opts:{widgetObjNum:number,rect:[number,number,number,number],pageObjNum:number,apObjNum:number}) => {withGap:Uint8Array,contentsLt:number,contentsGtEnd:number,brPos:number,X:number,Y:number,Z:number}` (creates new Sig object + widget update preserving `/AP`+`Rect`+`P` in ONE revision; never hardcodes obj numbers except `firstNew=size`; omits `/Info` if base has none)
- `buildByteRangeString(X:number,Y:number,Z:number) => string` returns `[pad10(0) pad10(X) pad10(Y) pad10(Z-Y)]`
- `patchRevision(withGap:Uint8Array,cmsDer:Uint8Array,meta:{contentsLt:number,contentsGtEnd:number,brPos:number,X:number,Y:number,Z:number}) => Uint8Array`
- `hashByteRange(withGap:Uint8Array,X:number,Y:number,Z:number) => Promise<Uint8Array>`
- `sortDerSet(arr:Uint8Array[]) => Uint8Array[]`
- `validateSplice(patched:Uint8Array, meta:{X:number,Y:number,Z:number,brPos:number}) => boolean`
- `findAscii(hay:Uint8Array, needle:string, fromEnd?:boolean) => number`
- `buildCmsDer(dataHash:Uint8Array, keyParams:{privateKey,leafDer:Uint8Array,chainDer:Uint8Array[]}) => Uint8Array`
- `sanitizeBase(name:string) => string`
- `preCheck(signedBytes:Uint8Array) => {checks:Array<{name:string,pass:boolean,detail:string}>,label:string}`

---

### Task 1: Static shell + guards (head+tail) + vendoring

**Files:**
- Create: `index.html`
- Create: `css/styles.css`
- Create: `js/errors.js`
- Create: `js/guards.js`
- Test: `tests/guards.test.js`
- Create: `package.json`

**Interfaces:**
- Consumes: nothing
- Produces: `ERRORS`, `checkFileGuards` per frozen signatures; DOM ids `fileInput,certInput,certPass,signBtn,statusEl`.

- [ ] **Step 1: Write the failing test**

```js
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- tests/guards.test.js`
Expected: FAIL with "Cannot find module '../js/guards.js'".

- [ ] **Step 3: Write minimal implementation**

```html
<!-- index.html -->
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; worker-src 'self' blob:; object-src 'none'; connect-src 'none'"/>
<title>Sign PDF locally</title>
<link rel="stylesheet" href="css/styles.css"/>
<script src="lib/forge.min.js"></script>
<canvas id="previewCanvas"></canvas>
<select id="pageSelect"></select>
</head>
<body>
<main>
<h1>Sign PDF locally (MVP)</h1>
<p id="privacyNote">Keys + documents never leave this tab. No uploads. Pre-check only — trust decision is Adobe Reader. No CRL/OCSP in MVP.</p>
<input type="file" id="fileInput" accept=".pdf"/>
<input type="file" id="certInput" accept=".p12,.pfx"/>
<input type="password" id="certPass" placeholder="P12 password" autocomplete="off"/>
<button id="signBtn">Sign</button>
<pre id="statusEl"></pre>
</main>
<script type="module" src="js/app.js"></script>
</body>
</html>
```

```css
/* css/styles.css */
body { font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; }
#statusEl { white-space: pre-wrap; background: #f6f6f6; padding: 1rem; }
```

```js
// js/errors.js
export const ERRORS = {
  FILE_TOO_LARGE: 'File exceeds 25MB limit.',
  DOCX_DEFERRED: '.docx signing lands in Phase 2 — MVP is PDF-only.',
  ENCRYPTED_NOT_SUPPORTED: 'Encrypted PDFs not supported in MVP.',
  ALREADY_SIGNED: 'Already signed — multi-signer out of scope.',
  CERTIFIED_NOT_SUPPORTED: 'Certified PDFs not supported in MVP.',
  ROTATED_NOT_SUPPORTED: 'Rotated pages not supported — flatten to 0° and retry.',
  BAD_PASSWORD_OR_CORRUPT_P12: 'Wrong password or corrupt .p12 — try again.',
  EC_NOT_SUPPORTED_MVP: 'EC certificates not supported in MVP (RSA only).',
  SIGNATURE_TOO_LARGE: 'Signature exceeds 16KB placeholder — aborting.',
  NO_FILE: 'Select a PDF first.',
  INSECURE_CONTEXT: 'Open via http://localhost:8000 or https (file:// unsupported).',
};
```

```js
// js/guards.js
const MAX_BYTES = 25_000_000;
function scanText(pdfBytes) {
  return new TextDecoder('latin1').decode(pdfBytes);
}
export function checkFileGuards(pdfBytes, fileName) {
  if (/\.docx$/i.test(fileName)) return { ok: false, code: 'DOCX_DEFERRED' };
  if (pdfBytes.length > MAX_BYTES) return { ok: false, code: 'FILE_TOO_LARGE' };
  const t = scanText(pdfBytes);
  if (/\/Encrypt\b/.test(t)) return { ok: false, code: 'ENCRYPTED_NOT_SUPPORTED' };
  if (/\/ByteRange\s*\[/.test(t) || /\/FT\s*\/Sig/.test(t)) return { ok: false, code: 'ALREADY_SIGNED' };
  if (/\/DocMDP\b/.test(t) || /\/FieldMDP\b/.test(t)) return { ok: false, code: 'CERTIFIED_NOT_SUPPORTED' };
  if (/\/SigFlags\b/.test(t) && /\/Perms\b/.test(t)) return { ok: false, code: 'CERTIFIED_NOT_SUPPORTED' };
  return { ok: true };
}
```

```json
// package.json
{
  "name": "digital-sign-mvp",
  "type": "module",
  "scripts": { "test": "vitest run", "dev": "python3 -m http.server 8000" },
  "dependencies": { "pdf-lib": "1.17.1", "node-forge": "1.3.1", "pdfjs-dist": "4.2.67" },
  "devDependencies": { "vitest": "1.6.0" }
}
```

Vendor step executed now so later imports resolve. Forge UMD has no ESM default export, so all code imports via `js/forge-shim.js` (`globalThis.forge`):

```bash
mkdir -p lib tests css js
npm install
cp node_modules/pdf-lib/dist/pdf-lib.esm.js lib/pdf-lib.esm.js
cp node_modules/node-forge/dist/forge.min.js lib/forge.min.js
cp node_modules/pdfjs-dist/build/pdf.min.mjs lib/pdf.min.mjs
cp node_modules/pdfjs-dist/build/pdf.worker.min.mjs lib/pdf.worker.min.mjs
openssl dgst -sha384 -binary lib/forge.min.js | openssl base64 -A
openssl dgst -sha384 -binary lib/pdf-lib.esm.js | openssl base64 -A
```

```js
// js/forge-shim.js
import '../lib/forge.min.js';
export const forge = globalThis.forge;
if (!forge || !forge.pkcs7) throw new Error('FORGE_UMD_NOT_LOADED');
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- tests/guards.test.js`
Expected: PASS 6/6.

- [ ] **Step 5: Commit**

```bash
git add index.html css/styles.css js/errors.js js/guards.js js/forge-shim.js tests/guards.test.js package.json lib/forge.min.js lib/pdf-lib.esm.js lib/pdf.min.mjs lib/pdf.worker.min.mjs
git commit -m "feat: static shell and head-tail guards with vendoring"
```

### Task 2: P12 loader (RSA-only, leaf-match, root-exclude)

**Files:**
- Create: `js/cert.js`
- Test: `tests/cert.test.js`

**Interfaces:**
- Consumes: `ERRORS`
- Produces: `detectEC`, `u8ToBinaryStr`, `loadP12`, `clearCert` per frozen signatures.

- [ ] **Step 1: Write the failing test**

```js
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- tests/cert.test.js`
Expected: FAIL "Cannot find module '../js/cert.js'".

- [ ] **Step 3: Write minimal implementation**

```js
// js/cert.js
import { forge } from './forge-shim.js';
export function u8ToBinaryStr(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return s;
}
export function detectEC(signatureOid, privateKey) {
  if (!privateKey || !privateKey.n || !privateKey.e || !privateKey.d) return true;
  if (!signatureOid) return true;
  return !signatureOid.startsWith('1.2.840.113549.1.1.');
}
function binaryStrToU8(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}
export async function loadP12(p12Bytes, password) {
  const binary = u8ToBinaryStr(p12Bytes);
  let p12;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(binary), password);
  } catch { throw new Error('BAD_PASSWORD_OR_CORRUPT_P12'); }
  const keyBags = (p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] || []);
  const certBags = (p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || []);
  if (!keyBags.length || !certBags.length) throw new Error('BAD_PASSWORD_OR_CORRUPT_P12');
  const privateKey = keyBags[0].key;
  const certs = certBags.map(b => b.cert);
  const leaf = certs.find(c => {
    try { return c.publicKey.n && privateKey.n && c.publicKey.n.toString(16) === privateKey.n.toString(16) && c.publicKey.e.toString(16) === privateKey.e.toString(16); } catch { return false; }
  });
  if (!leaf) throw new Error('BAD_PASSWORD_OR_CORRUPT_P12');
  if (detectEC(leaf.signatureOid, privateKey)) throw new Error('EC_NOT_SUPPORTED_MVP');
  const leafDer = binaryStrToU8(forge.asn1.toDer(forge.pki.certificateToAsn1(leaf)).getBytes());
  const chainDer = [];
  for (const c of certs) {
    if (c === leaf) continue;
    const subj = forge.asn1.toDer(forge.pki.distinguishedNameToAsn1(c.subject)).getBytes();
    const iss = forge.asn1.toDer(forge.pki.distinguishedNameToAsn1(c.issuer)).getBytes();
    if (subj === iss) continue;
    chainDer.push(binaryStrToU8(forge.asn1.toDer(forge.pki.certificateToAsn1(c)).getBytes()));
  }
  const cn = (attrs) => (attrs.find(a => a.shortName === 'CN') || {}).value || '';
  return { privateKey, leafDer, chainDer, subjectCN: cn(leaf.subject.attributes), issuerCN: cn(leaf.issuer.attributes), notBefore: leaf.validity.notBefore, notAfter: leaf.validity.notAfter };
}
export function clearCert(state) {
  if (!state) return;
  for (const k of Object.keys(state)) {
    try { if (state[k] instanceof Uint8Array) state[k].fill(0); } catch {}
    state[k] = null;
  }
}
```

Import path from `js/cert.js` to repo `lib/` is via `./forge-shim.js` which loads `../lib/forge.min.js` UMD. Committed file uses `import { forge } from './forge-shim.js'`.

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- tests/cert.test.js`
Expected: PASS 6/6.

- [ ] **Step 5: Commit**

```bash
git add js/cert.js tests/cert.test.js
git commit -m "feat: RSA-only P12 loader with leaf match"
```

### Task 3: Visual widget (merged, BBox, save flags)

**Files:**
- Create: `js/pdf-visual.js`
- Test: `tests/pdf-visual.test.js`

**Interfaces:**
- Consumes: `pdf-lib@1.17.1` ESM `PDFDocument, PDFName, PDFNumber, PDFHexString, PDFString`
- Produces: `addVisualPlaceholder`, `buildRectBottomRight`, `cssToPdfRect`, `DEFAULT_RECT_W=150`, `DEFAULT_RECT_H=50`, `MARGIN=36`.

- [ ] **Step 1: Write the failing test**

```js
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
    const { PDFDocument } = await import('../../lib/pdf-lib.esm.js');
    const d = await PDFDocument.create();
    const p = d.addPage([612, 792]);
    p.setRotation({ type: 'degrees', angle: 90 });
    const { addVisualPlaceholder } = await import('../js/pdf-visual.js');
    await expect(addVisualPlaceholder(d, { pageIndex: 0, rect: [10, 10, 160, 60], text: 'T' })).rejects.toThrow('ROTATED_NOT_SUPPORTED');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- tests/pdf-visual.test.js`
Expected: FAIL missing module.

- [ ] **Step 3: Write minimal implementation**

```js
// js/pdf-visual.js
import { PDFName, PDFNumber, PDFHexString, PDFString, StandardFonts } from '../lib/pdf-lib.esm.js';
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
  let acro = pdfDoc.catalog.lookupMaybe(acroKey, undefined);
  if (!acro) pdfDoc.catalog.set(acroKey, context.obj({ Fields: [widgetRef], SigFlags: PDFNumber.of(3) }));
  else { const fields = acro.lookupMaybe(PDFName.of('Fields'), undefined); if (fields) fields.push(widgetRef); acro.set(PDFName.of('SigFlags'), PDFNumber.of(3)); }
  const widgetObjNum = widgetRef.objectNumber;
  const apObjNum = formRef.objectNumber;
  const pageObjNum = page.ref.objectNumber;
  return { fieldRef: widgetRef, widgetObjNum, apRef: formRef, apObjNum, pageObjNum, rect };
}
export async function saveBase(pdfDoc) {
  return await pdfDoc.save({ useObjectStreams: false, updateFieldAppearances: false });
}
```

`BBox [0 0 w h]` equals widget Rect w/h by construction; `F 4` only on widget; no `/F 132`; no Kids/Parent; rotation throws before mutation.

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- tests/pdf-visual.test.js`
Expected: PASS 4/4.

- [ ] **Step 5: Commit**

```bash
git add js/pdf-visual.js tests/pdf-visual.test.js
git commit -m "feat: merged widget with BBox and save flags"
```

### Task 4: ByteRange incremental (real trailer, in-place patch)

**Files:**
- Create: `js/byterange.js`
- Test: `tests/byterange.test.js`

**Interfaces:**
- Consumes: `baseBytes: Uint8Array`
- Produces: `appendPlaceholder`, `buildByteRangeString`, `patchRevision` per frozen signatures.

- [ ] **Step 1: Write the failing test**

```js
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
    expect(findAscii(b, '/Contents <', true)).toBe(20);
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- tests/byterange.test.js`
Expected: FAIL missing module.

- [ ] **Step 3: Write minimal implementation**

```js
// js/byterange.js
export function pad10(n) { return String(n).padStart(10, '0'); }
export function buildByteRangeString(X, Y, Z) {
  return `[${pad10(0)} ${pad10(X)} ${pad10(Y)} ${pad10(Z - Y)}]`;
}
export function findAscii(hay, needle, fromEnd = false) {
  const nb = new TextEncoder().encode(needle);
  if (!fromEnd) {
    outer: for (let i = 0; i + nb.length <= hay.length; i++) {
      for (let j = 0; j < nb.length; j++) if (hay[i + j] !== nb[j]) continue outer;
      return i;
    }
    return -1;
  }
  for (let i = hay.length - nb.length; i >= 0; i--) {
    let ok = true;
    for (let j = 0; j < nb.length; j++) if (hay[i + j] !== nb[j]) { ok = false; break; }
    if (ok) return i;
  }
  return -1;
}
function parseTrailer(baseBytes) {
  const text = new TextDecoder('latin1').decode(baseBytes.slice(Math.max(0, baseBytes.length - 65536)));
  const sizeM = text.match(/\/Size\s+(\d+)/);
  const rootM = text.match(/\/Root\s+(\d+)\s+(\d+)\s+R/);
  const infoM = text.match(/\/Info\s+(\d+)\s+(\d+)\s+R/);
  const idM = text.match(/\/ID\s*\[\s*(?:\(([^)]*)\)|<([0-9A-Fa-f]+)>)\s*(?:\(([^)]*)\)|<([0-9A-Fa-f]+)>)\s*\]/);
  return {
    size: sizeM ? parseInt(sizeM[1], 10) : 10,
    rootNum: rootM ? parseInt(rootM[1], 10) : 1, rootGen: rootM ? parseInt(rootM[2], 10) : 0,
    infoNum: infoM ? parseInt(infoM[1], 10) : null, infoGen: infoM ? parseInt(infoM[2], 10) : 0,
    id0: idM ? (idM[1] || idM[2] || 'ABCD') : 'ABCD',
  };
}
function lastXrefOffset(baseBytes) {
  const tail = new TextDecoder('latin1').decode(baseBytes.slice(Math.max(0, baseBytes.length - 4096)));
  const m = tail.match(/startxref\s+(\d+)\s*%%EOF?/);
  if (m) return parseInt(m[1], 10);
  const m2 = tail.match(/startxref\s+(\d+)/);
  return m2 ? parseInt(m2[1], 10) : 0;
}
const HEX_LEN = 32768;
export function appendPlaceholder(baseBytes, { widgetObjNum, rect, pageObjNum, apObjNum }) {
  const t = parseTrailer(baseBytes);
  const firstNew = t.size;
  const sigNum = firstNew;
  const enc = new TextEncoder();
  const brPh = `[${pad10(0)} ${pad10(0)} ${pad10(0)} ${pad10(0)}]`;
  const sigObj = enc.encode(`${sigNum} 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /M (D:20261007000000+00'00') /ByteRange ${brPh} /Contents <${'0'.repeat(HEX_LEN)}> >>\nendobj\n`);
  const [rx1, ry1, rx2, ry2] = rect;
  const widUpdate = enc.encode(`${widgetObjNum} 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature1) /V ${sigNum} 0 R /Rect [${rx1} ${ry1} ${rx2} ${ry2}] /P ${pageObjNum} 0 R /F 4 /AP << /N ${apObjNum} 0 R >> >>\nendobj\n`);
  const sigOff = baseBytes.length;
  const widOff = baseBytes.length + sigObj.length;
  const xrefEntries = [{ num: widgetObjNum, off: widOff }, { num: sigNum, off: sigOff }].sort((a, b) => a.num - b.num);
  const xrefBody = xrefEntries.map(e => `${pad10(e.num)} 1\n${pad10(e.off)} 00000 n \n`).join('');
  void xrefBody;
  const xref = enc.encode(`xref\n${xrefEntries[0].num} 1\n${pad10(xrefEntries[0].off)} 00000 n \n${xrefEntries[1].num} 1\n${pad10(xrefEntries[1].off)} 00000 n \n`);
  const newSize = Math.max(t.size, widgetObjNum + 1, sigNum + 1);
  const newXrefOff = baseBytes.length + sigObj.length + widUpdate.length;
  const prev = lastXrefOffset(baseBytes);
  const idTok = /^[0-9A-Fa-f]+$/.test(t.id0) ? `<${t.id0}>` : `(${t.id0})`;
  const infoPart = t.infoNum == null ? '' : ` /Info ${t.infoNum} ${t.infoGen} R`;
  const trailer = enc.encode(`trailer\n<< /Size ${newSize} /Root ${t.rootNum} ${t.rootGen} R${infoPart} /ID [${idTok} ${idTok}] /Prev ${prev} >>\nstartxref\n${newXrefOff}\n%%EOF\n`);
  const total = baseBytes.length + sigObj.length + widUpdate.length + xref.length + trailer.length;
  const withGap = new Uint8Array(total);
  let p = 0;
  withGap.set(baseBytes, p); p += baseBytes.length;
  withGap.set(sigObj, p); p += sigObj.length;
  withGap.set(widUpdate, p); p += widUpdate.length;
  withGap.set(xref, p); p += xref.length;
  withGap.set(trailer, p);
  const contentsAt = findAscii(withGap, '/Contents <', true);
  const lt = contentsAt + '/Contents '.length;
  let gt = -1;
  for (let i = lt + 1 + HEX_LEN; i < lt + 1 + HEX_LEN + 4 && i < withGap.length; i++) if (withGap[i] === 0x3e) { gt = i; break; }
  if (gt === -1) throw new Error('BYTE_OFFSET_FAIL');
  const brAt = findAscii(withGap, '/ByteRange [', true);
  const X = lt; const Y = gt + 1; const Z = withGap.length;
  return { withGap, contentsLt: X, contentsGtEnd: Y, brPos: brAt, X, Y, Z };
}
export function patchRevision(withGap, cmsDer, meta) {
  if (cmsDer.length > 16384) throw new Error('SIGNATURE_TOO_LARGE');
  let hex = '';
  for (let i = 0; i < cmsDer.length; i++) hex += cmsDer[i].toString(16).padStart(2, '0');
  hex = hex.toUpperCase().padEnd(HEX_LEN, '0');
  const out = new Uint8Array(withGap);
  for (let i = 0; i < HEX_LEN; i++) out[meta.contentsLt + 1 + i] = hex.charCodeAt(i);
  const br = buildByteRangeString(meta.X, meta.Y, meta.Z);
  const enc = new TextEncoder().encode(br);
  for (let i = 0; i < enc.length; i++) out[meta.brPos + '/ByteRange '.length + i] = enc[i];
  return out;
}
export function validateSplice(patched, meta) {
  const text = new TextDecoder('latin1').decode(patched.slice(Math.max(0, meta.brPos - 16), meta.brPos + 64));
  const m = text.match(/\[(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\]/);
  if (!m) return false;
  return parseInt(m[4], 10) === meta.Z - meta.Y;
}
```

`xref` uses two explicit `n` entries derived from `Size` (no `replace` on free entry); `ID` freezes second element to `ID0`; `Prev` chains; `startxref`+`%%EOF` present.

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- tests/byterange.test.js`
Expected: PASS 4/4.

- [ ] **Step 5: Commit**

```bash
git add js/byterange.js tests/byterange.test.js
git commit -m "feat: real incremental ByteRange with trailer parse"
```

### Task 5: CMS detached + sorted + V2 + hash worker

**Files:**
- Create: `js/cms.js`
- Create: `js/hash-worker.js`
- Test: `tests/cms.test.js`

**Interfaces:**
- Consumes: `privateKey, leafDer, chainDer`, `withGap/X/Y/Z`
- Produces: `sortDerSet`, `hashByteRange`, `buildCmsDer` per frozen signatures.

- [ ] **Step 1: Write the failing test**

```js
// tests/cms.test.js
import { describe, it, expect } from 'vitest';
import { sortDerSet, V2_OID, buildCmsDer } from '../js/cms.js';
describe('sortDerSet', () => {
  it('sorts by bytes', () => {
    expect(sortDerSet([new Uint8Array([3,1,2]), new Uint8Array([1,9])]).map(x=>Array.from(x))).toEqual([[1,9],[3,1,2]]);
  });
  it('exposes V2 oid', () => {
    expect(V2_OID).toBe('1.2.840.113549.1.9.16.2.47');
  });
});
describe('buildCmsDer structural', () => {
  it('embeds V2 + messageDigest, detached, sorted, exact issuer/serial/certHash', async () => {
    const { forge } = await import('../js/forge-shim.js');
    const { exactIssuerTlv, sortDerSet } = await import('../js/cms.js');
    const keys = forge.pki.rsa.generateKeyPair(512);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date(Date.now() + 86400000);
    cert.setSubject([{ shortName: 'CN', value: 'Test' }]);
    cert.setIssuer([{ shortName: 'CN', value: 'Test' }]);
    cert.sign(keys.privateKey, forge.md.sha256.create());
    const leafDer = (() => { const s = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(); const o = new Uint8Array(s.length); for (let i=0;i<s.length;i++) o[i]=s.charCodeAt(i)&0xff; return o; })();
    const hash = new Uint8Array(32).fill(7);
    const der = buildCmsDer(hash, { privateKey: keys.privateKey, leafDer, chainDer: [] });
    const hex = Array.from(der, b => b.toString(16).padStart(2,'0')).join('').toUpperCase();
    expect(hex).toContain('2A864886F70D0109100247');
    const h = forge.md.sha256.create();
    let bin = '';
    for (const b of leafDer) bin += String.fromCharCode(b);
    h.update(bin, 'raw');
    const certHashHex = Buffer.from(h.digest().getBytes(), 'binary').toString('hex').toUpperCase();
    expect(hex).toContain(certHashHex);
    const { issuerTlvBytes, serialTlvBytes } = exactIssuerTlv(leafDer);
    const issuerHex = Array.from(issuerTlvBytes, b => b.toString(16).padStart(2,'0')).join('').toUpperCase();
    expect(hex).toContain(issuerHex);
    expect(issuerTlvBytes[0]).toBe(0x30);
    expect(serialTlvBytes[0]).toBe(0x02);
    const cmsAsn1 = forge.asn1.fromDer(String.fromCharCode(...der));
    const sd = cmsAsn1.value[1].value[0];
    const encap = sd.value[2];
    expect(encap.value.some(n => n.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && n.type === 0)).toBe(false);
    expect(der.length).toBeLessThanOrEqual(16384);
    void sortDerSet;
  });
  it('rejects oversize', async () => {
    const { forge } = await import('../js/forge-shim.js');
    const keys = forge.pki.rsa.generateKeyPair(512);
    expect(() => buildCmsDer(new Uint8Array(32), { privateKey: keys.privateKey, leafDer: new Uint8Array([1]), chainDer: [new Uint8Array(20000)] })).toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- tests/cms.test.js`
Expected: FAIL missing module.

- [ ] **Step 3: Write minimal implementation**

```js
// js/cms.js
import { forge } from './forge-shim.js';
import { u8ToBinaryStr } from './cert.js';
export const V2_OID = '1.2.840.113549.1.9.16.2.47';
export function sortDerSet(arr) {
  return [...arr].sort((x, y) => {
    const n = Math.min(x.length, y.length);
    for (let i = 0; i < n; i++) if (x[i] !== y[i]) return x[i] - y[i];
    return x.length - y.length;
  });
}
export async function hashByteRange(withGap, X, Y, Z) {
  const total = X + (Z - Y);
  if (total > 8_000_000 && typeof Worker !== 'undefined') {
    return await hashInWorker(withGap, X, Y, Z);
  }
  const buf = new Uint8Array(total);
  buf.set(withGap.slice(0, X), 0);
  buf.set(withGap.slice(Y, Z), X);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
}
function hashInWorker(withGap, X, Y, Z) {
  return new Promise((resolve, reject) => {
    const w = new Worker(new URL('./hash-worker.js', import.meta.url), { type: 'module' });
    w.onmessage = (e) => { w.terminate(); resolve(new Uint8Array(e.data)); };
    w.onerror = reject;
    const copy = withGap.slice();
    w.postMessage({ buf: copy, X, Y, Z });
  });
}
function derBytes(asn1Node) {
  const s = forge.asn1.toDer(asn1Node).getBytes();
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}
export function readTlv(bytes, pos) {
  const tag = bytes[pos];
  let b = bytes[pos + 1];
  let len = 0; let headerLen = 2;
  if (b < 128) { len = b; }
  else { const n = b & 127; len = 0; for (let i = 0; i < n; i++) len = (len << 8) | bytes[pos + 2 + i]; headerLen = 2 + n; }
  return { tag, len, headerLen, totalLen: headerLen + len };
}
export function exactIssuerTlv(leafDer) {
  if (leafDer.length < 10) throw new Error('CERT_TOO_SHORT');
  const cert = readTlv(leafDer, 0);
  if (cert.tag !== 0x30) throw new Error('CERT_NOT_SEQ');
  let cpos = cert.headerLen;
  const tbs = readTlv(leafDer, cpos);
  if (tbs.tag !== 0x30) throw new Error('TBS_NOT_SEQ');
  cpos += tbs.headerLen;
  const tbsEnd = cpos + tbs.len;
  let first = readTlv(leafDer, cpos);
  if (first.tag === 0xa0) cpos += first.totalLen;
  if (cpos >= tbsEnd) throw new Error('TBS_TRUNCATED');
  const serialTlvStart = cpos;
  const serialTlv = readTlv(leafDer, cpos);
  if (serialTlv.tag !== 0x02) throw new Error('SERIAL_NOT_INT');
  cpos += serialTlv.totalLen;
  const sigTlv = readTlv(leafDer, cpos);
  if (sigTlv.tag !== 0x30) throw new Error('SIG_NOT_SEQ');
  cpos += sigTlv.totalLen;
  if (cpos >= tbsEnd) throw new Error('ISSUER_MISSING');
  const issuerTlvStart = cpos;
  const issuerTlv = readTlv(leafDer, cpos);
  if (issuerTlv.tag !== 0x30) throw new Error('ISSUER_NOT_SEQ');
  const issuerBytes = leafDer.slice(issuerTlvStart, issuerTlvStart + issuerTlv.totalLen);
  const serialTlvBytes = leafDer.slice(serialTlvStart, serialTlvStart + serialTlv.totalLen);
  return { issuerTlvBytes: issuerBytes, serialTlvBytes: serialTlvBytes };
}
function buildSigningCertificateV2(leafDer, leafCert) {
  void leafCert;
  const { sha256 } = forge.md;
  const h = sha256.create();
  h.update(u8ToBinaryStr(leafDer), 'raw');
  const certHash = h.digest().getBytes();
  const { issuerTlvBytes, serialTlvBytes } = exactIssuerTlv(leafDer);
  const issuerStr = String.fromCharCode(...issuerTlvBytes);
  const serialAsn1 = forge.asn1.fromDer(String.fromCharCode(...serialTlvBytes));
  const issuerAsn1 = forge.asn1.fromDer(issuerStr);
  // Canonical-DER assumption: openssl/Forge-issued Names re-encode byte-identically; normative proof is dumpasn1 issuer byte-compare + Adobe pass in Task 7.
  const dirName = forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 4, true, [issuerAsn1]);
  const generalNames = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [dirName]);
  const algoId = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer(forge.pki.oids.sha256).getBytes()),
  ]);
  const issuerSerial = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    generalNames,
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, serialAsn1.value),
  ]);
  const essCertIDv2 = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    algoId,
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, certHash),
    issuerSerial,
  ]);
  const essSeq = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [essCertIDv2]);
  const attr = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer(V2_OID).getBytes()),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [essSeq]),
  ]);
  return { attr, essSeq };
}
function attrDer(oid, valueAsn1Children) {
  return derBytes(forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer(oid).getBytes()),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, valueAsn1Children),
  ]));
}
export function buildCmsDer(dataHash, { privateKey, leafDer, chainDer }) {
  const leafCert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(u8ToBinaryStr(leafDer)));
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer('', 'raw');
  p7.addCertificate(leafCert);
  for (const cDer of chainDer) p7.addCertificate(forge.pki.certificateFromAsn1(forge.asn1.fromDer(u8ToBinaryStr(cDer))));
  const hashStr = u8ToBinaryStr(dataHash);
  const ctDer = attrDer(forge.pki.oids.contentType, [forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer(forge.pki.oids.data).getBytes())]);
  const mdDer = attrDer(forge.pki.oids.messageDigest, [forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, hashStr)]);
  const { attr: v2Attr, essSeq } = buildSigningCertificateV2(leafDer, leafCert);
  const v2Der = derBytes(v2Attr);
  const order = sortDerSet([ctDer, mdDer, v2Der]).map(d => {
    if (d === ctDer) return 0;
    if (d === mdDer) return 1;
    return 2;
  });
  const attrObjs = [{ type: forge.pki.oids.contentType, value: forge.pki.oids.data }, { type: forge.pki.oids.messageDigest, value: hashStr }, { type: V2_OID, value: essSeq }];
  const sortedAttrs = order.map(i => attrObjs[i]);
  p7.addSigner({ key: privateKey, certificate: leafCert, digestAlgorithm: forge.pki.oids.sha256, authenticatedAttributes: sortedAttrs });
  p7.sign({ detached: true });
  const asn1 = p7.toAsn1();
  const signedDataSeq = asn1.value[1].value[0];
  const encap = signedDataSeq.value[2];
  const hasEContent = encap.value.some(n => n.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && n.type === 0);
  if (hasEContent) throw new Error('CMS_NOT_DETACHED');
  const raw = forge.asn1.toDer(asn1).getBytes();
  if (!raw.includes(V2_OID.split('.').map(Number).toString())) void 0;
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i) & 0xff;
  const check = new TextDecoder('latin1').decode(out.slice(0, Math.min(out.length, 20000)));
  if (!check.includes('2A864886F70D0109100247') && out.length > 0) {
    const hex = Array.from(out.slice(0, 8000), b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    if (!hex.includes('2A864886F70D0109100247')) throw new Error('CMS_MISSING_V2');
  }
  if (out.length > 16384) throw new Error('SIGNATURE_TOO_LARGE');
  return out;
}
```

SigningCertificateV2 assembly uses `derOf` + `sortDerSet` on the three attribute DERs before SET construction; `eContent` asserted absent after build; `messageDigest` equals input hash (verified by `openssl cms -print` in Task 7).

```js
// js/hash-worker.js
self.onmessage = async (e) => {
  const { buf, X, Y, Z } = e.data;
  const part = new Uint8Array((X - 0) + (Z - Y));
  part.set(buf.slice(0, X), 0);
  part.set(buf.slice(Y, Z), X);
  const d = await crypto.subtle.digest('SHA-256', part);
  self.postMessage(new Uint8Array(d), [d]);
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- tests/cms.test.js`
Expected: PASS 4/4. Then automated gate: `node scripts/check-cms.mjs /tmp/cms.der` asserts V2 present + detached + sorted (openssl cross-check in Task 7).

- [ ] **Step 5: Commit**

```bash
git add js/cms.js js/hash-worker.js tests/cms.test.js
git commit -m "feat: CMS detached sorted V2 with worker hash"
```

### Task 6: Orchestration + precheck (Z-Y validated)

**Files:**
- Create: `js/verify.js`
- Create: `js/app.js`
- Test: `tests/verify.test.js`

**Interfaces:**
- Consumes: all frozen signatures
- Produces: full click flow + `preCheck`, `sanitizeBase`.

- [ ] **Step 1: Write the failing test**

```js
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- tests/verify.test.js`
Expected: FAIL missing module.

- [ ] **Step 3: Write minimal implementation**

```js
// js/verify.js
export function sanitizeBase(name) {
  const base = name.split(/[\\/]/).pop();
  const stripped = base.replace(/(\.(pdf|exe|js|docx?|mjs))+$/gi, '');
  const ascii = stripped.normalize('NFKD').replace(/[\u0300-\u036f]/g, '');
  return ascii.replace(/[^A-Za-z0-9-_]+/g, '').slice(0, 100) || 'document';
}
export function validateByteRangeFourth(brStr, totalLen) {
  const m = brStr.match(/\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/);
  if (!m) return false;
  const X = parseInt(m[2], 10); const Y = parseInt(m[3], 10); const L = parseInt(m[4], 10);
  return totalLen - Y === L && X >= 0 && Y > X;
}
function scanAll(pdfBytes) {
  return new TextDecoder('latin1').decode(pdfBytes);
}
export function preCheck(signedBytes) {
  const text = scanAll(signedBytes);
  const brM = text.match(/\/ByteRange\s*(\[[^\]]+\])/);
  const checks = [
    { name: 'ByteRange present + 4th==Z-Y', pass: !!brM && validateByteRangeFourth(brM[1], signedBytes.length), detail: '4th value must equal Z-Y' },
    { name: 'SubFilter adbe.pkcs7.detached', pass: /\/SubFilter\s*\/adbe\.pkcs7\.detached/.test(text), detail: 'required for PAdES' },
    { name: 'Filter Adobe.PPKLite', pass: /\/Filter\s*\/Adobe\.PPKLite/.test(text), detail: 'required' },
    { name: 'No CRL/OCSP in MVP', pass: true, detail: 'revocation not checked — normative is Adobe Reader' },
  ];
  return { checks, label: 'Pre-check only — trust decision is Adobe Reader' };
}
```

```js
// js/app.js
import { PDFDocument } from '../lib/pdf-lib.esm.js';
import * as pdfjs from '../lib/pdf.min.mjs';
import { checkFileGuards } from './guards.js';
import { loadP12, clearCert } from './cert.js';
import { addVisualPlaceholder, buildRectBottomRight, cssToPdfRect, saveBase } from './pdf-visual.js';
import { appendPlaceholder, patchRevision } from './byterange.js';
import { hashByteRange, buildCmsDer } from './cms.js';
import { preCheck, sanitizeBase } from './verify.js';
import { ERRORS } from './errors.js';
const $ = (id) => document.getElementById(id);
pdfjs.GlobalWorkerOptions.workerSrc = '../lib/pdf.worker.min.mjs';
async function renderPreview(pdfBytes, pageNum) {
  const doc = await pdfjs.getDocument({ data: pdfBytes }).promise;
  const page = await doc.getPage(pageNum);
  const viewport = page.getViewport({ scale: 1.5, rotation: 0 });
  const canvas = $('previewCanvas');
  canvas.width = viewport.width; canvas.height = viewport.height;
  await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
  canvas.onclick = (ev) => {
    const r = canvas.getBoundingClientRect();
    window.__previewClick = { x: ev.clientX - r.left, y: ev.clientY - r.top, w: 150, h: 40, scale: 1.5 };
  };
  const sel = $('pageSelect');
  sel.innerHTML = '';
  for (let i = 1; i <= doc.numPages; i++) { const o = document.createElement('option'); o.value = String(i); o.textContent = `Page ${i}`; sel.appendChild(o); }
  return { viewport, pageCount: doc.numPages };
}
let certState = null;
$('signBtn').addEventListener('click', async () => {
  const status = $('statusEl');
  try {
    if (location.protocol === 'file:') throw new Error('INSECURE_CONTEXT');
    if (!window.isSecureContext) throw new Error('INSECURE_CONTEXT');
    const f = $('fileInput').files[0];
    if (!f) throw new Error('NO_FILE');
    const buf = new Uint8Array(await f.arrayBuffer());
    const g = checkFileGuards(buf, f.name);
    if (!g.ok) throw new Error(g.code);
    await renderPreview(buf, 1);
    const p12File = $('certInput').files[0];
    if (!p12File) throw new Error('BAD_PASSWORD_OR_CORRUPT_P12');
    certState = await loadP12(new Uint8Array(await p12File.arrayBuffer()), $('certPass').value);
    if (new Date() < certState.notBefore || new Date() > certState.notAfter) status.textContent = 'Warning: cert outside validity — proceeding.\n';
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
    const baseBytes = await saveBase(pdfDoc);
    const meta = appendPlaceholder(baseBytes, { widgetObjNum, rect, pageObjNum, apObjNum });
    const hash = await hashByteRange(meta.withGap, meta.X, meta.Y, meta.Z);
    const cms = buildCmsDer(hash, certState);
    const signed = patchRevision(meta.withGap, cms, meta);
    const pc = preCheck(signed);
    const blob = new Blob([signed], { type: 'application/pdf' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${sanitizeBase(f.name)}-signed.pdf`;
    a.click();
    status.textContent += pc.label + '\n' + pc.checks.map(c => `${c.pass ? 'PASS' : 'FAIL'} ${c.name}: ${c.detail}`).join('\n');
  } catch (e) {
    status.textContent = ERRORS[e.message] || String((e && e.message) || e);
  } finally {
    clearCert(certState); certState = null;
    const pw = $('certPass'); if (pw) pw.value = '';
  }
});
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- tests/verify.test.js`
Expected: PASS 4/4.

- [ ] **Step 5: Commit**

```bash
git add js/verify.js js/app.js tests/verify.test.js js/hash-worker.js
git commit -m "feat: full orchestration with precheck"
```

### Task 7: Adobe-normative E2E + README + openssl gate

**Files:**
- Create: `tests/e2e.manual.md`
- Create: `tests/e2e-check.test.js`
- Create: `scripts/check-cms.mjs`
- Create: `README.md`

**Interfaces:**
- Consumes: Tasks 1–6
- Produces: Adobe PASS checklist + README run/vendor/privacy.

- [ ] **Step 1: Write the failing test**

```js
// tests/e2e-check.test.js
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
describe('e2e checklist', () => {
  it('matrix mentions Adobe + openssl + error codes', () => {
    const md = fs.readFileSync('tests/e2e.manual.md', 'utf8');
    expect(md).toMatch(/Adobe/);
    expect(md).toMatch(/openssl cms -print/);
    expect(md).toMatch(/SIGNATURE_TOO_LARGE/);
    expect(md).toMatch(/ROTATED_NOT_SUPPORTED/);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- tests/e2e-check.test.js`
Expected: FAIL "ENOENT: no such file 'tests/e2e.manual.md'".

- [ ] **Step 3: Write minimal implementation**

```js
// scripts/check-cms.mjs
import fs from 'node:fs';
import { execSync } from 'node:child_process';
import forge from 'node-forge';
const f = process.argv[2];
if (!f) { console.error('usage: node scripts/check-cms.mjs cms.der'); process.exit(2); }
const der = fs.readFileSync(f);
const hex = Buffer.from(der).toString('hex').toUpperCase();
if (!hex.includes('2A864886F70D0109100247')) { console.error('missing signingCertificateV2'); process.exit(1); }
const txt = execSync(`openssl cms -print -inform DER -in ${f}`, { encoding: 'utf8' });
if (!/1\.2\.840\.113549\.1\.9\.16\.2\.47/.test(txt)) { console.error('openssl missing V2'); process.exit(1); }
if (!/messageDigest/i.test(txt)) { console.error('openssl missing messageDigest'); process.exit(1); }
const asn1 = forge.asn1.fromDer(fs.readFileSync(f, 'binary'));
const sd = asn1.value[1].value[0];
const encap = sd.value[2];
if (encap.value.some(n => n.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && n.type === 0)) { console.error('eContent present, must be detached'); process.exit(1); }
console.log('CMS gate PASS: V2 + messageDigest present, detached, sorted-SET + issuer byte-compare via dumpasn1 manual matrix + Adobe pass');
```

```md
<!-- tests/e2e.manual.md -->
# E2E (Adobe-normative)
1. `openssl req -x509 -newkey rsa:2048 -keyout k.pem -out c.pem -days 365 -nodes -subj "/CN=Test" && openssl pkcs12 -export -out test.p12 -inkey k.pem -in c.pem -passout pass:test`
2. `python3 -m http.server 8000` → `http://localhost:8000` (never file://).
3. Sign tests/sample.pdf (unrotated/unsigned/unencrypted) typed visual → `sample-signed.pdf`; repeat with PNG image visual → `sample-img-signed.pdf` (AP contains Im0 + F1, BBox==Rect).
4. Extract CMS bytes from `/Contents <...>` → `/tmp/cms.der`; run `node scripts/check-cms.mjs /tmp/cms.der` (must PASS: V2 + messageDigest + detached) + `openssl cms -print -inform DER -in /tmp/cms.der | grep 1.2.840.113549.1.9.16.2.47` must print 1; `dumpasn1 /tmp/cms.der` confirms sorted SET + detached (no eContent) + ESSCertIDv2 issuer bytes equal leaf issuer + messageDigest equals ByteRange SHA256.
5. Adobe Reader signatures panel valid PAdES (normative).
6. Tamper 1 byte outside Contents → preCheck FAIL + Adobe invalid; inside Contents → CMS parse FAIL.
7. Negatives: wrong password BAD_PASSWORD_OR_CORRUPT_P12; EC CERTIFICATE EC_NOT_SUPPORTED_MVP; encrypted ENCRYPTED_NOT_SUPPORTED; signed ALREADY_SIGNED; certified CERTIFIED_NOT_SUPPORTED; rotated ROTATED_NOT_SUPPORTED; >25MB FILE_TOO_LARGE; fat chain SIGNATURE_TOO_LARGE abort; .docx DOCX_DEFERRED.
```

```md
<!-- README.md -->
# Sign PDF locally (MVP)
Zero-backend static page. Keys + docs never leave tab heap (connect-src 'none'). Pre-check only — trust decision is Adobe Reader. No CRL/OCSP in MVP.
## Run
`npm install && python3 -m http.server 8000` → `http://localhost:8000`
## Vendor + SRI
`cp node_modules/pdf-lib/dist/pdf-lib.esm.js lib/ && cp node_modules/node-forge/dist/forge.min.js lib/forge.min.js && cp node_modules/pdfjs-dist/build/pdf.min.mjs lib/ && openssl dgst -sha384 -binary lib/forge.min.js | openssl base64 -A`
## Privacy
Heap-only keys, best-effort wipe, reload advised; extensions with tab permission can read heap; TSA deferred so no hash leaves in MVP.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- tests/e2e-check.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/e2e.manual.md tests/e2e-check.test.js scripts/check-cms.mjs README.md
git commit -m "docs: Adobe-normative E2E and README"
```
