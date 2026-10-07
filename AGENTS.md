# AGENTS.md — LocalSign

Static, zero-backend web app: sign PDFs in-browser with your own X.509
certificate (PAdES B-B). Private keys and document bytes never leave the tab.

## Quick start

- Serve: `python3 -m http.server 8000` → `http://localhost:8000` (never `file://`)
- Test: `npm test` (vitest, must stay green)
- Full cryptographic gate: sign in the browser, then
  `node scripts/check-cms.mjs /tmp/cms.der` + Adobe Reader (normative)

## Architecture (static files only, no build step)

- `index.html` — shell (valid HTML: no interactive elements in `<head>`), CSP
  `connect-src 'none'`, classic forge script + `js/app.js` module
- `js/guards.js` — intake rejects (full-file scan): docx, >25MB, encrypted,
  already-signed, certified
- `js/cert.js` — RSA-only P12 loader (fail-closed `detectEC`), heap-only keys
- `js/pdf-visual.js` — low-level merged AcroForm field+widget + AP stream;
  pure helpers: `buildRectBottomRight`, `cssToPdfRect`, `escapePdfText`,
  `normalizeDrag`
- `js/byterange.js` — manual incremental update; `appendPlaceholder` →
  `patchByteRange` → hash → `buildCmsDer` → `patchContents`
- `js/cms.js` — detached CMS with `signingCertificateV2`, DER-sorted SET
- `js/app.js` — orchestration, pdf.js preview, drag-select, staged status
- `lib/` — vendored UMD/ESM (forge UMD has NO exports: load only via
  `js/forge-shim.js` dynamic import; never static-import it)
- `assets/` — brand (see `assets/brand.md` for palette/usage rules)
- `tests/` — vitest; `scripts/check-cms.mjs` — openssl CMS gate

## Invariants (do not break)

1. **PAdES order:** final `ByteRange` values are written BEFORE hashing
   (they live inside the hashed region). See `patchByteRange` + regression test.
2. **Mapping:** preview px → PDF points is `1/scale` (pdf.js is linear);
   `toCanvas` excludes the canvas border and compensates CSS scaling.
3. **`lookupMaybe` needs a real class** (`PDFDict`/`PDFArray`) — never
   `undefined`; fails only when the key exists (e.g. pre-existing AcroForm).
4. **Same-origin network only:** browser may call same-origin `/ocsp`
   (allowlisted OCSP/TSA responders: serials/hashes only, never keys/docs);
   no other `fetch`/workers-to-remote; CSP is `connect-src 'self'`.
5. **RSA-only, `/Rotate 0`-only, PDF-only MVP** — reject others with the
   matching `ERRORS` code, don't attempt support silently.

## Rules

- Never commit `*.p12`, `*.pfx`, `*.pem`, `*.key`, or signed outputs with real
  certs. Scratch fixtures go in gitignored dirs and are deleted after use.
- Keep `npm test` green; crypto changes also need the openssl gate + Adobe check.
- Browser-verify UI changes with DevTools (screenshot + console) before pushing.
- Docs live in `docs/`; brand rules in `assets/brand.md` win on visual questions.
