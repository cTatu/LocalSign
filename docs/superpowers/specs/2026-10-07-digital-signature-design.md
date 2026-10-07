# Digital Signature Webservice — Design Spec (v4, R1–R5 fixes)
Date: 2026-10-07
Status: Revised after skeptical review v3 — awaiting re-review
Location: `/Users/ctatu/digital_sign_doc`

## 1. Goal & MVP boundary
Sign PDFs in a static webpage (visual + PAdES B-B cryptographic proof), keys + document bytes never leave tab heap. MVP: PDF-only, RSA-only, Forge-parse + Forge-RSA-sign with WebCrypto-digest exception (§4.4), zero network (`connect-src 'none'`), Adobe Reader as normative gate. DOCX + TSA (B-T) deferred to Phase 2.

## 2. Pinned stack
- `pdf-lib@1.17.1` low-level only (`PDFContext`, `PDFDict`, `PDFHexString`, `PDFName`, `PDFNumber`, `PDFRef`) — high-level form API has NO Sig support. `useObjectStreams:false` on every save (else manual xref patch impossible on XRef streams). `updateFieldAppearances:false`.
- `node-forge@1.3.1` — P12 parse + CMS build + RSA sign only. Hashing exception: ByteRange SHA-256 via `crypto.subtle.digest` (no key material, privacy preserved); Forge `md.sha256` only as fallback with Worker.
- `pdf.js@4.2.67` preview. Phase 2: `jszip@3.10.1` + xmldsig stack; TSA client deferred.

## 3. PDF visual appearance (low-level; R1 fix: single merged field+widget)
- Build via `context`: ONE merged field+widget object (no separate field dict, no duplicate /T): `<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature1) /V <sigRef> /Rect [x y x+150 y+50] /P <pageRef> /F 4 /AP << /N <apRef> >> >>`. `F 4` (print) lives ONLY on this widget. Append its ref to page `Annots` AND to `AcroForm.Fields` (merge, never overwrite), set `SigFlags 3`. No `/Kids`/`/Parent` split in MVP. No `/F 132` anywhere.
- Sig value dict `<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange [...] /Contents <...> /M (D:...) >>` as DIRECT objects (ByteRange/Contents never indirect refs).
- AP Form XObject: `<< /Type /XObject /Subtype /Form /BBox [0 0 150 50] /Matrix [1 0 0 1 0 0] /Resources << /XObject << /Im0 <imgRef> >> /Font << /F1 <fontRef> >> >> >>` + content stream drawing border + text/image. `BBox` w/h MUST equal Widget Rect w/h or appearance distorts.
- `/M` uses PDF-date `D:YYYYMMDDHHmmSS+TZ`, plus visible string labeled "client clock, unverified". CMS `signingTime` stays ISO8601 UTC with same label.
- Positioning: `pdfX = cropX + cssX*72/(96*scale)`; `pdfY = cropY + cropH - (cssY+cssH)*72/(96*scale)` (y-flip). Use `CropBox||MediaBox`. MVP: `/Rotate 0` ONLY — if page `/Rotate ∈ {90,180,270}` → reject `ROTATED_NOT_SUPPORTED` ("rotate/flatten PDF to 0° and retry; rotated support in Phase 2"). Render preview with PDF.js `viewport.rotation = 0` so no double-count. Default: last page bottom-right 150×50pt, 36pt margins; clamp/shrink if page < 222×122pt.
- EC detect: `signatureOid ∉ 1.2.840.113549.1.1.*` OR missing `privateKey.n/e/d` → `EC_NOT_SUPPORTED_MVP`.

## 4. Incremental ByteRange + CMS (R2/R3/R4 fixes: lengths, trailer, chain)
- Phase 1: pdf-lib save visual-only → `baseBytes` (`useObjectStreams:false`). Record old xref offset, `ID`, `Info` ref, `Root` ref, `Size`.
- Phase 2: append ONE revision containing BOTH: (a) updated merged field/widget object (adds `/V <sigRef>` + `/AP`), (b) new sig value object (indirect object; its `/ByteRange` + `/Contents` keys are DIRECT inline, never indirect refs) with placeholder `/ByteRange [0000000000 0000000000 0000000000 0000000000]` (all four 10-digit fixed) + `/Contents <00…0 (32768 hex chars = 16384 bytes)>`, then `xref` subsection (`<firstNewObj> <count>`, each `0000000000 65535 f` / `n` entries), `trailer << /Size <oldSize+newCount> /Root <sameRef> /Info <sameRef> /ID [<ID0> <ID0>] /Prev <oldXrefOffset> >>` (freeze 2nd ID element = copy of ID[0] in MVP), `startxref <newXrefOffset>`, `%%EOF`. Preserve `ID[0]`, carry `Info`, never drop `Root`. Record `contentsLt` (offset of `<`), `contentsGtEnd` (offset just after `>`), `brPos`.
- Boundaries (byte-exact, R2): `X = contentsLt`, `Y = contentsGtEnd`, `Z = total length`. Hash = `SHA256(bytes[0:X) || bytes[Y:Z))`. `ByteRange = [0 X Y (Z-Y)]` — 4th value is LENGTH `Z-Y`, NOT end-offset. Patch all four numbers in place, 10-digit zero-padded, same width. `ByteRange` + `Contents` direct objects; `Filter /Adobe.PPKLite`, `SubFilter /adbe.pkcs7.detached`, `Type /Sig`, widget `V → sigRef`.
- Phase 3: build CMS SignedData DER (Forge low-level, not `pkcs7.sign` defaults): `encapContentInfo.eContent ABSENT (detached — assert === undefined, never empty OCTET STRING)`; `digestAlgorithm SHA-256`; `signatureAlgorithm rsaEncryption+sha256`; signedAttrs `SET OF` DER-sorted by encoded bytes (manual sort — Forge does not auto-sort): `contentType`, `messageDigest == ByteRange SHA256`, `signingCertificateV2 (OID 1.2.840.113549.1.9.16.2.47, ESSCertIDv2 SHA256 of signer cert + exact issuer Name bytes + serial)`, optional `signingTime`. Sign with RSA private key.
- Splice CMS hex into gap in place, zero-pad remainder (`00…`), patch ByteRange digits in place with same width. Never change lengths/offsets post-hash. Placeholder 16KB fits B-B RSA (≈3.5–4.5KB DER typical; RSA-4096/3-chain ≈ 6–8KB). Chain rule (R4): leaf = cert matching privateKey, include leaf+ALL intermediates leaf-first, exclude root ONLY; never drop intermediates. If CMS > 16384 → `SIGNATURE_TOO_LARGE` → abort (no retry that drops intermediates). 24KB placeholder only in Phase 2 B-T (TSA token +4–8KB). Hash via `subtle.digest`, chunked Worker for >8MB; Forge sync fallback only inside Worker.
- Normative test: `openssl cms -print -inform DER` + `dumpasn1` byte-compare for ESSCertIDv2/sorted SET, plus Adobe Reader PAdES pass. Forge round-trip alone is insufficient.

## 5. Guards (B7/M3 fixes)
- Encrypted: `trailer.Encrypt` present (pdf-lib throws — map to) → `ENCRYPTED_NOT_SUPPORTED`.
- Already-signed: low-level scan for `FT/Sig` or `/ByteRange` (high-level `getForm()` misses Sig) → `ALREADY_SIGNED` ("multi-signer out of scope").
- Certified: `Catalog.Perms.DocMDP` / `FieldMDP` / `SigFlags` certified → `CERTIFIED_NOT_SUPPORTED` (approval would break certification).
- Linearized: `/Linearized` at offset 0 → warn "linearization lost, still valid", proceed.
- Filename: sanitize non-ASCII/double-extensions; output `<base>-signed.pdf`.

## 6. Security / privacy (M2 wording)
- MVP network: none. CSP vendored: `default-src 'self'; script-src 'self'; worker-src 'self' blob:; object-src 'none'; connect-src 'none'` so audit proves no exfiltration. CDN mode (optional): add `script-src https://cdn.jsdelivr.net` + SRI.
- Keys/docs in tab heap only; best-effort wipe (overwrite mutable Uint8Arrays, null refs, clear password field, advise reload). Note: browser extensions/content-scripts with tab permission can read heap — qualify "stays in tab heap, not sent over network".
- TSA Phase 2 sends digest+nonce+policy+TLS metadata only; vendored mode avoids CDN contact.

## 7. Errors / Testing
- Errors: `BAD_PASSWORD_OR_CORRUPT_P12`, `EC_NOT_SUPPORTED_MVP`, `FILE_TOO_LARGE` (>25MB), `ENCRYPTED_NOT_SUPPORTED`, `ALREADY_SIGNED`, `CERTIFIED_NOT_SUPPORTED`, `ROTATED_NOT_SUPPORTED` (/Rotate != 0), `SIGNATURE_TOO_LARGE`, `DOCX_DEFERRED`.
- Tests: Adobe-normative matrix (typed-visual, image-visual, tamper-outside-Contents, tamper-inside-Contents, wrong password, expired, encrypted/signed/certified/rotated rejects, 25MB+), openssl byte-compare vector, ByteRange `[0 X Y Z-Y]` length check, splice idempotence, Worker hash for 25MB without freeze.
- Pre-check panel labeled "Pre-check only — trust decision is Adobe Reader"; states "no CRL/OCSP in MVP".

## 8. Phase 2 (deferred)
- 2a TSA B-T via same-origin proxy after CORS proof (URL/policy/10s timeout/1 retry→B-B fallback, 24KB placeholder).
- 2b DOCX with exc-c14n stack + DrawingML SignatureLine (not docProps).
- Later: extension/native host for OS-store auto-detect; WebCrypto-sign path for non-extractable keys (mutually exclusive with Forge-sign); LTV; multi-signer.
