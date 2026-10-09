# E2E (Adobe-normative)
1. `openssl req -x509 -newkey rsa:2048 -keyout k.pem -out c.pem -days 365 -nodes -subj "/CN=Test" && openssl pkcs12 -export -out test.p12 -inkey k.pem -in c.pem -passout pass:test`
2. `python3 -m http.server 8000` → `http://localhost:8000` (never file://).
3. Sign tests/sample.pdf (unrotated/unsigned/unencrypted) typed visual → `sample-signed.pdf`; repeat with PNG image visual → `sample-img-signed.pdf` (AP contains Im0 + F1, BBox==Rect).
4. Extract CMS bytes from `/Contents <...>` → `/tmp/cms.der`; run `node scripts/check-cms.mjs /tmp/cms.der` (must PASS: V2 + messageDigest + detached) + `openssl cms -print -inform DER -in /tmp/cms.der | grep 1.2.840.113549.1.9.16.2.47` must print 1; `dumpasn1 /tmp/cms.der` confirms sorted SET + detached (no eContent) + ESSCertIDv2 issuer bytes equal leaf issuer + messageDigest equals ByteRange SHA256.
5. Adobe Reader signatures panel valid PAdES (normative).
6. Tamper 1 byte outside Contents → verdict INVALID + Adobe invalid; inside Contents → CMS parse FAIL. Verify card on the signed file must show the official verdict.
7. Negatives: wrong password BAD_PASSWORD_OR_CORRUPT_P12; EC CERTIFICATE EC_NOT_SUPPORTED_MVP; encrypted ENCRYPTED_NOT_SUPPORTED; signed ALREADY_SIGNED; certified CERTIFIED_NOT_SUPPORTED; rotated ROTATED_NOT_SUPPORTED; >25MB FILE_TOO_LARGE; fat chain SIGNATURE_TOO_LARGE abort; .docx DOCX_DEFERRED.
