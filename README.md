# ![LocalSign](assets/logo.svg)

Sign PDFs in your browser with your own digital certificate. Zero backend — keys and documents never leave the tab. Pre-check only — trust decision is Adobe Reader. No CRL/OCSP in MVP.
## Run
`npm install && python3 -m http.server 8000` → `http://localhost:8000`
## Vendor + SRI
`cp node_modules/pdf-lib/dist/pdf-lib.esm.js lib/ && cp node_modules/node-forge/dist/forge.min.js lib/forge.min.js && cp node_modules/pdfjs-dist/build/pdf.min.mjs lib/ && openssl dgst -sha384 -binary lib/forge.min.js | openssl base64 -A`
## Privacy
Heap-only keys, best-effort wipe, reload advised; extensions with tab permission can read heap; TSA deferred so no hash leaves in MVP.
