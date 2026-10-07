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
