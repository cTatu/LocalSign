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
