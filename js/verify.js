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
