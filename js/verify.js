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
    { nameKey: 'chk_br', pass: !!brM && validateByteRangeFourth(brM[1], signedBytes.length), detailKey: 'chk_br_d' },
    { nameKey: 'chk_sub', pass: /\/SubFilter\s*\/adbe\.pkcs7\.detached/.test(text), detailKey: 'chk_sub_d' },
    { nameKey: 'chk_filter', pass: /\/Filter\s*\/Adobe\.PPKLite/.test(text), detailKey: 'chk_filter_d' },
    { nameKey: 'chk_noocsp', pass: true, detailKey: 'chk_noocsp_d' },
  ];
  return { checks, labelKey: 'precheck_label' };
}
