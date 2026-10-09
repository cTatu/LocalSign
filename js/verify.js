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
