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
