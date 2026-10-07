// js/cms.js
import { forge } from './forge-shim.js';
import { u8ToBinaryStr } from './cert.js';
export const V2_OID = '1.2.840.113549.1.9.16.2.47';
export function sortDerSet(arr) {
  return [...arr].sort((x, y) => {
    const n = Math.min(x.length, y.length);
    for (let i = 0; i < n; i++) if (x[i] !== y[i]) return x[i] - y[i];
    return x.length - y.length;
  });
}
export async function hashByteRange(withGap, X, Y, Z) {
  const total = X + (Z - Y);
  if (total > 8_000_000 && typeof Worker !== 'undefined') {
    return await hashInWorker(withGap, X, Y, Z);
  }
  const buf = new Uint8Array(total);
  buf.set(withGap.slice(0, X), 0);
  buf.set(withGap.slice(Y, Z), X);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
}
function hashInWorker(withGap, X, Y, Z) {
  return new Promise((resolve, reject) => {
    const w = new Worker(new URL('./hash-worker.js', import.meta.url), { type: 'module' });
    w.onmessage = (e) => { w.terminate(); resolve(new Uint8Array(e.data)); };
    w.onerror = reject;
    const copy = withGap.slice();
    w.postMessage({ buf: copy, X, Y, Z });
  });
}
function derBytes(asn1Node) {
  const s = forge.asn1.toDer(asn1Node).getBytes();
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}
export function readTlv(bytes, pos) {
  const tag = bytes[pos];
  let b = bytes[pos + 1];
  let len = 0; let headerLen = 2;
  if (b < 128) { len = b; }
  else { const n = b & 127; len = 0; for (let i = 0; i < n; i++) len = (len << 8) | bytes[pos + 2 + i]; headerLen = 2 + n; }
  return { tag, len, headerLen, totalLen: headerLen + len };
}
export function exactIssuerTlv(leafDer) {
  if (leafDer.length < 10) throw new Error('CERT_TOO_SHORT');
  const cert = readTlv(leafDer, 0);
  if (cert.tag !== 0x30) throw new Error('CERT_NOT_SEQ');
  let cpos = cert.headerLen;
  const tbs = readTlv(leafDer, cpos);
  if (tbs.tag !== 0x30) throw new Error('TBS_NOT_SEQ');
  cpos += tbs.headerLen;
  const tbsEnd = cpos + tbs.len;
  let first = readTlv(leafDer, cpos);
  if (first.tag === 0xa0) cpos += first.totalLen;
  if (cpos >= tbsEnd) throw new Error('TBS_TRUNCATED');
  const serialTlvStart = cpos;
  const serialTlv = readTlv(leafDer, cpos);
  if (serialTlv.tag !== 0x02) throw new Error('SERIAL_NOT_INT');
  cpos += serialTlv.totalLen;
  const sigTlv = readTlv(leafDer, cpos);
  if (sigTlv.tag !== 0x30) throw new Error('SIG_NOT_SEQ');
  cpos += sigTlv.totalLen;
  if (cpos >= tbsEnd) throw new Error('ISSUER_MISSING');
  const issuerTlvStart = cpos;
  const issuerTlv = readTlv(leafDer, cpos);
  if (issuerTlv.tag !== 0x30) throw new Error('ISSUER_NOT_SEQ');
  const issuerBytes = leafDer.slice(issuerTlvStart, issuerTlvStart + issuerTlv.totalLen);
  const serialTlvBytes = leafDer.slice(serialTlvStart, serialTlvStart + serialTlv.totalLen);
  return { issuerTlvBytes: issuerBytes, serialTlvBytes: serialTlvBytes };
}
function buildSigningCertificateV2(leafDer, leafCert) {
  void leafCert;
  const { sha256 } = forge.md;
  const h = sha256.create();
  h.update(u8ToBinaryStr(leafDer), 'raw');
  const certHash = h.digest().getBytes();
  const { issuerTlvBytes, serialTlvBytes } = exactIssuerTlv(leafDer);
  const issuerStr = String.fromCharCode(...issuerTlvBytes);
  const serialAsn1 = forge.asn1.fromDer(String.fromCharCode(...serialTlvBytes));
  const issuerAsn1 = forge.asn1.fromDer(issuerStr);
  // Canonical-DER assumption: openssl/Forge-issued Names re-encode byte-identically; normative proof is dumpasn1 issuer byte-compare + Adobe pass in Task 7.
  const dirName = forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 4, true, [issuerAsn1]);
  const generalNames = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [dirName]);
  const algoId = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer(forge.pki.oids.sha256).getBytes()),
  ]);
  const issuerSerial = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    generalNames,
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, serialAsn1.value),
  ]);
  const essCertIDv2 = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    algoId,
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, certHash),
    issuerSerial,
  ]);
  const essSeq = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [essCertIDv2]);
  const attr = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer(V2_OID).getBytes()),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [essSeq]),
  ]);
  return { attr, essSeq };
}
function attrDer(oid, valueAsn1Children) {
  return derBytes(forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer(oid).getBytes()),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, valueAsn1Children),
  ]));
}
function concatU8(parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
function derWrap(tag, content) {
  const len = content.length;
  let header;
  if (len < 128) {
    header = new Uint8Array([tag, len]);
  } else {
    const lb = [];
    let n = len;
    while (n > 0) { lb.unshift(n & 0xff); n >>>= 8; }
    header = new Uint8Array([tag, 0x80 | lb.length, ...lb]);
  }
  return concatU8([header, content]);
}
function intNode(v) {
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, forge.asn1.integerToDer(v).getBytes());
}
function oidNode(dotted) {
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer(dotted).getBytes());
}
function sha256Aid() {
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    oidNode(forge.pki.oids.sha256),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
  ]);
}
// Manual SignedData assembly with forge.asn1 primitives.
//
// The brief's forge-pkcs7 vehicle (p7.addSigner/p7.sign) cannot satisfy the
// frozen contract with the vendored forge: its internal attribute encoder only
// handles contentType/messageDigest/signingTime, so the V2 attribute value is
// emitted as an empty SET (certHash/issuer lost), and sign() unconditionally
// overwrites messageDigest with digest(empty content) instead of the input
// ByteRange hash. Manual assembly preserves every frozen mechanism
// (attrDer+sortDerSet order mapping, essSeq value-node, exact issuer TLV,
// GeneralNames [4], 3-field ESSCertIDv2, gates) with correct bytes.
export function buildCmsDer(dataHash, { privateKey, leafDer, chainDer }) {
  const { issuerTlvBytes, serialTlvBytes } = exactIssuerTlv(leafDer);
  const leafNode = forge.asn1.fromDer(u8ToBinaryStr(leafDer));
  const chainNodes = chainDer.map((cDer) => forge.asn1.fromDer(u8ToBinaryStr(cDer)));
  const hashStr = u8ToBinaryStr(dataHash);
  const ctDer = attrDer(forge.pki.oids.contentType, [oidNode(forge.pki.oids.data)]);
  const mdDer = attrDer(forge.pki.oids.messageDigest, [forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, hashStr)]);
  const { essSeq } = buildSigningCertificateV2(leafDer);
  const v2Der = derBytes(forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    oidNode(V2_OID),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [essSeq]),
  ]));
  const ders = [ctDer, mdDer, v2Der];
  const order = sortDerSet(ders).map(d => {
    if (d === ctDer) return 0;
    if (d === mdDer) return 1;
    return 2;
  });
  const sortedDers = order.map(i => ders[i]);
  // Signature input: DER of SET OF Attribute (UNIVERSAL SET tag 0x31).
  const signingInput = u8ToBinaryStr(derWrap(0x31, concatU8(sortedDers)));
  const md = forge.md.sha256.create();
  md.update(signingInput, 'raw');
  const sigStr = privateKey.sign(md, 'RSASSA-PKCS1-V1_5');
  const issuerNode = forge.asn1.fromDer(String.fromCharCode(...issuerTlvBytes));
  const serialNode = forge.asn1.fromDer(String.fromCharCode(...serialTlvBytes));
  const sid = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [issuerNode, serialNode]);
  const signedAttrsNode = forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true,
    sortedDers.map(d => forge.asn1.fromDer(u8ToBinaryStr(d))));
  const rsaAid = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    oidNode(forge.pki.oids.rsaEncryption),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
  ]);
  const signerInfo = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    intNode(1),
    sid,
    sha256Aid(),
    signedAttrsNode,
    rsaAid,
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, sigStr),
  ]);
  const encap = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    oidNode(forge.pki.oids.data),
  ]);
  const signedDataSeq = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    intNode(1),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [sha256Aid()]),
    encap,
    forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [leafNode, ...chainNodes]),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [signerInfo]),
  ]);
  const ci = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    oidNode(forge.pki.oids.signedData),
    forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [signedDataSeq]),
  ]);
  const hasEContent = encap.value.some(n => n.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && n.type === 0);
  if (hasEContent) throw new Error('CMS_NOT_DETACHED');
  const out = derBytes(ci);
  const hex = Array.from(out, b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  if (!hex.includes('2A864886F70D010910022F')) throw new Error('CMS_MISSING_V2');
  if (out.length > 16384) throw new Error('SIGNATURE_TOO_LARGE');
  return out;
}
