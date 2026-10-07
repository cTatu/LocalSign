// js/cert.js
import { forge } from './forge-shim.js';
export function u8ToBinaryStr(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return s;
}
export function detectEC(signatureOid, privateKey) {
  if (!privateKey || !privateKey.n || !privateKey.e || !privateKey.d) return true;
  if (!signatureOid) return true;
  return !signatureOid.startsWith('1.2.840.113549.1.1.');
}
function binaryStrToU8(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}
export async function loadP12(p12Bytes, password) {
  const binary = u8ToBinaryStr(p12Bytes);
  let p12;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(binary), password);
  } catch { throw new Error('BAD_PASSWORD_OR_CORRUPT_P12'); }
  const keyBags = (p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] || []);
  const certBags = (p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || []);
  if (!keyBags.length || !certBags.length) throw new Error('BAD_PASSWORD_OR_CORRUPT_P12');
  const privateKey = keyBags[0].key;
  const certs = certBags.map(b => b.cert);
  const leaf = certs.find(c => {
    try { return c.publicKey.n && privateKey.n && c.publicKey.n.toString(16) === privateKey.n.toString(16) && c.publicKey.e.toString(16) === privateKey.e.toString(16); } catch { return false; }
  });
  if (!leaf) throw new Error('BAD_PASSWORD_OR_CORRUPT_P12');
  if (detectEC(leaf.signatureOid, privateKey)) throw new Error('EC_NOT_SUPPORTED_MVP');
  const leafDer = binaryStrToU8(forge.asn1.toDer(forge.pki.certificateToAsn1(leaf)).getBytes());
  const chainDer = [];
  for (const c of certs) {
    if (c === leaf) continue;
    const subj = forge.asn1.toDer(forge.pki.distinguishedNameToAsn1(c.subject)).getBytes();
    const iss = forge.asn1.toDer(forge.pki.distinguishedNameToAsn1(c.issuer)).getBytes();
    if (subj === iss) continue;
    chainDer.push(binaryStrToU8(forge.asn1.toDer(forge.pki.certificateToAsn1(c)).getBytes()));
  }
  const cn = (attrs) => (attrs.find(a => a.shortName === 'CN') || {}).value || '';
  return { privateKey, leafDer, chainDer, subjectCN: cn(leaf.subject.attributes), issuerCN: cn(leaf.issuer.attributes), notBefore: leaf.validity.notBefore, notAfter: leaf.validity.notAfter };
}
export function clearCert(state) {
  if (!state) return;
  for (const k of Object.keys(state)) {
    try { if (state[k] instanceof Uint8Array) state[k].fill(0); } catch {}
    state[k] = null;
  }
}
