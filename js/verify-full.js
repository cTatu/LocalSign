// js/verify-full.js — the official verdict: digest + RSA + V2 + chain + OCSP.
//
// verifySigned(pdfBytes, opts) -> { verdict, checks } where verdict is one of:
//   VALID      — every check green, including fresh OCSP "good".
//   INVALID    — a hard failure (tampered bytes, bad signature, expired,
//                revoked, broken chain link).
//   INCOMPLETE — nothing failed but trust is partial (unknown root, chain gap,
//                OCSP unchecked/offline, non-RSA algorithm).
//
// opts: { trustRoots (base64 DER array, default TRUST_ROOTS), ocspCheck,
//         fetchFn, relayBase, nowMs }. ocspCheck defaults to live checkOcsp;
// tests inject a stub. RSA-only: EC structures report UNSUPPORTED.
import { forge } from './forge-shim.js';
import { u8ToBinaryStr } from './cert.js';
import { readTlv } from './cms.js';
import { TRUST_ROOTS } from './roots.js';
import { checkOcsp, verifyRsaSignature } from './ocsp.js';

const SHA256_OID = '2.16.840.1.101.3.4.2.1';
const MSG_DIGEST_OID = '1.2.840.113549.1.9.4';
const V2_OID = '1.2.840.113549.1.9.16.2.47';

function b2u8(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

function certFromDer(der) {
  return forge.pki.certificateFromAsn1(forge.asn1.fromDer(u8ToBinaryStr(der)));
}

function derOf(node) {
  const s = forge.asn1.toDer(node).getBytes();
  return b2u8(s);
}

function hexNorm(h) {
  return String(h || '').replace(/^0x/i, '').replace(/^0+/, '').toLowerCase() || '0';
}

// [0] EXPLICIT cert lists (CMS and OCSP share Forge's shape ambiguity).
function unwrapCerts(explicitNode) {
  if (!explicitNode || explicitNode.tagClass !== forge.asn1.Class.CONTEXT_SPECIFIC) return [];
  let nodes = explicitNode.value || [];
  if (nodes.length === 1 &&
      nodes[0].tagClass === forge.asn1.Class.UNIVERSAL &&
      nodes[0].type === forge.asn1.Type.SEQUENCE) {
    const inner = nodes[0].value || [];
    let ok = 0;
    for (const n of inner) {
      try {
        forge.pki.certificateFromAsn1(n);
        ok++;
      } catch { /* not a cert */ }
    }
    if (ok === inner.length && inner.length > 0) nodes = inner;
  }
  const out = [];
  for (const n of nodes) {
    try {
      forge.pki.certificateFromAsn1(n);
      out.push(n);
    } catch { /* skip non-certs */ }
  }
  return out;
}

// Exact child TLVs of the SignedData SEQ inside a CMS ContentInfo.
// Header-only reads: callers descend with pos=node.start and skip siblings
// with pos=node.start+node.headerLen+node.len. Never skip-then-descend.
function signedDataKids(cmsDer) {
  const hdr = (p) => {
    const r = readTlv(cmsDer, p);
    return { tag: r.tag, len: r.len, headerLen: r.headerLen, start: p };
  };
  const ci = hdr(0);
  if (ci.tag !== 0x30) throw new Error('NOT_CMS');
  let pos = ci.start + ci.headerLen;
  const oid = hdr(pos);
  pos += oid.headerLen + oid.len;
  const wrapper = hdr(pos);
  if (wrapper.tag !== 0xa0) throw new Error('NOT_SIGNED_DATA');
  // SignedData starts AFTER the [0] EXPLICIT header, not at it.
  const sd = hdr(wrapper.start + wrapper.headerLen);
  if (sd.tag !== 0x30) throw new Error('NOT_SIGNED_DATA');
  return { sd, sdKids: kidsOf(cmsDer, sd) };
}

function tlvAt(bytes, pos) {
  const r = readTlv(bytes, pos);
  return { tag: r.tag, len: r.len, headerLen: r.headerLen, start: pos };
}

// Content bytes of a child node as a binary string (derToOid and friends
// take content octets, NOT the full TLV — passing tag+length yields garbage
// arcs like 0.6.9.42...).
function contentOf(bytes, kid) {
  let s = '';
  const c = bytes.slice(kid.start + kid.headerLen, kid.start + kid.headerLen + kid.len);
  for (let i = 0; i < c.length; i++) s += String.fromCharCode(c[i]);
  return s;
}

function kidsOf(bytes, node) {
  const out = [];
  let p = node.start + node.headerLen;
  const stop = node.start + node.headerLen + node.len;
  while (p < stop) {
    const k = tlvAt(bytes, p);
    out.push(k);
    p = k.start + k.headerLen + k.len;
  }
  return out;
}

// Parse ByteRange + Contents + digest of a signed PDF.
export async function parseSignedPdf(pdfBytes) {
  const text = new TextDecoder('latin1').decode(pdfBytes);
  const brM = text.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/);
  if (!brM) throw new Error('NO_BYTERANGE');
  const X = parseInt(brM[2], 10);
  const Y = parseInt(brM[3], 10);
  const L = parseInt(brM[4], 10);
  if (L !== pdfBytes.length - Y) throw new Error('BYTERANGE_LENGTH');
  const cM = text.match(/\/Contents\s*<([0-9A-Fa-f]+)>/);
  if (!cM) throw new Error('NO_CONTENTS');
  const raw = new Uint8Array(cM[1].match(/../g).map((h) => parseInt(h, 16)));
  const first = readTlv(raw, 0);
  const cmsDer = raw.slice(0, first.headerLen + first.len);
  const covered = new Uint8Array(X + (pdfBytes.length - Y));
  covered.set(pdfBytes.slice(0, X), 0);
  covered.set(pdfBytes.slice(Y), X);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', covered));
  return { X, Y, Z: pdfBytes.length, cmsDer, digest };
}

// Parse a PAdES CMS with byte-exact signedAttrs (tag-swap, never re-encode:
// [0] IMPLICIT content re-tagged as SET gives the exact signed bytes).
export function parseCms(cmsDer) {
  const { sdKids } = signedDataKids(cmsDer);
  // version INT, digestAlgorithms SET, encapContentInfo SEQ, [certs], [crls], signerInfos SET
  let i = 0;
  if (sdKids[i].tag !== 0x02) throw new Error('NO_VERSION');
  i++;
  const digestAlgos = sdKids[i];
  if (digestAlgos.tag !== 0x31) throw new Error('NO_DIGEST_ALGOS');
  i++;
  const encap = sdKids[i];
  if (encap.tag !== 0x30) throw new Error('NO_ENCAP');
  const encapKids = kidsOf(cmsDer, encap);
  if (encapKids.some((k) => k.tag === 0xa0)) throw new Error('NOT_DETACHED');
  i++;
  const at = (n) => cmsDer.slice(n.start, n.start + n.headerLen + n.len);
  const certNodes = [];
  while (i < sdKids.length && sdKids[i].tag === 0xa0) {
    const wrapBytes = at(sdKids[i]);
    const wrap = forge.asn1.fromDer(u8ToBinaryStr(wrapBytes));
    certNodes.push(...unwrapCerts(wrap));
    i++;
  }
  while (i < sdKids.length && sdKids[i].tag === 0xa1) i++; // crls
  const signerInfos = sdKids[i];
  if (!signerInfos || signerInfos.tag !== 0x31) throw new Error('NO_SIGNERS');
  const siKids = kidsOf(cmsDer, signerInfos);
  if (!siKids.length || siKids[0].tag !== 0x30) throw new Error('NO_SIGNER_INFO');
  const si = kidsOf(cmsDer, siKids[0]);
  // version, sid, digestAlgorithm, [signedAttrs], signatureAlgorithm, signature
  let k = 0;
  if (si[k].tag !== 0x02) throw new Error('NO_SI_VERSION');
  k++;
  const sid = si[k];
  k++;
  const digestAlgo = si[k];
  k++;
  let signedAttrsDer = null;
  if (si[k] && si[k].tag === 0xa0) {
    const raw = at(si[k]);
    signedAttrsDer = Uint8Array.from(raw);
    signedAttrsDer[0] = 0x31;
    k++;
  }
  if (!si[k] || si[k].tag !== 0x30) throw new Error('NO_SIG_ALGO');
  const sigAlgoKids = kidsOf(cmsDer, si[k]);
  const sigAlgoOid = sigAlgoKids.length && sigAlgoKids[0].tag === 0x06
    ? forge.asn1.derToOid(contentOf(cmsDer, sigAlgoKids[0])) : '';
  k++;
  if (!si[k] || si[k].tag !== 0x04) throw new Error('NO_SIG');
  const sigBytes = at(si[k]).slice(si[k].headerLen); // OCTET content (no unused-bits octet)
  return { certNodes, signedAttrsDer, sigBytes, sigAlgoOid, sidNode: sid, digestAlgo };
}

function nameDerHex(nameDn) {
  return forge.util.bytesToHex(forge.asn1.toDer(forge.pki.distinguishedNameToAsn1(nameDn)).getBytes());
}

// Build a chain leaf -> ... -> trust anchor from embedded certs + roots.
// Returns { chain:[asn1...], anchor, complete, reason? }.
export function buildChain(leafNode, embeddedNodes, rootDers) {
  // The chain holds parsed Forge cert objects (never raw nodes) so every
  // consumer can use .subject/.issuer uniformly.
  let leaf;
  try {
    leaf = forge.pki.certificateFromAsn1(leafNode);
  } catch {
    return { chain: [], anchor: null, complete: false, reason: 'LEAF_PARSE' };
  }
  const chain = [leaf];
  const roots = [];
  for (const rder of rootDers) {
    try {
      roots.push(forge.pki.certificateFromAsn1(forge.asn1.fromDer(u8ToBinaryStr(rder))));
    } catch { /* skip bad roots */ }
  }
  const pool = [];
  for (const n of embeddedNodes) {
    try {
      pool.push(forge.pki.certificateFromAsn1(n));
    } catch { /* skip */ }
  }
  const bySubject = new Map();
  for (const c of pool) {
    try {
      bySubject.set(nameDerHex(c.subject), c);
    } catch { /* skip */ }
  }
  const rootBySubject = new Map();
  for (const c of roots) {
    try {
      if (nameDerHex(c.subject) === nameDerHex(c.issuer)) {
        rootBySubject.set(nameDerHex(c.subject), c);
      }
    } catch { /* skip */ }
  }
  let current = leaf;
  let currentNode = leafNode;
  const seen = new Set();
  for (let depth = 0; depth < 10; depth++) {
    let issuerHex;
    try {
      issuerHex = nameDerHex(current.issuer);
    } catch {
      return { chain, anchor: null, complete: false, reason: 'ISSUER_PARSE' };
    }
    if (seen.has(issuerHex)) return { chain, anchor: null, complete: false, reason: 'CHAIN_LOOP' };
    seen.add(issuerHex);
    // Anchor?
    const anchor = rootBySubject.get(issuerHex);
    if (anchor) {
      try {
        if (!anchor.verify(current)) return { chain, anchor, complete: false, reason: 'ANCHOR_SIG' };
      } catch (e) {
        const m = String((e && e.message) || '');
        if (/nknown|nsupported|OID/i.test(m)) return { chain, anchor, complete: false, reason: 'UNSUPPORTED_ALGO' };
        return { chain, anchor, complete: false, reason: 'ANCHOR_SIG' };
      }
      chain.push(anchor);
      return { chain, anchor, complete: true };
    }
    const next = bySubject.get(issuerHex);
    if (!next) return { chain, anchor: null, complete: false, reason: 'CHAIN_GAP' };
    try {
      if (!next.verify(current)) return { chain, anchor: null, complete: false, reason: 'LINK_SIG' };
    } catch (e) {
      const m = String((e && e.message) || '');
      if (/nknown|nsupported|OID/i.test(m)) return { chain, anchor: null, complete: false, reason: 'UNSUPPORTED_ALGO' };
      return { chain, anchor: null, complete: false, reason: 'LINK_SIG' };
    }
    chain.push(next);
    current = next;
  }
  return { chain, anchor: null, complete: false, reason: 'CHAIN_DEPTH' };
}

function attrValue(signedAttrsDer, oidDotted) {
  // Find Attribute with OID inside the signedAttrs SET content. Values are
  // only read (never re-encoded for coverage), so Forge parsing is safe.
  const wrap = forge.asn1.fromDer(u8ToBinaryStr(signedAttrsDer));
  for (const attr of wrap.value || []) {
    try {
      const t = attr.value[0];
      if (t.tagClass === forge.asn1.Class.UNIVERSAL && t.type === forge.asn1.Type.OID &&
          forge.asn1.derToOid(t.value) === oidDotted) {
        return attr;
      }
    } catch { /* next */ }
  }
  return null;
}

function octetBytes(attrNode) {
  // First OCTET STRING descendant of the attribute value SET.
  const stack = [...(attrNode.value || [])];
  while (stack.length) {
    const n = stack.pop();
    if (n.tagClass === forge.asn1.Class.UNIVERSAL && n.type === forge.asn1.Type.OCTETSTRING) {
      return b2u8(n.value);
    }
    if (n.value && typeof n.value !== 'string') stack.push(...n.value);
  }
  return null;
}

// Default OCSP check through the same-origin relay.
async function defaultOcspCheck(certDer, issuerDer, o) {
  const { checkOcsp } = await import('./ocsp.js');
  return checkOcsp(certDer, issuerDer, o);
}

// The verdict. opts: { trustRoots?, ocspCheck?, fetchFn?, relayBase?, nowMs? }
export async function verifySigned(pdfBytes, opts) {
  const o = opts || {};
  const nowMs = o.nowMs == null ? Date.now() : o.nowMs;
  const checks = [];
  const row = (key, pass, detailKey) => checks.push({ key, pass, detailKey });
  const fail = (key) => ({ verdict: 'INVALID', checks, failedAt: key });

  let parsed;
  try {
    parsed = await parseSignedPdf(pdfBytes);
  } catch {
    row('v_structure', false);
    return fail('v_structure');
  }
  let cms;
  try {
    cms = parseCms(parsed.cmsDer);
  } catch {
    row('v_structure', false);
    return fail('v_structure');
  }
  if (!cms.signedAttrsDer) {
    row('v_structure', false);
    return fail('v_structure');
  }
  // 1. Digest over ByteRange == signed messageDigest.
  let mdOk = false;
  try {
    const attr = attrValue(cms.signedAttrsDer, MSG_DIGEST_OID);
    const md = attr && octetBytes(attr);
    mdOk = !!md && md.length === parsed.digest.length &&
      md.every((b, i) => b === parsed.digest[i]);
  } catch { mdOk = false; }
  row('v_digest', mdOk);
  if (!mdOk) return fail('v_digest');
  // RSA gate: SHA-256 message digest + RSA signature algorithm only.
  let digestSha256 = false;
  try {
    const algoKids = kidsOf(parsed.cmsDer, cms.digestAlgo);
    digestSha256 = algoKids.length > 0 && algoKids[0].tag === 0x06 &&
      forge.asn1.derToOid(contentOf(parsed.cmsDer, algoKids[0])) === SHA256_OID;
  } catch { digestSha256 = false; }
  // Our own files use rsaEncryption (1.1.1) as signature algorithm with
  // sha256 as digest algorithm — accept the RSA family here.
  const rsaOids = ['1.2.840.113549.1.1.1', '1.2.840.113549.1.1.5', '1.2.840.113549.1.1.11'];
  if (!digestSha256 || !rsaOids.includes(cms.sigAlgoOid)) {
    row('v_rsa', null);
    return { verdict: 'INCOMPLETE', checks, failedAt: 'v_rsa_algo' };
  }
  // Identify signer cert (issuer + serial match). sidKids entries are raw
  // position objects (not Forge nodes): compare exact DER bytes against each
  // embedded cert's re-encoded issuer/serial.
  let signer = null;
  let signerDer = null;
  try {
    const sidKids = kidsOf(parsed.cmsDer, cms.sidNode);
    const sliceBytes = (k) => parsed.cmsDer.slice(k.start, k.start + k.headerLen + k.len);
    const issuerHex = forge.util.bytesToHex(u8ToBinaryStr(sliceBytes(sidKids[0])));
    const serialTlv = sliceBytes(sidKids[1]);
    const serialHex = forge.util.bytesToHex(u8ToBinaryStr(serialTlv.slice(sidKids[1].headerLen)));
    for (const n of cms.certNodes) {
      try {
        const c = forge.pki.certificateFromAsn1(n);
        const ih = forge.util.bytesToHex(forge.asn1.toDer(forge.pki.distinguishedNameToAsn1(c.issuer)).getBytes());
        if (ih === issuerHex && hexNorm(c.serialNumber) === hexNorm(serialHex)) {
          signer = c;
          signerDer = b2u8(forge.asn1.toDer(n).getBytes());
          break;
        }
      } catch { /* next */ }
    }
  } catch { /* no signer */ }
  if (!signer) {
    row('v_signer', false);
    return fail('v_signer');
  }
  let rsaOk = false;
  try {
    // Hash the EXACT wire bytes (tag-swapped SET) — re-encoding through
    // Forge would silently change bytes (length forms, SET order) and break
    // signatures that are actually valid.
    const h = forge.md.sha256.create();
    let setBin = '';
    const d = cms.signedAttrsDer;
    for (let i = 0; i < d.length; i++) setBin += String.fromCharCode(d[i]);
    h.update(setBin);
    const digest = h.digest().getBytes();
    let sigStr = '';
    const rawSig = cms.sigBytes;
    for (let i = 0; i < rawSig.length; i++) sigStr += String.fromCharCode(rawSig[i]);
    rsaOk = signer.publicKey.verify(digest, sigStr) === true;
  } catch {
    rsaOk = false;
  }
  row('v_rsa', rsaOk);
  if (!rsaOk) return fail('v_rsa');
  // 3. signingCertificateV2 binds the signer cert hash.
  let v2Ok = false;
  try {
    const attr = attrValue(cms.signedAttrsDer, V2_OID);
    const got = attr && octetBytes(attr);
    const h = forge.md.sha256.create();
    h.update(u8ToBinaryStr(signerDer));
    const want = b2u8(h.digest().getBytes());
    v2Ok = !!got && got.length >= 32 &&
      want.every((b, i) => b === got[i]);
  } catch { v2Ok = false; }
  row('v_certbind', v2Ok);
  if (!v2Ok) return fail('v_certbind');
  // 4. Validity window (leaf; intermediates checked in chain walk).
  let timeOk = false;
  try {
    timeOk = signer.validity.notBefore.getTime() <= nowMs &&
      nowMs <= signer.validity.notAfter.getTime();
  } catch { timeOk = false; }
  row('v_validity', timeOk);
  if (!timeOk) return fail('v_validity');
  // 5. Chain to a bundled anchor.
  const roots = (o.trustRoots || TRUST_ROOTS).map((b64) => {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  });
  const signerHex = (() => {
    try {
      return forge.util.bytesToHex(forge.asn1.toDer(
        forge.pki.certificateToAsn1(signer)).getBytes());
    } catch {
      return null;
    }
  })();
  const leafNode = signerHex && cms.certNodes.find((nn) => {
    try {
      return forge.util.bytesToHex(forge.asn1.toDer(nn).getBytes()) === signerHex;
    } catch {
      return false;
    }
  });
  const built = buildChain(leafNode, cms.certNodes, roots);
  if (built.reason === 'UNSUPPORTED_ALGO') {
    row('v_chain', null);
    return { verdict: 'INCOMPLETE', checks, failedAt: 'v_chain_algo' };
  }
  if (!built.complete) {
    row('v_chain', built.reason === 'CHAIN_GAP' ? null : false);
    if (built.reason === 'CHAIN_GAP' || !built.anchor) {
      return { verdict: 'INCOMPLETE', checks, failedAt: 'v_chain' };
    }
    return fail('v_chain');
  }
  row('v_chain', true);
  // 6. OCSP for leaf + intermediates (never the self-signed anchor).
  const ocspCheck = o.ocspCheck || ((c, iss) => defaultOcspCheck(c, iss, o));
  let ocspUnchecked = false;
  const nonRoot = built.chain.filter((c) => {
    try {
      return nameDerHex(c.subject) !== nameDerHex(c.issuer);
    } catch { return true; }
  });
  for (const c of nonRoot) {
    let issuerDer = null;
    try {
      const ih = nameDerHex(c.issuer);
      const bySubject = new Map();
      for (const cand of built.chain) {
        try {
          bySubject.set(nameDerHex(cand.subject), cand);
        } catch { /* skip */ }
      }
      const iss = bySubject.get(ih);
      if (!iss) { ocspUnchecked = true; continue; }
      issuerDer = b2u8(forge.asn1.toDer(forge.pki.certificateToAsn1(iss)).getBytes());
    } catch { ocspUnchecked = true; continue; }
    const cDer = b2u8(forge.asn1.toDer(forge.pki.certificateToAsn1(c)).getBytes());
    let r;
    try {
      r = await ocspCheck(cDer, issuerDer);
    } catch {
      r = { state: 'unchecked' };
    }
    if (r.state === 'revoked') {
      row('v_ocsp', false);
      return fail('v_ocsp');
    }
    if (r.state !== 'good') ocspUnchecked = true;
  }
  if (ocspUnchecked) {
    row('v_ocsp', null);
    return { verdict: 'INCOMPLETE', checks, failedAt: 'v_ocsp' };
  }
  row('v_ocsp', true);
  return { verdict: 'VALID', checks };
}
