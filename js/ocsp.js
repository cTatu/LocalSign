// js/ocsp.js — OCSP request building + BasicOCSPResponse validation.
//
// Privacy: a request carries only issuer hashes + serial (public cert
// identifiers). It goes through the same-origin /ocsp relay because CA
// responders send no CORS headers; keys/docs/passwords are never involved.
//
// Scope: RSA signatures only (matches the RSA-only signing MVP); EC-signed
// structures report UNSUPPORTED rather than failing silently.
import { forge } from './forge-shim.js';
import { u8ToBinaryStr } from './cert.js';
import { apiUrl } from './api.js';

export const AIA_OCSP_OID = '1.3.6.1.5.5.7.48.1';
const BASIC_OCSP_OID = '1.3.6.1.5.5.7.48.1.1';
const OCSPSIGNING_OID = '1.3.6.1.5.5.7.3.9';
const FRESH_DAYS = 7;
const SKEW_MS = 15 * 60 * 1000;

function b2u8(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

// BIT STRING content bytes: Forge keeps the leading unused-bits octet (0x00)
// in .value — RSA/CMS signatures need it stripped.
function bitStrBytes(node) {
  const raw = b2u8(node.value);
  if (raw.length && raw[0] === 0x00) return raw.slice(1);
  return raw;
}

function sha1bytes(binStr) {
  const h = forge.md.sha1.create();
  h.update(binStr, 'raw');
  return h.digest().getBytes();
}

function certFromDer(der) {
  return forge.pki.certificateFromAsn1(forge.asn1.fromDer(u8ToBinaryStr(der)));
}

function oidBytes(dotted) {
  return forge.asn1.oidToDer(dotted).getBytes();
}

// Exact issuer Name/Key identifiers for CertID (SHA-1, RFC 6960 default).
// Key hash MUST be getPublicKeyFingerprint (SHA-1 over the BIT STRING value
// octets excluding tag/length but including the unused-bits octet) — hashing
// Forge's parsed node value instead gives a different (wrong) digest.
export function certIdParts(issuerDer) {
  const issuer = certFromDer(issuerDer);
  const nameDer = forge.asn1.toDer(forge.pki.distinguishedNameToAsn1(issuer.subject)).getBytes();
  const keyHashHex = forge.pki.getPublicKeyFingerprint(issuer.publicKey, {
    md: forge.md.sha1.create(),
  }).toHex();
  const keyHash = new Uint8Array(keyHashHex.match(/../g).map((h) => parseInt(h, 16)));
  return {
    nameHash: b2u8(sha1bytes(nameDer)),
    keyHash,
  };
}

function seq(children) {
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, children);
}
function oidNode(dotted) {
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, oidBytes(dotted));
}
function octet(bytes) {
  const s = typeof bytes === 'string' ? bytes : String.fromCharCode(...bytes);
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, s);
}

// Build a bare OCSPRequest DER for (issuer, subjectSerialHex).
export function buildOcspRequest(issuerDer, serialHex) {
  const { nameHash, keyHash } = certIdParts(issuerDer);
  let hex = String(serialHex).replace(/^0x/i, '');
  if (hex.length % 2) hex = '0' + hex;
  // DER INTEGER is signed: pad a leading zero when the high bit is set,
  // otherwise verifiers read the serial as negative (openssl emits 02 09
  // 00 FF.. for an 8-byte serial starting with FF).
  if (parseInt(hex.slice(0, 2), 16) & 0x80) hex = '00' + hex;
  const algo = seq([oidNode(forge.pki.oids.sha1),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, '')]);
  const certId = seq([
    algo,
    octet(String.fromCharCode(...nameHash)),
    octet(String.fromCharCode(...keyHash)),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false,
      forge.util.hexToBytes(hex)),
  ]);
  const request = seq([certId]);
  const requestList = seq([request]);
  const tbsRequest = seq([requestList]);
  const ocspRequest = seq([tbsRequest]);
  return b2u8(forge.asn1.toDer(ocspRequest).getBytes());
}

// AuthorityInformationAccess OCSP responder URLs named inside a cert,
// parsed structurally (AccessDescription with method id-ad-ocsp, [6] URI).
// Length-delimited parsing keeps trailing ASN.1 bytes out of the URL.
export function ocspUrls(certDer) {
  const urls = [];
  try {
    const cert = certFromDer(certDer);
    const exts = cert.extensions || [];
    for (const e of exts) {
      if (e.id !== '1.3.6.1.5.5.7.1.1' || typeof e.value !== 'string') continue;
      const raw = e.value;
      let pos = 0;
      const readLen = () => {
        let b = raw.charCodeAt(pos++) & 0xff;
        if (b < 128) return b;
        const n = b & 127;
        let len = 0;
        for (let i = 0; i < n; i++) len = (len << 8) | (raw.charCodeAt(pos++) & 0xff);
        return len;
      };
      // Reads tag+length only; pos stops at the value start. Callers descend
      // with pos=node.start and skip with pos=node.start+node.len.
      const readTlv = () => {
        const tag = raw.charCodeAt(pos++) & 0xff;
        const len = readLen();
        return { tag, len, start: pos };
      };
      if ((raw.charCodeAt(pos) & 0xff) !== 0x30) continue;
      const outer = readTlv();
      pos = outer.start;
      const end = outer.start + outer.len;
      while (pos < end) {
        const ad = readTlv();
        if (ad.tag !== 0x30) break;
        const adEnd = ad.start + ad.len;
        pos = ad.start;
        const method = readTlv();
        const methodBytes = raw.slice(method.start, method.start + method.len);
        pos = method.start + method.len;
        const gn = readTlv();
        if (methodBytes === String.fromCharCode(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01) &&
            gn.tag === 0x86) {
          urls.push(raw.slice(gn.start, gn.start + gn.len));
        }
        pos = adEnd;
      }
    }
  } catch { /* unparsable -> no urls */ }
  return [...new Set(urls)].filter((u) => /^https?:\/\//i.test(u));
}

const DIGEST_PREFIX = {
  '1.2.840.113549.1.1.11': { hash: 'sha256', pre: '3031300d060960864801650304020105000420' },
  '1.2.840.113549.1.1.12': { hash: 'sha384', pre: '3041300d060960864801650304020205000430' },
  '1.2.840.113549.1.1.13': { hash: 'sha512', pre: '3051300d060960864801650304020305000440' },
};

function oidOf(node) {
  return forge.asn1.oidToDer ? forge.asn1.derToOid(node.value) : null;
}

// Verify an RSA PKCS#1 v1.5 signature with a cert's public key, using
// Forge's own verifier (hand-rolled modPow got the padding wrong).
export function verifyRsaSignature(signerCertDer, dataBytes, sigBytes, sigAlgoOid) {
  const spec = DIGEST_PREFIX[sigAlgoOid];
  if (!spec) return { ok: false, reason: 'UNSUPPORTED_ALGO' };
  let cert;
  try {
    cert = certFromDer(signerCertDer);
  } catch {
    return { ok: false, reason: 'BAD_CERT' };
  }
  const pub = cert.publicKey;
  if (!pub || typeof pub.verify !== 'function' || !pub.n || !pub.e) {
    return { ok: false, reason: 'NOT_RSA' };
  }
  try {
    const h = forge.md[spec.hash].create();
    let bin = '';
    for (let i = 0; i < dataBytes.length; i++) bin += String.fromCharCode(dataBytes[i]);
    h.update(bin);
    let sigStr = '';
    for (let i = 0; i < sigBytes.length; i++) sigStr += String.fromCharCode(sigBytes[i]);
    return pub.verify(h.digest().getBytes(), sigStr)
      ? { ok: true }
      : { ok: false, reason: 'BAD_SIGNATURE' };
  } catch {
    return { ok: false, reason: 'VERIFY_ERROR' };
  }
}

function asn1Bytes(node) {
  return b2u8(forge.asn1.toDer(node).getBytes());
}

// Embedded certs of a BasicOCSPResponse ([0] EXPLICIT). Forge may preserve
// the EXPLICIT wrapper as an inner SEQUENCE OF, so unwrap one level when
// every child parses as a certificate — but never when it doesn't (a single
// Certificate is itself a SEQUENCE).
function embeddedCerts(basic) {
  if (basic.value.length <= 3) return [];
  const wrap = basic.value[3];
  if (!wrap || wrap.tagClass !== forge.asn1.Class.CONTEXT_SPECIFIC) return [];
  let nodes = wrap.value || [];
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
  return nodes;
}

// Validate a BasicOCSPResponse for (issuer, serialHex) at nowMs.
// Returns {state:'good'|'revoked'|'unknown'|'unchecked', ...detail}.
export function validateOcspResponse(respDer, issuerDer, serialHex, nowMs) {
  const now = nowMs == null ? Date.now() : nowMs;
  let resp;
  try {
    resp = forge.asn1.fromDer(u8ToBinaryStr(respDer));
  } catch {
    return { state: 'unchecked', reason: 'UNPARSABLE' };
  }
  try {
    const outer = resp.value;
    const status = parseInt(forge.util.bytesToHex(outer[0].value), 16);
    if (status !== 0) return { state: 'unchecked', reason: 'RESP_ERROR_' + status };
    const rb = outer[1].value[0];
    const typeOid = forge.asn1.derToOid(rb.value[0].value);
    if (typeOid !== BASIC_OCSP_OID) return { state: 'unchecked', reason: 'NOT_BASIC' };
    const basicOctets = rb.value[1].value;
    const basic = forge.asn1.fromDer(basicOctets);
    const tbs = basic.value[0];
    const tbsDer = asn1Bytes(tbs);
    const sigAlgoNode = basic.value[1];
    const sigAlgoOid = forge.asn1.derToOid(sigAlgoNode.value[0].value);
    const sigBytes = bitStrBytes(basic.value[2]);
    const responses = tbs.value[2].value;
    // Find our serial.
    let single = null;
    for (const r of responses) {
      const certId = r.value[0];
      const serialNode = certId.value[3];
      const serialBytes = serialNode.value;
      let hex = forge.util.bytesToHex(serialBytes).replace(/^0+/, '') || '0';
      const want = String(serialHex).replace(/^0+/, '') || '0';
      if (hex.toLowerCase() === want.toLowerCase()) {
        single = r;
        break;
      }
    }
    if (!single) return { state: 'unchecked', reason: 'SERIAL_NOT_FOUND' };
    // Responder authorization: issuer itself, or embedded cert issued by
    // issuer carrying id-kp-OCSPSigning.
    const embedded = embeddedCerts(basic);
    const issuer = certFromDer(issuerDer);
    const issuerNameDer = forge.asn1.toDer(forge.pki.distinguishedNameToAsn1(issuer.subject)).getBytes();
    let signerDer = null;
    for (const c of embedded) {
      try {
        const rc = forge.pki.certificateFromAsn1(c);
        const eku = (rc.extensions || []).find((e) => e.id === '2.5.29.37');
        // eku.value is raw DER (SEQ OF OID): search the DER bytes of
        // id-kp-OCSPSigning, not the dotted string (never present raw).
        const ekuDer = eku && typeof eku.value === 'string' ? eku.value : '';
        const ocspEkuDer = String.fromCharCode(0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09);
        const hasOcspEku = ekuDer.indexOf(ocspEkuDer) >= 0;
        const issuedByIssuer = forge.asn1.toDer(forge.pki.distinguishedNameToAsn1(rc.issuer)).getBytes() === issuerNameDer;
        if (hasOcspEku && issuedByIssuer) {
          signerDer = b2u8(forge.asn1.toDer(c).getBytes());
          // Responder cert itself must verify under the issuer key.
          const rcTbs = forge.asn1.toDer(c.value[0]).getBytes();
          const rcAlgo = forge.asn1.derToOid(c.value[1].value[0].value);
          const chk = verifyRsaSignature(issuerDer, b2u8(rcTbs), bitStrBytes(c.value[2]), rcAlgo);
          if (!chk.ok) return { state: 'unchecked', reason: 'RESPONDER_CHAIN' };
          break;
        }
      } catch { /* next candidate */ }
    }
    if (!signerDer) {
      // Fall back to the issuer CA signing directly (RFC 6960 §4.2.2.2).
      signerDer = issuerDer;
    }
    const sig = verifyRsaSignature(signerDer, tbsDer, sigBytes, sigAlgoOid);
    if (!sig.ok) return { state: 'unchecked', reason: 'BAD_RESPONSE_SIG' };
    // Status + freshness.
    const statusNode = single.value[1];
    let state = 'unknown';
    let detail = null;
    if (statusNode.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && statusNode.type === 0) {
      state = 'good';
    } else if (statusNode.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && statusNode.type === 1) {
      state = 'revoked';
      try {
        detail = { time: single.value[1].value[0].value };
      } catch { /* optional */ }
    }
    const parseTime = (n) => {
      try {
        const s = n.value;
        let ms;
        if (/^\d{12}Z$/.test(s)) {
          const yy = parseInt(s.slice(0, 2), 10);
          const yyyy = yy >= 50 ? 1900 + yy : 2000 + yy;
          ms = Date.UTC(yyyy, +s.slice(2, 4) - 1, +s.slice(4, 6), +s.slice(6, 8), +s.slice(8, 10), +s.slice(10, 12));
        } else if (/^\d{14}Z$/.test(s)) {
          ms = Date.UTC(+s.slice(0, 4), +s.slice(4, 6) - 1, +s.slice(6, 8), +s.slice(8, 10), +s.slice(10, 12), +s.slice(12, 14));
        } else {
          return NaN;
        }
        return ms;
      } catch {
        return NaN;
      }
    };
    const thisUpdate = parseTime(single.value[2]);
    if (Number.isNaN(thisUpdate) || thisUpdate - now > SKEW_MS || now - thisUpdate > FRESH_DAYS * 86400000) {
      return { state: 'unchecked', reason: 'STALE' };
    }
    if (state === 'good') return { state: 'good', thisUpdate };
    if (state === 'revoked') return { state: 'revoked', detail };
    return { state: 'unknown' };
  } catch {
    return { state: 'unchecked', reason: 'PARSE_ERROR' };
  }
}

// Full live check for one cert: build request, POST each responder URL found
// in its AIA through the same-origin relay, validate answers. First
// definitive (good/revoked) answer wins; otherwise {state:'unchecked'}.
export async function checkOcsp(certDer, issuerDer, opts) {
  const o = opts || {};
  const nowMs = o.nowMs == null ? Date.now() : o.nowMs;
  const fetchFn = o.fetchFn || fetch;
  const relayBase = o.relayBase || apiUrl('/ocsp');
  let serialHex;
  try {
    serialHex = certFromDer(certDer).serialNumber || '0';
  } catch {
    return { state: 'unchecked', reason: 'BAD_CERT' };
  }
  const urls = ocspUrls(certDer);
  if (!urls.length) return { state: 'unchecked', reason: 'NO_RESPONDER' };
  let req;
  try {
    req = buildOcspRequest(issuerDer, serialHex);
  } catch {
    return { state: 'unchecked', reason: 'REQ_BUILD' };
  }
  let body = '';
  for (let i = 0; i < req.length; i++) body += String.fromCharCode(req[i]);
  for (const u of urls.slice(0, 3)) {
    try {
      const r = await fetchFn(relayBase + '?url=' + encodeURIComponent(u), {
        method: 'POST',
        headers: { 'Content-Type': 'application/ocsp-request' },
        body,
      });
      if (!r.ok) continue;
      const buf = new Uint8Array(await r.arrayBuffer());
      const v = validateOcspResponse(buf, issuerDer, serialHex, nowMs);
      if (v.state === 'good' || v.state === 'revoked') return v;
    } catch { /* next responder */ }
  }
  return { state: 'unchecked', reason: 'NO_ANSWER' };
}
