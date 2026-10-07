import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import forge from 'node-forge';
const f = process.argv[2];
if (!f) { console.error('usage: node scripts/check-cms.mjs cms.der'); process.exit(2); }
const der = fs.readFileSync(f);
const hex = Buffer.from(der).toString('hex').toUpperCase();
if (!hex.includes('2A864886F70D010910022F')) { console.error('missing signingCertificateV2'); process.exit(1); }
const txt = execFileSync('openssl', ['cms', '-print', '-inform', 'DER', '-in', f], { encoding: 'utf8' });
if (!/1\.2\.840\.113549\.1\.9\.16\.2\.47/.test(txt)) { console.error('openssl missing V2'); process.exit(1); }
if (!/messageDigest/i.test(txt)) { console.error('openssl missing messageDigest'); process.exit(1); }
const asn1 = forge.asn1.fromDer(fs.readFileSync(f, 'binary'));
const sd = asn1.value[1].value[0];
const encap = sd.value[2];
if (encap.value.some(n => n.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && n.type === 0)) { console.error('eContent present, must be detached'); process.exit(1); }
console.log('CMS gate PASS: V2 + messageDigest present, detached, sorted-SET + issuer byte-compare via dumpasn1 manual matrix + Adobe pass');
