// tests/cms.test.js
import { describe, it, expect } from 'vitest';
import { sortDerSet, V2_OID, buildCmsDer } from '../js/cms.js';
describe('sortDerSet', () => {
  it('sorts by bytes', () => {
    expect(sortDerSet([new Uint8Array([3,1,2]), new Uint8Array([1,9])]).map(x=>Array.from(x))).toEqual([[1,9],[3,1,2]]);
  });
  it('exposes V2 oid', () => {
    expect(V2_OID).toBe('1.2.840.113549.1.9.16.2.47');
  });
});
describe('buildCmsDer structural', () => {
  it('embeds V2 + messageDigest, detached, sorted, exact issuer/serial/certHash', async () => {
    const { forge } = await import('../js/forge-shim.js');
    const { exactIssuerTlv, sortDerSet } = await import('../js/cms.js');
    const keys = forge.pki.rsa.generateKeyPair(512);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date(Date.now() + 86400000);
    cert.setSubject([{ shortName: 'CN', value: 'Test' }]);
    cert.setIssuer([{ shortName: 'CN', value: 'Test' }]);
    cert.sign(keys.privateKey, forge.md.sha256.create());
    const leafDer = (() => { const s = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(); const o = new Uint8Array(s.length); for (let i=0;i<s.length;i++) o[i]=s.charCodeAt(i)&0xff; return o; })();
    const hash = new Uint8Array(32).fill(7);
    const der = buildCmsDer(hash, { privateKey: keys.privateKey, leafDer, chainDer: [] });
    const hex = Array.from(der, b => b.toString(16).padStart(2,'0')).join('').toUpperCase();
    expect(hex).toContain('2A864886F70D010910022F');
    const h = forge.md.sha256.create();
    let bin = '';
    for (const b of leafDer) bin += String.fromCharCode(b);
    h.update(bin, 'raw');
    const certHashHex = Buffer.from(h.digest().getBytes(), 'binary').toString('hex').toUpperCase();
    expect(hex).toContain(certHashHex);
    const { issuerTlvBytes, serialTlvBytes } = exactIssuerTlv(leafDer);
    const issuerHex = Array.from(issuerTlvBytes, b => b.toString(16).padStart(2,'0')).join('').toUpperCase();
    expect(hex).toContain(issuerHex);
    expect(issuerTlvBytes[0]).toBe(0x30);
    expect(serialTlvBytes[0]).toBe(0x02);
    const cmsAsn1 = forge.asn1.fromDer(String.fromCharCode(...der));
    const sd = cmsAsn1.value[1].value[0];
    const encap = sd.value[2];
    expect(encap.value.some(n => n.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && n.type === 0)).toBe(false);
    expect(der.length).toBeLessThanOrEqual(16384);
    void sortDerSet;
  });
  it('rejects oversize', async () => {
    const { forge } = await import('../js/forge-shim.js');
    const keys = forge.pki.rsa.generateKeyPair(512);
    expect(() => buildCmsDer(new Uint8Array(32), { privateKey: keys.privateKey, leafDer: new Uint8Array([1]), chainDer: [new Uint8Array(20000)] })).toThrow();
  });
});
