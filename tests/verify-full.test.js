// tests/verify-full.test.js — official verdict engine. Trust anchors are
// injected (test root), so no network and no real CAs are involved.
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import {
  parseSignedPdf,
  parseCms,
  buildChain,
  verifySigned,
} from '../js/verify-full.js';
import { forge } from '../js/forge-shim.js';

const F = (n) => new Uint8Array(fs.readFileSync(`tests/fixtures/${n}`));
const b64der = (name) => Buffer.from(F(name)).toString('base64');
const TEST_ROOTS = [b64der('t-root.der')];
const goodOcsp = async () => ({ state: 'good' });

function nodeFromDer(der) {
  let s = '';
  for (const b of der) s += String.fromCharCode(b);
  return forge.asn1.fromDer(s);
}

describe('parseSignedPdf', () => {
  it('extracts ByteRange, CMS and digest', async () => {
    const p = await parseSignedPdf(F('signed-test.pdf'));
    expect(p.Z).toBe(F('signed-test.pdf').length);
    expect(p.cmsDer.length).toBeGreaterThan(1000);
    expect(p.digest.length).toBe(32);
  });
  it('rejects unsigned input', async () => {
    await expect(parseSignedPdf(new Uint8Array([1, 2, 3]))).rejects.toThrow();
  });
});

describe('parseCms', () => {
  it('finds detached CMS with RSA signer and embedded chain', async () => {
    const p = await parseSignedPdf(F('signed-test.pdf'));
    const cms = parseCms(p.cmsDer);
    expect(cms.signedAttrsDer.length).toBeGreaterThan(50);
    expect(cms.sigAlgoOid).toBe('1.2.840.113549.1.1.1'); // rsaEncryption (sha256 digest algo alongside)
    expect(cms.certNodes.length).toBeGreaterThanOrEqual(2);
  });
});

describe('buildChain', () => {
  it('completes leaf->int->test anchor', async () => {
    const p = await parseSignedPdf(F('signed-test.pdf'));
    const cms = parseCms(p.cmsDer);
    const leaf = nodeFromDer(F('t-leaf.der'));
    const int = nodeFromDer(F('t-int.der'));
    const built = buildChain(leaf, [leaf, int], TEST_ROOTS.map((b) => Uint8Array.from(Buffer.from(b, 'base64'))));
    expect(built.complete).toBe(true);
    expect(built.chain.length).toBe(3);
  });
  it('reports CHAIN_GAP against unknown roots', async () => {
    const p = await parseSignedPdf(F('signed-test.pdf'));
    const cms = parseCms(p.cmsDer);
    void cms;
    const leaf = nodeFromDer(F('t-leaf.der'));
    const built = buildChain(leaf, [leaf], []);
    expect(built.complete).toBe(false);
    expect(built.reason).toBe('CHAIN_GAP');
  });
});

describe('verifySigned', () => {
  it('VALID for the fixture file with trusted root + good OCSP', async () => {
    const v = await verifySigned(F('signed-test.pdf'), {
      trustRoots: TEST_ROOTS,
      ocspCheck: goodOcsp,
    });
    expect(v.failedAt).toBe(undefined);
    expect(v.verdict).toBe('VALID');
    expect(v.checks.every((c) => c.pass === true)).toBe(true);
  }, 30000);
  it('INVALID when a byte outside Contents is tampered', async () => {
    const bad = Uint8Array.from(F('signed-test.pdf'));
    bad[100] ^= 0xff;
    const v = await verifySigned(bad, { trustRoots: TEST_ROOTS, ocspCheck: goodOcsp });
    expect(v.verdict).toBe('INVALID');
    expect(v.failedAt).toBe('v_digest');
  }, 30000);
  it('INVALID on revoked OCSP', async () => {
    const v = await verifySigned(F('signed-test.pdf'), {
      trustRoots: TEST_ROOTS,
      ocspCheck: async () => ({ state: 'revoked' }),
    });
    expect(v.verdict).toBe('INVALID');
    expect(v.failedAt).toBe('v_ocsp');
  }, 30000);
  it('INCOMPLETE against unknown roots', async () => {
    const v = await verifySigned(F('signed-test.pdf'), {
      trustRoots: [],
      ocspCheck: goodOcsp,
    });
    expect(v.verdict).toBe('INCOMPLETE');
  }, 30000);
});
