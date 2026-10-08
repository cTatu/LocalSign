// tests/ocsp.test.js — OCSP builder/validator. Fixtures in tests/fixtures/:
// t-* = generated test chain (throwaway keys, committed for determinism),
// fnmt-* = real captured FNMT intermediate + OCSP response + openssl request.
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import {
  buildOcspRequest,
  ocspUrls,
  validateOcspResponse,
  verifyRsaSignature,
  checkOcsp,
} from '../js/ocsp.js';

const F = (n) => new Uint8Array(fs.readFileSync(`tests/fixtures/${n}`));
// Response captured 2026-10-08T12:16:01Z; pin validation clock +1h so the
// freshness assertion never rots.
const FNMT_NOW = Date.parse('2026-10-08T12:16:01Z') + 3600000;
const LEAF_SERIAL = '186583804B3E707A66D1EBBEEFC1090B';

describe('buildOcspRequest', () => {
  it('matches openssl bytes on the fixture chain', () => {
    const got = buildOcspRequest(F('t-int.der'), 'FF48900A2DAE462E');
    expect(Array.from(got)).toEqual(Array.from(F('ref.req')));
  });
  it('matches openssl bytes for FNMT', () => {
    const got = buildOcspRequest(F('fnmt-int.der'), LEAF_SERIAL);
    expect(Array.from(got)).toEqual(Array.from(F('fnmt.req')));
  });
});

describe('ocspUrls', () => {
  it('parses AIA without trailing ASN.1 garbage', () => {
    expect(ocspUrls(F('fnmt-int.der')).every((u) => /^https?:\/\/[^\x00-\x1f]*$/.test(u))).toBe(true);
  });
  it('finds the configured responder URL', () => {
    expect(ocspUrls(F('t-leaf.der'))).toEqual(['http://127.0.0.1:9/ocsp']);
  });
});

describe('verifyRsaSignature', () => {
  it('rejects tampered signatures', () => {
    // Flip a byte inside the signed tbsResponseData: the response signature
    // must stop verifying (tampering trailing cert bytes would prove nothing,
    // as they are not signature-covered).
    const bad = Uint8Array.from(F('fnmt-good.resp.der'));
    bad[100] ^= 0xff;
    const v = validateOcspResponse(bad, F('fnmt-int.der'), LEAF_SERIAL, FNMT_NOW);
    expect(v.state).not.toBe('good');
  });
  it('rejects non-RSA signers', () => {
    expect(verifyRsaSignature(F('t-leaf.der'), new Uint8Array([1]), new Uint8Array([2]), '1.2.840.10045.4.3.2'))
      .toEqual({ ok: false, reason: 'UNSUPPORTED_ALGO' });
  });
});

describe('validateOcspResponse', () => {
  it('accepts the captured FNMT good response', () => {
    expect(validateOcspResponse(F('fnmt-good.resp.der'), F('fnmt-int.der'), LEAF_SERIAL, FNMT_NOW))
      .toMatchObject({ state: 'good' });
  });
  it('rejects wrong serial', () => {
    expect(validateOcspResponse(F('fnmt-good.resp.der'), F('fnmt-int.der'), '00', FNMT_NOW).state)
      .not.toBe('good');
  });
  it('treats ancient responses as stale, not good', () => {
    expect(validateOcspResponse(F('fnmt-good.resp.der'), F('fnmt-int.der'), LEAF_SERIAL, Date.parse('2027-01-01T00:00:00Z')))
      .toMatchObject({ state: 'unchecked', reason: 'STALE' });
  });
});

describe('checkOcsp', () => {
  it('relays through fetch and validates a good answer', async () => {
    const bytes = F('fnmt-good.resp.der');
    const seen = [];
    const fetchFn = async (url, opts) => {
      seen.push({ url, type: opts.headers['Content-Type'] });
      return { ok: true, arrayBuffer: async () => bytes };
    };
    // t-leaf carries an AIA OCSP URL (closed port) but the injected relay
    // answers with the captured FNMT response for a DIFFERENT cert, so the
    // serial lookup must fail closed, not claim good.
    const v = await checkOcsp(F('t-leaf.der'), F('t-int.der'), { fetchFn, nowMs: FNMT_NOW });
    expect(seen.length).toBe(1);
    expect(seen[0].url).toContain('/ocsp?url=');
    expect(v.state).not.toBe('good');
  });
  it('reports unchecked when the relay is down', async () => {
    const fetchFn = async () => { throw new Error('down'); };
    const v = await checkOcsp(F('t-leaf.der'), F('t-int.der'), { fetchFn, nowMs: FNMT_NOW });
    expect(v.state).toBe('unchecked');
  });
  it('reports NO_RESPONDER without AIA', async () => {
    const v = await checkOcsp(F('t-int.der'), F('t-root.der'), {
      fetchFn: async () => { throw new Error('must not be called'); },
      nowMs: FNMT_NOW,
    });
    expect(v).toMatchObject({ state: 'unchecked', reason: 'NO_RESPONDER' });
  });
});
