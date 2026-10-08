// tests/server.test.js — /ocsp proxy + static behavior (fake upstream, no network).
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { createServer, _resetOcspRate } from '../server.js';

let app;
let upstream;
let appPort;
let upPort;
const seen = [];

function listen(srv) {
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve(srv.address().port)));
}

beforeAll(async () => {
  upstream = http.createServer((req, res) => {
    let n = 0;
    const chunks = [];
    req.on('data', (c) => { n += c.length; chunks.push(c); });
    req.on('end', () => {
      seen.push({ url: req.url, type: req.headers['content-type'], body: Buffer.concat(chunks) });
      res.writeHead(200, { 'Content-Type': 'application/ocsp-response' });
      res.end(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05]));
    });
  });
  upPort = await listen(upstream);
  process.env.OCSP_ALLOW_LOOPBACK = '1';
  app = createServer();
  appPort = await listen(app);
});

afterAll(() => {
  app.close();
  upstream.close();
  delete process.env.OCSP_ALLOW_LOOPBACK;
});

const up = () => `http://127.0.0.1:${upPort}/ocsp`;

describe('ocsp proxy', () => {
  it('healthz ok', async () => {
    const r = await fetch(`http://127.0.0.1:${appPort}/healthz`);
    expect(r.status).toBe(200);
    expect(await r.text()).toBe('ok');
  });
  it('forwards POST body + content-type to allowlisted host', async () => {
    const body = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05]);
    const r = await fetch(`http://127.0.0.1:${appPort}/ocsp?url=${encodeURIComponent(up())}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/ocsp-request' },
      body,
    });
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toBe('application/ocsp-response');
    expect(seen.length).toBe(1);
    expect(seen[0].body.equals(body)).toBe(true);
    expect(seen[0].type).toBe('application/ocsp-request');
  });
  it('rejects private-network targets', async () => {
    for (const bad of ['http://10.0.0.1/ocsp', 'http://169.254.169.254/x', 'ftp://example.com/ocsp']) {
      const r = await fetch(`http://127.0.0.1:${appPort}/ocsp?url=${encodeURIComponent(bad)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/ocsp-request' },
        body: Buffer.from([1, 2, 3]),
      });
      expect(r.status).toBe(400);
    }
  });
  it('rejects oversize bodies', async () => {    const r = await fetch(`http://127.0.0.1:${appPort}/ocsp?url=${encodeURIComponent(up())}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/ocsp-request' },
      body: Buffer.alloc(70000, 7),
    });
    expect(r.status).toBe(413);
  });
  it('rate-limits floods with 429', async () => {
    _resetOcspRate();
    process.env.OCSP_RATE_PER_MIN = '2';
    const codes = [];
    for (let i = 0; i < 3; i++) {
      const r = await fetch(`http://127.0.0.1:${appPort}/ocsp?url=${encodeURIComponent(up())}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/ocsp-request' },
        body: Buffer.from([9]),
      });
      codes.push(r.status);
      await r.arrayBuffer();
    }
    delete process.env.OCSP_RATE_PER_MIN;
    expect(codes).toEqual([200, 200, 429]);
  });
});

describe('static', () => {
  it('serves index at /', async () => {
    const r = await fetch(`http://127.0.0.1:${appPort}/`);
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toContain('text/html');
  });
  it('blocks path traversal', async () => {
    const r = await fetch(`http://127.0.0.1:${appPort}/..%2f..%2fetc%2fpasswd`);
    expect([400, 403, 404].includes(r.status)).toBe(true);
  });
  it('404s missing files', async () => {
    const r = await fetch(`http://127.0.0.1:${appPort}/nope-xyz`);
    expect(r.status).toBe(404);
  });
});

describe('cors', () => {
  it('answers preflight with ACAO', async () => {
    const r = await fetch(`http://127.0.0.1:${appPort}/ocsp?url=${encodeURIComponent(up())}`, {
      method: 'OPTIONS',
    });
    expect(r.status).toBe(204);
    expect(r.headers.get('access-control-allow-origin')).toBe('*');
  });
  it('stamps ACAO on proxied responses', async () => {
    const r = await fetch(`http://127.0.0.1:${appPort}/ocsp?url=${encodeURIComponent(up())}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/ocsp-request' },
      body: Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05]),
    });
    expect(r.status).toBe(200);
    expect(r.headers.get('access-control-allow-origin')).toBe('*');
  });
});
