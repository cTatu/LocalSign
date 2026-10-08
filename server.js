// server.js — LocalSign Node server: static files + same-origin OCSP relay.
//
// Browsers cannot read OCSP/TSA responses cross-origin (no CORS headers on
// responders), so /ocsp relays request bytes to the responder named in `url`
// and streams the response back. It never sees private keys, passwords, or
// documents — only cert identifiers/hashes.
//
// Relay guardrails (no allowlist — any public CA must work):
// http(s) only, DNS must resolve to a public IP (no private/link-local/
// loopback targets), request <=64KB, response <=1MB, 30 req/min per IP.
// Private hosts, oversize payloads and floods are rejected with 400/413/429.
//
//   POST /ocsp?url=<responder-url>   body: OCSP request DER (<=64KB)
//   GET  /ocsp?url=<responder-url>&req=<base64url-DER>
//   GET  /healthz                     -> 200 ok
//
// Env: PORT (default 8000), OCSP_RATE_PER_MIN (default 30).
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns';
import net from 'node:net';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PORT = parseInt(process.env.PORT || '8000', 10);
const MAX_BODY = 65536;
const MAX_RESPONSE = 1048576;
const TIMEOUT_MS = 10000;

function ratePerMin() {
  return parseInt(process.env.OCSP_RATE_PER_MIN || '30', 10);
}

// Fixed-window per-IP counter for /ocsp only.
const buckets = new Map();
function rateOk(ip) {
  const now = Date.now();
  const windowMs = 60000;
  let b = buckets.get(ip);
  if (!b || now - b.start >= windowMs) {
    b = { start: now, n: 0 };
    buckets.set(ip, b);
  }
  b.n += 1;
  if (buckets.size > 10000) buckets.clear();
  return b.n <= ratePerMin();
}

function isPrivateIp(addr) {
  if (net.isIPv4(addr)) {
    const [a, b] = addr.split('.').map(Number);
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 169 && b === 254) || a === 0;
  }
  const low = addr.toLowerCase();
  return low === '::1' || low.startsWith('fc') || low.startsWith('fd') ||
    low.startsWith('fe80') || low === '::';
}

async function publicHost(hostname) {
  // Literal IPs are checked directly; names go through DNS first so
  // private/rebound targets are rejected before any socket opens.
  if (net.isIP(hostname)) {
    if (!isPrivateIp(hostname)) return true;
    // Loopback is private by definition; tests opt in explicitly to run a
    // fake upstream on 127.0.0.1. Never set this in production.
    return process.env.OCSP_ALLOW_LOOPBACK === '1' &&
      (hostname === '127.0.0.1' || hostname === '::1' || hostname.toLowerCase() === 'localhost');
  }
  let addrs;
  try {
    addrs = await dns.promises.lookup(hostname, { all: true });
  } catch {
    return false;
  }
  return addrs.length > 0 && addrs.every((a) => !isPrivateIp(a.address));
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8',
  '.pdf': 'application/pdf',
};

function serveStatic(req, res) {
  const url = new URL(req.url, 'http://x');
  let p = decodeURIComponent(url.pathname);
  if (p.endsWith('/')) p += 'index.html';
  const file = path.normalize(path.join(ROOT, p));
  if (!file.startsWith(ROOT + path.sep) && file !== ROOT) {
    res.writeHead(403); res.end('forbidden');
    return;
  }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) {
      res.writeHead(404); res.end('not found');
      return;
    }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'Content-Length': st.size,
    });
    fs.createReadStream(file).pipe(res);
  });
}

function readBody(req) {
  // Drain-then-reject: keeps the HTTP exchange clean so oversized uploads get
  // a 413 response instead of a hung socket.
  return new Promise((resolve, reject) => {
    const chunks = [];
    let n = 0;
    let overflow = false;
    req.on('data', (c) => {
      n += c.length;
      if (n > MAX_BODY) {
        overflow = true;
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (overflow) reject(new Error('BODY_TOO_LARGE'));
      else resolve(Buffer.concat(chunks));
    });
    req.on('error', reject);
  });
}

async function forward(responderUrl, method, body, inType) {
  let target;
  try {
    target = new URL(responderUrl);
  } catch {
    throw new Error('BAD_URL');
  }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    throw new Error('BAD_URL');
  }
  if (!(await publicHost(target.hostname))) {
    throw new Error('PRIVATE_HOST');
  }
  return new Promise((resolve, reject) => {
    const lib = target.protocol === 'https:' ? https : http;
    const rq = lib.request(
      {
        hostname: target.hostname,
        port: target.port || (target.protocol === 'https:' ? 443 : 80),
        path: target.pathname + target.search,
        method,
        headers: {
          'Content-Type': inType,
          'Content-Length': body.length,
          'Accept': 'application/ocsp-response, application/timestamp-reply',
        },
        timeout: TIMEOUT_MS,
      },
      (rs) => {
        const chunks = [];
        let n = 0;
        let tooBig = false;
        rs.on('data', (c) => {
          n += c.length;
          if (n > MAX_RESPONSE) {
            tooBig = true;
            rs.destroy();
            return;
          }
          chunks.push(c);
        });
        rs.on('end', () => {
          if (tooBig) {
            reject(new Error('UPSTREAM_TOO_LARGE'));
            return;
          }
          resolve({
            status: rs.statusCode,
            type: rs.headers['content-type'] || 'application/octet-stream',
            body: Buffer.concat(chunks),
          });
        });
      }
    );
    rq.on('timeout', () => { rq.destroy(); reject(new Error('UPSTREAM_TIMEOUT')); });
    rq.on('error', () => reject(new Error('UPSTREAM_ERROR')));
    rq.end(body);
  });
}

// Test hook: reset /ocsp rate counters for deterministic tests.
export function _resetOcspRate() {
  buckets.clear();
}

export function createServer() {
  return http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://x');
      if (url.pathname === '/healthz') {
        res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end('ok');
        return;
      }
      if (url.pathname === '/ocsp') {
        // Cross-origin frontend (static site) must be able to read responses,
        // so the proxy answers CORS itself. Upstream responders never see the
        // browser; only serials/hashes transit here.
        const cors = {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Max-Age': '86400',
        };
        if (req.method === 'OPTIONS') {
          res.writeHead(204, cors); res.end();
          return;
        }
        const responder = url.searchParams.get('url') || '';
        const clientIp = (req.socket && req.socket.remoteAddress) || 'unknown';
        if (!rateOk(clientIp)) {
          res.writeHead(429, { 'Access-Control-Allow-Origin': '*' });
          res.end('RATE_LIMITED');
          return;
        }
        if (req.method === 'POST') {
          const body = await readBody(req);
          const out = await forward(responder, 'POST', body,
            req.headers['content-type'] || 'application/ocsp-request');
          res.writeHead(out.status, {
            'Content-Type': out.type,
            'Access-Control-Allow-Origin': '*',
          });
          res.end(out.body);
          return;
        }
        if (req.method === 'GET') {
          const b64 = url.searchParams.get('req') || '';
          const body = Buffer.from(b64.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
          if (!body.length || body.length > MAX_BODY) {
            res.writeHead(400); res.end('bad req');
            return;
          }
          const out = await forward(responder, 'POST', body, 'application/ocsp-request');
          res.writeHead(out.status, {
            'Content-Type': out.type,
            'Access-Control-Allow-Origin': '*',
          });
          res.end(out.body);
          return;
        }
        res.writeHead(405); res.end('method not allowed');
        return;
      }
      if (req.method === 'GET' || req.method === 'HEAD') {
        serveStatic(req, res);
        return;
      }
      res.writeHead(405); res.end('method not allowed');
    } catch (e) {
      const code = e.message === 'BODY_TOO_LARGE' ? 413
        : e.message === 'PRIVATE_HOST' || e.message === 'BAD_URL' ? 400
        : 502;
      res.writeHead(code); res.end(e.message);
    }
  });
}

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  createServer().listen(PORT, () => console.log(`LocalSign on :${PORT}`));
}
