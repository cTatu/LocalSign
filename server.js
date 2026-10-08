// server.js — LocalSign Node server: static files + same-origin OCSP proxy.
//
// Browsers cannot read OCSP/TSA responses cross-origin (no CORS headers on
// responders), so /ocsp is a dumb same-origin pipe: it forwards request bytes
// to an allowlisted responder and streams the response back. It never sees
// private keys, passwords, or documents — only cert identifiers/hashes.
//
//   POST /ocsp?url=<responder-url>   body: OCSP request DER (<=64KB)
//   GET  /ocsp?url=<responder-url>&req=<base64url-DER>
//   GET  /healthz                     -> 200 ok
//
// Env: PORT (default 8000), OCSP_ALLOWLIST (comma hostnames).
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PORT = parseInt(process.env.PORT || '8000', 10);
// Read per call (not at import) so tests and hosting dashboards can inject
// OCSP_ALLOWLIST at runtime.
function allowlist() {
  return new Set(
    (process.env.OCSP_ALLOWLIST ||
      'ocspusu.cert.fnmt.es,ocsp.digicert.com,r11.o.lencr.org,freetsa.org')
      .split(',')
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean)
  );
}
const MAX_BODY = 65536;
const TIMEOUT_MS = 10000;

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

function forward(responderUrl, method, body, inType) {
  return new Promise((resolve, reject) => {
    let target;
    try {
      target = new URL(responderUrl);
    } catch {
      reject(new Error('BAD_URL'));
      return;
    }
    if ((target.protocol !== 'http:' && target.protocol !== 'https:') ||
        !allowlist().has(target.hostname.toLowerCase())) {
      reject(new Error('HOST_NOT_ALLOWED'));
      return;
    }
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
        rs.on('data', (c) => chunks.push(c));
        rs.on('end', () => resolve({
          status: rs.statusCode,
          type: rs.headers['content-type'] || 'application/octet-stream',
          body: Buffer.concat(chunks),
        }));
      }
    );
    rq.on('timeout', () => { rq.destroy(); reject(new Error('UPSTREAM_TIMEOUT')); });
    rq.on('error', () => reject(new Error('UPSTREAM_ERROR')));
    rq.end(body);
  });
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
        : e.message === 'HOST_NOT_ALLOWED' || e.message === 'BAD_URL' ? 400
        : 502;
      res.writeHead(code); res.end(e.message);
    }
  });
}

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  createServer().listen(PORT, () => console.log(`LocalSign on :${PORT}`));
}
