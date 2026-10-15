#!/usr/bin/env node
'use strict';
/**
 * IRNetFree Plus, headless: the same pages as the desktop app over HTTP, for a
 * machine without a screen — a VPS running the Server tab, as 3x-ui does — and
 * for development. The one service (src/main/plus/service.js) behind a small
 * RPC (POST /rpc { channel, arg }) and Server-Sent Events (/events). Node core
 * only.
 *
 *   node src/server/server.js [--port 6970] [--host 127.0.0.1] [--token SECRET]
 *                             [--token-file /path] [--data-dir /path] [--no-auth]
 *
 * Bound to 127.0.0.1 by default (reach it with `ssh -L`). Any other address
 * needs a token: made and printed when none is given, or kept in --token-file.
 * The DNS-rebinding and cross-origin guards are upstream's (guard.js).
 */
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { createPlusService } = require('../main/plus/service');
const { INVOKE, EVENTS, WINDOW } = require('../main/plus/apiMap');
const { hostAllowed, originAllowed } = require('./guard');

process.on('unhandledRejection', (e) => { console.error('  ! unhandled rejection (still running): ' + ((e && e.stack) || e)); });
for (const s of [process.stdout, process.stderr]) s.on('error', () => {});

function parseArgs(argv) {
  const a = { port: 6970, host: '127.0.0.1', token: null, tokenFile: null, dataDir: null, noAuth: false };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    const val = () => argv[++i];
    if (k === '--port' || k === '-p') { const n = parseInt(val(), 10); if (Number.isInteger(n) && n >= 0) a.port = n; }
    else if (k === '--host' || k === '-h') a.host = val();
    else if (k === '--token' || k === '-t') a.token = val();
    else if (k === '--token-file') a.tokenFile = val();
    else if (k === '--data-dir' || k === '-d') a.dataDir = val();
    else if (k === '--no-auth') a.noAuth = true;
  }
  return a;
}

/** The token in `file`, or a new one written there (0600) when it is missing or empty. */
function tokenFromFile(file) {
  let t = '';
  try { t = fs.readFileSync(file, 'utf8').trim(); } catch { /* made below */ }
  if (t) return t;
  t = crypto.randomBytes(16).toString('hex');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, t + '\n', { mode: 0o600 });
  return t;
}

const args = parseArgs(process.argv.slice(2));
const isLoopback = args.host === '127.0.0.1' || args.host === '::1' || args.host === 'localhost';
if (args.tokenFile && !args.token) {
  try { args.token = tokenFromFile(args.tokenFile); }
  catch (e) { console.error('\n  Cannot read or create the token file ' + args.tokenFile + ': ' + e.message + '\n'); process.exit(1); }
}
if (!isLoopback && !args.token && !args.noAuth) args.token = crypto.randomBytes(16).toString('hex');
const TOKEN = args.token;

const RENDERER = path.join(__dirname, '..', 'renderer');
const ASSETS = path.join(__dirname, '..', '..', 'assets');
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.woff2': 'font/woff2', '.woff': 'font/woff'
};
const mimeFor = (p) => MIME[path.extname(p).toLowerCase()] || 'application/octet-stream';
const version = (() => { try { return require('../../package.json').version; } catch { return '0.0.0'; } })();
// its own folder by default: a desktop Plus on the same machine keeps its store to itself
const dataDir = path.resolve(args.dataDir || process.env.IRNF_PLUS_DATA || path.join(os.homedir(), '.irnetfree-plus'));

/** The page with the HTTP bridge loaded ahead of everything else. */
function indexHtml() {
  const html = fs.readFileSync(path.join(RENDERER, 'index.html'), 'utf8');
  return html.replace(/<script /, '<script src="__api.js"></script>\n  <script ');
}
const apiScript = () => 'window.__PLUS_API__ = ' + JSON.stringify({ INVOKE, EVENTS, WINDOW }) + ';\n' + fs.readFileSync(path.join(__dirname, 'web-api.js'), 'utf8');

const sse = new Set();
const service = createPlusService({
  dataDir, version, platform: process.platform, isElectron: false,
  send: (channel, payload) => {
    const line = 'data: ' + JSON.stringify({ channel, payload }) + '\n\n';
    for (const res of sse) { try { res.write(line); } catch { /* gone */ } }
  }
});

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a, 'utf8'), y = Buffer.from(b, 'utf8');
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
const authed = (req, url) => !TOKEN || safeEqual(url.searchParams.get('token'), TOKEN) || safeEqual(req.headers['x-irnetfree-token'], TOKEN);

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
function sendFile(res, file) {
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); res.end('not found'); return; }
    res.writeHead(200, { 'Content-Type': mimeFor(file), 'Cache-Control': 'no-cache' });
    res.end(data);
  });
}
function readBody(req) {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', (c) => { b += c; if (b.length > 5e6) req.destroy(); });
    req.on('end', () => resolve(b));
  });
}

async function handle(req, res) {
  if (!hostAllowed(req.headers.host, { token: TOKEN, noAuth: args.noAuth, loopbackBind: isLoopback })) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    return res.end('forbidden host');
  }
  let url;
  try { url = new URL(req.url, 'http://localhost'); } catch { res.writeHead(400); return res.end('bad request'); }
  const p = url.pathname;

  if (p === '/rpc' && req.method === 'POST') {
    if (!authed(req, url)) return sendJson(res, 401, { error: 'unauthorized' });
    if (!originAllowed(req.headers)) return sendJson(res, 403, { error: 'cross-origin request refused' });
    let body;
    try { body = JSON.parse((await readBody(req)) || '{}'); } catch { return sendJson(res, 400, { error: 'bad json' }); }
    if (body.channel === 'app:quit') {
      sendJson(res, 200, { result: { ok: true } });
      return stop('app:quit');
    }
    try {
      const result = await service.invoke(body.channel, body.arg);
      return sendJson(res, 200, { result: result === undefined ? null : result });
    } catch (e) { return sendJson(res, 200, { error: (e && e.message) || String(e) }); }
  }

  if (p === '/events') {
    if (!authed(req, url)) return sendJson(res, 401, { error: 'unauthorized' });
    if (!originAllowed(req.headers)) return sendJson(res, 403, { error: 'cross-origin request refused' });
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    res.write('retry: 3000\n\n');
    sse.add(res);
    const ping = setInterval(() => { try { res.write(': ping\n\n'); } catch { /* gone */ } }, 25000);
    req.on('close', () => { clearInterval(ping); sse.delete(res); });
    return undefined;
  }

  if (req.method !== 'GET') { res.writeHead(405); return res.end('method not allowed'); }
  if (p === '/' || p === '/index.html') {
    if (!authed(req, url)) { res.writeHead(401, { 'Content-Type': 'text/plain' }); return res.end('unauthorized — open with ?token=...'); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    return res.end(indexHtml());
  }
  if (p === '/__api.js') {
    res.writeHead(200, { 'Content-Type': MIME['.js'], 'Cache-Control': 'no-cache' });
    return res.end(apiScript());
  }
  if (p.startsWith('/assets/')) {
    const file = path.join(ASSETS, path.normalize(p.slice('/assets/'.length)));
    if (!file.startsWith(ASSETS + path.sep)) { res.writeHead(403); return res.end('forbidden'); }
    return sendFile(res, file);
  }
  const file = path.join(RENDERER, path.normalize(p).replace(/^(\.\.[/\\])+/, ''));
  if (!file.startsWith(RENDERER + path.sep)) { res.writeHead(403); return res.end('forbidden'); }
  return sendFile(res, file);
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((e) => {
    console.error('  ! request failed: ' + ((e && e.message) || e));
    try { if (!res.headersSent) res.writeHead(500); res.end(); } catch { /* gone */ }
  });
});
server.on('error', (e) => {
  console.error(e.code === 'EADDRINUSE' ? `\n  Port ${args.port} is in use — pick another with --port <n>.\n` : '\n  Server error: ' + (e.message || e) + '\n');
  process.exit(1);
});
server.listen(args.port, args.host, () => {
  const port = server.address().port;
  const q = TOKEN && !args.tokenFile ? '?token=' + TOKEN : '';
  console.log('');
  console.log('  IRNetFree Plus (headless) — v' + version);
  console.log('  Data dir : ' + dataDir);
  console.log('  Listening: http://' + (isLoopback ? '127.0.0.1' : args.host) + ':' + port + '/' + q);
  if (isLoopback) console.log('  Bound to localhost — from another machine: ssh -N -L ' + port + ':127.0.0.1:' + port + ' user@HOST');
  console.log('');
});

let stopping = false;
async function stop(why) {
  if (stopping) return;
  stopping = true;
  console.log('\nShutting down (' + why + ')…');
  try { await service.shutdown(); } catch { /* exiting anyway */ }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGINT', () => stop('SIGINT'));
process.on('SIGTERM', () => stop('SIGTERM'));
