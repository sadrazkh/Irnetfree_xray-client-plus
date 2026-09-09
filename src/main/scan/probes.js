'use strict';
/**
 * plus: what the IP scanner measures through one SOCKS5 port of a throwaway
 * core. Every probe resolves; a failure is `{ ok: false, error }` and a
 * timeout is `error: 'timeout'`, so a batch of twenty never has one bad IP
 * throw the rest away.
 *
 * The download speaks HTTP/1.1 itself over the tunnelled socket (wrapped in
 * tls.connect for https), because http.request cannot ride a socket we
 * already hold and an Agent per port is more machinery than a GET needs. The
 * body is counted as raw bytes after the header terminator, so Content-Length
 * and chunked answers are the same to it. Throughput is first body byte to
 * last body byte — connection setup is a latency, not a bandwidth.
 */
const net = require('net');
const tls = require('tls');
const { socks5Connect, httpThroughProxy } = require('../netutils');
const { delayStats } = require('./score');

const DELAY_DEFAULTS = { n: 3, host: 'cp.cloudflare.com', port: 80, path: '/', timeout: 8000 };
const DOWN_DEFAULTS = { host: 'speed.cloudflare.com', port: 443, path: '/__down?bytes=10000000', tls: true, bytes: 10e6, maxMs: 8000, timeout: 8000, rejectUnauthorized: true };
const UP_DEFAULTS = { host: 'speed.cloudflare.com', port: 443, path: '/__up', tls: true, bytes: 2e6, timeout: 20000, rejectUnauthorized: true };
const UA = 'IRNetFree-scan';
const MIN_INTERVAL_S = 0.05;     // a one-chunk body would otherwise divide by ~0

const errName = (e) => (e && (e.code || e.message)) || String(e);
const round2 = (v) => Math.round(v * 100) / 100;
const mbpsOf = (bytes, ms) => (bytes > 0 ? round2(bytes * 8 / 1e6 / Math.max(MIN_INTERVAL_S, ms / 1000)) : 0);

function failure(error, extra) {
  return Object.assign({ ok: false, bytes: 0, ms: -1, ttfb: -1, mbps: 0, error }, extra);
}

/**
 * SOCKS5 CONNECT to host:port, then TLS on top when asked. Resolves the
 * stream to speak HTTP on; rejects with a plain Error otherwise.
 */
function openStream(socksPort, o) {
  return socks5Connect('127.0.0.1', socksPort, o.host, o.port, o.timeout).then((raw) => {
    if (!o.tls) return raw;
    return new Promise((resolve, reject) => {
      const opts = { socket: raw, ALPNProtocols: ['http/1.1'], rejectUnauthorized: o.rejectUnauthorized !== false };
      if (net.isIP(o.host) === 0) opts.servername = o.host;      // SNI only for a name (RFC 6066)
      let settled = false;
      const done = (err, s) => {
        if (settled) return;
        settled = true;
        clearTimeout(to);
        if (err) { try { raw.destroy(); } catch { /* gone */ } reject(err); } else resolve(s);
      };
      const to = setTimeout(() => done(new Error('timeout')), o.timeout);
      const secure = tls.connect(opts, () => done(null, secure));
      secure.once('error', (e) => done(e));
      raw.once('close', () => done(new Error('closed')));
    });
  });
}

/** Parse "HTTP/1.1 200 OK" → 200 (0 when it is not a status line). */
function statusOf(line) {
  const m = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(line);
  return m ? Number(m[1]) : 0;
}

/**
 * downloadThroughProxy(socksPort, { host, port, path, tls, bytes, maxMs, timeout, rejectUnauthorized })
 *   → { ok, bytes, ms, ttfb, mbps, error }
 * Stops at `bytes`, at end of stream, or `maxMs` after the first body byte.
 * `timeout` bounds the connect, the wait for headers, and any idle gap.
 */
function downloadThroughProxy(socksPort, opts = {}) {
  const o = Object.assign({}, DOWN_DEFAULTS, opts);
  const start = Date.now();
  return new Promise((resolve) => {
    openStream(socksPort, o).then((stream) => {
      let done = false, headerDone = false, head = Buffer.alloc(0);
      let bytes = 0, tFirst = 0, tLast = 0, maxTimer = null;
      const finish = (r) => {
        if (done) return;
        done = true;
        if (maxTimer) clearTimeout(maxTimer);
        try { stream.destroy(); } catch { /* gone */ }
        resolve(r);
      };
      const stats = (ok, error) => ({
        ok, bytes, ms: Date.now() - start, ttfb: tFirst ? tFirst - start : -1,
        mbps: mbpsOf(bytes, tLast - tFirst), error: error || null
      });
      // a failure once the body has started keeps the partial numbers
      const fail = (error) => finish(bytes ? stats(false, error) : failure(error, { ms: Date.now() - start }));

      stream.setTimeout(o.timeout, () => fail('timeout'));
      stream.on('data', (d) => {
        const now = Date.now();
        if (!headerDone) {
          head = Buffer.concat([head, d]);
          const idx = head.indexOf('\r\n\r\n');
          if (idx === -1) { if (head.length > 65536) fail('bad response'); return; }
          headerDone = true;
          const status = statusOf(head.subarray(0, idx).toString('latin1'));
          if (status < 200 || status >= 300) return fail('HTTP ' + status);
          d = head.subarray(idx + 4);
          head = null;
          if (!d.length) return;
        }
        if (!tFirst) { tFirst = now; maxTimer = setTimeout(() => finish(stats(true)), o.maxMs); }
        tLast = now;
        bytes += d.length;
        if (bytes >= o.bytes) finish(stats(true));
      });
      stream.on('end', () => (bytes ? finish(stats(true)) : fail('closed')));
      stream.on('close', () => (bytes ? finish(stats(true)) : fail('closed')));
      stream.on('error', (e) => fail(errName(e)));
      stream.write(`GET ${o.path} HTTP/1.1\r\nHost: ${o.host}\r\nUser-Agent: ${UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n`);
    }, (e) => resolve(failure(errName(e), { ms: Date.now() - start })));
  });
}

/**
 * uploadThroughProxy(socksPort, { host, port, path, tls, bytes, timeout, rejectUnauthorized })
 *   → { ok, bytes, ms, ttfb, mbps, error }
 * POSTs `bytes` zeros with a Content-Length and waits for the status line;
 * `ttfb` is when it arrived, `mbps` is the body against that time.
 */
function uploadThroughProxy(socksPort, opts = {}) {
  const o = Object.assign({}, UP_DEFAULTS, opts);
  const start = Date.now();
  return new Promise((resolve) => {
    openStream(socksPort, o).then((stream) => {
      let done = false, sent = 0, tFirst = 0, head = Buffer.alloc(0);
      const finish = (r) => {
        if (done) return;
        done = true;
        try { stream.destroy(); } catch { /* gone */ }
        resolve(r);
      };
      const fail = (error) => finish(failure(error, { bytes: sent, ms: Date.now() - start }));

      stream.setTimeout(o.timeout, () => fail('timeout'));
      stream.on('data', (d) => {
        head = Buffer.concat([head, d]);
        const nl = head.indexOf('\r\n');
        if (nl === -1) { if (head.length > 65536) fail('bad response'); return; }
        const status = statusOf(head.subarray(0, nl).toString('latin1'));
        if (status < 200 || status >= 300) return fail('HTTP ' + status);
        const now = Date.now();
        finish({ ok: true, bytes: sent, ms: now - start, ttfb: now - start, mbps: mbpsOf(sent, now - tFirst), error: null });
      });
      stream.on('close', () => fail('closed'));
      stream.on('error', (e) => fail(errName(e)));
      stream.write(
        `POST ${o.path} HTTP/1.1\r\nHost: ${o.host}\r\nUser-Agent: ${UA}\r\n` +
        `Content-Type: application/octet-stream\r\nContent-Length: ${o.bytes}\r\nConnection: close\r\n\r\n`
      );
      tFirst = Date.now();
      const chunk = Buffer.alloc(65536);
      const pump = () => {
        while (!done && sent < o.bytes) {
          const n = Math.min(chunk.length, o.bytes - sent);
          const ok = stream.write(n === chunk.length ? chunk : chunk.subarray(0, n));
          sent += n;
          if (!ok) { stream.once('drain', pump); return; }
        }
      };
      pump();
    }, (e) => resolve(failure(errName(e), { ms: Date.now() - start })));
  });
}

/**
 * delaySeries(socksPort, { n, host, port, path, timeout }) → delayStats
 * `n` GETs in a row through the tunnel. A first request that fails ends the
 * series with the rest counted as lost: a dead IP costs one timeout, not n.
 */
async function delaySeries(socksPort, opts = {}) {
  const o = Object.assign({}, DELAY_DEFAULTS, opts);
  const n = Math.max(1, Math.floor(Number(o.n) || DELAY_DEFAULTS.n));
  const samples = [];
  for (let i = 0; i < n; i++) {
    const r = await httpThroughProxy(socksPort, { host: o.host, port: o.port, path: o.path, timeout: o.timeout });
    samples.push(r.ok ? r.ms : -1);
    if (i === 0 && !r.ok) { while (samples.length < n) samples.push(-1); break; }
  }
  return delayStats(samples);
}

module.exports = { downloadThroughProxy, uploadThroughProxy, delaySeries, DELAY_DEFAULTS, DOWN_DEFAULTS, UP_DEFAULTS };
