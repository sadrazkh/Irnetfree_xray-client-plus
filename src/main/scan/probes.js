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
 * and chunked answers are the same to it. Connection setup is a latency, not
 * a bandwidth, so `ttfb` is reported apart and the throughput starts at the
 * first body byte: `mbpsRaw` is first byte to last byte, `mbps` leaves out the
 * first `warmupMs` after the first byte as well — TCP slow start ramps up
 * during that time and a mean over the ramp understates every link the same
 * way a shared one does.
 */
const net = require('net');
const tls = require('tls');
const { socks5Connect } = require('../netutils');
const { delayStats, needOf } = require('./score');

const DELAY_DEFAULTS = { n: 3, host: 'cp.cloudflare.com', port: 80, path: '/', timeout: 8000, expect: '204', passRatio: 0.66 };
const DOWN_DEFAULTS = { host: 'speed.cloudflare.com', port: 443, path: '/__down?bytes=10000000', tls: true, bytes: 10e6, maxMs: 6000, timeout: 8000, warmupMs: 300, rejectUnauthorized: true };
const UP_DEFAULTS = { host: 'speed.cloudflare.com', port: 443, path: '/__up', tls: true, bytes: 2e6, timeout: 20000, rejectUnauthorized: true };
const UA = 'IRNetFree-scan';
const MIN_INTERVAL_S = 0.05;     // a one-chunk body would otherwise divide by ~0

const errName = (e) => (e && (e.code || e.message)) || String(e);
const round2 = (v) => Math.round(v * 100) / 100;
const mbpsOf = (bytes, ms) => (bytes > 0 ? round2(bytes * 8 / 1e6 / Math.max(MIN_INTERVAL_S, ms / 1000)) : 0);

function failure(error, extra) {
  return Object.assign({ ok: false, bytes: 0, ms: -1, ttfb: -1, mbps: 0, mbpsRaw: 0, warm: false, error }, extra);
}

/**
 * throughputMeter(warmupMs) → { add(now, n), bytes, first, last, stats() }
 * Counts body chunks as they arrive. stats() gives `mbpsRaw` over first byte
 * to last byte and `mbps` over the bytes that arrived `warmupMs` or later
 * after the first byte, against that shorter interval (never under 50 ms).
 * A transfer that ended inside the warm-up has nothing warm to measure, so
 * `mbps` falls back to `mbpsRaw` and `warm` says so. Pure, so the arithmetic
 * is tested with made-up arrival times.
 */
function throughputMeter(warmupMs) {
  const warmup = Math.max(0, Number(warmupMs) || 0);
  const m = { bytes: 0, first: 0, last: 0, started: false };
  let warmBytes = 0;
  m.add = (now, n) => {
    if (!m.started) { m.started = true; m.first = now; }
    m.last = now;
    m.bytes += n;
    if (now - m.first >= warmup) warmBytes += n;
  };
  m.stats = () => {
    const mbpsRaw = mbpsOf(m.bytes, m.last - m.first);
    const warm = m.started && m.last - m.first >= warmup;
    return { mbpsRaw, warm, mbps: warm ? mbpsOf(warmBytes, m.last - m.first - warmup) : mbpsRaw };
  };
  return m;
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
 * downloadThroughProxy(socksPort, { host, port, path, tls, bytes, maxMs, timeout, warmupMs, rejectUnauthorized })
 *   → { ok, bytes, ms, ttfb, mbps, mbpsRaw, warm, error }
 * Stops at `bytes`, at end of stream, or `maxMs` after the first body byte.
 * `timeout` bounds the connect, the wait for headers, and any idle gap.
 * `ttfb` is the wait for the first body byte; `mbps` and `mbpsRaw` are what
 * throughputMeter says about the body.
 */
function downloadThroughProxy(socksPort, opts = {}) {
  const o = Object.assign({}, DOWN_DEFAULTS, opts);
  const start = Date.now();
  return new Promise((resolve) => {
    openStream(socksPort, o).then((stream) => {
      let done = false, headerDone = false, head = Buffer.alloc(0), maxTimer = null;
      const meter = throughputMeter(o.warmupMs);
      const finish = (r) => {
        if (done) return;
        done = true;
        if (maxTimer) clearTimeout(maxTimer);
        try { stream.destroy(); } catch { /* gone */ }
        resolve(r);
      };
      const stats = (ok, error) => Object.assign(
        { ok, bytes: meter.bytes, ms: Date.now() - start, ttfb: meter.started ? meter.first - start : -1 },
        meter.stats(), { error: error || null }
      );
      // a failure once the body has started keeps the partial numbers
      const fail = (error) => finish(meter.bytes ? stats(false, error) : failure(error, { ms: Date.now() - start }));

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
        if (!meter.started) maxTimer = setTimeout(() => finish(stats(true)), o.maxMs);
        meter.add(now, d.length);
        if (meter.bytes >= o.bytes) finish(stats(true));
      });
      stream.on('end', () => (meter.bytes ? finish(stats(true)) : fail('closed')));
      stream.on('close', () => (meter.bytes ? finish(stats(true)) : fail('closed')));
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

/* --------------------------- what a pass means (2026-11-01) --------------------------- */

/*
 * The owner: "a result must mean what it says — fewer false positives and
 * negatives". What the code did before, and why it was not enough:
 *  - the delay probe was upstream's httpThroughProxy, which counts ANY status
 *    below 500 as an answer — a 403 or 404 page some box in the path wrote
 *    passed as a working tunnel. The probe below takes the status the probe
 *    page is known to give (cp.cloudflare.com and the probe's own page: 204)
 *    and calls anything else a wrong answer;
 *  - a row with one answered sample out of two was alive (loss < 1) — one
 *    lucky answer was a pass. score.js now asks for passRatio of the samples;
 *  - the first failed sample ended the series, so one dropped packet on a
 *    good target made it dead. Now a TIMEOUT — the failure a busy machine or a
 *    slow moment makes — is tried again; a definitive no (the tunnel closed,
 *    the proxy refused, a wrong answer) still ends it at once, and so does a
 *    series that can no longer pass;
 *  - a failure said only "timeout" or "closed"; every probe now says WHERE it
 *    failed (`reason`), and the row shows it.
 */

/** The reasons a row can carry, in the order a target meets them. */
const REASONS = ['no-tcp', 'tls', 'core', 'proxy-refused', 'proxy-closed', 'timeout', 'wrong-answer', 'unstable', 'download-failed'];
/** A failure that is an answer: trying the same thing again would only cost the time. */
const DEFINITIVE = new Set(['core', 'proxy-refused', 'proxy-closed', 'wrong-answer']);

/**
 * readExpect('204' | '200-299' | '200,204' | '2xx' | '') → (status) → boolean, or null when it does not read.
 * Empty is 200–399: a page that answers at all, as long as it is not an error.
 */
function readExpect(text) {
  const s = String(text == null ? '' : text).trim().toLowerCase();
  if (!s) return (c) => c >= 200 && c < 400;
  const parts = s.split(/[\s,]+/).filter(Boolean);
  const tests = [];
  for (const p of parts) {
    let m;
    if ((m = /^([1-5])xx$/.exec(p))) { const h = Number(m[1]) * 100; tests.push((c) => c >= h && c < h + 100); continue; }
    if ((m = /^(\d{3})(?:-(\d{3}))?$/.exec(p))) {
      const a = Number(m[1]), b = m[2] ? Number(m[2]) : a;
      if (a < 100 || b > 599 || b < a) return null;
      tests.push((c) => c >= a && c <= b);
      continue;
    }
    return null;
  }
  return (c) => tests.some((t) => t(c));
}

/** A socks5Connect failure, by where it happened. */
function socksReason(e) {
  const m = String((e && (e.code || e.message)) || e || '');
  if (/ECONNREFUSED|ECONNRESET.*127\.0\.0\.1/i.test(m)) return 'core';
  if (/timeout/i.test(m)) return 'timeout';
  if (/connect failed code/i.test(m)) return 'proxy-refused';
  return 'proxy-closed';
}

/**
 * tunnelGet(socksPort, { host, port, path, timeout, expect }) → { ok, ms, status, reason, error }
 *
 * One GET through the core: SOCKS5 CONNECT, the request, the status line —
 * timed from before the CONNECT (what a user's first request waits). `ok`
 * only when the status is one `expect` accepts (readExpect). `reason`:
 * 'core' (nothing listens on the SOCKS port), 'proxy-refused' (the core
 * refused the CONNECT), 'proxy-closed' (the tunnel closed before an answer:
 * the server refused the handshake or could not be reached), 'timeout',
 * 'wrong-answer' (`status` says which).
 */
function tunnelGet(socksPort, opts = {}) {
  const o = Object.assign({}, DELAY_DEFAULTS, opts);
  const accept = typeof o.expect === 'function' ? o.expect : (readExpect(o.expect) || readExpect(''));
  const start = Date.now();
  const bad = (reason, error, extra) => Object.assign({ ok: false, ms: -1, status: 0, reason, error: error || reason }, extra);
  return socks5Connect('127.0.0.1', socksPort, o.host, o.port, o.timeout).then((socket) => new Promise((resolve) => {
    let done = false, buf = '';
    const finish = (r) => { if (done) return; done = true; clearTimeout(to); try { socket.destroy(); } catch { /* gone */ } resolve(r); };
    const left = Math.max(1, o.timeout - (Date.now() - start));
    const to = setTimeout(() => finish(bad('timeout')), left);
    socket.on('data', (d) => {
      buf += d.toString('latin1');
      const nl = buf.indexOf('\r\n');
      if (nl === -1) { if (buf.length > 8192) finish(bad('wrong-answer', 'no status line')); return; }
      const status = statusOf(buf.slice(0, nl));
      if (!status) return finish(bad('wrong-answer', 'not HTTP'));
      if (!accept(status)) return finish(bad('wrong-answer', 'HTTP ' + status, { status }));
      return finish({ ok: true, ms: Date.now() - start, status, reason: '', error: null });
    });
    socket.on('error', (e) => finish(bad('proxy-closed', errName(e))));
    socket.on('close', () => finish(bad('proxy-closed', 'closed')));
    socket.write(`GET ${o.path} HTTP/1.1\r\nHost: ${o.host}\r\nUser-Agent: ${UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n`);
  }), (e) => bad(socksReason(e), errName(e)));
}

/**
 * delaySeries(socksPort, { n, host, port, path, timeout, expect, passRatio }) → delayStats + { reason, status }
 *
 * `n` GETs in a row through the tunnel (tunnelGet). A definitive failure
 * before any success ends the series — a dead target costs one try, not n —
 * and so does a series that can no longer reach passRatio; a timeout is
 * tried again. Every sample not taken counts as lost. `reason` is the first
 * failure's ('' when none), `status` a wrong answer's.
 */
async function delaySeries(socksPort, opts = {}) {
  const o = Object.assign({}, DELAY_DEFAULTS, opts);
  const n = Math.max(1, Math.floor(Number(o.n) || DELAY_DEFAULTS.n));
  const need = needOf(n, o.passRatio);
  const get = typeof o.get === 'function' ? o.get : tunnelGet;
  const samples = [];
  let reason = '', status = 0, okCount = 0, failed = 0;
  for (let i = 0; i < n; i++) {
    const r = await get(socksPort, { host: o.host, port: o.port, path: o.path, timeout: o.timeout, expect: o.expect });
    samples.push(r.ok ? r.ms : -1);
    if (r.ok) { okCount++; continue; }
    failed++;
    if (!reason) { reason = r.reason || 'timeout'; status = r.status || 0; }
    const hopeless = n - failed < need;
    if (hopeless || (okCount === 0 && DEFINITIVE.has(r.reason))) break;
  }
  while (samples.length < n) samples.push(-1);
  return Object.assign(delayStats(samples), { reason, status });
}

/**
 * tlsPing(host, port, { servername, timeout }) → { ok, ms, reason, error }
 *
 * The pre-check's TLS step: a TCP connect and a TLS handshake under the SNI
 * the config sends, nothing more (no certificate check — a pin or a fronted
 * name is the core's business; the question is only "does this address finish
 * a handshake for this name"). 'no-tcp' when the connect fails, 'tls' when the
 * handshake does. `ms` is the handshake's end.
 */
function tlsPing(host, port, opts = {}) {
  const timeout = Number(opts.timeout) || 3000;
  const start = Date.now();
  return new Promise((resolve) => {
    let connected = false, done = false;
    const sock = net.connect({ host, port });
    let secure = null;
    const finish = (r) => {
      if (done) return;
      done = true;
      clearTimeout(to);
      try { (secure || sock).destroy(); } catch { /* gone */ }
      resolve(r);
    };
    const fail = (e) => finish({ ok: false, ms: -1, reason: connected ? 'tls' : 'no-tcp', error: errName(e) });
    const to = setTimeout(() => fail(new Error('timeout')), timeout);
    sock.once('error', fail);
    sock.once('connect', () => {
      connected = true;
      const o = { socket: sock, rejectUnauthorized: false, ALPNProtocols: Array.isArray(opts.alpn) && opts.alpn.length ? opts.alpn : undefined };
      if (opts.servername && net.isIP(opts.servername) === 0) o.servername = opts.servername;
      secure = tls.connect(o, () => finish({ ok: true, ms: Date.now() - start, reason: '', error: null }));
      secure.once('error', fail);
    });
  });
}

module.exports = {
  downloadThroughProxy, uploadThroughProxy, delaySeries, tunnelGet, tlsPing, readExpect, needOf, throughputMeter,
  REASONS, DELAY_DEFAULTS, DOWN_DEFAULTS, UP_DEFAULTS
};
