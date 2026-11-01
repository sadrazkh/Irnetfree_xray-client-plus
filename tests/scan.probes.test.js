'use strict';
/**
 * IP-scan probes: download, upload and delay through a SOCKS5 port.
 *
 * Everything runs on 127.0.0.1 with ephemeral ports: a SOCKS5 stub routes a
 * CONNECT by the requested host name to a local byte server, plain or TLS
 * (the self-signed fixture from certPin.test.js; its expiry does not matter
 * because the TLS tests turn verification off, and one test checks that the
 * default does verify). What matters: byte counts are exact, timings are
 * sane, `maxMs` caps a download that would never end, the warm-up arithmetic
 * is exact on made-up arrival times and shows up in a real download, every
 * failure comes back as a value (never a rejection), and the TLS wrap sends
 * SNI and ALPN.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');
const fs = require('node:fs');
const path = require('node:path');

const { downloadThroughProxy, uploadThroughProxy, delaySeries, throughputMeter, DOWN_DEFAULTS } = require('../src/main/scan/probes');

const FIXTURE = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'selfsigned.json'), 'utf8'));
const CERT = FIXTURE.certificate.join('\n');
const KEY = FIXTURE.key.join('\n');

/* ----------------------------- local servers ----------------------------- */

/** The byte server both the plain and the TLS listener share. */
function makeHandler(log) {
  return (req, res) => {
    const u = new URL(req.url, 'http://x');
    log.push({ method: req.method, url: req.url, host: req.headers.host });
    if (u.pathname === '/down') {
      const n = Number(u.searchParams.get('bytes'));
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': n });
      const chunk = Buffer.alloc(65536, 0x41);
      let sent = 0;
      const pump = () => {
        while (sent < n) {
          const k = Math.min(chunk.length, n - sent);
          sent += k;
          if (!res.write(k === chunk.length ? chunk : chunk.subarray(0, k))) { res.once('drain', pump); return; }
        }
        res.end();
      };
      pump();
    } else if (u.pathname === '/slow') {
      // chunked, never-ending: 4 KB every 15 ms until the client goes away
      res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
      const t = setInterval(() => { if (!res.write(Buffer.alloc(4096, 0x42))) { /* backpressure: just skip a tick */ } }, 15);
      res.on('close', () => clearInterval(t));
    } else if (u.pathname === '/hang') {
      // never answers; the test tears the socket down
      req.on('data', () => {});
    } else if (u.pathname === '/up' && req.method === 'POST') {
      let n = 0;
      req.on('data', (d) => { n += d.length; });
      req.on('end', () => { log.push({ received: n }); res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ received: n })); });
    } else if (u.pathname === '/') {
      res.writeHead(204); res.end();
    } else {
      res.writeHead(404); res.end('nope');
    }
  };
}

/** A SOCKS5 server that CONNECTs by the requested host name to a local port. */
function socksStub(routes) {
  const srv = net.createServer((sock) => {
    sock.on('error', () => {});
    let stage = 0, buf = Buffer.alloc(0);
    const refuse = () => { try { sock.end(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])); } catch { /* gone */ } };
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0) {
        if (buf.length < 2 || buf.length < 2 + buf[1]) return;
        buf = buf.subarray(2 + buf[1]);
        sock.write(Buffer.from([5, 0]));
        stage = 1;
        if (!buf.length) return;
      }
      if (stage === 1) {
        if (buf.length < 5) return;
        const atyp = buf[3];
        let host, need;
        if (atyp === 3) { need = 5 + buf[4] + 2; if (buf.length < need) return; host = buf.subarray(5, 5 + buf[4]).toString(); }
        else if (atyp === 1) { need = 10; if (buf.length < need) return; host = [...buf.subarray(4, 8)].join('.'); }
        else return refuse();
        const rest = buf.subarray(need);
        stage = 2;
        const target = routes[host];
        if (!target) return refuse();
        const up = net.connect(target, '127.0.0.1', () => {
          sock.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, target >> 8, target & 255]));
          if (rest.length) up.write(rest);
          sock.removeListener('data', onData);
          sock.pipe(up); up.pipe(sock);
        });
        up.on('error', () => { refuse(); try { sock.destroy(); } catch { /* gone */ } });
        sock.on('close', () => up.destroy());
      }
    };
    sock.on('data', onData);
  });
  return srv;
}

const listen = (srv) => new Promise((r) => srv.listen(0, '127.0.0.1', () => r(srv.address().port)));

/** The whole local rig; `fn(rig)` runs with it up, then everything is torn down. */
async function withRig(fn) {
  const log = [];
  const handler = makeHandler(log);
  const plain = http.createServer(handler);
  const sni = [], alpn = [];
  const secure = https.createServer({
    cert: CERT, key: KEY, ALPNProtocols: ['http/1.1'],
    SNICallback: (name, cb) => { sni.push(name); cb(null, tls.createSecureContext({ cert: CERT, key: KEY })); }
  }, handler);
  secure.on('secureConnection', (s) => alpn.push(s.alpnProtocol));
  const plainPort = await listen(plain);
  const tlsPort = await listen(secure);
  const socks = socksStub({ 'plain.test': plainPort, 'tls.test': tlsPort, 'dead.test': 1 });
  const socksPort = await listen(socks);
  try {
    return await fn({ socksPort, plainPort, tlsPort, log, sni, alpn });
  } finally {
    for (const s of [plain, secure, socks]) { try { s.closeAllConnections && s.closeAllConnections(); } catch { /* none */ } }
    await Promise.all([plain, secure, socks].map((s) => new Promise((r) => s.close(() => r()))));
  }
}

const DOWN_SHAPE = ['ok', 'bytes', 'ms', 'ttfb', 'mbps', 'mbpsRaw', 'warm', 'error'].sort();
const UP_SHAPE = ['ok', 'bytes', 'ms', 'ttfb', 'mbps', 'error'].sort();
const assertDown = (r) => assert.deepEqual(Object.keys(r).sort(), DOWN_SHAPE, JSON.stringify(r));
const assertUp = (r) => assert.deepEqual(Object.keys(r).sort(), UP_SHAPE, JSON.stringify(r));

/* ----------------------------- warm-up arithmetic ----------------------------- */

test('throughputMeter: mbps leaves out the warm-up after the first byte, mbpsRaw does not', () => {
  const m = throughputMeter(300);
  for (const [t, n] of [[0, 1e6], [100, 1e6], [400, 1e6], [700, 1e6]]) m.add(t, n);
  assert.equal(m.bytes, 4e6);
  assert.equal(m.first, 0, 'a first chunk at t=0 still counts as the first');
  assert.equal(m.last, 700);
  const s = m.stats();
  assert.equal(s.mbpsRaw, 45.71, '32 Mb over the whole 0.7 s');
  assert.equal(s.mbps, 40, 'the 16 Mb that arrived from t=300 on, over the 0.4 s after the warm-up');
  assert.equal(s.warm, true);
});

test('throughputMeter: a transfer that ends inside the warm-up falls back to the raw figure and says so', () => {
  const m = throughputMeter(1000);
  m.add(0, 5e5); m.add(200, 5e5);
  assert.deepEqual(m.stats(), { mbpsRaw: 40, mbps: 40, warm: false });
});

test('throughputMeter: warm-up 0 is the raw figure; one chunk uses the 50 ms floor; nothing received is 0', () => {
  const zero = throughputMeter(0);
  zero.add(0, 1e6); zero.add(250, 1e6);
  assert.deepEqual(zero.stats(), { mbpsRaw: 64, mbps: 64, warm: true });
  const one = throughputMeter(0);
  one.add(5, 1e6);
  assert.deepEqual(one.stats(), { mbpsRaw: 160, mbps: 160, warm: true });
  assert.deepEqual(throughputMeter(300).stats(), { mbpsRaw: 0, mbps: 0, warm: false });
  assert.equal(DOWN_DEFAULTS.warmupMs, 300);
  assert.equal(DOWN_DEFAULTS.maxMs, 6000);
});

/* ----------------------------- download ----------------------------- */

test('download (plain): exact byte count, sane timings, an HTTP/1.1 GET with the Host header', async () => {
  await withRig(async (rig) => {
    const r = await downloadThroughProxy(rig.socksPort, { host: 'plain.test', port: 80, path: '/down?bytes=300000', tls: false, bytes: 300000, maxMs: 5000, timeout: 3000 });
    assertDown(r);
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.bytes, 300000);
    assert.ok(r.ttfb >= 0 && r.ttfb <= r.ms, `ttfb ${r.ttfb} ms ${r.ms}`);
    assert.ok(r.mbps > 0);
    assert.ok(r.mbpsRaw > 0);
    assert.equal(r.error, null);
    assert.deepEqual(rig.log[0], { method: 'GET', url: '/down?bytes=300000', host: 'plain.test' });
  });
});

test('download: a loopback transfer over in a few ms is shorter than the warm-up, so mbps is the raw figure with warm: false; warm-up 0 is always warm', async () => {
  await withRig(async (rig) => {
    const r = await downloadThroughProxy(rig.socksPort, { host: 'plain.test', port: 80, path: '/down?bytes=200000', tls: false, bytes: 200000, maxMs: 5000, timeout: 3000, warmupMs: 2000 });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.warm, false);
    assert.equal(r.mbps, r.mbpsRaw);
    const z = await downloadThroughProxy(rig.socksPort, { host: 'plain.test', port: 80, path: '/down?bytes=200000', tls: false, bytes: 200000, maxMs: 5000, timeout: 3000, warmupMs: 0 });
    assert.equal(z.warm, true);
    assert.equal(z.mbps, z.mbpsRaw);
  });
});

test('download: a stream that outlives the warm-up reports a warm mbps measured after it', async () => {
  await withRig(async (rig) => {
    const r = await downloadThroughProxy(rig.socksPort, { host: 'plain.test', port: 80, path: '/slow', tls: false, bytes: 1e9, maxMs: 700, timeout: 3000, warmupMs: 300 });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.warm, true);
    assert.ok(r.mbps > 0 && r.mbpsRaw > 0, JSON.stringify(r));
    assert.ok(r.ms >= 650, 'ran to maxMs: ' + r.ms);
  });
});

test('download stops at `bytes` even when the server would send more', async () => {
  await withRig(async (rig) => {
    const r = await downloadThroughProxy(rig.socksPort, { host: 'plain.test', port: 80, path: '/down?bytes=2000000', tls: false, bytes: 100000, maxMs: 5000, timeout: 3000 });
    assert.equal(r.ok, true);
    assert.ok(r.bytes >= 100000 && r.bytes < 2000000, String(r.bytes));
  });
});

test('download honours maxMs on a stream that never ends and still reports what it got', async () => {
  await withRig(async (rig) => {
    const t0 = Date.now();
    const r = await downloadThroughProxy(rig.socksPort, { host: 'plain.test', port: 80, path: '/slow', tls: false, bytes: 1e9, maxMs: 300, timeout: 3000 });
    const took = Date.now() - t0;
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.ok(r.bytes > 0);
    assert.ok(took >= 280 && took < 2000, 'took ' + took);
    assert.ok(r.mbps > 0);
  });
});

test('download: a server that never answers is a timeout, not a hang and not a rejection', async () => {
  await withRig(async (rig) => {
    const t0 = Date.now();
    const r = await downloadThroughProxy(rig.socksPort, { host: 'plain.test', port: 80, path: '/hang', tls: false, bytes: 1000, maxMs: 5000, timeout: 300 });
    assertDown(r);
    assert.equal(r.ok, false);
    assert.equal(r.error, 'timeout');
    assert.equal(r.bytes, 0);
    assert.equal(r.warm, false);
    assert.ok(Date.now() - t0 < 2000);
  });
});

test('download: a refused CONNECT, a dead proxy port and a non-2xx status are failures with a reason', async () => {
  await withRig(async (rig) => {
    const refused = await downloadThroughProxy(rig.socksPort, { host: 'nowhere.test', port: 80, path: '/', tls: false, timeout: 1000 });
    assert.equal(refused.ok, false);
    assert.match(refused.error, /socks connect failed/);

    const deadProxy = await downloadThroughProxy(1, { host: 'plain.test', port: 80, path: '/', tls: false, timeout: 1000 });
    assert.equal(deadProxy.ok, false);
    assert.equal(typeof deadProxy.error, 'string');

    const notFound = await downloadThroughProxy(rig.socksPort, { host: 'plain.test', port: 80, path: '/missing', tls: false, timeout: 1000 });
    assert.equal(notFound.ok, false);
    assert.equal(notFound.error, 'HTTP 404');
  });
});

/* ----------------------------- upload ----------------------------- */

test('upload (plain): the sink receives every byte and the probe times the status line', async () => {
  await withRig(async (rig) => {
    const r = await uploadThroughProxy(rig.socksPort, { host: 'plain.test', port: 80, path: '/up', tls: false, bytes: 200000, timeout: 3000 });
    assertUp(r);
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.bytes, 200000);
    assert.ok(r.ttfb > 0 && r.ttfb <= r.ms);
    assert.ok(r.mbps > 0);
    assert.ok(rig.log.some(e => e.received === 200000), JSON.stringify(rig.log));
  });
});

test('upload: no answer is a timeout; a refused CONNECT is a failure', async () => {
  await withRig(async (rig) => {
    const r = await uploadThroughProxy(rig.socksPort, { host: 'plain.test', port: 80, path: '/hang', tls: false, bytes: 1000, timeout: 300 });
    assert.equal(r.ok, false);
    assert.equal(r.error, 'timeout');
    const refused = await uploadThroughProxy(rig.socksPort, { host: 'nowhere.test', port: 80, path: '/up', tls: false, bytes: 10, timeout: 1000 });
    assert.equal(refused.ok, false);
    assert.match(refused.error, /socks connect failed/);
  });
});

/* ----------------------------- delay ----------------------------- */

test('delaySeries: n requests in a row, summarised with a median', async () => {
  await withRig(async (rig) => {
    const s = await delaySeries(rig.socksPort, { n: 3, host: 'plain.test', port: 80, path: '/', timeout: 2000 });
    assert.deepEqual(Object.keys(s).sort(), ['avg', 'jitter', 'loss', 'median', 'min', 'reason', 'samples', 'status']);
    assert.equal(s.samples.length, 3);
    assert.equal(s.loss, 0);
    assert.equal(s.reason, '');
    assert.ok(s.min >= 0 && s.median >= s.min && s.avg >= s.min);
    assert.equal(rig.log.filter(e => e.url === '/').length, 3);
  });
});

test('delaySeries: a definitive first failure ends the series — the rest count as lost, the reason kept', async () => {
  await withRig(async (rig) => {
    const t0 = Date.now();
    const s = await delaySeries(rig.socksPort, { n: 3, host: 'nowhere.test', port: 80, path: '/', timeout: 500 });
    assert.equal(s.loss, 1);
    assert.deepEqual(s.samples, [-1, -1, -1]);
    assert.equal(s.reason, 'proxy-refused');
    assert.ok(Date.now() - t0 < 1500, 'one failure, not three timeouts');
  });
});

/* ----------------------------- what a pass means (2026-11-01) ----------------------------- */

const { tunnelGet, tlsPing, readExpect, needOf, REASONS } = require('../src/main/scan/probes');
const freePort = () => new Promise((r) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });

test('readExpect: a status, a range, a list, a class; empty is 200–399; junk does not read', () => {
  const t = (s, c) => readExpect(s)(c);
  assert.equal(t('204', 204), true);
  assert.equal(t('204', 200), false);
  assert.equal(t('200-299', 250), true);
  assert.equal(t('200,204', 204), true);
  assert.equal(t('2xx 3xx', 302), true);
  assert.equal(t('2xx', 404), false);
  assert.equal(t('', 302), true);
  assert.equal(t('', 403), false, 'an error page is not an answer');
  for (const bad of ['abc', '99', '600', '300-200', '6xx']) assert.equal(readExpect(bad), null, bad);
});

test('tunnelGet: the expected status is a pass, another one a wrong answer; each failure says where it happened', async () => {
  await withRig(async (rig) => {
    const ok = await tunnelGet(rig.socksPort, { host: 'plain.test', port: 80, path: '/', timeout: 2000, expect: '204' });
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.equal(ok.status, 204);
    assert.ok(ok.ms >= 0);
    const wrong = await tunnelGet(rig.socksPort, { host: 'plain.test', port: 80, path: '/nope', timeout: 2000, expect: '204' });
    assert.deepEqual([wrong.ok, wrong.reason, wrong.status], [false, 'wrong-answer', 404], 'a 404 is not a working tunnel');
    const loose = await tunnelGet(rig.socksPort, { host: 'plain.test', port: 80, path: '/nope', timeout: 2000, expect: '' });
    assert.equal(loose.reason, 'wrong-answer', 'not even the loose 200–399');
    const refused = await tunnelGet(rig.socksPort, { host: 'nowhere.test', port: 80, path: '/', timeout: 1000 });
    assert.equal(refused.reason, 'proxy-refused');
    const closed = await tunnelGet(rig.socksPort, { host: 'dead.test', port: 80, path: '/', timeout: 1000 });
    assert.ok(['proxy-refused', 'proxy-closed'].includes(closed.reason), closed.reason);
    const hang = await tunnelGet(rig.socksPort, { host: 'plain.test', port: 80, path: '/hang', timeout: 400 });
    assert.equal(hang.reason, 'timeout');
  });
  assert.equal((await tunnelGet(await freePort(), { host: 'x.test', port: 80, path: '/', timeout: 1000 })).reason, 'core', 'nothing on the SOCKS port: the core is not there');
  assert.ok(REASONS.includes('unstable') && REASONS.includes('no-tcp'));
});

test('delaySeries: a timeout is tried again, a series that can no longer pass stops, and the expectation reaches every request', async () => {
  const fake = (script) => { let i = 0; const calls = []; return { calls, get: async (port, o) => { calls.push(o); return script[i++] || { ok: false, reason: 'timeout' }; } }; };
  const ok = (ms) => ({ ok: true, ms, status: 204, reason: '' });
  const to = { ok: false, ms: -1, reason: 'timeout' };
  let f = fake([to, ok(50), ok(70)]);
  let s = await delaySeries(1, { n: 3, get: f.get });
  assert.deepEqual(s.samples, [-1, 50, 70], 'a timeout, then two answers');
  assert.equal(s.reason, 'timeout');
  assert.equal(f.calls.length, 3);
  f = fake([to, to, ok(1)]);
  s = await delaySeries(1, { n: 3, get: f.get });
  assert.equal(f.calls.length, 2, 'two of three can no longer be reached: the third is not asked');
  assert.deepEqual(s.samples, [-1, -1, -1]);
  f = fake([{ ok: false, reason: 'proxy-closed' }, ok(1), ok(1)]);
  s = await delaySeries(1, { n: 3, get: f.get });
  assert.equal(f.calls.length, 1, 'a closed tunnel first is an answer, not a hiccup');
  assert.equal(s.reason, 'proxy-closed');
  f = fake([ok(40), { ok: false, reason: 'proxy-closed' }, ok(60)]);
  s = await delaySeries(1, { n: 3, get: f.get });
  assert.deepEqual(s.samples, [40, -1, 60], 'after a success a closed tunnel is one lost sample');
  f = fake([ok(40), to, ok(60)]);
  await delaySeries(1, { n: 3, get: f.get, passRatio: 1 });
  assert.equal(f.calls.length, 2, 'passRatio 1: the first loss ends it');
  f = fake([ok(1)]);
  await delaySeries(1, { n: 1, get: f.get, expect: '200-299', host: 'h', port: 8080, path: '/p', timeout: 99 });
  assert.deepEqual(f.calls[0], { host: 'h', port: 8080, path: '/p', timeout: 99, expect: '200-299' });
  assert.deepEqual([needOf(3, 0.66), needOf(2, 0.66), needOf(4, 0.66), needOf(5, 0.66), needOf(1, 0.66), needOf(3, 1), needOf(3, 0)], [2, 2, 3, 4, 1, 3, 2]);
});

test('tlsPing: a finished handshake under the SNI is a pass; a plain server is `tls`, nothing listening `no-tcp`', async () => {
  await withRig(async (rig) => {
    const ok = await tlsPing('127.0.0.1', rig.tlsPort, { servername: 'tls.test', timeout: 2000 });
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.ok(rig.sni.includes('tls.test'));
    const plain = await tlsPing('127.0.0.1', rig.plainPort, { servername: 'tls.test', timeout: 1500 });
    assert.deepEqual([plain.ok, plain.reason], [false, 'tls']);
  });
  const none = await tlsPing('127.0.0.1', await freePort(), { servername: 'x.test', timeout: 1000 });
  assert.deepEqual([none.ok, none.reason], [false, 'no-tcp']);
});

/* ----------------------------- TLS ----------------------------- */

test('download (TLS): the SOCKS stream is wrapped in tls.connect with SNI and ALPN http/1.1', async () => {
  await withRig(async (rig) => {
    const r = await downloadThroughProxy(rig.socksPort, { host: 'tls.test', port: 443, path: '/down?bytes=150000', tls: true, bytes: 150000, maxMs: 5000, timeout: 3000, rejectUnauthorized: false });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.bytes, 150000);
    assert.ok(r.mbps > 0);
    assert.deepEqual(rig.sni, ['tls.test']);
    assert.deepEqual(rig.alpn, ['http/1.1']);
    assert.equal(rig.log[0].host, 'tls.test');
  });
});

test('upload (TLS) works the same way', async () => {
  await withRig(async (rig) => {
    const r = await uploadThroughProxy(rig.socksPort, { host: 'tls.test', port: 443, path: '/up', tls: true, bytes: 120000, timeout: 3000, rejectUnauthorized: false });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.bytes, 120000);
    assert.ok(rig.log.some(e => e.received === 120000));
  });
});

test('TLS verifies the certificate by default — a self-signed server is a failure, fast', async () => {
  await withRig(async (rig) => {
    const t0 = Date.now();
    const r = await downloadThroughProxy(rig.socksPort, { host: 'tls.test', port: 443, path: '/down?bytes=10', tls: true, bytes: 10, timeout: 3000 });
    assert.equal(r.ok, false);
    assert.notEqual(r.error, 'timeout');
    assert.match(r.error, /CERT|SELF_SIGNED|certificate/i);
    assert.ok(Date.now() - t0 < 2000);
  });
});

test('TLS: a plain server behind the tunnel is a handshake failure, not a hang', async () => {
  await withRig(async (rig) => {
    const r = await downloadThroughProxy(rig.socksPort, { host: 'plain.test', port: 443, path: '/', tls: true, bytes: 10, timeout: 1000 });
    assert.equal(r.ok, false);
    assert.equal(typeof r.error, 'string');
  });
});
