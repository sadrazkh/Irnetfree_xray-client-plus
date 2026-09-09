'use strict';
/**
 * IP-scan probes: download, upload and delay through a SOCKS5 port.
 *
 * Everything runs on 127.0.0.1 with ephemeral ports: a SOCKS5 stub routes a
 * CONNECT by the requested host name to a local byte server, plain or TLS
 * (the self-signed fixture from certPin.test.js; its expiry does not matter
 * because the TLS tests turn verification off, and one test checks that the
 * default does verify). What matters: byte counts are exact, timings are
 * sane, `maxMs` caps a download that would never end, every failure comes
 * back as a value (never a rejection), and the TLS wrap sends SNI and ALPN.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');
const fs = require('node:fs');
const path = require('node:path');

const { downloadThroughProxy, uploadThroughProxy, delaySeries } = require('../src/main/scan/probes');

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

const SHAPE = ['ok', 'bytes', 'ms', 'ttfb', 'mbps', 'error'];
const assertShape = (r) => assert.deepEqual(Object.keys(r).sort(), [...SHAPE].sort(), JSON.stringify(r));

/* ----------------------------- download ----------------------------- */

test('download (plain): exact byte count, sane timings, an HTTP/1.1 GET with the Host header', async () => {
  await withRig(async (rig) => {
    const r = await downloadThroughProxy(rig.socksPort, { host: 'plain.test', port: 80, path: '/down?bytes=300000', tls: false, bytes: 300000, maxMs: 5000, timeout: 3000 });
    assertShape(r);
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.bytes, 300000);
    assert.ok(r.ttfb >= 0 && r.ttfb <= r.ms, `ttfb ${r.ttfb} ms ${r.ms}`);
    assert.ok(r.mbps > 0);
    assert.equal(r.error, null);
    assert.deepEqual(rig.log[0], { method: 'GET', url: '/down?bytes=300000', host: 'plain.test' });
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
    assertShape(r);
    assert.equal(r.ok, false);
    assert.equal(r.error, 'timeout');
    assert.equal(r.bytes, 0);
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
    assertShape(r);
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

test('delaySeries: n requests in a row, summarised', async () => {
  await withRig(async (rig) => {
    const s = await delaySeries(rig.socksPort, { n: 3, host: 'plain.test', port: 80, path: '/', timeout: 2000 });
    assert.deepEqual(Object.keys(s).sort(), ['avg', 'jitter', 'loss', 'min', 'samples']);
    assert.equal(s.samples.length, 3);
    assert.equal(s.loss, 0);
    assert.ok(s.min >= 0 && s.avg >= s.min);
    assert.equal(rig.log.filter(e => e.url === '/').length, 3);
  });
});

test('delaySeries: a first request that fails ends the series — the rest count as lost', async () => {
  await withRig(async (rig) => {
    const t0 = Date.now();
    const s = await delaySeries(rig.socksPort, { n: 3, host: 'nowhere.test', port: 80, path: '/', timeout: 500 });
    assert.equal(s.loss, 1);
    assert.deepEqual(s.samples, [-1, -1, -1]);
    assert.ok(Date.now() - t0 < 1500, 'one failure, not three timeouts');
  });
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
