'use strict';
/**
 * The way a scan leaves the machine (upstream.js): the address box of the option,
 * a SOCKS5 client against a little server in this file, every direct dial of a
 * config through the port, and the check that a path tells the truth: an address
 * that cannot exist must not answer. Loopback only: the "reserved" address of a
 * check is handed in, and nothing here reaches the network.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const tls = require('node:tls');
const { execFileSync } = require('node:child_process');

const U = require('../src/main/scan/upstream');
const { tlsPing } = require('../src/main/scan/probes');
const C = require('../src/main/scan/cdnRanges');
const { buildMultiTestConfig } = require('../src/main/configBuilder');
const F = require('./fixtures');

/** A self-signed certificate from the test's own key, or null where openssl is missing. */
function cert() {
  try {
    const key = execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=t', '-keyout', '-', '-out', '-', '-days', '2'], { stdio: ['ignore', 'pipe', 'ignore'], encoding: 'utf8' });
    return { key, cert: key };
  } catch { return null; }
}

/**
 * A SOCKS5 server on loopback. `route(host, port)` says where a CONNECT goes: a local
 * port, `false` for a refusal, 'close' for "success, then the connection just ends"
 * (Xray's inbound on an address nothing answers), and null to wait for ever.
 */
async function socksServer({ route, auth = null, replyBeforeDial = false } = {}) {
  const seen = [];
  const srv = net.createServer((c) => {
    let stage = 0, buf = Buffer.alloc(0);
    c.on('error', () => {});
    c.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0) {
        if (buf.length < 2 || buf.length < 2 + buf[1]) return;
        const methods = [...buf.subarray(2, 2 + buf[1])];
        buf = buf.subarray(2 + buf[1]);
        if (auth) {
          if (!methods.includes(2)) { c.end(Buffer.from([5, 255])); return; }
          c.write(Buffer.from([5, 2]));
          stage = 1;
        } else { c.write(Buffer.from([5, 0])); stage = 2; }
      }
      if (stage === 1) {
        if (buf.length < 2 || buf.length < 3 + buf[1]) return;
        const u = buf.subarray(2, 2 + buf[1]).toString();
        const plen = buf[2 + buf[1]];
        if (buf.length < 3 + buf[1] + plen) return;
        const p = buf.subarray(3 + buf[1], 3 + buf[1] + plen).toString();
        buf = buf.subarray(3 + buf[1] + plen);
        if (u !== auth.user || p !== auth.pass) { c.end(Buffer.from([1, 1])); return; }
        c.write(Buffer.from([1, 0]));
        stage = 2;
      }
      if (stage === 2) {
        if (buf.length < 5) return;
        const atyp = buf[3];
        const hlen = atyp === 1 ? 4 : atyp === 4 ? 16 : 1 + buf[4];
        if (buf.length < 4 + hlen + 2) return;
        const raw = buf.subarray(4, 4 + hlen);
        const host = atyp === 1 ? [...raw].join('.') : atyp === 4 ? raw.toString('hex') : raw.subarray(1).toString();
        const port = buf.readUInt16BE(4 + hlen);
        buf = buf.subarray(4 + hlen + 2);
        stage = 3;
        seen.push({ host, port, atyp });
        const where = route ? route(host, port) : null;
        const ok = Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        if (where === false) { c.end(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])); return; }
        if (where === 'close') { c.write(ok); setTimeout(() => c.destroy(), 20); return; }
        if (where === null) { if (replyBeforeDial) c.write(ok); return; }
        const up = net.connect(where, '127.0.0.1', () => { c.write(ok); if (buf.length) up.write(buf); c.removeAllListeners('data'); c.pipe(up); up.pipe(c); });
        up.on('error', () => c.destroy());
      }
    });
  });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  return { srv, seen, up: { host: '127.0.0.1', port: srv.address().port }, close: () => { srv.close(); } };
}

test('parseUpstream reads an address the way people write one', () => {
  assert.deepEqual(U.parseUpstream('127.0.0.1:30810'), { host: '127.0.0.1', port: 30810 });
  assert.deepEqual(U.parseUpstream(' socks5://127.0.0.1:30810/ '), { host: '127.0.0.1', port: 30810 });
  assert.deepEqual(U.parseUpstream('socks://proxy.example:1080'), { host: 'proxy.example', port: 1080 });
  assert.deepEqual(U.parseUpstream('[2606:4700::1]:1080'), { host: '2606:4700::1', port: 1080 });
  assert.deepEqual(U.parseUpstream('me:p@ss:w@127.0.0.1:1080'), { host: '127.0.0.1', port: 1080, user: 'me', pass: 'p@ss:w' });
  assert.deepEqual(U.parseUpstream('me@127.0.0.1:1080'), { host: '127.0.0.1', port: 1080, user: 'me', pass: '' });
  for (const bad of ['', null, 'host', '127.0.0.1', '127.0.0.1:0', '127.0.0.1:70000', '127.0.0.1:x', '2606:4700::1:1080', '[nope]:1080', ':1080', '@1.1.1.1:80', 'a b:80']) {
    assert.equal(U.parseUpstream(bad), null, String(bad));
  }
});

test('upstreamOf: off is null however the box reads; on and unreadable says so', () => {
  assert.equal(U.upstreamOf(null), null);
  assert.equal(U.upstreamOf({ on: false, addr: 'junk' }), null);
  assert.deepEqual(U.upstreamOf({ on: true, addr: 'junk' }), { error: 'proxy-addr' });
  assert.deepEqual(U.upstreamOf({ on: true, addr: '127.0.0.1:1' }), { host: '127.0.0.1', port: 1 });
  assert.deepEqual(U.sanitizeUpstream({ on: 1, addr: ' 1.1.1.1:2 ', x: 1 }), { on: true, addr: '1.1.1.1:2' });
  assert.deepEqual(U.sanitizeUpstream('x'), { on: false, addr: '' });
});

test('connectRequest: each kind of address as SOCKS5 writes it', () => {
  assert.deepEqual([...U.connectRequest('1.2.3.4', 443)], [5, 1, 0, 1, 1, 2, 3, 4, 1, 187]);
  assert.deepEqual([...U.connectRequest('a.io', 80)], [5, 1, 0, 3, 4, 97, 46, 105, 111, 0, 80]);
  const v6 = U.connectRequest('2606:4700::1', 443);
  assert.equal(v6[3], 4);
  assert.equal(v6.subarray(4, 20).toString('hex'), '26064700000000000000000000000001');
  assert.equal(U.connectRequest('::1', 1).subarray(4, 20).toString('hex'), '00000000000000000000000000000001');
});

test('socksConnect reaches through, with a password when asked, and each failure has its own code', async () => {
  const echo = net.createServer((c) => { c.on('error', () => {}); c.on('data', (d) => c.write(d)); });
  await new Promise((res) => echo.listen(0, '127.0.0.1', res));
  const p = echo.address().port;
  const plain = await socksServer({ route: () => p });
  const sock = await U.socksConnect(plain.up, '1.2.3.4', 443);
  sock.resume();
  const echoed = await new Promise((res) => { sock.once('data', (d) => res(d.toString())); sock.write('hi'); });
  assert.equal(echoed, 'hi');
  sock.destroy();
  assert.deepEqual(plain.seen, [{ host: '1.2.3.4', port: 443, atyp: 1 }]);

  const guarded = await socksServer({ route: () => p, auth: { user: 'u', pass: 'p' } });
  const ok = await U.socksConnect(Object.assign({}, guarded.up, { user: 'u', pass: 'p' }), 'a.io', 80);
  ok.destroy();
  await assert.rejects(U.socksConnect(Object.assign({}, guarded.up, { user: 'u', pass: 'no' }), 'a.io', 80), { code: 'PROXY_AUTH' });
  await assert.rejects(U.socksConnect(guarded.up, 'a.io', 80), { code: 'PROXY_AUTH' });

  const refusing = await socksServer({ route: () => false });
  await assert.rejects(U.socksConnect(refusing.up, 'a.io', 80), { code: 'TARGET' });
  const silent = await socksServer({ route: () => null });
  await assert.rejects(U.socksConnect(silent.up, 'a.io', 80, 80), { code: 'TARGET' });

  const notSocks = net.createServer((c) => { c.on('error', () => {}); c.end('HTTP/1.1 400 Bad\r\n\r\n'); });
  await new Promise((res) => notSocks.listen(0, '127.0.0.1', res));
  await assert.rejects(U.socksConnect({ host: '127.0.0.1', port: notSocks.address().port }, 'a.io', 80), { code: 'PROXY_BAD' });

  const free = await new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const n = s.address().port; s.close(() => res(n)); }); });
  await assert.rejects(U.socksConnect({ host: '127.0.0.1', port: free }, 'a.io', 80), { code: 'PROXY_DOWN' });

  for (const s of [plain, guarded, refusing, silent]) s.close();
  echo.close();
  notSocks.close();
});

test('withUpstream sends every direct dial through the port, and nothing when off', () => {
  const plain = buildMultiTestConfig([F.VLESS_WS_TLS], [41000]);
  assert.deepEqual(U.withUpstream(JSON.parse(JSON.stringify(plain)), null), plain);
  const c = U.withUpstream(buildMultiTestConfig([F.VLESS_WS_TLS], [41000]), { host: '127.0.0.1', port: 30810 });
  const byTag = new Map(c.outbounds.map((o) => [o.tag, o]));
  assert.equal(byTag.get('test-out-0').streamSettings.sockopt.dialerProxy, U.TAG);
  assert.equal(byTag.get('direct').streamSettings.sockopt.dialerProxy, U.TAG);
  assert.deepEqual(byTag.get(U.TAG), { tag: U.TAG, protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port: 30810 }] } });
  assert.equal(byTag.get(U.TAG).streamSettings, undefined, 'the port itself dials plainly');
  const auth = U.withUpstream({ outbounds: [] }, { host: 'h', port: 1, user: 'u', pass: 'p' });
  assert.deepEqual(auth.outbounds[0].settings.servers[0].users, [{ user: 'u', pass: 'p' }]);
});

test('withUpstream: a dial that goes through a helper stays on it, the helper takes the port; a blackhole dials nothing', () => {
  const c = U.withUpstream({
    outbounds: [
      { tag: 'main', protocol: 'vless', streamSettings: { sockopt: { dialerProxy: 'dpi-1', tcpFastOpen: true } } },
      { tag: 'dpi-1', protocol: 'freedom', settings: { fragment: {} } },
      { tag: 'old', protocol: 'vless', proxySettings: { tag: 'dpi-1' } },
      { tag: 'block', protocol: 'blackhole' },
      { tag: 'dns-out', protocol: 'dns' }
    ]
  }, { host: 'h', port: 1 });
  const byTag = new Map(c.outbounds.map((o) => [o.tag, o]));
  assert.deepEqual(byTag.get('main').streamSettings.sockopt, { dialerProxy: 'dpi-1', tcpFastOpen: true });
  assert.equal(byTag.get('dpi-1').streamSettings.sockopt.dialerProxy, U.TAG);
  assert.equal(byTag.get('old').streamSettings, undefined);
  assert.equal(byTag.get('block').streamSettings, undefined);
  assert.equal(byTag.get('dns-out').streamSettings, undefined);
});

/* ------------------------------------ the truth of a path ------------------------------------ */

test('checkPath direct: an address that accepts a connect is a lie, one that does not is clean', async () => {
  const listener = net.createServer((c) => { c.on('error', () => {}); c.destroy(); });
  await new Promise((res) => listener.listen(0, '127.0.0.1', res));
  const lying = await U.checkPath(null, { control: [['127.0.0.1', listener.address().port]], directMs: 500 });
  assert.deepEqual(lying, { via: 'direct', state: 'lying' });
  const free = listener.address().port;
  await new Promise((res) => listener.close(res));
  assert.deepEqual(await U.checkPath(null, { control: [['127.0.0.1', free]], directMs: 500 }), { via: 'direct', state: 'clean' });
});

test('checkPath through a port: a reply alone proves nothing; a finished handshake is a lie; a port that fails says how', async (t) => {
  const pem = cert();
  if (!pem) { t.skip('no openssl here'); return; }
  const site = tls.createServer(pem, (c) => { c.on('error', () => {}); c.end(); });
  site.on('tlsClientError', () => {});
  await new Promise((res) => site.listen(0, '127.0.0.1', res));
  const control = [['192.0.2.1', 443]];
  const opts = { control, proxyMs: 800 };

  // a VPN's port: it reaches a TLS server whatever address it was asked for
  const vpn = await socksServer({ route: () => site.address().port });
  assert.deepEqual(await U.checkPath(vpn.up, opts), { via: 'proxy', state: 'lying' });
  assert.equal(vpn.seen[0].host, '192.0.2.1');

  // Xray's direct inbound: success at once, then nothing, the address being nowhere
  const direct = await socksServer({ route: () => 'close' });
  assert.deepEqual(await U.checkPath(direct.up, opts), { via: 'proxy', state: 'clean' });
  // …and one that says success and just stays silent
  const quiet = await socksServer({ route: () => null, replyBeforeDial: true });
  assert.deepEqual(await U.checkPath(quiet.up, Object.assign({}, opts, { proxyMs: 200 })), { via: 'proxy', state: 'clean' });
  // a server that really tries the address, and says it could not
  const honest = await socksServer({ route: () => false });
  assert.deepEqual(await U.checkPath(honest.up, opts), { via: 'proxy', state: 'clean' });

  const guarded = await socksServer({ route: () => 'close', auth: { user: 'u', pass: 'p' } });
  assert.equal((await U.checkPath(guarded.up, opts)).state, 'proxy-auth');
  const notSocks = net.createServer((c) => { c.on('error', () => {}); c.end('nope'); });
  await new Promise((res) => notSocks.listen(0, '127.0.0.1', res));
  assert.equal((await U.checkPath({ host: '127.0.0.1', port: notSocks.address().port }, opts)).state, 'proxy-bad');
  const free = await new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const n = s.address().port; s.close(() => res(n)); }); });
  const down = await U.checkPath({ host: '127.0.0.1', port: free }, opts);
  assert.equal(down.state, 'proxy-down');
  assert.match(down.error, /does not answer/);

  for (const s of [vpn, direct, quiet, honest, guarded]) s.close();
  site.close();
  notSocks.close();
});

test('tlsPing through a port: a handshake counts, and a success reply with nothing behind it does not', async (t) => {
  const pem = cert();
  if (!pem) { t.skip('no openssl here'); return; }
  const site = tls.createServer(pem, (c) => { c.on('error', () => {}); c.end(); });
  site.on('tlsClientError', () => {});
  await new Promise((res) => site.listen(0, '127.0.0.1', res));
  const good = await socksServer({ route: () => site.address().port });
  const yes = await tlsPing('203.0.113.9', 443, { servername: 'x.example', timeout: 2000, dial: U.dialVia(good.up) });
  assert.equal(yes.ok, true);
  assert.equal(good.seen[0].host, '203.0.113.9');

  const nothing = await socksServer({ route: () => 'close' });
  const no = await tlsPing('203.0.113.9', 443, { servername: 'x.example', timeout: 800, dial: U.dialVia(nothing.up) });
  assert.deepEqual([no.ok, no.reason], [false, 'tls'], 'the port said success: only the handshake failed');

  const free = await new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const n = s.address().port; s.close(() => res(n)); }); });
  const dead = await tlsPing('203.0.113.9', 443, { timeout: 500, dial: U.dialVia({ host: '127.0.0.1', port: free }) });
  assert.deepEqual([dead.ok, dead.reason], [false, 'no-tcp']);
  for (const s of [good, nothing]) s.close();
  site.close();
});

test('fetchText through a port: the body arrives by way of it', async () => {
  const site = http.createServer((q, r) => r.end('list-body'));
  await new Promise((res) => site.listen(0, '127.0.0.1', res));
  const port = await socksServer({ route: () => site.address().port });
  assert.equal(await C.fetchText(`http://127.0.0.1:${site.address().port}/`, { via: port.up }), 'list-body');
  assert.equal(port.seen.length, 1);
  const free = await new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const n = s.address().port; s.close(() => res(n)); }); });
  await assert.rejects(C.fetchText(`http://127.0.0.1:${site.address().port}/`, { via: { host: '127.0.0.1', port: free } }), /does not answer/);
  port.close();
  site.closeAllConnections();
  site.close();
});
