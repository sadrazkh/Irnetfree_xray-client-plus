'use strict';
/**
 * The CDN lists behind the address presets (cdnRanges.js, 2026-11-02): each read
 * from its own public list as that list really looks, a list that fails leaving
 * what was there, the page's channel keeping the answer across a restart, and the
 * lists the app ships all readable by the address box.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const C = require('../src/main/scan/cdnRanges');
const T = require('../src/main/scan/targets');
const { createScan } = require('../src/main/scan/index');

const FASTLY = JSON.stringify({ addresses: ['23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24', '151.101.0.0/16'], ipv6_addresses: ['2a04:4e40::/32', '2a04:4e42::/32'] });
const GCORE = JSON.stringify({ addresses: ['92.223.40.5/32', '95.85.69.4/32', '80.93.215.5/32', '5.188.126.8/32'], addresses_v6: ['2a01:68c0:0:1:ffff::22/128', '2a03:90c0:4c1:2801::4/128'] });
const CF_GLOBAL = JSON.stringify({
  CLOUDFRONT_GLOBAL_IP_LIST: ['18.160.0.0/15', '54.192.0.0/16', '204.246.168.0/22', '205.251.249.0/24', '120.52.22.96/27'],
  CLOUDFRONT_REGIONAL_EDGE_IP_LIST: ['13.113.196.64/26']
});
const AWS = JSON.stringify({
  prefixes: [{ ip_prefix: '13.113.196.64/26', service: 'CLOUDFRONT' }, { ip_prefix: '3.5.140.0/22', service: 'AMAZON' }],
  ipv6_prefixes: [{ ipv6_prefix: '2600:9000:3000::/36', service: 'CLOUDFRONT' }, { ipv6_prefix: '2a05:d000::/25', service: 'AMAZON' }]
});
const CF4 = '173.245.48.0/20\n103.21.244.0/22\n103.22.200.0/22\n104.16.0.0/13\n';
const CF6 = '2400:cb00::/32\n2606:4700::/32\r\n';

const ANSWERS = {
  'https://www.cloudflare.com/ips-v4': CF4,
  'https://www.cloudflare.com/ips-v6': CF6,
  'https://api.fastly.com/public-ip-list': FASTLY,
  'https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips': CF_GLOBAL,
  'https://ip-ranges.amazonaws.com/ip-ranges.json': AWS,
  'https://api.gcore.com/cdn/public-ip-list': GCORE
};
const answering = (over = {}) => async (url) => {
  const a = Object.prototype.hasOwnProperty.call(over, url) ? over[url] : ANSWERS[url];
  if (a instanceof Error) throw a;
  return a;
};

test('fetchList reads each CDN as its own list really looks', async () => {
  const get = answering();
  assert.deepEqual(await C.fetchList('cf', { get }), ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '104.16.0.0/13', '2400:cb00::/32', '2606:4700::/32']);
  assert.deepEqual(await C.fetchList('fastly', { get }), ['23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24', '151.101.0.0/16', '2a04:4e40::/32', '2a04:4e42::/32']);
  assert.deepEqual(await C.fetchList('gcore', { get }), ['92.223.40.5/32', '95.85.69.4/32', '80.93.215.5/32', '5.188.126.8/32', '2a01:68c0:0:1:ffff::22/128', '2a03:90c0:4c1:2801::4/128']);
});

test('CloudFront: the edges a viewer dials, not the regional caches, and only CloudFront\'s IPv6', async () => {
  const got = await C.fetchList('cloudfront', { get: answering() });
  assert.deepEqual(got, ['18.160.0.0/15', '54.192.0.0/16', '204.246.168.0/22', '205.251.249.0/24', '120.52.22.96/27', '2600:9000:3000::/36']);
});

test('fetchList refuses what is not the list', async () => {
  const fastly = (body) => C.fetchList('fastly', { get: answering({ 'https://api.fastly.com/public-ip-list': body }) });
  await assert.rejects(fastly('<html>blocked</html>'), /not the list/);
  await assert.rejects(fastly('{}'), /no addresses in it/);
  await assert.rejects(fastly(JSON.stringify({ addresses: ['1.1.1.0/24'], ipv6_addresses: [] })), /1 usable range/);
  await assert.rejects(fastly(JSON.stringify({ addresses: ['junk', 7, null, '1.1.1.1', '1.0.0.0/4'], ipv6_addresses: [] })), /0 usable range/);
  // Amazon's two lists are one answer: half of it is not the list
  await assert.rejects(C.fetchList('cloudfront', { get: answering({ 'https://ip-ranges.amazonaws.com/ip-ranges.json': new Error('read ECONNRESET') }) }), /ECONNRESET/);
});

test('cleanRanges keeps what the address box reads, once each', () => {
  assert.deepEqual(C.cleanRanges([' 1.1.1.0/24 ', '1.1.1.0/24', '2606:4700::/32', '1.1.1.1', 'host.example/24', '1.2.3.4/33', '', null, {}]), ['1.1.1.0/24', '2606:4700::/32']);
});

test('updateLists: what arrives replaces the list with the difference counted; what fails keeps its place', async () => {
  const stored = { fastly: { ranges: ['151.101.0.0/16', '1.2.3.0/24'], updatedAt: 5 }, gcore: { ranges: ['9.9.9.9/32'], updatedAt: 7 } };
  const u = await C.updateLists(null, stored, { get: answering({ 'https://api.gcore.com/cdn/public-ip-list': new Error('no answer in time') }), now: 1000 });
  const row = (id) => u.results.find((r) => r.id === id);
  assert.deepEqual(u.results.map((r) => r.id), ['cf', 'fastly', 'cloudfront', 'gcore']);
  assert.deepEqual(row('fastly'), { id: 'fastly', name: 'Fastly', ok: true, count: 6, added: 5, removed: 1 });
  assert.deepEqual(row('gcore'), { id: 'gcore', name: 'Gcore', ok: false, error: 'no answer in time' });
  assert.equal(u.stored.fastly.updatedAt, 1000);
  assert.deepEqual(u.stored.gcore, stored.gcore);
  assert.deepEqual(stored.fastly.ranges, ['151.101.0.0/16', '1.2.3.0/24'], 'what it was handed is not written to');
  const one = await C.updateLists(['fastly'], {}, { get: answering(), now: 1000 });
  assert.deepEqual(one.results.map((r) => r.id), ['fastly']);
});

test('readStored keeps what still reads; presetsOf falls back to what shipped', () => {
  const good = { ranges: ['1.1.1.0/24', '1.1.2.0/24', '1.1.3.0/24', '1.1.4.0/24', '1.1.5.0/24'], updatedAt: 9 };
  assert.deepEqual(C.readStored({ fastly: good, gcore: { ranges: ['1.1.1.0/24'] }, cloudfront: 'x', evil: good, cf: { ranges: 3 } }), { fastly: good });
  for (const junk of [null, undefined, 3, 'x', []]) assert.deepEqual(C.readStored(junk), {});
  const p = C.presetsOf({ fastly: good });
  assert.deepEqual(p.fastly, good);
  assert.deepEqual(p.gcore, { ranges: T.PRESETS.gcore.ranges, updatedAt: T.CDN_SHIPPED_AT });
  assert.deepEqual(Object.keys(p), ['cf', 'fastly', 'cloudfront', 'gcore']);
});

test('the lists the app ships are all readable, dated, and big enough to be the real thing', () => {
  assert.ok(T.CDN_SHIPPED_AT > Date.parse('2026-01-01'));
  for (const id of C.CDN_IDS) {
    const list = T.PRESETS[id].ranges;
    assert.ok(list.length >= 20, `${id}: ${list.length}`);
    assert.deepEqual(C.cleanRanges(list), list, `${id}: every entry reads, once`);
    assert.deepEqual(T.parseTargetText(list.join('\n')).errors, []);
    assert.ok(list.some((r) => r.includes(':')) && list.some((r) => !r.includes(':')), `${id}: both IPv4 and IPv6`);
  }
});

/* ------------------------------------ fetchText ------------------------------------ */

async function withServer(handler, fn) {
  const srv = http.createServer(handler);
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  try {
    return await fn(`http://127.0.0.1:${srv.address().port}/`);
  } finally {
    srv.closeAllConnections();
    await new Promise((res) => srv.close(res));
  }
}

test('fetchText: the body of a 200; a redirect, an error, an oversized or silent answer each reject', async () => {
  await withServer((req, res) => res.end('hello'), async (url) => {
    assert.equal(await C.fetchText(url), 'hello');
  });
  await withServer((req, res) => { res.statusCode = 301; res.setHeader('Location', 'http://127.0.0.1:1/'); res.end(); }, async (url) => {
    await assert.rejects(C.fetchText(url), /HTTP 301/);
  });
  await withServer((req, res) => { res.statusCode = 403; res.end('no'); }, async (url) => {
    await assert.rejects(C.fetchText(url), /HTTP 403/);
  });
  await withServer((req, res) => res.end(Buffer.alloc(2000)), async (url) => {
    await assert.rejects(C.fetchText(url, { maxBytes: 100 }), /too large/);
  });
  await withServer(() => { /* never answers */ }, async (url) => {
    await assert.rejects(C.fetchText(url, { idleMs: 50 }), /no answer in time/);
  });
  await withServer((req, res) => { res.write('part'); setTimeout(() => res.destroy(), 10); }, async (url) => {
    await assert.rejects(C.fetchText(url), /cut off|aborted|ECONNRESET|socket hang up/);
  });
  await assert.rejects(C.fetchText('http://example.com/list'), /https only/);
});

/* ------------------------------------ the channel ------------------------------------ */

function harness(data = {}, fetchText = answering()) {
  const handlers = {};
  const logs = [];
  const ctx = {
    handle: (ch, fn) => { handlers[ch] = fn; },
    send() {},
    log: (m, kind) => logs.push([kind, m]),
    store: {
      get: (k, d) => (Object.prototype.hasOwnProperty.call(data, k) ? data[k] : d),
      set: (k, v) => { data[k] = JSON.parse(JSON.stringify(v)); },
      setLazy: (k, v) => { data[k] = JSON.parse(JSON.stringify(v)); }
    },
    state: { servers: [] },
    xray: { binExists: () => false }
  };
  createScan(ctx, { fetchText }).register();
  return { handlers, logs, data };
}

test('scan:cdnUpdate: the presets follow, the store keeps it across a restart, the log says what happened', async () => {
  const data = {};
  const s = harness(data, answering({ 'https://api.gcore.com/cdn/public-ip-list': new Error('read ECONNRESET') }));
  const shipped = s.handlers['scan:presets']().ranges;
  assert.deepEqual(shipped.fastly.ranges, T.PRESETS.fastly.ranges);
  assert.deepEqual(shipped['warp-wg'], T.PRESETS['warp-wg'], 'what is not a CDN list stays');
  assert.deepEqual(shipped['cf-tls-ports'], T.PRESETS['cf-tls-ports']);

  const r = await s.handlers['scan:cdnUpdate']({});
  assert.equal(r.results.find((x) => x.id === 'fastly').ok, true);
  assert.equal(r.results.find((x) => x.id === 'gcore').error, 'read ECONNRESET');
  assert.equal(r.ranges.fastly.ranges.length, 6);
  assert.deepEqual(r.ranges.gcore.ranges, T.PRESETS.gcore.ranges, 'the one that failed stays as it was');
  assert.ok(s.logs.some(([k, m]) => k === 'warn' && /Gcore list not updated \(read ECONNRESET\)/.test(m)));
  assert.ok(s.logs.some(([k, m]) => k === 'info' && /Fastly list updated — 6 range\(s\)/.test(m)));

  assert.equal(s.handlers['scan:presets']().ranges.fastly.ranges.length, 6);
  const again = harness(data, answering());
  assert.equal(again.handlers['scan:presets']().ranges.fastly.ranges.length, 6, 'read back after a restart');
  assert.ok(again.handlers['scan:presets']().ranges.fastly.updatedAt > T.CDN_SHIPPED_AT);
});

test('scan:cdnUpdate: a second click while one runs joins it instead of asking twice', async () => {
  let calls = 0;
  const s = harness({}, async (url) => { calls++; await new Promise((res) => setImmediate(res)); return ANSWERS[url]; });
  const [a, b] = await Promise.all([s.handlers['scan:cdnUpdate']({}), s.handlers['scan:cdnUpdate']({})]);
  assert.equal(a, b);
  assert.equal(calls, Object.keys(ANSWERS).length);
  await s.handlers['scan:cdnUpdate']({ ids: ['fastly'] });
  assert.equal(calls, Object.keys(ANSWERS).length + 1, 'and a later click asks again');
});
