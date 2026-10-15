'use strict';
/**
 * The scanner's ECH fetch (src/main/scan/ech.js): the DNS query it writes,
 * the HTTPS answers and ECHConfigLists it reads, and fetchEchConfig's
 * results — all on canned messages built here, through injected transports.
 * The default transports run only against 127.0.0.1 listeners on ephemeral
 * ports (a UDP responder, and a TLS server whose self-signed certificate the
 * DoH transport must refuse); nothing leaves the machine.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const dgram = require('node:dgram');
const dns = require('node:dns');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');

const { buildQuery, parseHttpsAnswer, parseEchConfigList, fetchEchConfig, defaultTransports } = require('../src/main/scan/ech');

/* ------------------------------ wire helpers ------------------------------ */

const u8 = (n) => Buffer.from([n & 0xff]);
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const cat = (...parts) => Buffer.concat(parts);

/** 'a.b' → 01 'a' 01 'b' 00; '' or '.' → 00 (the root). */
function encodeName(name) {
  const labels = String(name).replace(/\.$/, '').split('.').filter(Boolean);
  return cat(...labels.map((l) => cat(u8(l.length), Buffer.from(l, 'latin1'))), u8(0));
}

/** One ECHConfig: version, length, contents (an X25519 key, one suite, the public name, no extensions). */
function echConfig({ version = 0xfe0d, publicName = 'cloudflare-ech.com', configId = 1 } = {}) {
  const contents = version === 0xfe0d
    ? cat(
      u8(configId), u16(0x0020),
      u16(32), Buffer.alloc(32, 0x42),
      u16(4), u16(0x0001), u16(0x0001),
      u8(0),
      u8(publicName.length), Buffer.from(publicName, 'latin1'),
      u16(0))
    : Buffer.from('opaque contents of another version');
  return cat(u16(version), u16(contents.length), contents);
}

/** An ECHConfigList: u16 total length, then the configs. */
function echConfigList(...configs) {
  const body = cat(...configs);
  return cat(u16(body.length), body);
}

/** HTTPS RDATA: priority, target name, then [key, value] SvcParams in order. */
function httpsRdata({ priority = 1, target = '.', params = [] } = {}) {
  return cat(u16(priority), encodeName(target), ...params.map(([k, v]) => cat(u16(k), u16(v.length), v)));
}

const ALPN = cat(u8(2), Buffer.from('h3'), u8(2), Buffer.from('h2'));
const LIST = echConfigList(echConfig());
const LIST_B64 = LIST.toString('base64');

/**
 * A response to `name`'s HTTPS query: the header, the question, and the
 * answers, each owned by a compression pointer (0xc00c) to the question name.
 */
function response({ id = 0x1234, rcode = 0, tc = false, name = 'cloudflare-ech.com', answers = [] } = {}) {
  const flags = 0x8000 | 0x0100 | 0x0080 | (tc ? 0x0200 : 0) | rcode;
  const header = cat(u16(id), u16(flags), u16(1), u16(answers.length), u16(0), u16(0));
  const question = cat(encodeName(name), u16(65), u16(1));
  const rrs = answers.map(({ type = 65, ttl = 300, rdata }) => cat(u16(0xc00c), u16(type), u16(1), u32(ttl), u16(rdata.length), rdata));
  return cat(header, question, ...rrs);
}

const echRecord = (opts = {}) => ({ ttl: opts.ttl, rdata: httpsRdata({ priority: opts.priority ?? 1, params: [[1, ALPN], [5, opts.list || LIST]] }) });

/** What a query asks for: { id, flags, qdcount, name, qtype, qclass }. */
function readQuery(buf) {
  let pos = 12;
  const labels = [];
  while (buf[pos]) { labels.push(buf.subarray(pos + 1, pos + 1 + buf[pos]).toString('latin1')); pos += 1 + buf[pos]; }
  pos += 1;
  return { id: buf.readUInt16BE(0), flags: buf.readUInt16BE(2), qdcount: buf.readUInt16BE(4), name: labels.join('.'), qtype: buf.readUInt16BE(pos), qclass: buf.readUInt16BE(pos + 2) };
}

/** A transport that records its calls and answers the query it got with `answer(query)`. */
function fakeTransports(answer) {
  const calls = { udp: [], https: [] };
  return {
    calls,
    transports: {
      udp: async (host, port, query, timeoutMs) => { calls.udp.push({ host, port, query, timeoutMs }); return answer(query, calls.udp.length); },
      https: async (url, query, timeoutMs) => { calls.https.push({ url, query, timeoutMs }); return answer(query, calls.https.length); }
    }
  };
}
const timeout = () => Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' });
const answering = (opts) => (query) => response({ id: query.readUInt16BE(0), ...opts });

/* -------------------------------- buildQuery ------------------------------- */

test('buildQuery: header with RD=1 and one question, labels, QTYPE 65, QCLASS IN', () => {
  const q = buildQuery('cloudflare-ech.com', { id: 0x1234 });
  assert.deepEqual(q.subarray(0, 12), Buffer.from([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]));
  assert.deepEqual(q.subarray(12), cat(u8(14), Buffer.from('cloudflare-ech'), u8(3), Buffer.from('com'), u8(0), u16(65), u16(1)));
  assert.equal(q.length, 12 + 20 + 4);
});

test('buildQuery: a trailing dot is the same name; no id → a random one', () => {
  assert.deepEqual(buildQuery('crypto.cloudflare.com.', { id: 7 }), buildQuery('crypto.cloudflare.com', { id: 7 }));
  const ids = new Set(Array.from({ length: 20 }, () => buildQuery('a.example').readUInt16BE(0)));
  assert.ok(ids.size > 1);
  for (const id of ids) assert.ok(id >= 0 && id <= 0xffff);
});

test('buildQuery: refuses what DNS cannot carry', () => {
  assert.throws(() => buildQuery(''));
  assert.throws(() => buildQuery('a..b'));
  assert.throws(() => buildQuery('x'.repeat(64) + '.com'));
  assert.throws(() => buildQuery(Array.from({ length: 5 }, () => 'y'.repeat(60)).join('.')));
});

/* ----------------------------- parseHttpsAnswer ---------------------------- */

test('parseHttpsAnswer: one record behind a compression pointer → its ech value, ttl, rcode', () => {
  const r = parseHttpsAnswer(response({ answers: [echRecord({ ttl: 300 })] }), { id: 0x1234 });
  assert.equal(r.rcode, 0);
  assert.equal(r.ttl, 300);
  assert.equal(r.records, 1);
  assert.equal(r.truncated, false);
  assert.equal(r.lists.length, 1);
  assert.deepEqual(r.lists[0], LIST);
});

test('parseHttpsAnswer: two records → the lowest SvcPriority first, its ttl', () => {
  const other = echConfigList(echConfig({ publicName: 'other.example', configId: 2 }));
  const r = parseHttpsAnswer(response({ answers: [echRecord({ priority: 2, list: other, ttl: 60 }), echRecord({ priority: 1, ttl: 120 })] }));
  assert.equal(r.lists.length, 2);
  assert.deepEqual(r.lists[0], LIST);
  assert.deepEqual(r.lists[1], other);
  assert.equal(r.ttl, 120);
  assert.equal(r.records, 2);
});

test('parseHttpsAnswer: an alias-mode record (priority 0) first is passed over', () => {
  const alias = { rdata: httpsRdata({ priority: 0, target: 'pool.example.net' }) };
  const r = parseHttpsAnswer(response({ answers: [alias, echRecord({ ttl: 90 })] }));
  assert.equal(r.records, 2);
  assert.equal(r.lists.length, 1);
  assert.deepEqual(r.lists[0], LIST);
  assert.equal(r.ttl, 90);
});

test('parseHttpsAnswer: other record types are skipped; a record without ech counts but gives no list', () => {
  const cname = { type: 5, rdata: encodeName('edge.example.net') };
  const noEch = { rdata: httpsRdata({ params: [[1, ALPN]] }) };
  const r = parseHttpsAnswer(response({ answers: [cname, noEch] }));
  assert.equal(r.records, 1);
  assert.deepEqual(r.lists, []);
  assert.equal(r.ttl, null);
});

test('parseHttpsAnswer: rcode 3 comes back as rcode 3 with no lists', () => {
  const r = parseHttpsAnswer(response({ rcode: 3 }));
  assert.equal(r.rcode, 3);
  assert.deepEqual(r.lists, []);
});

test('parseHttpsAnswer: every truncation of an answer throws', () => {
  const full = response({ answers: [echRecord()] });
  for (let n = 0; n < full.length; n++) assert.throws(() => parseHttpsAnswer(full.subarray(0, n)), undefined, `cut at ${n}`);
});

test('parseHttpsAnswer: an SvcParam longer than its record throws', () => {
  const rdata = cat(u16(1), u8(0), u16(5), u16(200), Buffer.alloc(4));
  assert.throws(() => parseHttpsAnswer(response({ answers: [{ rdata }] })), /overruns/);
});

test('parseHttpsAnswer: an id other than the query\'s throws; no id given → not checked', () => {
  const msg = response({ id: 0x1234, answers: [echRecord()] });
  assert.throws(() => parseHttpsAnswer(msg, { id: 0x4321 }), /id/);
  assert.equal(parseHttpsAnswer(msg).lists.length, 1);
});

test('parseHttpsAnswer: a pointer loop and a query (QR=0) throw', () => {
  const loop = cat(u16(1), u16(0x8180), u16(1), u16(0), u16(0), u16(0), u16(0xc00c), u16(65), u16(1));
  assert.throws(() => parseHttpsAnswer(loop), /pointer/);
  assert.throws(() => parseHttpsAnswer(buildQuery('a.example', { id: 1 })), /not a DNS response/);
});

/* ---------------------------- parseEchConfigList --------------------------- */

test('parseEchConfigList: one config → its version and public name', () => {
  assert.deepEqual(parseEchConfigList(LIST), { configs: [{ version: 0xfe0d, publicName: 'cloudflare-ech.com' }] });
});

test('parseEchConfigList: a config of an unknown version is skipped by its length', () => {
  const list = echConfigList(echConfig({ version: 0xfe0a }), echConfig({ publicName: 'second.example' }));
  assert.deepEqual(parseEchConfigList(list), { configs: [{ version: 0xfe0d, publicName: 'second.example' }] });
});

test('parseEchConfigList: base64 in, the same answer', () => {
  assert.deepEqual(parseEchConfigList(LIST_B64), parseEchConfigList(LIST));
});

test('parseEchConfigList: contents too short → publicName null; lengths that do not add up throw', () => {
  const short = cat(u16(0xfe0d), u16(3), u8(1), u16(0x20));
  assert.deepEqual(parseEchConfigList(echConfigList(short)), { configs: [{ version: 0xfe0d, publicName: null }] });
  assert.throws(() => parseEchConfigList(cat(u16(LIST.length), LIST.subarray(2))), /length/);
  assert.throws(() => parseEchConfigList(cat(u16(6), u16(0xfe0d), u16(50), u16(0))), /overruns/);
  assert.throws(() => parseEchConfigList(''));
});

/* ------------------------------ fetchEchConfig ----------------------------- */

test('fetchEchConfig: over udp — the resolver, port 53 and the name from the query form', async () => {
  const { calls, transports } = fakeTransports(answering({ answers: [echRecord({ ttl: 300 })] }));
  const r = await fetchEchConfig('cloudflare-ech.com+udp://1.1.1.1', { serverName: 'ignored.example', timeout: 1500, transports });
  assert.deepEqual(r, { ok: true, list: LIST_B64, publicName: 'cloudflare-ech.com', via: 'udp://1.1.1.1:53', ttl: 300 });
  assert.equal(calls.udp.length, 1);
  assert.equal(calls.https.length, 0);
  const { host, port, query, timeoutMs } = calls.udp[0];
  assert.equal(host, '1.1.1.1');
  assert.equal(port, 53);
  assert.equal(timeoutMs, 1500);
  const asked = readQuery(query);
  assert.equal(asked.name, 'cloudflare-ech.com');
  assert.equal(asked.qtype, 65);
  assert.equal(asked.qclass, 1);
  assert.equal(asked.flags, 0x0100);
});

test('fetchEchConfig: a port in the form is used, an IPv6 resolver is bracketed in via', async () => {
  const { calls, transports } = fakeTransports(answering({ answers: [echRecord()] }));
  const r = await fetchEchConfig('cloudflare-ech.com+udp://[2606:4700:4700::1111]:5353', { transports });
  assert.equal(r.ok, true);
  assert.equal(r.via, 'udp://[2606:4700:4700::1111]:5353');
  assert.equal(calls.udp[0].host, '2606:4700:4700::1111');
  assert.equal(calls.udp[0].port, 5353);
});

test('fetchEchConfig: no name in the form → the serverName is asked for; neither → no name to ask for', async () => {
  const { calls, transports } = fakeTransports(answering({ name: 'crypto.cloudflare.com', answers: [echRecord()] }));
  const r = await fetchEchConfig('udp://1.1.1.1', { serverName: 'crypto.cloudflare.com', transports });
  assert.equal(r.ok, true);
  assert.equal(readQuery(calls.udp[0].query).name, 'crypto.cloudflare.com');

  const none = await fetchEchConfig('udp://1.1.1.1', { transports });
  assert.equal(none.ok, false);
  assert.equal(none.error, 'no name to ask for');
  assert.equal(calls.udp.length, 1);
});

test('fetchEchConfig: the https form hands the DoH URL to the https transport', async () => {
  const { calls, transports } = fakeTransports(answering({ answers: [echRecord({ ttl: 42 })] }));
  const r = await fetchEchConfig('cloudflare-ech.com+https://1.1.1.1/dns-query', { transports });
  assert.deepEqual(r, { ok: true, list: LIST_B64, publicName: 'cloudflare-ech.com', via: 'https://1.1.1.1/dns-query', ttl: 42 });
  assert.equal(calls.udp.length, 0);
  assert.equal(calls.https.length, 1);
  assert.equal(calls.https[0].url, 'https://1.1.1.1/dns-query');
  assert.equal(calls.https[0].timeoutMs, 4000);
  assert.equal(readQuery(calls.https[0].query).name, 'cloudflare-ech.com');
  assert.equal(readQuery(calls.https[0].query).id, 0);
});

test('fetchEchConfig: a base64 list, an empty one and none at all are skipped, nothing asked', async () => {
  const { calls, transports } = fakeTransports(() => { throw new Error('must not be asked'); });
  for (const v of [LIST_B64, '', undefined, null, '   ']) {
    assert.deepEqual(await fetchEchConfig(v, { serverName: 'a.example', transports }), { ok: false, skipped: true });
  }
  assert.equal(calls.udp.length + calls.https.length, 0);
});

test('fetchEchConfig: a udp timeout is retried once with a new id', async () => {
  const { calls, transports } = fakeTransports((query, n) => {
    if (n === 1) throw timeout();
    return response({ id: query.readUInt16BE(0), answers: [echRecord()] });
  });
  const r = await fetchEchConfig('cloudflare-ech.com+udp://1.1.1.1', { transports });
  assert.equal(r.ok, true);
  assert.equal(calls.udp.length, 2);
  assert.notEqual(readQuery(calls.udp[0].query).id, readQuery(calls.udp[1].query).id);
});

test('fetchEchConfig: two timeouts → a plain error; another failure is not retried', async () => {
  const twice = fakeTransports(() => { throw timeout(); });
  const r = await fetchEchConfig('cloudflare-ech.com+udp://1.1.1.1', { timeout: 2000, transports: twice.transports });
  assert.equal(r.ok, false);
  assert.equal(r.via, 'udp://1.1.1.1:53');
  assert.match(r.error, /no answer from udp:\/\/1\.1\.1\.1:53 within 2 s/);
  assert.equal(twice.calls.udp.length, 2);

  const refused = fakeTransports(() => { throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }); });
  const r2 = await fetchEchConfig('cloudflare-ech.com+udp://1.1.1.1', { transports: refused.transports });
  assert.equal(r2.ok, false);
  assert.match(r2.error, /could not ask udp:\/\/1\.1\.1\.1:53: connect ECONNREFUSED/);
  assert.equal(refused.calls.udp.length, 1);
});

test('fetchEchConfig: an HTTPS record without ech → ok:false in plain words', async () => {
  const { transports } = fakeTransports(answering({ answers: [{ rdata: httpsRdata({ params: [[1, ALPN]] }) }] }));
  const r = await fetchEchConfig('cloudflare-ech.com+udp://1.1.1.1', { transports });
  assert.deepEqual(r, { ok: false, error: 'cloudflare-ech.com has an HTTPS record but no ECH config in it', via: 'udp://1.1.1.1:53' });
});

test('fetchEchConfig: no HTTPS record, NXDOMAIN, SERVFAIL, a wrong id, a malformed list → ok:false', async () => {
  const cases = [
    [answering({ answers: [] }), /has no HTTPS record/],
    [answering({ rcode: 3 }), /does not exist \(NXDOMAIN\)/],
    [answering({ rcode: 2 }), /SERVFAIL/],
    [(query) => response({ id: query.readUInt16BE(0) ^ 1, answers: [echRecord()] }), /unreadable answer from .*id/],
    [answering({ answers: [echRecord({ list: cat(u16(9), u16(0xfe0d)) })] }), /ECH config .* unreadable/],
    [answering({ answers: [echRecord({ list: echConfigList(echConfig({ version: 0xfe0a })) })] }), /no config of a version/],
    [answering({ tc: true }), /too large for UDP/]
  ];
  for (const [answer, re] of cases) {
    const r = await fetchEchConfig('cloudflare-ech.com+udp://1.1.1.1', { transports: fakeTransports(answer).transports });
    assert.equal(r.ok, false);
    assert.equal(r.via, 'udp://1.1.1.1:53');
    assert.match(r.error, re);
  }
});

test('fetchEchConfig: a scheme other than udp or https is refused without asking', async () => {
  const { calls, transports } = fakeTransports(() => { throw new Error('must not be asked'); });
  for (const scheme of ['h2', 'quic', 'tcp']) {
    const r = await fetchEchConfig(`cloudflare-ech.com+${scheme}://dns.google/dns-query`, { transports });
    assert.equal(r.ok, false);
    assert.equal(r.error, `unsupported resolver scheme: ${scheme}`);
  }
  assert.equal(calls.udp.length + calls.https.length, 0);
});

test('fetchEchConfig: never throws — a transport that throws synchronously is an error value', async () => {
  const r = await fetchEchConfig('cloudflare-ech.com+https://1.1.1.1/dns-query', { transports: { https: () => { throw new Error('boom'); } } });
  assert.deepEqual(r, { ok: false, error: 'could not ask https://1.1.1.1/dns-query: boom', via: 'https://1.1.1.1/dns-query' });
});

/* ---------------------- default transports, on loopback --------------------- */

/** A UDP responder on 127.0.0.1: answers each query with `reply(query)`, or not at all when it returns null. */
async function udpResponder(reply) {
  const sock = dgram.createSocket('udp4');
  const seen = [];
  sock.on('message', (msg, rinfo) => {
    seen.push(msg);
    const out = reply(msg);
    if (out) sock.send(out, rinfo.port, rinfo.address);
  });
  await new Promise((resolve) => sock.bind(0, '127.0.0.1', resolve));
  return { port: sock.address().port, seen, close: () => new Promise((resolve) => sock.close(resolve)) };
}

test('defaultTransports.udp: sends the query and resolves with the first reply', async (t) => {
  const srv = await udpResponder((q) => response({ id: q.readUInt16BE(0), answers: [echRecord()] }));
  t.after(srv.close);
  const query = buildQuery('cloudflare-ech.com', { id: 0x2222 });
  const answer = await defaultTransports.udp('127.0.0.1', srv.port, query, 2000);
  assert.deepEqual(srv.seen[0], query);
  assert.deepEqual(parseHttpsAnswer(answer, { id: 0x2222 }).lists[0], LIST);
});

test('defaultTransports.udp: no reply → rejects with ETIMEDOUT', async (t) => {
  const srv = await udpResponder(() => null);
  t.after(srv.close);
  const started = Date.now();
  await assert.rejects(defaultTransports.udp('127.0.0.1', srv.port, buildQuery('a.example', { id: 1 }), 150), (e) => e.code === 'ETIMEDOUT');
  assert.ok(Date.now() - started < 2000);
});

test('defaultTransports.udp: a host name is looked up first', async (t) => {
  const srv = await udpResponder((q) => response({ id: q.readUInt16BE(0), answers: [echRecord()] }));
  t.after(srv.close);
  const real = dns.promises.lookup;
  const looked = [];
  dns.promises.lookup = async (host) => { looked.push(host); return { address: '127.0.0.1', family: 4 }; };
  t.after(() => { dns.promises.lookup = real; });
  const answer = await defaultTransports.udp('resolver.example', srv.port, buildQuery('a.example', { id: 3 }), 2000);
  assert.deepEqual(looked, ['resolver.example']);
  assert.equal(parseHttpsAnswer(answer, { id: 3 }).rcode, 0);
});

test('fetchEchConfig with the default udp transport, against the loopback responder', async (t) => {
  const srv = await udpResponder((q) => response({ id: q.readUInt16BE(0), answers: [echRecord({ ttl: 77 })] }));
  t.after(srv.close);
  const r = await fetchEchConfig(`cloudflare-ech.com+udp://127.0.0.1:${srv.port}`, { timeout: 2000 });
  assert.deepEqual(r, { ok: true, list: LIST_B64, publicName: 'cloudflare-ech.com', via: `udp://127.0.0.1:${srv.port}`, ttl: 77 });
});

test('defaultTransports.https: verifies the certificate — a self-signed DoH server is refused', async (t) => {
  const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'selfsigned.json'), 'utf8'));
  let hits = 0;
  const srv = https.createServer({ cert: fixture.certificate.join('\n'), key: fixture.key.join('\n') }, (req, res) => {
    hits++;
    res.writeHead(200, { 'content-type': 'application/dns-message' });
    res.end(response({ id: 0, answers: [echRecord()] }));
  });
  await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => srv.close(resolve)));
  await assert.rejects(
    defaultTransports.https(`https://127.0.0.1:${srv.address().port}/dns-query`, buildQuery('a.example', { id: 0 }), 2000),
    (e) => /CERT|SELF_SIGNED|ALTNAME/.test(String(e.code))
  );
  assert.equal(hits, 0);
});

test('defaultTransports.https: a URL that is not https is refused before anything is dialled', async () => {
  await assert.rejects(defaultTransports.https('http://127.0.0.1/dns-query', buildQuery('a.example', { id: 0 }), 500), /not an https URL/);
  await assert.rejects(defaultTransports.https('::nonsense', buildQuery('a.example', { id: 0 }), 500), /not a URL/);
});
