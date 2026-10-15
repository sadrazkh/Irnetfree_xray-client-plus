'use strict';
/**
 * plus: the scanner's ECH config, fetched once. A config whose
 * `tlsSettings.echConfigList` is a DNS query (`name+udp://1.1.1.1`,
 * `name+https://1.1.1.1/dns-query`, or the resolver alone with the SNI as the
 * name) would have every throwaway core ask DNS itself; the scan asks once
 * here — an HTTPS record (type 65), its `ech` SvcParam (key 5) — and hands
 * every core the base64 ECHConfigList, which `echConfigList` also accepts.
 *
 * The DNS wire format is written and read by hand (RFC 1035 + RFC 9460) so
 * the parsers are pure and tested on canned messages; the two transports are
 * the only code that touches a socket, and tests inject their own.
 */
const crypto = require('crypto');
const dgram = require('dgram');
const dns = require('dns');
const https = require('https');
const net = require('net');
const { domainToASCII } = require('url');
const { echQueryOf } = require('../configBuilder');

const TYPE_HTTPS = 65;
const CLASS_IN = 1;
const KEY_ECH = 5;
const ECH_VERSION = 0xfe0d;
const DEFAULT_TIMEOUT = 4000;
const MAX_DNS_MESSAGE = 65535;
const RCODES = { 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' };

const timeoutError = (ms) => Object.assign(new Error(`timeout after ${ms} ms`), { code: 'ETIMEDOUT' });
const isTimeout = (e) => !!e && e.code === 'ETIMEDOUT';
const errText = (e) => (e && (e.message || e.code)) || String(e);
const randomId = (not) => {
  let id;
  do id = crypto.randomInt(0, 0x10000); while (id === not);
  return id;
};
const hostForUrl = (h) => (net.isIP(h) === 6 ? `[${h}]` : h);

/** A bounds-checked view of a DNS message: every read past the end throws. */
function reader(buf) {
  const need = (pos, n) => {
    if (pos + n > buf.length) throw new Error('truncated DNS message');
  };
  return {
    u8: (pos) => { need(pos, 1); return buf[pos]; },
    u16: (pos) => { need(pos, 2); return buf.readUInt16BE(pos); },
    u32: (pos) => { need(pos, 4); return buf.readUInt32BE(pos); },
    bytes: (pos, n) => { need(pos, n); return Buffer.from(buf.subarray(pos, pos + n)); },
    need
  };
}

/**
 * A domain name at `pos`, following compression pointers. → { name, end }:
 * `end` is where the name ends in place (after its first pointer, if any).
 * A pointer must point backwards, so a loop cannot spin.
 */
function readName(r, pos) {
  const labels = [];
  let end = -1;
  let wire = 0;
  let floor = pos;
  for (;;) {
    const len = r.u8(pos);
    if ((len & 0xc0) === 0xc0) {
      const target = r.u16(pos) & 0x3fff;
      if (end === -1) end = pos + 2;
      if (target >= floor) throw new Error('bad compression pointer in DNS message');
      floor = target;
      pos = target;
      continue;
    }
    if (len & 0xc0) throw new Error('bad label in DNS message');
    if (len === 0) {
      if (end === -1) end = pos + 1;
      return { name: labels.join('.'), end };
    }
    wire += len + 1;
    if (wire > 255) throw new Error('name too long in DNS message');
    labels.push(r.bytes(pos + 1, len).toString('latin1'));
    pos += 1 + len;
  }
}

/**
 * The wire form of a DNS query for `name`'s HTTPS record: RD=1, one
 * question (QTYPE 65, QCLASS IN), nothing else. `id` defaults to a random
 * one. Throws on a name DNS cannot carry.
 */
function buildQuery(name, { id } = {}) {
  let s = String(name == null ? '' : name).trim().replace(/\.$/, '');
  if (/[^\x00-\x7f]/.test(s)) s = domainToASCII(s);
  const labels = s ? s.split('.') : [];
  if (!labels.length || labels.some((l) => !l || l.length > 63)) throw new Error(`not a DNS name: ${name}`);
  const qname = Buffer.concat([...labels.map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, 'latin1')])), Buffer.from([0])]);
  if (qname.length > 255) throw new Error(`not a DNS name: ${name}`);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(Number.isInteger(id) ? id & 0xffff : randomId(), 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(TYPE_HTTPS, 0);
  tail.writeUInt16BE(CLASS_IN, 2);
  return Buffer.concat([header, qname, tail]);
}

/** One HTTPS RR's RDATA → { priority, ech: Buffer | null }; alias mode (0) carries no params. */
function readSvcb(r, pos, end) {
  const priority = r.u16(pos);
  const target = readName(r, pos + 2);
  if (target.end > end) throw new Error('HTTPS record overruns its length');
  if (priority === 0) return { priority, ech: null };
  let ech = null;
  let p = target.end;
  while (p < end) {
    if (p + 4 > end) throw new Error('HTTPS record overruns its length');
    const key = r.u16(p);
    const len = r.u16(p + 2);
    if (p + 4 + len > end) throw new Error('HTTPS record overruns its length');
    if (key === KEY_ECH && !ech) ech = r.bytes(p + 4, len);
    p += 4 + len;
  }
  return { priority, ech };
}

/**
 * Every ECH config list a DNS answer carries, from its HTTPS records' `ech`
 * SvcParam, lowest SvcPriority first. → { lists, ttl, rcode, records,
 * truncated }: `ttl` that of the record `lists[0]` came from (null when
 * none), `records` how many HTTPS records the answer had (alias mode
 * included), `truncated` the TC bit. Throws on a truncated or malformed
 * message, on a message that is not a response, and on an id other than
 * `id` when one is given.
 */
function parseHttpsAnswer(buf, { id } = {}) {
  if (!Buffer.isBuffer(buf)) {
    if (buf instanceof Uint8Array) buf = Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength);
    else throw new Error('not a DNS message');
  }
  const r = reader(buf);
  r.need(0, 12);
  if (Number.isInteger(id) && r.u16(0) !== (id & 0xffff)) throw new Error('DNS answer id does not match the query');
  const flags = r.u16(2);
  if (!(flags & 0x8000)) throw new Error('not a DNS response');
  const rcode = flags & 0x000f;
  const truncated = !!(flags & 0x0200);
  const qdcount = r.u16(4);
  const ancount = r.u16(6);
  let pos = 12;
  for (let i = 0; i < qdcount; i++) {
    pos = readName(r, pos).end;
    r.need(pos, 4);
    pos += 4;
  }
  const found = [];
  let records = 0;
  for (let i = 0; i < ancount; i++) {
    pos = readName(r, pos).end;
    const type = r.u16(pos);
    const klass = r.u16(pos + 2);
    const ttl = r.u32(pos + 4);
    const rdlength = r.u16(pos + 8);
    const start = pos + 10;
    r.need(start, rdlength);
    pos = start + rdlength;
    if (type !== TYPE_HTTPS || klass !== CLASS_IN) continue;
    records++;
    const rec = readSvcb(r, start, pos);
    if (rec.priority > 0 && rec.ech) found.push({ priority: rec.priority, ech: rec.ech, ttl });
  }
  found.sort((a, b) => a.priority - b.priority);
  return { lists: found.map((f) => f.ech), ttl: found.length ? found[0].ttl : null, rcode, records, truncated };
}

/**
 * What an ECHConfigList holds: `{ configs: [{ version, publicName }] }`.
 * Takes the wire bytes or their base64. Configs of a version other than
 * 0xfe0d are skipped by their length; `publicName` is null when the config's
 * contents are too short to hold one. Throws when the list's lengths do not
 * add up (a core would refuse it too).
 */
function parseEchConfigList(bufOrBase64) {
  let buf;
  if (Buffer.isBuffer(bufOrBase64)) buf = bufOrBase64;
  else if (bufOrBase64 instanceof Uint8Array) buf = Buffer.from(bufOrBase64);
  else buf = Buffer.from(String(bufOrBase64 == null ? '' : bufOrBase64).trim(), 'base64');
  if (buf.length < 2) throw new Error('ECHConfigList too short');
  const total = buf.readUInt16BE(0);
  if (total !== buf.length - 2) throw new Error('ECHConfigList length does not match its content');
  const configs = [];
  let pos = 2;
  while (pos < buf.length) {
    if (pos + 4 > buf.length) throw new Error('ECHConfig header cut short');
    const version = buf.readUInt16BE(pos);
    const length = buf.readUInt16BE(pos + 2);
    const start = pos + 4;
    if (start + length > buf.length) throw new Error('ECHConfig overruns the list');
    pos = start + length;
    if (version !== ECH_VERSION) continue;
    configs.push({ version, publicName: publicNameOf(buf.subarray(start, pos)) });
  }
  return { configs };
}

/** ECHConfigContents (0xfe0d) → its public_name, or null when it cannot be read. */
function publicNameOf(c) {
  let p = 0;
  const has = (n) => p + n <= c.length;
  if (!has(3)) return null;
  p += 3;                                   // config_id, kem_id
  if (!has(2)) return null;
  p += 2 + c.readUInt16BE(p);               // public_key
  if (!has(2)) return null;
  p += 2 + c.readUInt16BE(p);               // cipher_suites
  if (!has(1)) return null;
  p += 1;                                   // maximum_name_length
  if (!has(1)) return null;
  const len = c[p];
  p += 1;
  if (!len || !has(len)) return null;
  return c.subarray(p, p + len).toString('latin1');
}

/**
 * Sends one DNS query over UDP and resolves with the first reply. A host
 * name is looked up first; the socket is connected (only the resolver's own
 * replies reach it) and always closed. Rejects with code ETIMEDOUT when
 * nothing comes back within `timeoutMs`.
 */
function udpTransport(host, port, query, timeoutMs) {
  const ms = Number(timeoutMs) > 0 ? Number(timeoutMs) : DEFAULT_TIMEOUT;
  return new Promise((resolve, reject) => {
    let sock = null;
    let done = false;
    const finish = (err, msg) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (sock) { try { sock.close(); } catch { /* already closed */ } }
      if (err) reject(err); else resolve(msg);
    };
    const timer = setTimeout(() => finish(timeoutError(ms)), ms);
    const family = net.isIP(host);
    const addr = family ? Promise.resolve({ address: host, family }) : dns.promises.lookup(host);
    addr.then(({ address, family: fam }) => {
      if (done) return;
      sock = dgram.createSocket(fam === 6 ? 'udp6' : 'udp4');
      sock.on('error', finish);
      sock.on('message', (msg) => finish(null, msg));
      sock.connect(Number(port) || 53, address, () => {
        if (done) return;
        sock.send(query, (err) => { if (err) finish(err); });
      });
    }, finish);
  });
}

/**
 * Sends one DNS query as a DoH POST (RFC 8484) and resolves with the answer
 * body. The certificate is verified as usual (SNI = the URL's host when it is
 * a name). Rejects on a status other than 200, and with code ETIMEDOUT when
 * the answer has not arrived within `timeoutMs`.
 */
function httpsTransport(url, query, timeoutMs) {
  const ms = Number(timeoutMs) > 0 ? Number(timeoutMs) : DEFAULT_TIMEOUT;
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch { return reject(new Error(`not a URL: ${url}`)); }
    if (u.protocol !== 'https:') return reject(new Error(`not an https URL: ${url}`));
    const host = u.hostname.replace(/^\[|\]$/g, '');
    let done = false;
    let req = null;
    const finish = (err, body) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (err && req) req.destroy();
      if (err) reject(err); else resolve(body);
    };
    const timer = setTimeout(() => finish(timeoutError(ms)), ms);
    const opts = {
      method: 'POST',
      host,
      port: u.port || 443,
      path: (u.pathname || '/') + u.search,
      agent: false,
      headers: {
        'content-type': 'application/dns-message',
        accept: 'application/dns-message',
        'content-length': query.length
      }
    };
    if (!net.isIP(host)) opts.servername = host;
    try {
      req = https.request(opts, (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          return finish(new Error(`HTTP ${res.statusCode}`));
        }
        const chunks = [];
        let size = 0;
        res.on('data', (c) => {
          size += c.length;
          if (size > MAX_DNS_MESSAGE) finish(new Error('answer larger than a DNS message'));
          else chunks.push(c);
        });
        res.on('end', () => finish(null, Buffer.concat(chunks)));
        res.on('error', finish);
      });
    } catch (e) {
      return finish(e);
    }
    req.on('error', finish);
    req.end(query);
  });
}

/** The transports fetchEchConfig uses unless it is handed its own. */
const defaultTransports = { udp: udpTransport, https: httpsTransport };

function rcodeError(rcode, name) {
  const label = RCODES[rcode] || `rcode ${rcode}`;
  if (rcode === 3) return `${name} does not exist (NXDOMAIN)`;
  if (rcode === 2) return `the resolver could not answer for ${name} (SERVFAIL)`;
  if (rcode === 5) return `the resolver refused the query (REFUSED)`;
  return `the resolver answered with an error (${label})`;
}

/**
 * Resolves an `echConfigList` that is a DNS query into the base64
 * ECHConfigList itself, once, for every core of a scan. Never throws:
 * `{ ok: true, list, publicName, via, ttl }`, `{ ok: false, skipped: true }`
 * when there is nothing to fetch (empty, or already a list), or
 * `{ ok: false, error, via }` in plain words.
 */
async function fetchEchConfig(echConfigList, { serverName, timeout = DEFAULT_TIMEOUT, transports } = {}) {
  let q;
  try { q = echQueryOf(echConfigList); } catch { q = null; }
  if (!q) return { ok: false, skipped: true };
  const t = Object.assign({}, defaultTransports, transports || {});
  const ms = Number(timeout) > 0 ? Number(timeout) : DEFAULT_TIMEOUT;
  const port = q.port || 53;
  const via = q.scheme === 'udp' ? `udp://${hostForUrl(q.host)}:${port}` : q.server;
  const fail = (error) => ({ ok: false, error, via });
  try {
    const name = String(q.name || serverName || '').trim().replace(/\.$/, '');
    if (!name) return fail('no name to ask for');
    if (q.scheme !== 'udp' && q.scheme !== 'https') return fail(`unsupported resolver scheme: ${q.scheme}`);

    let id;
    let query;
    try {
      // RFC 8484: a DoH query's id SHOULD be 0, so caches can share answers.
      id = q.scheme === 'https' ? 0 : randomId();
      query = buildQuery(name, { id });
    } catch {
      return fail(`not a name to ask for: ${name}`);
    }

    let answer;
    try {
      if (q.scheme === 'https') {
        answer = await t.https(q.server, query, ms);
      } else {
        try {
          answer = await t.udp(q.host, port, query, ms);
        } catch (e) {
          if (!isTimeout(e)) throw e;
          id = randomId(id);
          query = buildQuery(name, { id });
          answer = await t.udp(q.host, port, query, ms);
        }
      }
    } catch (e) {
      if (isTimeout(e)) return fail(`no answer from ${via} within ${Math.round(ms / 100) / 10} s${q.scheme === 'udp' ? ' (asked twice)' : ''}`);
      return fail(`could not ask ${via}: ${errText(e)}`);
    }

    let parsed;
    try {
      parsed = parseHttpsAnswer(answer, { id });
    } catch (e) {
      return fail(`unreadable answer from ${via}: ${errText(e)}`);
    }
    if (parsed.rcode !== 0) return fail(rcodeError(parsed.rcode, name));
    if (!parsed.lists.length) {
      if (!parsed.records && parsed.truncated) return fail(`the answer for ${name} was too large for UDP; use the https form`);
      if (!parsed.records) return fail(`${name} has no HTTPS record`);
      return fail(`${name} has an HTTPS record but no ECH config in it`);
    }

    const list = parsed.lists[0];
    let configs;
    try {
      ({ configs } = parseEchConfigList(list));
    } catch (e) {
      return fail(`the ECH config for ${name} is unreadable: ${errText(e)}`);
    }
    if (!configs.length) return fail(`the ECH config for ${name} has no config of a version the cores know`);
    const named = configs.find((c) => c.publicName);
    return { ok: true, list: list.toString('base64'), publicName: named ? named.publicName : null, via, ttl: parsed.ttl };
  } catch (e) {
    return fail(errText(e));
  }
}

module.exports = { buildQuery, parseHttpsAnswer, parseEchConfigList, fetchEchConfig, defaultTransports };
