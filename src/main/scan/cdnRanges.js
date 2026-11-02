'use strict';
/**
 * plus: the CDNs' published address lists behind the presets under the address
 * box. 2026-11-02 (the owner: "Fastly, Amazon's CDN and Gcore beside Cloudflare,
 * and let the lists be updated"). targets.js carries the lists as shipped; the
 * Update button asks each CDN for its own public list here, and the answer is
 * kept in the store over the shipped one. A list that fails leaves what was
 * there, with the reason. Only addresses: nothing here picks a host or an SNI.
 *
 * Amazon's two lists are each half of what a scan wants. ip-ranges.json's
 * CLOUDFRONT service also holds the regional edge caches, which sit between the
 * edges and the origin and are not what a viewer dials (98 of its 216 IPv4
 * prefixes on 2026-11-02), so IPv4 comes from list-cloudfront-ips' global list.
 * That list has no IPv6, so IPv6 comes from ip-ranges.json.
 */
const http = require('http');
const https = require('https');
const T = require('./targets');

const STORE_KEY = 'scanCdnRanges';
const IDLE_MS = 20000;
/** ip-ranges.json is 2.7 MB. */
const MAX_BYTES = 8 * 1024 * 1024;
/** Fewer ranges than this is not the list, whatever the answer says it is. */
const MIN_RANGES = 5;

const lines = (text) => String(text).split(/\r?\n/);
const fieldOf = (obj, name) => {
  if (!obj || !Array.isArray(obj[name])) throw new Error(`no ${name} in it`);
  return obj[name];
};
const fields = (...names) => (text) => {
  const obj = JSON.parse(text);
  return names.flatMap((n) => fieldOf(obj, n));
};

const PROVIDERS = {
  cf: {
    name: 'Cloudflare',
    sources: [
      { url: 'https://www.cloudflare.com/ips-v4', read: lines },
      { url: 'https://www.cloudflare.com/ips-v6', read: lines }
    ]
  },
  fastly: {
    name: 'Fastly',
    sources: [{ url: 'https://api.fastly.com/public-ip-list', read: fields('addresses', 'ipv6_addresses') }]
  },
  cloudfront: {
    name: 'CloudFront',
    sources: [
      { url: 'https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips', read: fields('CLOUDFRONT_GLOBAL_IP_LIST') },
      {
        url: 'https://ip-ranges.amazonaws.com/ip-ranges.json',
        read: (text) => fieldOf(JSON.parse(text), 'ipv6_prefixes').filter((p) => p && p.service === 'CLOUDFRONT').map((p) => p.ipv6_prefix)
      }
    ]
  },
  gcore: {
    name: 'Gcore',
    sources: [{ url: 'https://api.gcore.com/cdn/public-ip-list', read: fields('addresses', 'addresses_v6') }]
  }
};
const CDN_IDS = Object.keys(PROVIDERS);

/** The entries that are a CIDR the address box reads, each once, in the order given. */
function cleanRanges(items) {
  const out = new Set();
  for (const raw of items) {
    const s = typeof raw === 'string' ? raw.trim() : '';
    if (!/^[0-9a-f:.]+\/\d+$/i.test(s)) continue;
    const { ranges, errors } = T.parseTargetText(s);
    if (ranges.length === 1 && !errors.length) out.add(s);
  }
  return Array.from(out);
}

/**
 * The body of a 200, as text; anything else rejects with what happened. https
 * only (plain http to loopback is the tests' seam). A redirect is an error: all
 * four lists answer where they are, and a list from elsewhere is not theirs.
 * The reason is settled before the request is destroyed, and destroyed without
 * an error: req.destroy(err) on a response whose last bytes are being read gives
 * the error to a socket no request holds any more, which ends the process.
 */
function fetchText(url, { idleMs = IDLE_MS, maxBytes = MAX_BYTES } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : (u.protocol === 'http:' && u.hostname === '127.0.0.1' ? http : null);
    if (!mod) return reject(new Error('https only'));
    const req = mod.get(u, { headers: { 'User-Agent': 'IRNetFree-Plus', Accept: '*/*' } }, (res) => {
      const code = res.statusCode || 0;
      if (code !== 200) { res.resume(); return reject(new Error(`HTTP ${code}`)); }
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > maxBytes) { reject(new Error('the answer is too large')); req.destroy(); return; }
        chunks.push(c);
      });
      res.on('error', reject);
      res.on('close', () => { if (!res.complete) reject(new Error('the answer was cut off')); });
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      return undefined;
    });
    req.on('error', reject);
    req.setTimeout(idleMs, () => { reject(new Error('no answer in time')); req.destroy(); });
    return undefined;
  });
}

/** One CDN's list from its own sources; every source must answer, or it rejects. */
async function fetchList(id, { get = fetchText } = {}) {
  const p = PROVIDERS[id];
  const answers = await Promise.all(p.sources.map((s) => get(s.url)));
  let items;
  try {
    items = p.sources.flatMap((s, i) => s.read(answers[i]));
  } catch (e) {
    throw new Error('the answer is not the list: ' + e.message);
  }
  const got = cleanRanges(items);
  if (got.length < MIN_RANGES) throw new Error(`the answer has ${got.length} usable range(s)`);
  return got;
}

/** The store's copy, only what still reads: { id: { ranges, updatedAt } }. */
function readStored(raw) {
  const out = {};
  if (!raw || typeof raw !== 'object') return out;
  for (const id of CDN_IDS) {
    const e = raw[id];
    if (!e || typeof e !== 'object' || !Array.isArray(e.ranges)) continue;
    const ranges = cleanRanges(e.ranges);
    if (ranges.length >= MIN_RANGES) out[id] = { ranges, updatedAt: Number(e.updatedAt) || 0 };
  }
  return out;
}

/** Every CDN's preset as the page reads it: { id: { ranges, updatedAt } }, the shipped list where the store has none. */
function presetsOf(stored) {
  const out = {};
  for (const id of CDN_IDS) {
    const s = stored && stored[id];
    out[id] = s ? { ranges: s.ranges.slice(), updatedAt: s.updatedAt } : { ranges: T.PRESETS[id].ranges.slice(), updatedAt: T.CDN_SHIPPED_AT };
  }
  return out;
}

/**
 * updateLists(ids, stored, { get, now }) → { stored, results }: each CDN asked at
 * once. `results` is one row per CDN: { id, name, ok, count, added, removed } or
 * { id, name, ok: false, error }; a failed one keeps its place in `stored`.
 */
async function updateLists(ids, stored, opts = {}) {
  const wanted = CDN_IDS.filter((id) => !Array.isArray(ids) || !ids.length || ids.includes(id));
  const now = Number(opts.now) || Date.now();
  const before = presetsOf(stored);
  const next = Object.assign({}, stored);
  const results = await Promise.all(wanted.map(async (id) => {
    const name = PROVIDERS[id].name;
    try {
      const ranges = await fetchList(id, opts);
      const had = new Set(before[id].ranges);
      const has = new Set(ranges);
      next[id] = { ranges, updatedAt: now };
      return { id, name, ok: true, count: ranges.length, added: ranges.filter((r) => !had.has(r)).length, removed: before[id].ranges.filter((r) => !has.has(r)).length };
    } catch (e) {
      return { id, name, ok: false, error: (e && e.message) || String(e) };
    }
  }));
  return { stored: next, results };
}

module.exports = { STORE_KEY, CDN_IDS, PROVIDERS, MIN_RANGES, cleanRanges, fetchText, fetchList, readStored, presetsOf, updateLists };
