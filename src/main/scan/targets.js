'use strict';
/**
 * plus: the IP-scan target list. Pure.
 *
 * The text box takes one item per line or comma-separated: `1.2.3.4`,
 * `1.2.3.0/24`, `1.2.3.10-1.2.3.60`, `#` comments. IPv4 only this release.
 *
 * Ranges are kept as integer intervals and walked on demand. A `/8` is
 * sixteen million addresses; building that array to take the first few
 * thousand would stall the main process, so expansion stops at `max` and
 * an address covered by an earlier range is skipped as a whole interval,
 * not one lookup at a time.
 */

/** Cloudflare's published IPv4 blocks (https://www.cloudflare.com/ips-v4). */
const CF_IPV4_RANGES = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
];

const DEFAULT_MAX = 5000;
const MIN_PREFIX = 8;

/** Dotted quad → unsigned integer, or null. Multiplication keeps it unsigned. */
function ip4ToInt(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s || '').trim());
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (o > 255) return null;
    n = n * 256 + o;
  }
  return n;
}

function intToIp4(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/** One token → an inclusive interval { start, end, size }, or { error }. */
function parseItem(token) {
  const cidr = /^([^/]+)\/(\d{1,2})$/.exec(token);
  if (cidr) {
    const base = ip4ToInt(cidr[1]);
    const prefix = Number(cidr[2]);
    if (base === null) return { error: 'invalid address: ' + token };
    if (prefix < MIN_PREFIX || prefix > 32) return { error: `prefix must be /${MIN_PREFIX} to /32: ` + token };
    const size = 2 ** (32 - prefix);
    const start = base - (base % size);
    return { start, end: start + size - 1, size };
  }
  const dash = token.indexOf('-');
  if (dash !== -1) {
    const a = ip4ToInt(token.slice(0, dash)), b = ip4ToInt(token.slice(dash + 1));
    if (a === null || b === null) return { error: 'invalid range: ' + token };
    if (b < a) return { error: 'range end before start: ' + token };
    return { start: a, end: b, size: b - a + 1 };
  }
  const n = ip4ToInt(token);
  if (n === null) return { error: 'invalid address: ' + token };
  return { start: n, end: n, size: 1 };
}

/** The whole text → intervals in input order plus the lines that did not parse. */
function parseTargetText(text) {
  const ranges = [], errors = [];
  const lines = String(text || '').split(/\r?\n/);
  lines.forEach((raw, i) => {
    const hash = raw.indexOf('#');
    const line = (hash === -1 ? raw : raw.slice(0, hash)).trim();
    if (!line) return;
    for (const token of line.split(/[\s,;]+/).filter(Boolean)) {
      const item = parseItem(token);
      if (item.error) errors.push({ line: i + 1, msg: item.error });
      else ranges.push(Object.assign(item, { text: token, line: i + 1 }));
    }
  });
  return { ranges, errors };
}

/**
 * Addresses of range i that no earlier range covers, in order. Called with
 * the earlier ranges so a duplicate block is jumped over instead of walked.
 */
function* freshAddresses(range, earlier) {
  for (let n = range.start; n <= range.end; n++) {
    const covering = earlier.find(e => n >= e.start && n <= e.end);
    if (covering) { n = covering.end; continue; }
    yield n;
  }
}

/**
 * expandTargets(text, { max }) → { ips, errors, truncated }
 * `truncated` is true only when an address that would have been new was left
 * out — reaching exactly `max` is not a truncation.
 */
function expandTargets(text, opts = {}) {
  const max = Math.max(1, Math.floor(Number(opts.max) || DEFAULT_MAX));
  const { ranges, errors } = parseTargetText(text);
  const ips = [];
  let truncated = false;
  outer: for (let i = 0; i < ranges.length; i++) {
    for (const n of freshAddresses(ranges[i], ranges.slice(0, i))) {
      if (ips.length >= max) { truncated = true; break outer; }
      ips.push(intToIp4(n));
    }
  }
  return { ips, errors, truncated };
}

/**
 * sampleTargets(text, n, rng) → n distinct addresses, taken round-robin over
 * the ranges so a big block does not crowd the small ones out. When the text
 * describes no more than n addresses, all of them come back.
 */
function sampleTargets(text, n, rng = Math.random) {
  const want = Math.max(0, Math.floor(Number(n) || 0));
  if (!want) return [];
  const { ranges } = parseTargetText(text);
  if (!ranges.length) return [];
  const total = ranges.reduce((s, r) => s + r.size, 0);
  if (total <= want) return expandTargets(text, { max: want }).ips;

  const picked = ranges.map(() => new Set());
  const seen = new Set();
  const out = [];
  // Overlapping ranges can hand the same address back twice, so the loop is
  // bounded by attempts, not by the output length alone.
  for (let round = 0; out.length < want && round < want * 4 + 16; round++) {
    let progressed = false;
    for (let i = 0; i < ranges.length && out.length < want; i++) {
      const r = ranges[i];
      if (picked[i].size >= r.size) continue;
      let v = r.start + Math.floor(rng() * r.size);
      // a collision in a nearly used-up range: walk forward to the next free one
      for (let tries = 0; picked[i].has(v); tries++) {
        v = tries < 8 ? r.start + Math.floor(rng() * r.size) : (v >= r.end ? r.start : v + 1);
      }
      picked[i].add(v);
      progressed = true;
      if (seen.has(v)) continue;
      seen.add(v);
      out.push(intToIp4(v));
    }
    if (!progressed) break;
  }
  return out;
}

module.exports = { expandTargets, sampleTargets, parseTargetText, CF_IPV4_RANGES, ip4ToInt, intToIp4 };
