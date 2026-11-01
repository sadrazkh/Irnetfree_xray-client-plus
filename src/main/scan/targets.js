'use strict';
/**
 * plus: what a scan run tests — addresses × ports × SNIs (spec v3 §4.1). Pure.
 *
 * The address box takes one item per line or comma/space/`;` separated, `#`
 * comments: an IPv4 address, an IPv4 CIDR (/8–/32), an `a-b` range, an IPv6
 * address or CIDR (/16–/128), or a host name. Any of them may carry a port —
 * `1.2.3.4:2053`, `1.2.3.0/24:443`, `host.example:2087`, and IPv6 only in
 * brackets: `[2606:4700::1]:443`, `[2606:4700::/120]:443`.
 *
 * IPv4 ranges are kept as integer intervals and walked on demand. A `/8` is
 * sixteen million addresses; building that array to take the first few
 * thousand would stall the main process, so expansion stops at `max` and an
 * address covered by an earlier range is skipped as a whole interval, not one
 * lookup at a time. IPv6 blocks (BigInt) are never walked: a /32 is 2^96
 * addresses, so a block gives a sample of itself.
 */

/** Cloudflare's published IPv4 blocks (https://www.cloudflare.com/ips-v4). */
const CF_IPV4_RANGES = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
];

/** Cloudflare's published IPv6 blocks (https://www.cloudflare.com/ips-v6). */
const CF_IPV6_RANGES = [
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
  '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32'
];

/**
 * The presets under the address box. WARP over MASQUE dials 162.159.198.0/24;
 * WARP over WireGuard is engage.cloudflareclient.com's seven /24 on the ports
 * its endpoint answers on. The `*-ports` presets fill the Ports box.
 */
const PRESETS = {
  cf: { ranges: CF_IPV4_RANGES.concat(CF_IPV6_RANGES) },
  'warp-masque': { ranges: ['162.159.198.0/24'] },
  'warp-wg': {
    ranges: ['162.159.192.0/24', '162.159.193.0/24', '162.159.195.0/24', '188.114.96.0/24', '188.114.97.0/24', '188.114.98.0/24', '188.114.99.0/24'],
    ports: [500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010,
      1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956,
      7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886]
  },
  'cf-tls-ports': [443, 2053, 2083, 2087, 2096, 8443],
  'cf-plain-ports': [80, 8080, 8880, 2052, 2082, 2086, 2095]
};

const DEFAULT_MAX = 5000;
const DEFAULT_PER_RANGE = 20;
const DEFAULT_V6_PER_RANGE = 100;
const MIN_PREFIX = 8;
const MIN_PREFIX6 = 16;
const MAX_PORTS = 1000;
const TWO_53 = 2n ** 53n;
const TWO_32 = 2n ** 32n;
/** A range up to this many addresses is drawn from a shuffled list of it; a bigger one by rejection. */
const ENUMERATE_UP_TO = 4096;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const posInt = (v, d) => Math.max(1, Math.floor(Number(v) || d));
const tokensOf = (line) => line.split(/[\s,;]+/).filter(Boolean);
/** The text's lines without their `#` comments, trimmed, with their 1-based numbers; empty lines left out. */
function linesOf(text) {
  const out = [];
  String(text == null ? '' : text).split(/\r?\n/).forEach((raw, i) => {
    const hash = raw.indexOf('#');
    const line = (hash === -1 ? raw : raw.slice(0, hash)).trim();
    if (line) out.push({ line, no: i + 1 });
  });
  return out;
}

/* ------------------------------- addresses ------------------------------- */

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

/** IPv6 text (`::` and a dotted IPv4 tail allowed, no zone) → BigInt, or null. */
function ip6ToBig(s) {
  let str = String(s == null ? '' : s).trim();
  if (!str || !str.includes(':') || /[^0-9a-fA-F:.]/.test(str)) return null;
  let tail = null;
  if (str.includes('.')) {
    const cut = str.lastIndexOf(':');
    tail = ip4ToInt(str.slice(cut + 1));
    if (tail === null) return null;
    str = str.slice(0, cut + 1) + '0:0';   // the dotted quad is the last two groups
  }
  const dbl = str.indexOf('::');
  if (dbl !== str.lastIndexOf('::')) return null;
  let groups;
  if (dbl === -1) {
    groups = str.split(':');
    if (groups.length !== 8) return null;
  } else {
    const head = str.slice(0, dbl), rest = str.slice(dbl + 2);
    const h = head ? head.split(':') : [], t = rest ? rest.split(':') : [];
    if (h.length + t.length > 7) return null;
    groups = h.concat(new Array(8 - h.length - t.length).fill('0'), t);
  }
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  if (tail !== null) n = (n & ~0xffffffffn) | BigInt(tail);
  return n;
}

/** BigInt → IPv6 text as RFC 5952 writes it: lowercase, no leading zeros, the first longest run of 2+ zero groups as `::`. */
function bigToIp6(n) {
  const g = [];
  for (let i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & 0xffffn));
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i >= 2 && j - i > bestLen) { best = i; bestLen = j - i; }
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  if (best === -1) return hex.join(':');
  return hex.slice(0, best).join(':') + '::' + hex.slice(best + bestLen).join(':');
}

/**
 * A DNS name a target or an SNI can be: labels of [a-z0-9-] (1–63 each), at
 * least two of them, 253 at most in all — and a last label that is not all
 * digits, so `300.1.1.1` is a bad address rather than a name. Lowercase in.
 */
function isDnsName(s) {
  if (!s || s.length > 253) return false;
  const labels = s.split('.');
  if (labels.length < 2) return false;
  if (!labels.every((l) => /^[a-z0-9-]{1,63}$/.test(l))) return false;
  return !/^\d+$/.test(labels[labels.length - 1]);
}

/** An address as text → { kind: 'v4' | 'v6', n }, or null. */
function parseAddr(s) {
  const n4 = ip4ToInt(s);
  if (n4 !== null) return { kind: 'v4', n: n4 };
  const n6 = ip6ToBig(s);
  return n6 === null ? null : { kind: 'v6', n: n6 };
}

/**
 * normalizeAddr(s) → '1.2.3.4' | '2606:4700::1' (RFC 5952) | 'host.example'
 * (lowercase) | null. One spelling per address, so a tested-before set and
 * a de-duplication compare like with like. `[v6]` is taken too; a port is not.
 */
function normalizeAddr(s) {
  const t = String(s == null ? '' : s).trim();
  const br = /^\[([^\]]*)\]$/.exec(t);
  if (br) {
    const n = ip6ToBig(br[1]);
    return n === null ? null : bigToIp6(n);
  }
  const a = parseAddr(t);
  if (a) return a.kind === 'v4' ? intToIp4(a.n) : bigToIp6(a.n);
  const h = t.toLowerCase();
  return isDnsName(h) ? h : null;
}

/** '1.2.3.4:443' | '[2606:4700::1]:443' | 'host.example:443'; no port → the address alone (IPv6 unbracketed). */
function addrPort(addr, port) {
  const a = String(addr == null ? '' : addr);
  if (port == null || port === '') return a;
  return (a.includes(':') && !a.startsWith('[') ? `[${a}]` : a) + ':' + port;
}

/* ------------------------------ the address box ------------------------------ */

/** A port as written → 1–65535, or null. */
function portValue(s) {
  if (!/^\d{1,5}$/.test(String(s))) return null;
  const p = Number(s);
  return p >= 1 && p <= 65535 ? p : null;
}

function v4Range(start, end) {
  return { kind: 'v4', size: end - start + 1, start, end };
}

/**
 * An IPv6 block. parseTargetText keeps its BigInt bounds non-enumerable, so a
 * parsed range still goes through JSON.stringify (an IPC or HTTP reply).
 */
function v6Range(start, end) {
  const count = end - start + 1n;
  return { kind: 'v6', size: count > TWO_53 ? Infinity : Number(count), start, end, count };
}

/** The address part of a token (no port) → a range, or { error }. `v6only`: it was in brackets. */
function parseBody(body, token, v6only) {
  const slash = body.indexOf('/');
  if (slash !== -1) {
    const a = parseAddr(body.slice(0, slash));
    const pfx = body.slice(slash + 1);
    if (!a || (v6only && a.kind !== 'v6')) return { error: 'invalid address: ' + token };
    if (!/^\d{1,3}$/.test(pfx)) return { error: 'invalid prefix: ' + token };
    const prefix = Number(pfx);
    if (a.kind === 'v4') {
      if (prefix < MIN_PREFIX || prefix > 32) return { error: `prefix must be /${MIN_PREFIX} to /32: ` + token };
      const size = 2 ** (32 - prefix);
      const start = a.n - (a.n % size);
      return v4Range(start, start + size - 1);
    }
    if (prefix < MIN_PREFIX6 || prefix > 128) return { error: `an IPv6 prefix must be /${MIN_PREFIX6} to /128: ` + token };
    const bits = BigInt(128 - prefix);
    const start = (a.n >> bits) << bits;
    return v6Range(start, start + (1n << bits) - 1n);
  }
  const dash = body.indexOf('-');
  if (dash !== -1) {
    const a = parseAddr(body.slice(0, dash)), b = parseAddr(body.slice(dash + 1));
    // an address on either side makes it a range; neither — a host name with a dash, below
    if (a || b) {
      if (!a || !b || a.kind !== b.kind || (v6only && a.kind !== 'v6')) return { error: 'invalid range: ' + token };
      if (b.n < a.n) return { error: 'range end before start: ' + token };
      return a.kind === 'v4' ? v4Range(a.n, b.n) : v6Range(a.n, b.n);
    }
  }
  const one = parseAddr(body);
  if (one && !(v6only && one.kind !== 'v6')) return one.kind === 'v4' ? v4Range(one.n, one.n) : v6Range(one.n, one.n);
  const host = body.toLowerCase();
  if (!v6only && isDnsName(host)) return { kind: 'host', size: 1, host };
  return { error: 'invalid address: ' + token };
}

/** One token → { kind, port, size, … } or { error }. */
function parseItem(token) {
  let body = token, port = null;
  if (token.startsWith('[')) {
    const m = /^\[([^\]]+)\](?::(.*))?$/.exec(token);
    if (!m) return { error: 'invalid address: ' + token };
    if (!m[1].includes(':')) return { error: 'brackets are for IPv6 only: ' + token };
    body = m[1];
    if (m[2] !== undefined && (port = portValue(m[2])) === null) return { error: 'invalid port (1–65535): ' + token };
    const r = parseBody(body, token, true);
    return r.error ? r : Object.assign(r, { port });
  }
  // one colon: a port; more: an IPv6 address, which takes a port only in brackets
  const colon = token.indexOf(':');
  if (colon !== -1 && colon === token.lastIndexOf(':')) {
    body = token.slice(0, colon);
    if (!body) return { error: 'invalid address: ' + token };
    if ((port = portValue(token.slice(colon + 1))) === null) return { error: 'invalid port (1–65535): ' + token };
  }
  const r = parseBody(body, token, false);
  return r.error ? r : Object.assign(r, { port });
}

/**
 * parseTargetText(text) → { ranges, errors }: the ranges in the order written,
 * each { kind: 'v4' | 'v6' | 'host', text, line, port, size, …internal }, and
 * the tokens that did not parse as { line, msg }. `size` is Infinity past 2^53.
 */
function parseTargetText(text) {
  const ranges = [], errors = [];
  for (const { line, no } of linesOf(text)) {
    for (const token of tokensOf(line)) {
      const item = parseItem(token);
      if (item.error) { errors.push({ line: no, msg: item.error }); continue; }
      const r = { kind: item.kind, text: token, line: no, port: item.port, size: item.size };
      if (item.kind === 'v4') Object.assign(r, { start: item.start, end: item.end });
      else if (item.kind === 'host') r.host = item.host;
      else Object.defineProperties(r, { start: { value: item.start }, end: { value: item.end }, count: { value: item.count } });
      ranges.push(r);
    }
  }
  return { ranges, errors };
}

/* --------------------------------- drawing --------------------------------- */

/** A uniform BigInt in [0, count). */
function randomBig(count, rng) {
  if (count <= 1n) return 0n;
  if (count <= TWO_32) return BigInt(Math.floor(rng() * Number(count)));
  const bits = count.toString(2).length + 32;   // 32 spare bits: the modulo bias is nil
  let r = 0n;
  for (let b = 0; b < bits; b += 32) r = (r << 32n) | BigInt(Math.floor(rng() * 4294967296));
  return r % count;
}

/**
 * IPv4 addresses of range i that no earlier range with the same port covers,
 * in order. Called with those ranges so a duplicate block is jumped over
 * instead of walked.
 */
function* freshAddresses(range, earlier) {
  for (let n = range.start; n <= range.end; n++) {
    const covering = earlier.find((e) => n >= e.start && n <= e.end);
    if (covering) { n = covering.end; continue; }
    yield n;
  }
}

/** An IPv6 block's share of an expansion: all of it when it is no bigger than `per`, else `per` random addresses. */
function* v6Sample(r, per, rng, taken) {
  if (r.count <= BigInt(per)) {
    for (let n = r.start; n <= r.end; n++) yield bigToIp6(n);
    return;
  }
  const mine = new Set();
  for (let tries = 0, budget = per * 30 + 100; mine.size < per && tries < budget; tries++) {
    const a = bigToIp6(r.start + randomBig(r.count, rng));
    if (mine.has(a) || taken(a)) continue;
    mine.add(a);
    yield a;
  }
}

/**
 * expandTargets(text, { max, v6PerRange, rng }) → { addrs: [{ addr, port }], errors, truncated }
 * Every address of the IPv4 ranges and host names in order; an IPv6 block
 * gives min(size, v6PerRange) addresses (random, or all of a small one). The
 * same address with the same port once. `truncated` is true only when an
 * address that would have been new was left out — reaching exactly `max` is
 * not a truncation.
 */
function expandTargets(text, opts = {}) {
  const max = posInt(opts.max, DEFAULT_MAX);
  const v6PerRange = posInt(opts.v6PerRange, DEFAULT_V6_PER_RANGE);
  const rng = typeof opts.rng === 'function' ? opts.rng : Math.random;
  const { ranges, errors } = parseTargetText(text);
  const addrs = [];
  const seen = new Set();   // `addr|port` of the IPv6 and host targets
  let truncated = false;
  const room = () => (addrs.length < max ? true : (truncated = true, false));
  outer: for (let i = 0; i < ranges.length; i++) {
    const r = ranges[i];
    if (r.kind === 'v4') {
      const earlier = ranges.slice(0, i).filter((e) => e.kind === 'v4' && e.port === r.port);
      for (const n of freshAddresses(r, earlier)) {
        if (!room()) break outer;
        addrs.push({ addr: intToIp4(n), port: r.port });
      }
    } else if (r.kind === 'host') {
      const key = r.host + '|' + r.port;
      if (seen.has(key)) continue;
      if (!room()) break outer;
      seen.add(key);
      addrs.push({ addr: r.host, port: r.port });
    } else {
      for (const a of v6Sample(r, v6PerRange, rng, (x) => seen.has(x + '|' + r.port))) {
        const key = a + '|' + r.port;
        if (seen.has(key)) continue;
        if (!room()) break outer;
        seen.add(key);
        addrs.push({ addr: a, port: r.port });
      }
    }
  }
  return { addrs, errors, truncated };
}

/**
 * drawTargets(text, { perRange, max, exclude, rng })
 *   → { addrs: [{ addr, port }], errors, ranges, exhausted, truncated }
 *
 * A fresh sample (spec v2.2 §2.1): `perRange` distinct addresses from every
 * range in the text, in the order written, capped at `max` in total — so the
 * cap cuts the last ranges, never a corner of the first. `exclude` is a Set of
 * addresses (normalizeAddr spellings) tested before: they are skipped while a
 * range still has others and come back only when it has not; such a range is
 * counted in `exhausted`. A host name is a range of one. With no `rng` every
 * call is a new draw.
 *
 * A small range is enumerated and shuffled (a /20 is 4096 numbers, nothing);
 * a big one — and every big IPv6 block — is sampled by rejection: twenty draws
 * out of a /13's half million never collide in practice, and the bounded loop
 * only matters for a block whose untested part is nearly gone.
 */
function drawTargets(text, opts = {}) {
  const perRange = posInt(opts.perRange, DEFAULT_PER_RANGE);
  const max = posInt(opts.max, DEFAULT_MAX);
  const exclude = opts.exclude instanceof Set ? opts.exclude : new Set();
  const rng = typeof opts.rng === 'function' ? opts.rng : Math.random;
  const { ranges, errors } = parseTargetText(text);
  const seen4 = new Map();   // port → Set of IPv4 integers taken
  const seen = new Set();    // `addr|port` of the IPv6 and host targets taken
  const addrs = [];
  let exhausted = 0, truncated = false;

  const shuffle = (arr) => {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      const t = arr[i]; arr[i] = arr[j]; arr[j] = t;
    }
    return arr;
  };
  const tested = (addr) => exclude.size > 0 && exclude.has(addr);

  /** The range's candidates: an IPv4 integer, or IPv6 / host text. */
  function access(r) {
    if (r.kind === 'v4') {
      let s = seen4.get(r.port);
      if (!s) seen4.set(r.port, (s = new Set()));
      return {
        at: (i) => r.start + i,
        random: () => r.start + Math.floor(rng() * r.size),
        seen: (n) => s.has(n),
        excluded: (n) => exclude.size > 0 && exclude.has(intToIp4(n)),
        take: (n) => { s.add(n); return intToIp4(n); }
      };
    }
    const at = r.kind === 'host' ? () => r.host : (i) => bigToIp6(r.start + BigInt(i));
    return {
      at,
      random: r.kind === 'host' ? at : () => bigToIp6(r.start + randomBig(r.count, rng)),
      seen: (a) => seen.has(a + '|' + r.port),
      excluded: tested,
      take: (a) => { seen.add(a + '|' + r.port); return a; }
    };
  }

  outer: for (const r of ranges) {
    const want = Math.min(perRange, r.size);
    const acc = access(r);
    let got = 0, repeated = false;
    /** Takes c; false when the cap leaves no room for it. */
    const take = (c) => {
      if (addrs.length >= max) { truncated = true; return false; }
      if (acc.excluded(c)) repeated = true;
      addrs.push({ addr: acc.take(c), port: r.port });
      got++;
      return true;
    };
    if (r.size <= ENUMERATE_UP_TO) {
      const fresh = [], old = [];
      for (let i = 0; i < r.size; i++) {
        const c = acc.at(i);
        if (acc.seen(c)) continue;
        (acc.excluded(c) ? old : fresh).push(c);
      }
      const order = shuffle(fresh).concat(shuffle(old));
      for (let i = 0; i < order.length && got < want; i++) if (!take(order[i])) break outer;
    } else {
      let tries = 0, allowTested = false;
      const budget = want * 30 + 100;
      while (got < want) {
        if (tries++ >= budget) {
          if (allowTested) break;      // even the tested part is used up (the same block written twice, say)
          allowTested = true; tries = 0;
        }
        const c = acc.random();
        if (acc.seen(c) || (!allowTested && acc.excluded(c))) continue;
        if (!take(c)) break outer;
      }
    }
    if (repeated) exhausted++;
  }
  return { addrs, errors, ranges: ranges.length, exhausted, truncated };
}

/* ------------------------------- ports, SNIs ------------------------------- */

/**
 * parsePorts('443, 2053 2083-2087;8443') → { ports, errors }: in the order
 * written, each once; a range holds at most 1000 ports and so does the whole
 * box (what is past it is left out, said once). Errors: { token, msg }.
 */
function parsePorts(text) {
  const ports = [], errors = [], seen = new Set();
  let full = false;
  for (const { line } of linesOf(text)) {
    for (const token of tokensOf(line.replace(/\s*-\s*/g, '-'))) {
      const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(token);
      if (!m) { errors.push({ token, msg: 'invalid port: ' + token }); continue; }
      const a = Number(m[1]), b = m[2] === undefined ? a : Number(m[2]);
      if (a < 1 || b < 1 || a > 65535 || b > 65535) { errors.push({ token, msg: 'a port is 1 to 65535: ' + token }); continue; }
      if (b < a) { errors.push({ token, msg: 'range end before start: ' + token }); continue; }
      if (b - a + 1 > MAX_PORTS) { errors.push({ token, msg: `a port range holds at most ${MAX_PORTS} ports: ` + token }); continue; }
      for (let p = a; p <= b; p++) {
        if (seen.has(p)) continue;
        if (ports.length >= MAX_PORTS) {
          if (!full) errors.push({ token, msg: `at most ${MAX_PORTS} ports: ${token} and what follows are left out` });
          full = true;
          break;
        }
        seen.add(p);
        ports.push(p);
      }
    }
  }
  return { ports, errors };
}

/**
 * parseSnis(text) → { snis, errors }: names one per line or comma/space
 * separated, `#` comments, lowercased, each once. A name is a DNS name
 * (isDnsName); a scheme, a path, a port, a `*` or an IP address is an error
 * for that token — { token, msg }.
 */
function parseSnis(text) {
  const snis = [], errors = [], seen = new Set();
  for (const { line } of linesOf(text)) {
    for (const token of tokensOf(line)) {
      const t = token.toLowerCase();
      let msg = '';
      if (/^[a-z][a-z0-9+.-]*:\/\//.test(t)) msg = 'a name only, no scheme: ';
      else if (t.includes('*')) msg = 'a wildcard is not a name: ';
      else if (t.includes('/')) msg = 'a name only, no path: ';
      else if (parseAddr(t.replace(/^\[(.*)\]$/, '$1'))) msg = 'an IP address is not an SNI: ';
      else if (t.includes(':')) msg = 'a name only, no port: ';
      else if (!isDnsName(t)) msg = 'invalid name: ';
      if (msg) { errors.push({ token, msg: msg + token }); continue; }
      if (seen.has(t)) continue;
      seen.add(t);
      snis.push(t);
    }
  }
  return { snis, errors };
}

/**
 * buildTargets({ addrs, ports, snis, defaultAddr, defaultPort, max })
 *   → { targets: [{ addr, port, sni, key }], truncated }
 *
 * The product a run tests. No addresses → the config's own (defaultAddr). An
 * address with its own port is tested on that port only; the others on every
 * port of `ports` (none → defaultPort). No SNIs → [null], the config's own.
 * In the order address, port, SNI; one target per key
 * (`addrPort(addr, port)|sni`). Past `max` the rest is left out and
 * `truncated` says so — exactly `max` is not a truncation.
 */
function buildTargets(opts = {}) {
  const { addrs, ports, snis, defaultAddr, defaultPort } = opts || {};
  const cap = posInt(opts && opts.max, DEFAULT_MAX);
  const list = Array.isArray(addrs) && addrs.length ? addrs : [{ addr: defaultAddr, port: null }];
  const portList = Array.isArray(ports) && ports.length ? ports : [defaultPort == null || defaultPort === '' ? null : defaultPort];
  const sniList = Array.isArray(snis) && snis.length ? snis : [null];
  const targets = [], keys = new Set();
  let truncated = false;
  outer: for (const a of list) {
    const own = a.port != null ? [a.port] : portList;
    for (const port of own) {
      for (const s of sniList) {
        const sni = s || null;
        const key = addrPort(a.addr, port) + '|' + (sni || '');
        if (keys.has(key)) continue;
        if (targets.length >= cap) { truncated = true; break outer; }
        keys.add(key);
        targets.push({ addr: a.addr, port, sni, key });
      }
    }
  }
  return { targets, truncated };
}

/* ------------------------------- lazy spaces ------------------------------- */

/*
 * 2026-11-01 (the owner: "remove the 5000 cap — all of them, or N random from
 * all of them together, or N from each range"). A run no longer receives a
 * LIST of targets: it receives a SPACE, `{ size, at(i) }`, and walks it. An
 * IPv4 range stays two integers however big it is — a /8 is 16,777,216
 * addresses and none of them is ever put in an array — so "all of them" costs
 * the time to test them and nothing to hold. A segment is a stretch of one
 * kind with one port; the space finds index i's segment by binary search over
 * their start offsets. IPv6 blocks cannot be walked (a /32 is 2^96) and stay
 * sampled, v6PerRange of each, as before. A sample of N "from all of them
 * together" is N distinct indices drawn uniformly over the whole space — each
 * range weighted by its size by construction — kept as N numbers, not N
 * addresses.
 */

/** The most a sample ("N random", "N from each range") takes: past it, "all of them" walks without a list. */
const MAX_SAMPLE = 1000000;

/** The index of the last start ≤ i (starts ascending, starts[0] = 0). */
function segmentAt(starts, i) {
  let lo = 0, hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= i) lo = mid; else hi = mid - 1;
  }
  return lo;
}

/** A space over segments [{ size, port, addrAt(j) }]: `at(i)` → { addr, port }. */
function spaceOf(segments, extra) {
  const segs = segments.filter((s) => s.size > 0);
  const starts = new Float64Array(segs.length);
  let size = 0;
  segs.forEach((s, k) => { starts[k] = size; size += s.size; });
  const at = (i) => {
    if (!(i >= 0 && i < size)) return null;
    const k = segmentAt(starts, i);
    const s = segs[k];
    return { addr: s.addrAt(i - starts[k]), port: s.port };
  };
  return Object.assign({ size, segments: segs, at }, extra);
}

/** Interval subtraction: the parts of [a, b] no interval of `taken` (sorted, disjoint) covers. */
function subtract(a, b, taken) {
  const out = [];
  let from = a;
  for (const [s, e] of taken) {
    if (e < from) continue;
    if (s > b) break;
    if (s > from) out.push([from, Math.min(b, s - 1)]);
    from = Math.max(from, e + 1);
    if (from > b) break;
  }
  if (from <= b) out.push([from, b]);
  return out;
}

/** `taken` with [a, b] merged in, still sorted and disjoint. */
function mergeInto(taken, a, b) {
  const out = [];
  let cur = [a, b], placed = false;
  for (const iv of taken) {
    if (iv[1] < cur[0] - 1) out.push(iv);
    else if (iv[0] > cur[1] + 1) { if (!placed) { out.push(cur); placed = true; } out.push(iv); }
    else cur = [Math.min(cur[0], iv[0]), Math.max(cur[1], iv[1])];
  }
  if (!placed) out.push(cur);
  return out;
}

/**
 * addressSpace(text, { v6PerRange, rng }) → { size, at(i), segments, ranges, errors, v6Sampled }
 *
 * Every address the box names, in the order written, the same address with
 * the same port once: an IPv4 range less what an earlier range with the same
 * port covered (interval arithmetic, not a lookup per address); a host name
 * once per port; an IPv6 block min(size, v6PerRange) of its addresses (all of
 * a small one, a random draw of a big one — `v6Sampled` counts the blocks
 * drawn from). `size` is exact; nothing past the parse is listed.
 */
function addressSpace(text, opts = {}) {
  const v6PerRange = posInt(opts.v6PerRange, DEFAULT_V6_PER_RANGE);
  const rng = typeof opts.rng === 'function' ? opts.rng : Math.random;
  const { ranges, errors } = parseTargetText(text);
  const takenByPort = new Map();   // port → sorted disjoint [start, end] of the IPv4 ranges so far
  const seen = new Set();          // `addr|port` of the hosts and IPv6 addresses
  const segments = [];
  let v6Sampled = 0;
  for (const r of ranges) {
    if (r.kind === 'v4') {
      const key = String(r.port);
      const taken = takenByPort.get(key) || [];
      for (const [s, e] of subtract(r.start, r.end, taken)) {
        segments.push({ kind: 'v4', size: e - s + 1, port: r.port, start: s, addrAt: (j) => intToIp4(s + j) });
      }
      takenByPort.set(key, mergeInto(taken, r.start, r.end));
    } else {
      const list = [];
      if (r.kind === 'host') {
        if (!seen.has(r.host + '|' + r.port)) { seen.add(r.host + '|' + r.port); list.push(r.host); }
      } else {
        if (r.count > BigInt(v6PerRange)) v6Sampled++;
        for (const a of v6Sample(r, v6PerRange, rng, (x) => seen.has(x + '|' + r.port))) {
          if (seen.has(a + '|' + r.port)) continue;
          seen.add(a + '|' + r.port);
          list.push(a);
        }
      }
      if (list.length) segments.push({ kind: r.kind, size: list.length, port: r.port, addrAt: (j) => list[j] });
    }
  }
  return spaceOf(segments, { ranges: ranges.length, errors, v6Sampled });
}

/** A space of a list [{ addr, port }] — a sample, a per-range draw — one segment per run of the same port. */
function listSpace(items) {
  const segments = [];
  let i = 0;
  while (i < items.length) {
    let j = i;
    while (j + 1 < items.length && items[j + 1].port === items[i].port) j++;
    const from = i, port = items[i].port;
    segments.push({ kind: 'list', size: j - i + 1, port, addrAt: (k) => items[from + k].addr });
    i = j + 1;
  }
  return spaceOf(segments);
}

/**
 * sampleSpace(space, n, { exclude, rng }) → { space, taken, repeated }
 *
 * "N random from all of them together": min(n, size) distinct indices,
 * uniform over the whole space, so a /16 next to a /24 gives 256 times as
 * many of its addresses — and the result in address order. `exclude` (a Set
 * of normalized addresses tested before) is skipped while the space has
 * others; when it has not, tested ones fill the rest and `repeated` counts
 * them. Over half of a space is drawn by a partial shuffle of all of it
 * (MAX_SAMPLE bounds that list); less, by drawing indices and throwing back
 * a repeat — few in practice.
 */
function sampleSpace(space, n, opts = {}) {
  const rng = typeof opts.rng === 'function' ? opts.rng : Math.random;
  const exclude = opts.exclude instanceof Set && opts.exclude.size ? opts.exclude : null;
  const M = space.size;
  const want = Math.min(Math.max(0, Math.floor(Number(n) || 0)), M, MAX_SAMPLE);
  const tested = (i) => !!exclude && exclude.has(space.at(i).addr);
  const picked = [];
  let repeated = 0;
  if (want * 2 > M) {
    const all = new Float64Array(M);
    for (let i = 0; i < M; i++) all[i] = i;
    for (let i = M - 1; i > 0; i--) { const j = Math.floor(rng() * (i + 1)); const t = all[i]; all[i] = all[j]; all[j] = t; }
    const old = [];
    for (let i = 0; i < M && picked.length < want; i++) { if (tested(all[i])) old.push(all[i]); else picked.push(all[i]); }
    while (picked.length < want && old.length) { picked.push(old.shift()); repeated++; }
  } else {
    const chosen = new Set();
    let tries = 0;
    const budget = want * 30 + 100;
    while (picked.length < want && tries++ < budget) {
      const i = Math.floor(rng() * M);
      if (chosen.has(i) || tested(i)) continue;
      chosen.add(i);
      picked.push(i);
    }
    // the untested part ran out: what was tested before fills the rest
    for (let i = 0; picked.length < want && i < M; i++) {
      const k = Math.floor(rng() * M);
      const c = chosen.has(k) ? (() => { for (let d = 1; d < M; d++) { const x = (k + d) % M; if (!chosen.has(x)) return x; } return -1; })() : k;
      if (c < 0) break;
      chosen.add(c);
      picked.push(c);
      repeated++;
    }
  }
  picked.sort((a, b) => a - b);
  return { space: listSpace(picked.map((i) => space.at(i))), taken: picked.length, repeated };
}

/**
 * targetSpace({ space, ports, snis, defaultAddr, defaultPort }) → { size, addresses, at(i) → { addr, port, sni, key } }
 *
 * buildTargets as a space: address, port, SNI in that order; an address with
 * its own port on that port alone, the others on every port of `ports`
 * (none → defaultPort); no SNIs → the config's own (null). An empty address
 * space → the config's own address. `addresses` is the address count.
 */
function targetSpace(opts = {}) {
  const base = opts.space && opts.space.size ? opts.space
    : spaceOf([{ kind: 'own', size: 1, port: null, addrAt: () => opts.defaultAddr }]);
  const portList = Array.isArray(opts.ports) && opts.ports.length ? opts.ports
    : [opts.defaultPort == null || opts.defaultPort === '' ? null : opts.defaultPort];
  const sniList = Array.isArray(opts.snis) && opts.snis.length ? opts.snis : [null];
  const S = sniList.length;
  const segs = base.segments.map((s) => ({ s, mult: (s.port != null ? 1 : portList.length) * S }));
  const starts = new Float64Array(segs.length);
  let size = 0;
  segs.forEach((x, k) => { starts[k] = size; size += x.s.size * x.mult; });
  const at = (i) => {
    if (!(i >= 0 && i < size)) return null;
    const k = segmentAt(starts, i);
    const { s, mult } = segs[k];
    const local = i - starts[k];
    const a = Math.floor(local / mult), r = local % mult;
    const port = s.port != null ? s.port : portList[Math.floor(r / S)];
    const sni = sniList[r % S] || null;
    const addr = s.addrAt(a);
    return { addr, port, sni, key: addrPort(addr, port) + '|' + (sni || '') };
  };
  return { size, addresses: base.size, ports: portList.length, snis: S, at };
}

/**
 * pickAddresses(text, pick, { exclude, rng, v6PerRange }) → { space, total, taken, ranges, errors, exhausted, repeated }
 *
 * The address box read the way the page's pick says:
 *  - `all`: every address (addressSpace) — `taken` = `total`;
 *  - `sample`: `count` random from all of them together (sampleSpace);
 *  - `random`: `perRange` from each range, as drawTargets has always drawn.
 * `total` is how many addresses the box names (IPv6 blocks counted as their
 * sample), `taken` how many the run tests.
 */
function pickAddresses(text, pick = {}, opts = {}) {
  const p = pick || {};
  const all = addressSpace(text, opts);
  const out = { total: all.size, ranges: all.ranges, errors: all.errors, exhausted: 0, repeated: 0, v6Sampled: all.v6Sampled };
  if (p.mode === 'sample') {
    const s = sampleSpace(all, p.count, opts);
    return Object.assign(out, { space: s.space, taken: s.taken, repeated: s.repeated, exhausted: s.repeated ? 1 : 0 });
  }
  if (p.mode === 'random') {
    const d = drawTargets(text, { perRange: Math.min(MAX_SAMPLE, posInt(p.perRange, DEFAULT_PER_RANGE)), max: MAX_SAMPLE, exclude: opts.exclude, rng: opts.rng });
    return Object.assign(out, { space: listSpace(d.addrs), taken: d.addrs.length, exhausted: d.exhausted, truncated: d.truncated });
  }
  return Object.assign(out, { space: all, taken: all.size });
}

/* --------------------------------- presets --------------------------------- */

/** Is IPv4 text `addr` inside one of the CIDRs? */
function inRanges4(addr, cidrs) {
  const n = ip4ToInt(addr);
  if (n === null) return false;
  return cidrs.some((c) => {
    const [base, bits] = c.split('/');
    const size = 2 ** (32 - Number(bits));
    const start = ip4ToInt(base);
    return n >= start && n < start + size;
  });
}

/** host of 'host:port' / '[v6]:port'. */
function endpointHost(ep) {
  const e = String(ep == null ? '' : ep).trim();
  const m6 = /^\[([^\]]+)\]/.exec(e);
  if (m6) return m6[1];
  const i = e.lastIndexOf(':');
  return i === -1 || e.indexOf(':') !== i ? e : e.slice(0, i);
}

/** The transports a CDN in front of the server carries. */
const CDN_NETWORKS = new Set(['ws', 'xhttp', 'splithttp', 'httpupgrade', 'grpc']);
const STREAM_PROTOCOLS = new Set(['vless', 'vmess', 'trojan', 'shadowsocks']);

/**
 * suggestPreset(server) → 'warp-masque' | 'warp-wg' | 'cf' | null: the preset
 * that fits a config. MASQUE with a WARP account, or dialling 162.159.198.0/24
 * → WARP MASQUE; WireGuard to engage.cloudflareclient.com or inside the WARP
 * ranges → WARP WireGuard; a ws / xhttp / httpupgrade / gRPC config over TLS
 * or plain (what a CDN carries; never REALITY) → Cloudflare.
 */
function suggestPreset(server) {
  const ob = server && server.outbound;
  if (!isObj(ob)) return null;
  const set = isObj(ob.settings) ? ob.settings : {};
  const st = isObj(ob.streamSettings) ? ob.streamSettings : {};
  if (ob.protocol === 'masque') {
    if (isObj(st.masqueSettings) && st.masqueSettings.warp != null) return 'warp-masque';
    const a = normalizeAddr(set.address || server.address);
    return a && inRanges4(a, PRESETS['warp-masque'].ranges) ? 'warp-masque' : null;
  }
  if (ob.protocol === 'wireguard') {
    const peer = Array.isArray(set.peers) && isObj(set.peers[0]) ? set.peers[0] : {};
    const h = normalizeAddr(endpointHost(peer.endpoint) || server.address);
    if (h === 'engage.cloudflareclient.com' || (h && inRanges4(h, PRESETS['warp-wg'].ranges))) return 'warp-wg';
    return null;
  }
  if (STREAM_PROTOCOLS.has(ob.protocol)) {
    const sec = String(st.security || 'none').toLowerCase();
    const net = String(st.network || 'tcp').toLowerCase();
    if ((sec === 'tls' || sec === 'none') && CDN_NETWORKS.has(net)) return 'cf';
  }
  return null;
}

module.exports = {
  parseTargetText, normalizeAddr, addrPort, expandTargets, drawTargets, parsePorts, parseSnis, buildTargets,
  addressSpace, sampleSpace, listSpace, targetSpace, pickAddresses, MAX_SAMPLE,
  PRESETS, suggestPreset, CF_IPV4_RANGES, ip4ToInt, intToIp4
};
