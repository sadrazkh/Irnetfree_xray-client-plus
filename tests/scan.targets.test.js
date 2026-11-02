'use strict';
/**
 * Scan targets (spec v3 §4.1): the address box → addresses, the Ports and SNI
 * boxes, and their product.
 *
 * What matters: every accepted form (IPv4 single / CIDR / a-b range, IPv6
 * single / CIDR, host names, a port on any of them, comments, commas), bad
 * tokens reported with their line number instead of aborting, duplicates
 * removed in first-seen order, a hard cap so a /8 never becomes a 16-million
 * element array and an IPv6 block is never walked, a draw that is fresh every
 * run and skips what was tested before, and a product of address × port ×
 * SNI that keeps its order and its cap.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');

const {
  expandTargets, drawTargets, parseTargetText, normalizeAddr, addrPort, parsePorts, parseSnis, buildTargets,
  PRESETS, suggestPreset, CF_IPV4_RANGES, ip4ToInt, intToIp4
} = require('../src/main/scan/targets');

/** mulberry32 — a tiny seeded rng so the sampling tests are repeatable. */
function seeded(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6D2B79F5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const ipToInt = (s) => s.split('.').reduce((n, o) => n * 256 + Number(o), 0);
const inRange = (ip, lo, hi) => ipToInt(ip) >= ipToInt(lo) && ipToInt(ip) <= ipToInt(hi);
const ips = (r) => r.addrs.map((a) => a.addr);
/** Expanded IPv6 text → BigInt, through Node's own parser (a URL host) rather than the module's. */
const v6Big = (s) => {
  const host = new URL(`http://[${s}]/`).hostname.slice(1, -1);
  const head = host.split('::')[0], tail = host.includes('::') ? host.split('::')[1] : '';
  const h = head ? head.split(':') : [], t = tail ? tail.split(':') : [];
  const groups = host.includes('::') ? h.concat(new Array(8 - h.length - t.length).fill('0'), t) : h;
  return groups.reduce((n, g) => (n << 16n) | BigInt(parseInt(g, 16)), 0n);
};
const inV6 = (addr, cidr) => {
  const [base, bits] = cidr.split('/');
  const shift = BigInt(128 - Number(bits));
  return (v6Big(addr) >> shift) === (v6Big(base) >> shift);
};

/* ------------------------------- IPv4, kept ------------------------------- */

test('a single address, a CIDR and an a-b range expand in order', () => {
  assert.deepEqual(expandTargets('1.1.1.1'), { addrs: [{ addr: '1.1.1.1', port: null }], errors: [], truncated: false });
  assert.deepEqual(ips(expandTargets('1.1.1.0/30')), ['1.1.1.0', '1.1.1.1', '1.1.1.2', '1.1.1.3']);
  assert.deepEqual(ips(expandTargets('10.0.0.1-10.0.0.3')), ['10.0.0.1', '10.0.0.2', '10.0.0.3']);
  assert.deepEqual(ips(expandTargets('1.1.1.1/32')), ['1.1.1.1']);
  // a CIDR whose base is not on the block boundary still means the whole block
  assert.deepEqual(ips(expandTargets('1.1.1.5/30')), ['1.1.1.4', '1.1.1.5', '1.1.1.6', '1.1.1.7']);
});

test('lines, commas, semicolons and whitespace separate items; # starts a comment', () => {
  const r = expandTargets('# header\n1.1.1.1, 2.2.2.2 3.3.3.3 # trailing\n\n  4.4.4.4;5.5.5.5  \r\n');
  assert.deepEqual(ips(r), ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5']);
  assert.deepEqual(r.errors, []);
});

test('a bad line is reported with its line number and the rest still expands', () => {
  const r = expandTargets('1.1.1.1\nnot-an-ip\n300.1.1.1\n2.2.2.2\n1.1.1.0/7\n5.5.5.5-5.5.5.1\n1.1.1.0/33');
  assert.deepEqual(ips(r), ['1.1.1.1', '2.2.2.2']);
  assert.deepEqual(r.errors.map(e => e.line), [2, 3, 5, 6, 7]);
  for (const e of r.errors) assert.equal(typeof e.msg, 'string');
  assert.match(r.errors[2].msg, /\/8/, 'a prefix shorter than /8 says so');
  assert.match(r.errors[3].msg, /range/i);
});

test('empty and junk input yield no targets and no crash', () => {
  assert.deepEqual(expandTargets(''), { addrs: [], errors: [], truncated: false });
  assert.deepEqual(expandTargets(null).addrs, []);
  assert.deepEqual(expandTargets(undefined).addrs, []);
  assert.deepEqual(expandTargets('# only a comment\n\n').addrs, []);
  assert.deepEqual(parseTargetText(null), { ranges: [], errors: [] });
});

test('duplicates are removed and the first occurrence keeps its place', () => {
  const r = expandTargets('2.2.2.2\n1.1.1.0/30\n1.1.1.2\n2.2.2.2\n1.1.1.1-1.1.1.5');
  assert.deepEqual(ips(r), ['2.2.2.2', '1.1.1.0', '1.1.1.1', '1.1.1.2', '1.1.1.3', '1.1.1.4', '1.1.1.5']);
});

test('max truncates and says so; the default cap is 5000', () => {
  const r = expandTargets('10.0.0.0/24', { max: 10 });
  assert.equal(r.addrs.length, 10);
  assert.equal(r.addrs[9].addr, '10.0.0.9');
  assert.equal(r.truncated, true);
  assert.equal(expandTargets('10.0.0.0/24', { max: 256 }).truncated, false, 'exactly max is not a truncation');
  assert.equal(expandTargets('10.0.0.0/16').addrs.length, 5000);
});

test('a /8 is expanded lazily — the cap is hit long before 16 million addresses exist', () => {
  const t0 = Date.now();
  const r = expandTargets('10.0.0.0/8', { max: 100 });
  assert.equal(r.addrs.length, 100);
  assert.equal(r.truncated, true);
  assert.ok(Date.now() - t0 < 500, 'took ' + (Date.now() - t0) + 'ms');
  // a repeated /8 is skipped as a whole, not walked address by address
  const t1 = Date.now();
  const r2 = expandTargets('10.0.0.0/8\n10.0.0.0/8\n11.0.0.0/8', { max: 5000 });
  assert.equal(r2.addrs.length, 5000);
  assert.ok(Date.now() - t1 < 500, 'took ' + (Date.now() - t1) + 'ms');
});

test('CF_IPV4_RANGES are 15 valid IPv4 CIDRs; ip4ToInt / intToIp4 round-trip', () => {
  assert.equal(CF_IPV4_RANGES.length, 15);
  for (const c of CF_IPV4_RANGES) {
    const [ip, prefix] = c.split('/');
    assert.equal(net.isIPv4(ip), true, c);
    assert.ok(Number(prefix) >= 8 && Number(prefix) <= 32, c);
    assert.equal(expandTargets(c, { max: 1 }).errors.length, 0, c);
  }
  assert.ok(CF_IPV4_RANGES.includes('104.16.0.0/13'));
  assert.ok(CF_IPV4_RANGES.includes('172.64.0.0/13'));
  assert.equal(ip4ToInt('255.255.255.255'), 4294967295);
  assert.equal(intToIp4(ip4ToInt('104.16.1.2')), '104.16.1.2');
  assert.equal(ip4ToInt('256.1.1.1'), null);
});

/* ------------------------------- addresses ------------------------------- */

test('normalizeAddr: one spelling per address — IPv4, IPv6 in RFC 5952, host names lowercased', () => {
  assert.equal(normalizeAddr('1.2.3.4'), '1.2.3.4');
  assert.equal(normalizeAddr(' 001.002.003.004 '), '1.2.3.4');
  assert.equal(normalizeAddr('2606:4700:0:0:0:0:0:1111'), '2606:4700::1111');
  assert.equal(normalizeAddr('2001:0DB8::0001'), '2001:db8::1', 'lowercase, no leading zeros');
  assert.equal(normalizeAddr('2001:db8:0:0:1:0:0:1'), '2001:db8::1:0:0:1', 'the first of two equal zero runs');
  assert.equal(normalizeAddr('2001:db8:0:0:0:1:0:0'), '2001:db8::1:0:0', 'the longest zero run');
  assert.equal(normalizeAddr('2001:db8:0:1:1:1:1:1'), '2001:db8:0:1:1:1:1:1', 'one zero group is not shortened');
  assert.equal(normalizeAddr('::'), '::');
  assert.equal(normalizeAddr('::1'), '::1');
  assert.equal(normalizeAddr('fe80::'), 'fe80::');
  assert.equal(normalizeAddr('::ffff:1.2.3.4'), '::ffff:102:304', 'a dotted tail is the last 32 bits');
  assert.equal(normalizeAddr('[2606:4700::1]'), '2606:4700::1');
  assert.equal(normalizeAddr('Edge-1.Example.COM'), 'edge-1.example.com');
  for (const bad of ['', null, undefined, '300.1.1.1', 'not-an-ip', 'localhost', '1.2.3.4:443', '[2606:4700::1]:443',
    '1::2::3', '1:2:3:4:5:6:7:8:9', 'fe80::1%eth0', 'a..b.com', 'under_score.example.com', 'host.example/24']) {
    assert.equal(normalizeAddr(bad), null, String(bad));
  }
  // what Node's own parser makes of them
  for (const a of ['2606:4700::1111', '2001:db8::1:0:0:1', '::ffff:102:304']) assert.equal(net.isIPv6(a), true, a);
});

test('addrPort: IPv6 in brackets when a port follows, the address alone without one', () => {
  assert.equal(addrPort('1.2.3.4', 443), '1.2.3.4:443');
  assert.equal(addrPort('2606:4700::1', 443), '[2606:4700::1]:443');
  assert.equal(addrPort('host.example', 2087), 'host.example:2087');
  assert.equal(addrPort('2606:4700::1', null), '2606:4700::1');
  assert.equal(addrPort('2606:4700::1'), '2606:4700::1');
  assert.equal(addrPort('1.2.3.4', undefined), '1.2.3.4');
});

test('IPv6: single addresses and CIDRs /16–/128, sizes in numbers (Infinity past 2^53), never walked', () => {
  const p = parseTargetText('2606:4700::1111\n2606:4700::/120\n2606:4700::/32\n2400:cb00::/15\n2606:4700::/129\n2606:4700::/16\n[2606:4700::5/126]');
  assert.deepEqual(p.ranges.map((r) => [r.kind, r.size, r.line]),
    [['v6', 1, 1], ['v6', 256, 2], ['v6', Infinity, 3], ['v6', Infinity, 6], ['v6', 4, 7]]);
  assert.deepEqual(p.errors.map((e) => e.line), [4, 5]);
  assert.match(p.errors[0].msg, /\/16/);
  assert.doesNotThrow(() => JSON.stringify(p), 'a parsed range goes through JSON (an IPC or HTTP reply)');

  assert.deepEqual(expandTargets('2606:4700:0::1111'), { addrs: [{ addr: '2606:4700::1111', port: null }], errors: [], truncated: false });
  // a small block is all of it, in order; the base snaps to the block
  assert.deepEqual(ips(expandTargets('2606:4700::5/126')), ['2606:4700::4', '2606:4700::5', '2606:4700::6', '2606:4700::7']);
  // a bigger one gives v6PerRange random addresses (default 100), distinct, inside
  const big = expandTargets('2606:4700::/120', { rng: seeded(1) });
  assert.equal(big.addrs.length, 100);
  assert.equal(new Set(ips(big)).size, 100);
  for (const a of ips(big)) assert.ok(inV6(a, '2606:4700::/120'), a);
  assert.equal(big.truncated, false);
  assert.equal(expandTargets('2606:4700::/120', { v6PerRange: 7, rng: seeded(1) }).addrs.length, 7);
  // a /16 is 2^112 addresses: sampled at once, not walked
  const t0 = Date.now();
  const huge = expandTargets('2606::/16\n2400:cb00::/32', { v6PerRange: 200 });
  assert.ok(Date.now() - t0 < 300, 'took ' + (Date.now() - t0) + 'ms');
  assert.equal(huge.addrs.length, 400);
  for (const a of ips(huge).slice(0, 200)) assert.ok(inV6(a, '2606::/16') && net.isIPv6(a), a);
  // the cap still holds
  const cut = expandTargets('2606:4700::/120\n1.1.1.1', { max: 50 });
  assert.equal(cut.addrs.length, 50);
  assert.equal(cut.truncated, true);
});

test('host names are targets of one, lowercased; a dash in a name is not a range', () => {
  const p = parseTargetText('Edge.Example.com\nedge-1.example.com\n1.2.3.4-edge.example.com\nlocalhost\nexample.123');
  assert.deepEqual(p.ranges.map((r) => [r.kind, r.size, r.text]),
    [['host', 1, 'Edge.Example.com'], ['host', 1, 'edge-1.example.com']]);
  assert.deepEqual(p.errors.map((e) => e.line), [3, 4, 5]);
  assert.match(p.errors[0].msg, /range/);
  assert.deepEqual(expandTargets('Edge.Example.com, edge.example.com\n1.1.1.1').addrs,
    [{ addr: 'edge.example.com', port: null }, { addr: '1.1.1.1', port: null }]);
});

test('a port on any token: IPv4, CIDR, range, host name, and IPv6 only in brackets', () => {
  const r = expandTargets('1.2.3.4:2053\n1.2.3.0/31:443\n1.2.3.8-1.2.3.9:8443\nhost.example:2087\n[2606:4700::1]:443\n[2606:4700::/127]:8443');
  assert.deepEqual(r.addrs, [
    { addr: '1.2.3.4', port: 2053 },
    { addr: '1.2.3.0', port: 443 }, { addr: '1.2.3.1', port: 443 },
    { addr: '1.2.3.8', port: 8443 }, { addr: '1.2.3.9', port: 8443 },
    { addr: 'host.example', port: 2087 },
    { addr: '2606:4700::1', port: 443 },
    { addr: '2606:4700::', port: 8443 }, { addr: '2606:4700::1', port: 8443 }
  ]);
  assert.deepEqual(r.errors, []);
  const p = parseTargetText('1.2.3.4:2053\n[2606:4700::1]\n2606:4700::1:443');
  assert.deepEqual(p.ranges.map((x) => x.port), [2053, null, null], 'an unbracketed IPv6 has no port: 2606:4700::1:443 is an address');
  assert.equal(p.ranges[2].size, 1);

  const bad = parseTargetText('1.2.3.4:0\n1.2.3.4:65536\n1.2.3.4:\nhost.example:abc\n[1.2.3.4]:443\n[2606:4700::1]:70000\n[host.example]:443\n:443\n[2606:4700::1]x');
  assert.deepEqual(bad.ranges, []);
  assert.deepEqual(bad.errors.map((e) => e.line), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.match(bad.errors[0].msg, /port/);
  assert.match(bad.errors[4].msg, /IPv6/);
  assert.equal(expandTargets('1.2.3.4:65535').addrs[0].port, 65535);
});

test('the same address on two ports is two targets; on the same port, one', () => {
  const r = expandTargets('1.2.3.4:443\n1.2.3.4:2053\n1.2.3.4\n1.2.3.4/30:443\n1.2.3.4/30\nh.example:443\nh.example:443\n[2606:4700::1]:443\n2606:4700::1');
  assert.deepEqual(r.addrs.map((a) => addrPort(a.addr, a.port)), [
    '1.2.3.4:443', '1.2.3.4:2053', '1.2.3.4',
    '1.2.3.5:443', '1.2.3.6:443', '1.2.3.7:443',   // 1.2.3.4:443 was already there
    '1.2.3.5', '1.2.3.6', '1.2.3.7',               // and 1.2.3.4 with no port
    'h.example:443', '[2606:4700::1]:443', '2606:4700::1'
  ]);
});

test('parseTargetText: kind, text as written, line, port and size per range', () => {
  const p = parseTargetText('1.2.3.0/24:443 Edge.Example.com\n\n[2606:4700::1]:443');
  assert.deepEqual(p.ranges.map(({ kind, text, line, port, size }) => ({ kind, text, line, port, size })), [
    { kind: 'v4', text: '1.2.3.0/24:443', line: 1, port: 443, size: 256 },
    { kind: 'host', text: 'Edge.Example.com', line: 1, port: null, size: 1 },
    { kind: 'v6', text: '[2606:4700::1]:443', line: 3, port: 443, size: 1 }
  ]);
});

/* ----------------------------- drawTargets ----------------------------- */

const countIn = (list, lo, hi) => list.filter(ip => inRange(ip, lo, hi)).length;

test('drawTargets: perRange from every range, in the order written, distinct, and the same seed gives the same draw', () => {
  const r = drawTargets('1.1.1.0/24\n2.2.2.0/24', { perRange: 3, rng: seeded(7) });
  assert.equal(r.addrs.length, 6);
  assert.equal(countIn(ips(r).slice(0, 3), '1.1.1.0', '1.1.1.255'), 3, 'the first range comes first');
  assert.equal(countIn(ips(r).slice(3), '2.2.2.0', '2.2.2.255'), 3);
  assert.equal(new Set(ips(r)).size, 6);
  assert.deepEqual([r.ranges, r.exhausted, r.truncated, r.errors], [2, 0, false, []]);
  assert.deepEqual(drawTargets('1.1.1.0/24\n2.2.2.0/24', { perRange: 3, rng: seeded(7) }), r);
  assert.notDeepEqual(ips(drawTargets('1.1.1.0/24\n2.2.2.0/24', { perRange: 3, rng: seeded(8) })), ips(r));
});

test('drawTargets: a range smaller than perRange gives all of it; bad lines are reported and skipped', () => {
  const r = drawTargets('1.1.1.1-1.1.1.2\nnot-an-ip\n3.3.3.3', { perRange: 5, rng: seeded(1) });
  assert.deepEqual(ips(r).sort(), ['1.1.1.1', '1.1.1.2', '3.3.3.3']);
  assert.deepEqual(r.errors.map(e => e.line), [2]);
  assert.equal(r.ranges, 2);
  assert.deepEqual(drawTargets('', { perRange: 5 }), { addrs: [], errors: [], ranges: 0, exhausted: 0, truncated: false });
});

test('drawTargets: the cap cuts the last ranges; reaching it exactly is not a truncation', () => {
  const text = '1.1.1.0/24\n2.2.2.0/24\n3.3.3.0/24';
  const cut = drawTargets(text, { perRange: 10, max: 25, rng: seeded(2) });
  assert.equal(cut.addrs.length, 25);
  assert.equal(cut.truncated, true);
  assert.equal(countIn(ips(cut), '3.3.3.0', '3.3.3.255'), 5, 'the third range is what got cut');
  const exact = drawTargets(text, { perRange: 10, max: 30, rng: seeded(2) });
  assert.equal(exact.addrs.length, 30);
  assert.equal(exact.truncated, false);
});

test('drawTargets: addresses tested before are skipped while others remain, and come back — counted as exhausted — only when a range has run out', () => {
  const exclude = new Set(['1.1.1.0', '1.1.1.1']);
  const fresh = drawTargets('1.1.1.0/30', { perRange: 2, exclude, rng: seeded(3) });
  assert.deepEqual(ips(fresh).sort(), ['1.1.1.2', '1.1.1.3']);
  assert.equal(fresh.exhausted, 0);
  const more = drawTargets('1.1.1.0/30', { perRange: 3, exclude, rng: seeded(3) });
  assert.equal(more.addrs.length, 3);
  assert.ok(ips(more).includes('1.1.1.2') && ips(more).includes('1.1.1.3'), 'the two fresh ones are always in');
  assert.equal(more.exhausted, 1);
  // the tested ones are not what a fresh draw across two ranges reaches for
  const two = drawTargets('1.1.1.0/30\n2.2.2.0/30', { perRange: 2, exclude, rng: seeded(4) });
  assert.equal(two.exhausted, 0);
  assert.equal(ips(two).some(ip => exclude.has(ip)), false);
  // a host name tested before is still drawn — it has nothing else — and counts
  const host = drawTargets('h.example\ng.example', { exclude: new Set(['h.example']) });
  assert.deepEqual(ips(host), ['h.example', 'g.example']);
  assert.equal(host.exhausted, 1);
});

test('drawTargets over a big block: inside it, none of the excluded, fast, and a new draw every call', () => {
  const exclude = new Set();
  const rnd = seeded(5);
  for (let i = 0; i < 1000; i++) exclude.add(intToIp4(ip4ToInt('104.16.0.0') + Math.floor(rnd() * 2 ** 19)));
  const t0 = Date.now();
  const r = drawTargets('104.16.0.0/13', { perRange: 200, exclude, rng: seeded(6) });
  assert.ok(Date.now() - t0 < 300, 'took ' + (Date.now() - t0) + 'ms');
  assert.equal(r.addrs.length, 200);
  assert.equal(new Set(ips(r)).size, 200);
  for (const ip of ips(r)) { assert.ok(inRange(ip, '104.16.0.0', '104.23.255.255'), ip); assert.equal(exclude.has(ip), false, ip); }
  assert.equal(r.exhausted, 0);
  const a = ips(drawTargets('104.16.0.0/13', { perRange: 20 })), b = ips(drawTargets('104.16.0.0/13', { perRange: 20 }));
  assert.notDeepEqual(a, b, 'Math.random: two runs are two samples');
});

test('drawTargets: the same block written twice does not repeat an address; a big block fully drawn stops at what it has', () => {
  const twice = drawTargets('1.1.1.0/30\n1.1.1.0/30', { perRange: 4, rng: seeded(9) });
  assert.equal(twice.addrs.length, 4);
  assert.equal(new Set(ips(twice)).size, 4);
  assert.equal(twice.ranges, 2);
  const big = drawTargets('10.0.0.0/19\n10.0.0.0/19', { perRange: 8192, max: 100000, rng: seeded(10) });
  assert.equal(big.addrs.length, 8192, 'the second copy finds every address already taken and gives up');
  assert.equal(new Set(ips(big)).size, 8192);
});

test('drawTargets: the same block on another port is drawn again — a target is an address and a port', () => {
  const r = drawTargets('1.1.1.0/30:443\n1.1.1.0/30:2053', { perRange: 4, rng: seeded(12) });
  assert.equal(r.addrs.length, 8);
  assert.deepEqual(r.addrs.slice(0, 4).map((a) => a.port), [443, 443, 443, 443]);
  assert.deepEqual(r.addrs.slice(4).map((a) => a.port), [2053, 2053, 2053, 2053]);
  assert.deepEqual(ips(r).slice(0, 4).sort(), ips(r).slice(4).sort());
});

test('drawTargets over IPv6: a /32 with 200 per range is fast and inside; excluded skipped; seeded draws repeat; a small block is all of it', () => {
  const t0 = Date.now();
  const r = drawTargets('2606:4700::/32\n104.16.0.0/13', { perRange: 200, rng: seeded(13) });
  assert.ok(Date.now() - t0 < 300, 'took ' + (Date.now() - t0) + 'ms');
  assert.equal(r.addrs.length, 400);
  const v6 = ips(r).slice(0, 200);
  assert.equal(new Set(v6).size, 200);
  for (const a of v6) { assert.ok(inV6(a, '2606:4700::/32'), a); assert.equal(normalizeAddr(a), a, 'drawn in the normalizeAddr spelling'); }
  assert.deepEqual(drawTargets('2606:4700::/32', { perRange: 5, rng: seeded(13) }).addrs, r.addrs.slice(0, 5));

  const exclude = new Set(['2606:4700::', '2606:4700::1']);
  const small = drawTargets('[2606:4700::/126]:443', { perRange: 2, exclude, rng: seeded(14) });
  assert.deepEqual(ips(small).sort(), ['2606:4700::2', '2606:4700::3']);
  assert.deepEqual(small.addrs.map((a) => a.port), [443, 443]);
  assert.equal(small.exhausted, 0);
  const all = drawTargets('2606:4700::/126', { perRange: 10, exclude, rng: seeded(14) });
  assert.equal(all.addrs.length, 4);
  assert.equal(all.exhausted, 1);
  assert.deepEqual(drawTargets('2606:4700::1\n2606:4700::1', { perRange: 3 }).addrs, [{ addr: '2606:4700::1', port: null }]);
});

/* ------------------------------- ports, SNIs ------------------------------- */

test('parsePorts: singles and ranges, any separator, de-duplicated in order; bad tokens are errors naming them', () => {
  assert.deepEqual(parsePorts('443, 2053 2083-2087;8443'), { ports: [443, 2053, 2083, 2084, 2085, 2086, 2087, 8443], errors: [] });
  assert.deepEqual(parsePorts('443\n2053 # tls\n443 2052 - 2053'), { ports: [443, 2053, 2052], errors: [] });
  assert.deepEqual(parsePorts(''), { ports: [], errors: [] });
  assert.deepEqual(parsePorts(null), { ports: [], errors: [] });
  const bad = parsePorts('0 65536 9-1 x 1-2000 80');
  assert.deepEqual(bad.ports, [80]);
  assert.deepEqual(bad.errors.map((e) => e.token), ['0', '65536', '9-1', 'x', '1-2000']);
  for (const e of bad.errors) assert.ok(e.msg.includes(e.token), e.msg);
  assert.deepEqual(parsePorts('1000-1999').ports.length, 1000, 'a range of exactly 1000 is allowed');
});

test('parsePorts: 1000 ports at most in all — the rest is left out and said once', () => {
  const r = parsePorts('1-1000 2000-2010 3000');
  assert.equal(r.ports.length, 1000);
  assert.equal(r.ports[999], 1000);
  assert.equal(r.errors.length, 1);
  assert.equal(r.errors[0].token, '2000-2010');
});

test('parseSnis: DNS names, lowercased, each once; a scheme, a path, a port, a wildcard or an IP is an error', () => {
  assert.deepEqual(parseSnis('Cover.Example.com\nb.example.net, c.example.org cover.example.com # comment\n'),
    { snis: ['cover.example.com', 'b.example.net', 'c.example.org'], errors: [] });
  assert.deepEqual(parseSnis(''), { snis: [], errors: [] });
  const bad = parseSnis('https://x.example.com\nx.example.com/path\nx.example.com:443\n*.example.com\n1.2.3.4\n[2606:4700::1]\nlocalhost\nbad_name.example.com\n' +
    'a'.repeat(64) + '.example.com\n' + ('a'.repeat(60) + '.').repeat(5) + 'com\nok.example.com');
  assert.deepEqual(bad.snis, ['ok.example.com']);
  assert.equal(bad.errors.length, 10);
  assert.deepEqual(bad.errors.slice(0, 5).map((e) => e.token), ['https://x.example.com', 'x.example.com/path', 'x.example.com:443', '*.example.com', '1.2.3.4']);
  assert.match(bad.errors[0].msg, /scheme/);
  assert.match(bad.errors[1].msg, /path/);
  assert.match(bad.errors[2].msg, /port/);
  assert.match(bad.errors[3].msg, /wildcard/);
  assert.match(bad.errors[4].msg, /IP/);
});

/* ------------------------------- buildTargets ------------------------------- */

test('buildTargets: address × port × SNI in that order, keyed addrPort|sni', () => {
  const r = buildTargets({
    addrs: [{ addr: '1.1.1.1', port: null }, { addr: '2606:4700::1', port: 8443 }],
    ports: [443, 2053], snis: ['a.example.com', 'b.example.com']
  });
  assert.equal(r.truncated, false);
  assert.deepEqual(r.targets, [
    { addr: '1.1.1.1', port: 443, sni: 'a.example.com', key: '1.1.1.1:443|a.example.com' },
    { addr: '1.1.1.1', port: 443, sni: 'b.example.com', key: '1.1.1.1:443|b.example.com' },
    { addr: '1.1.1.1', port: 2053, sni: 'a.example.com', key: '1.1.1.1:2053|a.example.com' },
    { addr: '1.1.1.1', port: 2053, sni: 'b.example.com', key: '1.1.1.1:2053|b.example.com' },
    { addr: '2606:4700::1', port: 8443, sni: 'a.example.com', key: '[2606:4700::1]:8443|a.example.com' },
    { addr: '2606:4700::1', port: 8443, sni: 'b.example.com', key: '[2606:4700::1]:8443|b.example.com' }
  ], 'an address with its own port is tested on that port only');
});

test('buildTargets: empty boxes fall back to the config — its address, its port, its SNI (null)', () => {
  assert.deepEqual(buildTargets({ addrs: [], ports: [], snis: [], defaultAddr: 'a.example.com', defaultPort: 443 }),
    { targets: [{ addr: 'a.example.com', port: 443, sni: null, key: 'a.example.com:443|' }], truncated: false });
  assert.deepEqual(buildTargets({ defaultAddr: 'a.example.com', defaultPort: 443, ports: [2053, 2083] }).targets.map((t) => t.key),
    ['a.example.com:2053|', 'a.example.com:2083|'], 'the ports box applies to the config\'s own address too');
  assert.deepEqual(buildTargets({ addrs: [{ addr: '1.1.1.1', port: null }], defaultPort: 8443, snis: ['x.example.com'] }).targets,
    [{ addr: '1.1.1.1', port: 8443, sni: 'x.example.com', key: '1.1.1.1:8443|x.example.com' }]);
  assert.deepEqual(buildTargets({ addrs: [{ addr: '1.1.1.1', port: null }] }).targets,
    [{ addr: '1.1.1.1', port: null, sni: null, key: '1.1.1.1|' }], 'no port anywhere: null');
});

test('buildTargets: one target per key; past max the rest is cut and truncated says so — exactly max is not', () => {
  const dup = buildTargets({ addrs: [{ addr: '1.1.1.1', port: 443 }, { addr: '1.1.1.1', port: null }], ports: [443, 2053] });
  assert.deepEqual(dup.targets.map((t) => t.key), ['1.1.1.1:443|', '1.1.1.1:2053|']);
  const addrs = expandTargets('10.0.0.0/24').addrs;   // 256
  const ports = parsePorts('1-20').ports;               // 20
  const cut = buildTargets({ addrs, ports, max: 5000 });
  assert.equal(cut.targets.length, 5000);
  assert.equal(cut.truncated, true);
  assert.equal(cut.targets[4999].key, '10.0.0.249:20|');
  const exact = buildTargets({ addrs: addrs.slice(0, 250), ports, max: 5000 });
  assert.equal(exact.targets.length, 5000);
  assert.equal(exact.truncated, false);
  assert.equal(buildTargets({ addrs, ports }).targets.length, 5000, 'the default cap is 5000');
  const t0 = Date.now();
  const huge = buildTargets({ addrs: expandTargets('10.0.0.0/16').addrs, ports: parsePorts('1-1000').ports, snis: ['a.example.com', 'b.example.com'] });
  assert.equal(huge.targets.length, 5000);
  assert.ok(Date.now() - t0 < 300, 'the cap stops the product early: ' + (Date.now() - t0) + 'ms');
});

/* --------------------------------- presets --------------------------------- */

test('PRESETS: Cloudflare v4 + v6, WARP MASQUE, WARP WireGuard with its ports, the CF port lists — all parse', () => {
  assert.equal(PRESETS.cf.ranges.length, 22);
  assert.deepEqual(PRESETS.cf.ranges.slice(0, 15), CF_IPV4_RANGES);
  assert.deepEqual(PRESETS.cf.ranges.slice(15), ['2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32']);
  assert.deepEqual(PRESETS['warp-masque'], { ranges: ['162.159.198.0/24'] });
  assert.equal(PRESETS['warp-wg'].ranges.length, 7);
  assert.equal(PRESETS['warp-wg'].ports.length, 54);
  assert.ok(PRESETS['warp-wg'].ports.includes(2408) && PRESETS['warp-wg'].ports.includes(500) && PRESETS['warp-wg'].ports.includes(4500));
  assert.deepEqual(PRESETS['cf-tls-ports'], [443, 2053, 2083, 2087, 2096, 8443]);
  assert.deepEqual(PRESETS['cf-plain-ports'], [80, 8080, 8880, 2052, 2082, 2086, 2095]);
  for (const name of ['cf', 'warp-masque', 'warp-wg']) {
    const p = parseTargetText(PRESETS[name].ranges.join('\n'));
    assert.deepEqual(p.errors, [], name);
    assert.equal(p.ranges.length, PRESETS[name].ranges.length, name);
  }
  for (const list of [PRESETS['warp-wg'].ports, PRESETS['cf-tls-ports'], PRESETS['cf-plain-ports']]) {
    assert.deepEqual(parsePorts(list.join(',')), { ports: list, errors: [] });
  }
  const t0 = Date.now();
  const d = drawTargets(PRESETS.cf.ranges.join('\n'), { perRange: 20, rng: seeded(15) });
  assert.ok(Date.now() - t0 < 300, 'took ' + (Date.now() - t0) + 'ms');
  assert.equal(d.addrs.length, 22 * 20);
  assert.equal(d.ranges, 22);
});

const srv = (protocol, outbound, address) => ({ id: 'x', name: 'x', protocol, address: address || 'a.example.com', port: 443, outbound });
const vlessOn = (network, security, extra) => srv('vless', {
  protocol: 'vless',
  settings: { vnext: [{ address: 'a.example.com', port: 443, users: [{ id: 'u' }] }] },
  streamSettings: Object.assign({ network, security }, extra || {})
});

test('suggestPreset: the CDN a ws config names or dials; Cloudflare when nothing says otherwise; an updated list counts', () => {
  const ws = (address, stream = {}) => ({
    address,
    outbound: { protocol: 'vless', settings: { vnext: [{ address, port: 443, users: [{ id: 'u' }] }] }, streamSettings: Object.assign({ network: 'ws', security: 'tls' }, stream) }
  });
  assert.equal(suggestPreset(ws('example.com')), 'cf');
  assert.equal(suggestPreset(ws('example.com', { wsSettings: { host: 'me.global.ssl.fastly.net' } })), 'fastly', 'a decoy SNI and a Fastly Host');
  assert.equal(suggestPreset(ws('example.com', { wsSettings: { headers: { Host: 'ME.FASTLY.NET' } } })), 'fastly');
  assert.equal(suggestPreset(ws('d1.cloudfront.net')), 'cloudfront');
  assert.equal(suggestPreset(ws('example.com', { tlsSettings: { serverName: 'd1.cloudfront.net' } })), 'cloudfront');
  assert.equal(suggestPreset(ws('cl-1.gcdn.co')), 'gcore');
  assert.equal(suggestPreset(ws('notfastly.net')), 'cf', 'a name that only ends the same way');
  assert.equal(suggestPreset(ws('151.101.1.1')), 'fastly', 'an address inside Fastly\'s list');
  assert.equal(suggestPreset(ws('104.16.0.1')), 'cf');
  // the list as it stands now, not as it shipped
  const lists = { fastly: { ranges: ['9.9.9.0/24', '2a04:4e40::/32'] }, cloudfront: { ranges: [] }, gcore: { ranges: [] } };
  assert.equal(suggestPreset(ws('9.9.9.9'), lists), 'fastly');
  assert.equal(suggestPreset(ws('151.101.1.1'), lists), 'cf');
});

test('suggestPreset: WARP MASQUE, WARP WireGuard, Cloudflare for what a CDN carries, else none', () => {
  const masque = (address, ms) => srv('masque', { protocol: 'masque', settings: { address, port: 443 }, streamSettings: { network: 'masque', security: 'tls', tlsSettings: {}, masqueSettings: ms } }, address);
  assert.equal(suggestPreset(masque('m.example.com', { warp: { privateKey: 'k', publicKey: 'p', address: ['172.16.0.2/32'] } })), 'warp-masque');
  assert.equal(suggestPreset(masque('162.159.198.2', {})), 'warp-masque', 'WARP\'s MASQUE range without an account');
  assert.equal(suggestPreset(masque('m.example.com', {})), null);

  const wg = (endpoint) => srv('wireguard', { protocol: 'wireguard', settings: { secretKey: 'k', address: ['10.0.0.2/32'], peers: [{ publicKey: 'p', endpoint }] } });
  assert.equal(suggestPreset(wg('engage.cloudflareclient.com:2408')), 'warp-wg');
  assert.equal(suggestPreset(wg('Engage.CloudflareClient.com:2408')), 'warp-wg');
  assert.equal(suggestPreset(wg('162.159.192.7:2408')), 'warp-wg');
  assert.equal(suggestPreset(wg('188.114.99.200:500')), 'warp-wg');
  assert.equal(suggestPreset(wg('188.114.100.1:2408')), null);
  assert.equal(suggestPreset(wg('cobra.example:42421')), null);
  assert.equal(suggestPreset(wg('[2606:4700:d0::a29f:c001]:2408')), null);

  assert.equal(suggestPreset(vlessOn('ws', 'tls', { tlsSettings: { serverName: 'a.example.com' } })), 'cf');
  assert.equal(suggestPreset(vlessOn('ws', 'none')), 'cf');
  assert.equal(suggestPreset(vlessOn('xhttp', 'tls')), 'cf');
  assert.equal(suggestPreset(vlessOn('httpupgrade', 'none')), 'cf');
  assert.equal(suggestPreset(vlessOn('grpc', 'tls')), 'cf');
  assert.equal(suggestPreset(vlessOn('grpc', 'reality', { realitySettings: {} })), null, 'never REALITY');
  assert.equal(suggestPreset(vlessOn('tcp', 'reality', { realitySettings: {} })), null);
  assert.equal(suggestPreset(vlessOn('tcp', 'tls')), null, 'raw TLS is not what a CDN carries');
  assert.equal(suggestPreset(vlessOn('kcp', 'none')), null);
  assert.equal(suggestPreset(srv('hysteria2', { protocol: 'hysteria', settings: { address: 'h.example', port: 443 }, streamSettings: { network: 'hysteria', security: 'tls' } })), null);
  assert.equal(suggestPreset(srv('socks', { protocol: 'socks', settings: { servers: [{ address: 's.example', port: 1080 }] } })), null);
  // a JSON server is judged by its main outbound
  const json = Object.assign(vlessOn('ws', 'tls'), { source: 'json', extraOutbounds: [] });
  assert.equal(suggestPreset(json), 'cf');
  for (const junk of [null, undefined, {}, { outbound: null }]) assert.equal(suggestPreset(junk), null);
});
