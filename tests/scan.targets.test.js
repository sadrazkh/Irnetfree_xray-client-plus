'use strict';
/**
 * IP-scan targets: the text box → a list of IPv4 addresses.
 *
 * What matters: every accepted form (single, CIDR, a-b range, comments, commas),
 * bad lines reported with their line number instead of aborting, duplicates
 * removed in first-seen order, a hard cap so a /8 never becomes a 16-million
 * element array, and sampling that spreads across the given ranges rather than
 * taking the first n of the first one.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');

const { expandTargets, sampleTargets, CF_IPV4_RANGES } = require('../src/main/scan/targets');

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

test('a single address, a CIDR and an a-b range expand in order', () => {
  assert.deepEqual(expandTargets('1.1.1.1'), { ips: ['1.1.1.1'], errors: [], truncated: false });
  assert.deepEqual(expandTargets('1.1.1.0/30').ips, ['1.1.1.0', '1.1.1.1', '1.1.1.2', '1.1.1.3']);
  assert.deepEqual(expandTargets('10.0.0.1-10.0.0.3').ips, ['10.0.0.1', '10.0.0.2', '10.0.0.3']);
  assert.deepEqual(expandTargets('1.1.1.1/32').ips, ['1.1.1.1']);
  // a CIDR whose base is not on the block boundary still means the whole block
  assert.deepEqual(expandTargets('1.1.1.5/30').ips, ['1.1.1.4', '1.1.1.5', '1.1.1.6', '1.1.1.7']);
});

test('lines, commas and whitespace separate items; # starts a comment', () => {
  const r = expandTargets('# header\n1.1.1.1, 2.2.2.2 3.3.3.3 # trailing\n\n  4.4.4.4  \r\n');
  assert.deepEqual(r.ips, ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4']);
  assert.deepEqual(r.errors, []);
});

test('a bad line is reported with its line number and the rest still expands', () => {
  const r = expandTargets('1.1.1.1\nnot-an-ip\n300.1.1.1\n2.2.2.2\n1.1.1.0/7\n5.5.5.5-5.5.5.1\n1.1.1.0/33');
  assert.deepEqual(r.ips, ['1.1.1.1', '2.2.2.2']);
  assert.deepEqual(r.errors.map(e => e.line), [2, 3, 5, 6, 7]);
  for (const e of r.errors) assert.equal(typeof e.msg, 'string');
  assert.match(r.errors[2].msg, /\/8/, 'a prefix shorter than /8 says so');
  assert.match(r.errors[3].msg, /range/i);
});

test('IPv6 is not a target this release', () => {
  const r = expandTargets('2606:4700::1111\n1.1.1.1');
  assert.deepEqual(r.ips, ['1.1.1.1']);
  assert.equal(r.errors.length, 1);
});

test('empty and junk input yield no targets and no crash', () => {
  assert.deepEqual(expandTargets(''), { ips: [], errors: [], truncated: false });
  assert.deepEqual(expandTargets(null).ips, []);
  assert.deepEqual(expandTargets(undefined).ips, []);
  assert.deepEqual(expandTargets('# only a comment\n\n').ips, []);
});

test('duplicates are removed and the first occurrence keeps its place', () => {
  const r = expandTargets('2.2.2.2\n1.1.1.0/30\n1.1.1.2\n2.2.2.2\n1.1.1.1-1.1.1.5');
  assert.deepEqual(r.ips, ['2.2.2.2', '1.1.1.0', '1.1.1.1', '1.1.1.2', '1.1.1.3', '1.1.1.4', '1.1.1.5']);
});

test('max truncates and says so; the default cap is 5000', () => {
  const r = expandTargets('10.0.0.0/24', { max: 10 });
  assert.equal(r.ips.length, 10);
  assert.equal(r.ips[9], '10.0.0.9');
  assert.equal(r.truncated, true);
  assert.equal(expandTargets('10.0.0.0/24', { max: 256 }).truncated, false, 'exactly max is not a truncation');
  assert.equal(expandTargets('10.0.0.0/16').ips.length, 5000);
});

test('a /8 is expanded lazily — the cap is hit long before 16 million addresses exist', () => {
  const t0 = Date.now();
  const r = expandTargets('10.0.0.0/8', { max: 100 });
  assert.equal(r.ips.length, 100);
  assert.equal(r.truncated, true);
  assert.ok(Date.now() - t0 < 500, 'took ' + (Date.now() - t0) + 'ms');
  // a repeated /8 is skipped as a whole, not walked address by address
  const t1 = Date.now();
  const r2 = expandTargets('10.0.0.0/8\n10.0.0.0/8\n11.0.0.0/8', { max: 5000 });
  assert.equal(r2.ips.length, 5000);
  assert.ok(Date.now() - t1 < 500, 'took ' + (Date.now() - t1) + 'ms');
});

test('sampleTargets spreads across the ranges instead of taking the first n', () => {
  const out = sampleTargets('1.1.1.0/24\n2.2.2.0/24', 4, seeded(7));
  assert.equal(out.length, 4);
  assert.equal(out.filter(ip => inRange(ip, '1.1.1.0', '1.1.1.255')).length, 2);
  assert.equal(out.filter(ip => inRange(ip, '2.2.2.0', '2.2.2.255')).length, 2);
  assert.equal(new Set(out).size, 4, 'no duplicates');
  // the same seed gives the same sample
  assert.deepEqual(sampleTargets('1.1.1.0/24\n2.2.2.0/24', 4, seeded(7)), out);
});

test('sampleTargets: a small range runs out and the others fill the rest; n beyond the total is everything', () => {
  const out = sampleTargets('1.1.1.1-1.1.1.2\n2.2.2.0/24', 10, seeded(3));
  assert.equal(out.length, 10);
  assert.equal(out.filter(ip => inRange(ip, '1.1.1.1', '1.1.1.2')).length, 2);
  assert.equal(new Set(out).size, 10);

  const all = sampleTargets('1.1.1.0/30\n1.1.1.2', 50, seeded(1));
  assert.deepEqual(all.sort(), ['1.1.1.0', '1.1.1.1', '1.1.1.2', '1.1.1.3']);
  assert.deepEqual(sampleTargets('', 5), []);
  assert.deepEqual(sampleTargets('1.1.1.1', 0), []);
});

test('sampleTargets over a /8 stays fast and inside the block', () => {
  const t0 = Date.now();
  const out = sampleTargets('104.16.0.0/13', 200, seeded(11));
  assert.equal(out.length, 200);
  assert.ok(Date.now() - t0 < 500);
  for (const ip of out) assert.ok(inRange(ip, '104.16.0.0', '104.23.255.255'), ip);
});

test('CF_IPV4_RANGES are 15 valid IPv4 CIDRs', () => {
  assert.equal(CF_IPV4_RANGES.length, 15);
  for (const c of CF_IPV4_RANGES) {
    const [ip, prefix] = c.split('/');
    assert.equal(net.isIPv4(ip), true, c);
    assert.ok(Number(prefix) >= 8 && Number(prefix) <= 32, c);
    assert.equal(expandTargets(c, { max: 1 }).errors.length, 0, c);
  }
  assert.ok(CF_IPV4_RANGES.includes('104.16.0.0/13'));
  assert.ok(CF_IPV4_RANGES.includes('172.64.0.0/13'));
});
