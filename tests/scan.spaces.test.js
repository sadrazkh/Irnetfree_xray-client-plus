'use strict';
/**
 * The scan's lazy target spaces (targets.js, 2026-11-01: "remove the 5000
 * cap — all of them, N random from all of them together, or N from each
 * range").
 *
 * What matters: a range is never listed — a /8 is two numbers, its size exact
 * and any address of it at once; a space reads the same addresses in the same
 * order as the old expansion did where both fit; a sample of N is uniform over
 * the union of the ranges (a range weighted by its size), distinct, in address
 * order, repeatable with a seed, and skips what was tested before while it
 * can; the product address × port × SNI is a space too, in buildTargets'
 * order with its keys; and the three picks say how many the box names and how
 * many the run takes.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');

const T = require('../src/main/scan/targets');

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
const walk = (space) => Array.from({ length: space.size }, (_, i) => space.at(i));

test('addressSpace: every address in the order written, an earlier range with the same port subtracted, nothing listed', () => {
  const s = T.addressSpace('10.0.0.0/30\n10.0.0.2-10.0.0.5\n10.0.0.1:443\nh.example\nh.example\n10.0.0.0/31:443');
  assert.equal(s.size, 9);
  assert.deepEqual(walk(s).map((a) => T.addrPort(a.addr, a.port)), [
    '10.0.0.0', '10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5', '10.0.0.1:443', 'h.example', '10.0.0.0:443'
  ]);
  assert.equal(s.at(-1), null);
  assert.equal(s.at(s.size), null);
  // what expandTargets says, item for item, where both fit
  const text = '1.1.1.0/29, 1.1.1.4-1.1.1.12; 2.2.2.2:2053 2.2.2.2 [2606:4700::1]:443 a.example:8443 9.9.9.0/30 9.9.9.1';
  assert.deepEqual(walk(T.addressSpace(text)), T.expandTargets(text).addrs);
});

test('addressSpace: a /8 is two numbers — its size, its first, middle and last address, at once', () => {
  const t0 = Date.now();
  const s = T.addressSpace('10.0.0.0/8\n10.128.0.0/9\n11.0.0.0/8');
  assert.ok(Date.now() - t0 < 200, 'no walk');
  assert.equal(s.size, 2 * 16777216, 'the /9 inside the first /8 counts once');
  assert.equal(s.segments.length, 2);
  assert.deepEqual(s.at(0), { addr: '10.0.0.0', port: null });
  assert.deepEqual(s.at(8388608), { addr: '10.128.0.0', port: null });
  assert.deepEqual(s.at(16777215), { addr: '10.255.255.255', port: null });
  assert.deepEqual(s.at(16777216), { addr: '11.0.0.0', port: null });
  assert.deepEqual(s.at(s.size - 1), { addr: '11.255.255.255', port: null });
});

test('addressSpace: an IPv6 block stays a sample of itself; a small one is all of it', () => {
  const s = T.addressSpace('2606:4700::/32\n2606:4700::1-2606:4700::3', { v6PerRange: 50, rng: seeded(3) });
  assert.equal(s.v6Sampled, 1);
  assert.ok(s.size >= 50 && s.size <= 53, String(s.size));
  assert.ok(walk(s).every((a) => net.isIPv6(a.addr)));
});

test('sampleSpace: N distinct addresses uniform over all the ranges together — weighted by size — in address order, the tested ones skipped', () => {
  const s = T.addressSpace('10.0.0.0/16\n192.168.1.0/24');
  const pick = T.sampleSpace(s, 2570, { rng: seeded(7) });
  assert.equal(pick.taken, 2570);
  const got = walk(pick.space).map((a) => a.addr);
  assert.equal(new Set(got).size, 2570);
  const small = got.filter((a) => a.startsWith('192.168.1.')).length;
  assert.ok(small >= 2 && small <= 25, 'the /24 gets about 1/257 of the draw: ' + small);
  const ints = got.map(T.ip4ToInt);
  for (let i = 1; i < ints.length; i++) assert.ok(ints[i - 1] < ints[i], 'address order');
  assert.deepEqual(walk(T.sampleSpace(s, 100, { rng: seeded(9) }).space), walk(T.sampleSpace(s, 100, { rng: seeded(9) }).space), 'a seed repeats');

  const tiny = T.addressSpace('10.9.9.0/30');
  const exclude = new Set(['10.9.9.0', '10.9.9.1']);
  const fresh = T.sampleSpace(tiny, 2, { exclude, rng: seeded(1) });
  assert.deepEqual(walk(fresh.space).map((a) => a.addr), ['10.9.9.2', '10.9.9.3']);
  assert.equal(fresh.repeated, 0);
  const all = T.sampleSpace(tiny, 9, { exclude, rng: seeded(1) });
  assert.equal(all.taken, 4, 'no more than there is');
  assert.equal(all.repeated, 2, 'the tested ones fill in when nothing else is left');
  const mid = T.addressSpace('10.8.0.0/24');
  const ex2 = new Set(walk(mid).slice(0, 200).map((a) => a.addr));
  const m = T.sampleSpace(mid, 100, { exclude: ex2, rng: seeded(5) });
  assert.equal(m.taken, 100);
  assert.equal(m.repeated, 44, 'the 56 untested first, then 44 tested ones');

  // a big space, a small sample: no list of the space is built
  const t0 = Date.now();
  const big = T.sampleSpace(T.addressSpace('10.0.0.0/8'), 1000, { rng: seeded(2), exclude: new Set(['10.0.0.1']) });
  assert.equal(big.taken, 1000);
  assert.ok(Date.now() - t0 < 500);
});

test('targetSpace: address × port × SNI as buildTargets orders them, keys and all, without a list', () => {
  const text = '1.1.1.1\n2.2.2.2:2053\nh.example';
  const want = T.buildTargets({ addrs: T.expandTargets(text).addrs, ports: [443, 8443], snis: ['a.example', 'b.example'] }).targets;
  const space = T.targetSpace({ space: T.addressSpace(text), ports: [443, 8443], snis: ['a.example', 'b.example'] });
  assert.equal(space.size, want.length);
  assert.equal(space.addresses, 3);
  assert.deepEqual(walk(space), want);
  const own = T.targetSpace({ space: null, defaultAddr: 'c.example', defaultPort: 443 });
  assert.deepEqual(walk(own), T.buildTargets({ defaultAddr: 'c.example', defaultPort: 443 }).targets, 'empty boxes: the config’s own');
  // a /8 × 6 ports × 2 SNIs: 201 million targets, any one of them at once
  const huge = T.targetSpace({ space: T.addressSpace('10.0.0.0/8'), ports: [443, 2053, 2083, 2087, 2096, 8443], snis: ['a.example', 'b.example'] });
  assert.equal(huge.size, 16777216 * 12);
  assert.deepEqual(huge.at(huge.size - 1), { addr: '10.255.255.255', port: 8443, sni: 'b.example', key: '10.255.255.255:8443|b.example' });
  assert.deepEqual(huge.at(13), { addr: '10.0.0.1', port: 443, sni: 'b.example', key: '10.0.0.1:443|b.example' });
});

test('pickAddresses: all of them, N random from all together, N from each range — with the totals the page shows', () => {
  const text = '10.0.0.0/24\n10.0.1.0/28\nh.example';
  const all = T.pickAddresses(text, { mode: 'all' });
  assert.deepEqual([all.total, all.taken, all.ranges, all.space.size], [273, 273, 3, 273]);
  const sample = T.pickAddresses(text, { mode: 'sample', count: 50 }, { rng: seeded(4) });
  assert.deepEqual([sample.total, sample.taken, sample.space.size], [273, 50, 50]);
  const per = T.pickAddresses(text, { mode: 'random', perRange: 5 }, { rng: seeded(4) });
  assert.deepEqual([per.total, per.taken], [273, 11], '5 + 5 + the one host');
  const bad = T.pickAddresses('10.0.0.0/33\n1.1.1.1', { mode: 'all' });
  assert.equal(bad.errors.length, 1);
  assert.equal(bad.taken, 1);
  assert.equal(T.pickAddresses('10.0.0.0/8', { mode: 'all' }).taken, 16777216, 'no cap on all of them');
  assert.equal(T.pickAddresses('10.0.0.0/8', { mode: 'sample', count: 5e9 }).taken, T.MAX_SAMPLE, 'a sample is a list: it stops at MAX_SAMPLE');
});
