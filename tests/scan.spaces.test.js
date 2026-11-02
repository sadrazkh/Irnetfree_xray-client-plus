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
 * order with its keys; the four picks say how many the box names and how many
 * the run takes; and N from each block follows a range's size, block by block,
 * however the box cuts the ranges.
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

/* ----------------------------- N from each block (2026-11-02) ----------------------------- */

const blockOf = (ip, prefix = 24) => (T.ip4ToInt(ip) - (T.ip4ToInt(ip) % 2 ** (32 - prefix))) / 2 ** (32 - prefix);
const perBlockCounts = (addrs, prefix) => {
  const m = new Map();
  for (const a of addrs) m.set(blockOf(a.addr, prefix), (m.get(blockOf(a.addr, prefix)) || 0) + 1);
  return [...m.values()];
};

test('drawBlocks: a range gives N for every 256 addresses, so its share follows its size', () => {
  const r = T.drawBlocks('10.0.0.0/22\n20.0.0.1/32\n30.0.0.0/30', { perBlock: 3, block: 24 }, { rng: seeded(21) });
  const of = (prefix) => r.addrs.filter((a) => a.addr.startsWith(prefix));
  assert.equal(of('10.').length, 12, 'a /22 is four /24s, 3 from each');
  assert.deepEqual(perBlockCounts(of('10.'), 24), [3, 3, 3, 3]);
  assert.deepEqual(of('20.').map((a) => a.addr), ['20.0.0.1'], 'a /32 is its one address');
  assert.equal(of('30.').length, 3, 'a /30 is one block of four');
  assert.equal(new Set(r.addrs.map((a) => a.addr)).size, r.addrs.length, 'distinct');
  assert.deepEqual([r.exhausted, r.truncated], [0, false]);
});

test('drawBlocks: a block is the address grid, not the way the box wrote the ranges', () => {
  const two = T.drawBlocks('1.1.1.1/32\n1.1.1.9/32\n1.1.2.1/32', { perBlock: 1, block: 24 }, { rng: seeded(22) }).addrs;
  assert.equal(two.length, 2, 'two /32s of one /24 share its one place');
  const across = T.drawBlocks('1.1.1.128-1.1.2.127', { perBlock: 2, block: 24 }, { rng: seeded(23) }).addrs;
  assert.deepEqual(perBlockCounts(across, 24), [2, 2], '256 addresses over a /24 boundary are two blocks');
  const twice = T.drawBlocks('1.1.1.0/25\n1.1.1.0/24', { perBlock: 3, block: 24 }, { rng: seeded(24) }).addrs;
  assert.equal(twice.length, 3, 'written twice, it is still one block');
});

test('drawBlocks: the block size is the setting; each port has its own blocks; a seed repeats it', () => {
  assert.deepEqual(perBlockCounts(T.drawBlocks('1.1.1.0/24', { perBlock: 2, block: 26 }, { rng: seeded(25) }).addrs, 26), [2, 2, 2, 2]);
  assert.equal(T.drawBlocks('1.1.0.0/20', { perBlock: 7, block: 20 }, { rng: seeded(26) }).addrs.length, 7);
  assert.equal(T.drawBlocks('1.1.1.0/24', { perBlock: 2, block: 99 }, { rng: seeded(27) }).addrs.length, 2, 'an unknown size reads as /24');
  const ports = T.drawBlocks('1.1.1.0/24:443\n1.1.1.0/24:2053', { perBlock: 2, block: 24 }, { rng: seeded(28) }).addrs;
  assert.deepEqual(ports.map((a) => a.port), [443, 443, 2053, 2053]);
  const once = T.drawBlocks('1.1.0.0/22', { perBlock: 4, block: 24 }, { rng: seeded(29) });
  assert.deepEqual(T.drawBlocks('1.1.0.0/22', { perBlock: 4, block: 24 }, { rng: seeded(29) }), once);
  assert.notDeepEqual(T.drawBlocks('1.1.0.0/22', { perBlock: 4, block: 24 }, { rng: seeded(30) }), once);
});

test('drawBlocks: what was tested is passed over while the block has others; then it repeats and says so', () => {
  const exclude = new Set(['1.1.1.0', '1.1.1.1', '1.1.1.2']);
  const fresh = T.drawBlocks('1.1.1.0/30', { perBlock: 1, block: 24 }, { rng: seeded(31), exclude });
  assert.deepEqual([fresh.addrs.map((a) => a.addr), fresh.exhausted], [['1.1.1.3'], 0]);
  const more = T.drawBlocks('1.1.1.0/30', { perBlock: 2, block: 24 }, { rng: seeded(32), exclude });
  assert.equal(more.addrs.length, 2);
  assert.ok(more.addrs.some((a) => a.addr === '1.1.1.3'));
  assert.equal(more.exhausted, 1);
});

test('drawBlocks: an IPv6 block gives N of itself, a host name itself; countPerBlock says the same number without drawing', () => {
  const text = '2606:4700::/32\n2606:4700::1/128\nhost.example:2087\n10.0.0.0/23\n10.0.1.5/32:443';
  const r = T.drawBlocks(text, { perBlock: 4, block: 24 }, { rng: seeded(33) });
  assert.equal(r.addrs.filter((a) => a.addr.includes(':')).length, 5, '4 of the /32, the /128 is its one address');
  assert.equal(r.addrs.filter((a) => a.addr === 'host.example').length, 1);
  assert.equal(r.addrs.filter((a) => a.addr.startsWith('10.') && a.port === null).length, 8);
  assert.equal(r.addrs.filter((a) => a.port === 443).length, 1);
  assert.equal(T.countPerBlock(text, { perBlock: 4, block: 24 }), r.addrs.length);
  assert.equal(T.drawBlocks('2606:4700::/32', { perBlock: 5000, block: 24 }, { rng: seeded(34) }).addrs.length, 100, 'IPv6 stays at most its usual sample');
});

test('countPerBlock: a /8 is arithmetic on its blocks, stopped at the sample limit', () => {
  assert.equal(T.countPerBlock('10.0.0.0/8', { perBlock: 1, block: 24 }), 65536);
  assert.equal(T.countPerBlock('10.0.0.0/8', { perBlock: 5, block: 16 }), 256 * 5);
  assert.equal(T.countPerBlock('10.0.0.0/8', { perBlock: 100, block: 24 }), T.MAX_SAMPLE);
  const big = T.drawBlocks('10.0.0.0/8', { perBlock: 1, block: 24 }, { rng: seeded(35) });
  assert.equal(big.addrs.length, 65536);
  assert.deepEqual(perBlockCounts(big.addrs.slice(0, 500), 24).every((n) => n === 1), true);
});

test('pickAddresses: pick block reads the box and says what it takes', () => {
  const p = T.pickAddresses('10.0.0.0/22\n20.0.0.1/32', { mode: 'block', perBlock: 2, block: 24 }, { rng: seeded(36) });
  assert.deepEqual([p.total, p.taken, p.ranges, p.exhausted, p.truncated], [1025, 9, 2, 0, false]);
  assert.equal(p.space.size, 9);
  assert.equal(new Set(Array.from({ length: 9 }, (_, i) => p.space.at(i).addr)).size, 9);
});
