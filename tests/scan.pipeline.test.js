'use strict';
/**
 * The scan runner's 2026-11-01 pipeline (scanner.js), with a fake core and
 * fake probes: a SPACE of items walked in chunks (a hundred million items,
 * only the walked part ever asked for), the TCP / TLS pre-check once per
 * address before any core and the dead never reaching one, the delay probes
 * capped across all the cores together, an item's own cores (the variants
 * only Xray-PattN runs), a variant the core refuses marking only its own rows
 * with what the core said, the variant written into the test config, and the
 * bounded memory of a run too big to list.
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const { runScan, runSpeed, KEEP_ALIVE } = require('../src/main/scan/scanner');
const { delayStats } = require('../src/main/scan/score');
const V = require('../src/main/scan/variants');
const T = require('../src/main/scan/targets');
const F = require('./fixtures');

const tick = (ms = 2) => new Promise((r) => setTimeout(r, ms));
const ready = async () => true;

function dialAddress(out) {
  const s = out.settings || {};
  return (s.vnext && s.vnext[0] && s.vnext[0].address) || (s.servers && s.servers[0] && s.servers[0].address) || s.address || null;
}

/** A core that never spawns; probes that answer from `spec`. Records peaks and what each core was handed. */
function rig(spec = {}) {
  const cores = [], log = [], portTo = new Map();
  const active = { delay: 0, pre: 0, core: 0 }, peak = { delay: 0, pre: 0, core: 0 };
  const enter = (k) => { active[k]++; peak[k] = Math.max(peak[k], active[k]); };
  let base = 42000;
  const xray = {
    binExists: () => true,
    version: async () => '26.11.1',
    startTest: async (cfg, engine) => {
      const outs = cfg.inbounds.map((inb, k) => cfg.outbounds.find((o) => o.tag === `test-out-${k}`));
      cfg.inbounds.forEach((inb, k) => portTo.set(inb.port, { addr: dialAddress(outs[k]), out: outs[k] }));
      if (spec.refuse && outs.some((o) => spec.refuse(o, engine))) throw new Error('spawn failed');
      const core = { engine, cfg, addrs: outs.map(dialAddress), cleaned: 0 };
      cores.push(core);
      enter('core');
      return { proc: null, cleanup: () => { if (!core.cleaned) active.core--; core.cleaned++; } };
    },
    validate: async (cfg) => ({ ok: false, error: 'Failed to start: infra/conf: unknown fingerprint: chrome_999' })
  };
  const probes = {
    tcpPing: async (host, port, timeout) => {
      log.push(['tcp', host, port]);
      enter('pre'); await tick(spec.preMs || 3); active.pre--;
      return spec.tcp ? spec.tcp(host) : { ok: true, ms: 10 };
    },
    tlsPing: async (host, port, o) => {
      log.push(['tls', host, port, o.servername]);
      enter('pre'); await tick(3); active.pre--;
      return spec.tls ? spec.tls(host) : { ok: true, ms: 20, reason: '' };
    },
    delaySeries: async (port, o) => {
      const at = portTo.get(port);
      log.push(['delay', at.addr, o]);
      enter('delay'); await tick(spec.delayMs || 3); active.delay--;
      return spec.delay ? spec.delay(at.addr, at.out) : delayStats([50, 60, 70]);
    },
    downloadThroughProxy: async () => ({ ok: true, bytes: 1, ms: 100, ttfb: 10, mbps: 5, mbpsRaw: 5, warm: true, error: null }),
    uploadThroughProxy: async () => ({ ok: true, bytes: 1, ms: 50, ttfb: 50, mbps: 2, error: null })
  };
  const getFreePorts = async (n) => { const b = base; base += 100; return Array.from({ length: n }, (_, k) => b + k); };
  return { xray, probes, getFreePorts, cores, log, peak };
}

function go(r, over = {}) {
  const results = [], progress = [];
  const opts = Object.assign({ batch: 4, coresInParallel: 2, probes: r.probes, getFreePorts: r.getFreePorts, waitReady: ready, speedTop: 0 }, over.opts);
  const args = Object.assign({
    server: F.VLESS_WS_TLS, engines: ['xray'], tests: { tcp: true, delay: true, down: false, up: false },
    xray: r.xray, token: { cancelled: false },
    onResult: (x) => results.push(x), onProgress: (p) => progress.push(p)
  }, over, { opts });
  return runScan(args).then((out) => ({ out, results, progress }));
}

const items = (addrs) => addrs.map((a) => ({ addr: a, port: 443, sni: null, key: a + ':443|' }));

test('a space is walked a chunk at a time: a hundred million items, only the walked part asked for, stopped by the token', async () => {
  const r = rig();
  const space = T.targetSpace({ space: T.addressSpace('10.0.0.0/8'), ports: [443, 2053, 2083, 2087, 2096, 8443] });
  let asked = 0;
  const counted = { size: space.size, at: (i) => { asked++; return space.at(i); } };
  const token = { cancelled: false };
  const seen = [];
  const { out } = await go(r, {
    targets: counted, token,
    onResult: (x) => { seen.push(x); if (seen.length >= 30) token.cancelled = true; }
  });
  assert.equal(counted.size, 100663296);
  assert.equal(out.cancelled, true);
  assert.ok(asked <= 128, 'never more than two chunks read: ' + asked);
  assert.ok(seen.length >= 30);
});

test('the pre-check: one TCP connect per address however many variants and cores share it; the dead never reach a core and carry `no-tcp`', async () => {
  const r = rig({ tcp: (host) => (host === '1.1.1.2' ? { ok: false, ms: -1, error: 'ECONNREFUSED' } : { ok: true, ms: 9 }) });
  const vs = V.buildVariants(F.VLESS_WS_TLS, V.sanitizeSpec({ dims: { fingerprint: ['chrome', 'firefox', 'safari'] } })).variants;
  const list = [];
  for (const t of items(['1.1.1.1', '1.1.1.2', '1.1.1.3'])) for (const v of vs) list.push(Object.assign({}, t, { key: t.key + '#' + v.key, variant: v }));
  const { results, progress } = await go(r, { targets: list, engines: ['xray', 'xray-pattn'] });
  const tcp = r.log.filter((e) => e[0] === 'tcp');
  assert.deepEqual(tcp.map((e) => e[1]).sort(), ['1.1.1.1', '1.1.1.2', '1.1.1.3'], 'three connects for 18 rows');
  assert.equal(results.length, 18);
  const dead = results.filter((x) => x.addr === '1.1.1.2');
  assert.equal(dead.length, 6, 'every variant on every core');
  for (const d of dead) {
    assert.deepEqual([d.reason, d.score, d.delay, d.tcp.ok, d.tcp.error], ['no-tcp', 0, null, false, 'ECONNREFUSED']);
    assert.ok(d.variant && d.variantLabel, 'the row names its variant');
  }
  assert.ok(r.cores.every((c) => !c.addrs.includes('1.1.1.2')), 'no core saw the dead address');
  for (const x of results.filter((y) => y.addr !== '1.1.1.2')) assert.deepEqual(x.tcp, { ok: true, ms: 9 }, 'the connect travels with the row');
  assert.deepEqual(progress.at(-1).reasons, { 'no-tcp': 6 });
});

test('the TLS form of the pre-check: a handshake under the item’s SNI (or the config’s), and a failure reads `tls`', async () => {
  const r = rig({ tls: (host) => (host === '1.1.1.3' ? { ok: false, ms: -1, reason: 'tls', error: 'reset' } : { ok: true, ms: 20, reason: '' }) });
  const list = items(['1.1.1.1', '1.1.1.3']);
  list[0].sni = 'front.example.org';
  const { results } = await go(r, { targets: list, sni: 'a.example.com', opts: { prefilterTls: true } });
  assert.deepEqual(r.log.filter((e) => e[0] === 'tls').map((e) => [e[1], e[3]]), [['1.1.1.1', 'front.example.org'], ['1.1.1.3', 'a.example.com']]);
  assert.equal(r.log.filter((e) => e[0] === 'tcp').length, 0);
  assert.equal(results.find((x) => x.addr === '1.1.1.3').reason, 'tls');
  assert.equal(results.find((x) => x.addr === '1.1.1.1').score > 0, true);
});

test('a UDP config skips the pre-check — its rows say so — and the delay decides', async () => {
  const r = rig();
  const { results } = await go(r, { targets: items(['1.1.1.1']), transport: 'udp' });
  assert.equal(r.log.filter((e) => e[0] === 'tcp').length, 0);
  assert.deepEqual(results[0].tcp, { ok: false, skipped: true, ms: 0 });
  assert.ok(results[0].score > 0);
});

test('filterConcurrency is the delay probes in flight across ALL the cores, not per core', async () => {
  const r = rig({ delayMs: 20 });
  await go(r, { targets: items(['1.1.1.1', '1.1.1.2', '1.1.1.3', '1.1.1.4', '1.1.1.5', '1.1.1.6', '1.1.1.7', '1.1.1.8']), engines: ['xray', 'xray-pattn'], opts: { batch: 4, coresInParallel: 4, filterConcurrency: 3 } });
  assert.ok(r.peak.core >= 2, 'several cores at once: ' + r.peak.core);
  assert.equal(r.peak.delay, 3, 'three series in flight, whatever the number of cores');
});

test('an item’s own cores: a variant gated to Xray-PattN runs there only, and the totals count it once', async () => {
  const r = rig();
  const fp = V.variantFromRaw({ fingerprint: 'firefox' });
  const dm = V.variantFromRaw({ dialMode: 'oob.0' });
  const list = [];
  for (const t of items(['1.1.1.1', '1.1.1.2'])) {
    list.push(Object.assign({}, t, { key: t.key + '#' + fp.key, variant: fp }));
    list.push(Object.assign({}, t, { key: t.key + '#' + dm.key, variant: dm, engines: ['xray-pattn'] }));
  }
  const { results, progress } = await go(r, { targets: list, engines: ['xray', 'xray-pattn'], total: 6 });
  assert.equal(results.length, 6);
  assert.ok(results.filter((x) => x.variant === dm.key).every((x) => x.engine === 'xray-pattn'));
  assert.deepEqual(results.filter((x) => x.variant === fp.key).map((x) => x.engine).sort(), ['xray', 'xray', 'xray-pattn', 'xray-pattn']);
  assert.deepEqual([progress.at(-1).done, progress.at(-1).total], [6, 6]);
  // the dialMode is in the config the PattN core was handed, the fingerprint in the other
  const pattn = r.cores.filter((c) => c.engine === 'xray-pattn').flatMap((c) => c.cfg.outbounds);
  assert.ok(pattn.some((o) => o.streamSettings && o.streamSettings.sockopt && o.streamSettings.sockopt.dialMode === 'oob.0'));
  const official = r.cores.filter((c) => c.engine === 'xray').flatMap((c) => c.cfg.outbounds);
  assert.ok(official.every((o) => !(o.streamSettings && o.streamSettings.sockopt && o.streamSettings.sockopt.dialMode)), 'never on the official core');
  assert.ok(official.some((o) => o.streamSettings && o.streamSettings.tlsSettings && o.streamSettings.tlsSettings.fingerprint === 'firefox'));
});

test('a core that refuses one variant of a mixed batch: the batch is run again variant by variant, only that variant’s rows fail, with what the core said', async () => {
  const bad = { key: 'fp=chrome_999', label: 'fp=chrome_999', set: { fingerprint: 'chrome_999' } };
  const good = V.variantFromRaw({ fingerprint: 'firefox' });
  const r = rig({ refuse: (o) => !!(o.streamSettings && o.streamSettings.tlsSettings && o.streamSettings.tlsSettings.fingerprint === 'chrome_999') });
  const list = [];
  for (const t of items(['1.1.1.1', '1.1.1.2'])) for (const v of [good, bad]) list.push(Object.assign({}, t, { key: t.key + '#' + v.key, variant: v }));
  const { results } = await go(r, { targets: list, opts: { batch: 4 } });
  assert.equal(results.length, 4);
  const failed = results.filter((x) => x.error);
  assert.deepEqual(failed.map((x) => x.variant), ['fp=chrome_999', 'fp=chrome_999']);
  for (const x of failed) {
    assert.equal(x.reason, 'core');
    assert.match(x.error, /spawn failed — Failed to start: infra\/conf: unknown fingerprint: chrome_999/);
  }
  assert.ok(results.filter((x) => x.variant === good.key).every((x) => x.score > 0), 'the good variant is measured');
});

test('a series that answered one of three is not a pass: score 0, `unstable`, no speed test', async () => {
  const r = rig({ delay: (addr) => (addr === '1.1.1.1' ? delayStats([40, -1, -1]) : delayStats([40, 50, 60])) });
  const { results } = await go(r, { targets: items(['1.1.1.1', '1.1.1.2']), tests: { tcp: true, delay: true, down: true, up: false }, opts: { speedTop: 5 } });
  const flaky = results.filter((x) => x.addr === '1.1.1.1');
  assert.deepEqual(flaky.map((x) => [x.phase, x.score, x.reason]), [[1, 0, 'unstable']]);
  assert.ok(results.some((x) => x.addr === '1.1.1.2' && x.phase === 2));
  // a looser ratio when the page asks for one
  const r2 = rig({ delay: () => delayStats([40, -1, -1]) });
  const { results: loose } = await go(r2, { targets: items(['1.1.1.1']), opts: { passRatio: 0.3 } });
  assert.ok(loose[0].score > 0);
  // the delay probe gets the expected answer and the ratio
  assert.equal(r2.log.find((e) => e[0] === 'delay')[2].passRatio, 0.3);
  assert.equal(r2.log.find((e) => e[0] === 'delay')[2].expect, '204');
});

test('keepRows false: every row still leaves through onResult, but only the best passing rows are kept', async () => {
  const many = Array.from({ length: KEEP_ALIVE * 2 + 50 }, (_, i) => `10.0.${i >> 8}.${i & 255}`);
  const r = rig({ tcp: (host) => (Number(host.split('.')[3]) % 2 ? { ok: false, ms: -1 } : { ok: true, ms: 5 }), preMs: 0, delayMs: 0 });
  const { out, results } = await go(r, { targets: items(many), keepRows: false, opts: { batch: 50, coresInParallel: 4, filterConcurrency: 64 } });
  assert.equal(results.length, many.length);
  assert.ok(out.results.length <= KEEP_ALIVE * 2, String(out.results.length));
  assert.ok(out.results.every((x) => x.score > 0), 'the dead are not kept');
});

test('runSpeed writes a row’s variant again into the speed core’s config', async () => {
  const r = rig();
  const v = V.variantFromRaw({ fingerprint: 'ios', alpn: 'h2' });
  const out = await runSpeed({
    server: F.VLESS_WS_TLS, rows: [{ addr: '1.1.1.1', port: 443, key: '1.1.1.1:443|#' + v.key, engine: 'xray', variant: v }],
    tests: { down: true }, opts: { probes: r.probes, getFreePorts: r.getFreePorts, waitReady: ready }, xray: r.xray
  });
  assert.equal(out.results[0].variant, v.key);
  const tls = r.cores[0].cfg.outbounds[0].streamSettings.tlsSettings;
  assert.deepEqual([tls.fingerprint, tls.alpn], ['ios', ['h2']]);
});
