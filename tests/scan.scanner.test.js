'use strict';
/**
 * IP-scan runner and channels, with a fake core and fake probes.
 *
 * What matters: phase 1 runs one throwaway core per engine per batch with the
 * engines side by side (never more cores alive than coresInParallel, never
 * more probes in flight than filterConcurrency), every IP×engine reported
 * once with phase 1 the moment it is done; phase 2 takes exactly the top
 * speedTop rows of each engine through one core per engine with at most
 * speedConcurrency transfers in flight across all of them, repeats the
 * download speedRounds times and keeps the fastest, and re-emits the row with
 * phase 2; progress that names the stage and carries the counters and an ETA;
 * a Stop in either stage that halts scheduling and kills every live core; a
 * core that fails to start marking its rows and not the run; a result shape
 * the tab can render; and channel replies/events that match the plan's
 * interface block to the letter.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');

const { runScan, runSpeed, byRank } = require('../src/main/scan/scanner');
const { createScan, PRESET_DEFAULTS, sanitizeOpts } = require('../src/main/scan/index');
const { delayStats } = require('../src/main/scan/score');
const { parseLink, buildShareLink } = require('../src/main/parser');
const F = require('./fixtures');

const tick = (ms = 2) => new Promise((r) => setTimeout(r, ms));
const until = async (pred, ms = 5000, what = 'condition') => {
  const t0 = Date.now();
  while (!pred()) { if (Date.now() - t0 > ms) throw new Error(`${what} not met within ${ms}ms`); await tick(5); }
};
const RESULT_KEYS = ['delay', 'down', 'engine', 'error', 'ip', 'phase', 'score', 'tcp', 'up'];
const PROGRESS_KEYS = ['alive', 'done', 'etaMs', 'speedDone', 'speedTotal', 'stage', 'total'];

/* ----------------------------- the fake rig ----------------------------- */

/** Address a test config dials for its k-th inbound (the real buildMultiTestConfig shapes). */
function dialAddress(out) {
  const s = out.settings || {};
  return (s.vnext && s.vnext[0] && s.vnext[0].address) || (s.servers && s.servers[0] && s.servers[0].address) || null;
}
const ipsOf = (cfg) => cfg.inbounds.map((inb, k) => dialAddress(cfg.outbounds[k]));

/**
 * fakeRig(spec): a core that never spawns and probes that answer from `spec`.
 * `peak` records how many cores / filter probes / downloads were alive at once.
 */
function fakeRig(spec = {}) {
  const calls = [], cores = [], portToIp = new Map(), log = [];
  const active = { core: 0, filter: 0, down: 0, up: 0 }, peak = { core: 0, filter: 0, down: 0, up: 0 };
  const enter = (k) => { active[k]++; peak[k] = Math.max(peak[k], active[k]); };
  const leave = (k) => { active[k]--; };
  const busy = async (k, ms) => { enter(k); await tick(ms); leave(k); };
  const downCalls = new Map();
  let portBase = 40000;                                 // a fresh block per core: two live cores must not share numbers
  const ipOf = (port) => portToIp.get(port);
  const xray = {
    binExists: (id) => (spec.installed || ['xray', 'xray-pattn']).includes(id),
    startTest: async (cfg, engine) => {
      calls.push({ cfg, engine });
      if (spec.failStart && spec.failStart(engine, calls.length, cfg)) throw new Error('spawn failed');
      cfg.inbounds.forEach((inb, k) => portToIp.set(inb.port, dialAddress(cfg.outbounds[k])));
      const core = { engine, ips: ipsOf(cfg), cleaned: 0 };
      cores.push(core);
      enter('core');
      return { proc: null, cleanup: () => { if (!core.cleaned) leave('core'); core.cleaned++; } };
    }
  };
  const getFreePorts = async (n) => { const b = portBase; portBase += 100; return Array.from({ length: n }, (_, k) => b + k); };   // numbers only, never bound
  const probeMs = spec.probeMs || 3;
  const probes = {
    tcpPing: async (host, port, timeout) => {
      log.push(['tcp', host, port, timeout]);
      await busy('filter', probeMs);
      return spec.tcp ? spec.tcp(host) : { ok: true, ms: 10 };
    },
    delaySeries: async (port, o) => {
      log.push(['delay', ipOf(port), o]);
      await busy('filter', probeMs);
      return spec.delay ? spec.delay(ipOf(port)) : delayStats([50, 60, 70]);
    },
    downloadThroughProxy: async (port, o) => {
      const ip = ipOf(port);
      const n = (downCalls.get(ip) || 0) + 1;
      downCalls.set(ip, n);
      log.push(['down', ip, o, n]);
      await busy('down', spec.downMs || probeMs);
      const custom = spec.down ? spec.down(ip, n) : null;
      if (custom) return custom;
      const mbps = spec.mbps ? spec.mbps(ip, n) : 5;
      return { ok: true, bytes: o.bytes, ms: 100, ttfb: 10, mbps, mbpsRaw: mbps, warm: true, error: null };
    },
    uploadThroughProxy: async (port, o) => {
      log.push(['up', ipOf(port), o]);
      await busy('up', probeMs);
      return { ok: true, bytes: o.bytes, ms: 50, ttfb: 50, mbps: 2, error: null };
    }
  };
  return { xray, getFreePorts, probes, calls, cores, log, peak, live: () => active.core };
}

const IPS = ['1.1.1.1', '1.1.1.2', '1.1.1.3', '1.1.1.4', '1.1.1.5'];
/** Distinct delays per IP: the last octet × 10 ms, so the ranking is decided. */
const delayByOctet = (ip) => { const ms = Number(ip.split('.')[3]) * 10; return delayStats([ms, ms, ms]); };
const downs = (rig) => rig.log.filter(e => e[0] === 'down');

function run(rig, over = {}) {
  const results = [], progress = [];
  const opts = Object.assign({ batch: 2, filterConcurrency: 8, coresInParallel: 2, probes: rig.probes, getFreePorts: rig.getFreePorts }, over.opts);
  const args = Object.assign({
    server: F.VLESS_WS_TLS, ips: IPS, engines: ['xray'], tests: { tcp: true, delay: true, down: true, up: false },
    xray: rig.xray, token: { cancelled: false },
    onResult: (r) => results.push(r), onProgress: (p) => progress.push(Object.assign({}, p))
  }, over, { opts });
  return { promise: runScan(args), results, progress, token: args.token };
}

/* ----------------------------- runScan: the two phases ----------------------------- */

test('phase 1: one core per engine per batch dialling exactly the batch, SNI on the name; phase 2: the top rows per engine through one core, re-emitted with phase 2', async () => {
  const rig = fakeRig({ delay: delayByOctet });
  const { promise, results, progress } = run(rig, { engines: ['xray', 'xray-pattn'] });
  const out = await promise;

  assert.equal(rig.calls.length, 8, '3 batches × 2 engines, then one speed core per engine');
  for (const engine of ['xray', 'xray-pattn']) {
    const ips = rig.cores.filter(c => c.engine === engine).map(c => c.ips.join()).sort();
    assert.deepEqual(ips, ['1.1.1.1,1.1.1.2', '1.1.1.1,1.1.1.2', '1.1.1.3,1.1.1.4', '1.1.1.5'], engine + ': three filter batches and the top-2 speed core');
  }
  for (const c of rig.cores) assert.equal(c.cleaned, 1, 'every core is cleaned up exactly once');
  const cfg = rig.calls[0].cfg;
  assert.equal(cfg.inbounds.length, 2);
  assert.equal(cfg.inbounds[1].port, cfg.inbounds[0].port + 1);
  assert.equal(cfg.outbounds[0].streamSettings.tlsSettings.serverName, 'a.example.com');
  assert.equal(cfg.outbounds[0].settings.vnext[0].address, ipsOf(cfg)[0]);

  const p1 = results.filter(r => r.phase === 1), p2 = results.filter(r => r.phase === 2);
  assert.equal(p1.length, 10, 'every IP × engine once in phase 1');
  assert.equal(p2.length, 4, 'speedTop is capped at the batch size: the top 2 per engine');
  assert.ok(results.indexOf(p2[0]) > results.indexOf(p1[9]), 'phase 2 starts after the last phase-1 row');
  for (const r of results) assert.deepEqual(Object.keys(r).sort(), RESULT_KEYS, JSON.stringify(r));
  for (const r of p1) {
    assert.deepEqual(r.tcp, { ok: true, ms: 10 });
    assert.equal(r.delay.median, Number(r.ip.split('.')[3]) * 10);
    assert.equal(r.down, null, 'no download in phase 1');
    assert.equal(r.up, null);
    assert.equal(r.error, null);
    assert.ok(r.score > 0);
  }
  assert.deepEqual(p2.map(r => r.ip).sort(), ['1.1.1.1', '1.1.1.1', '1.1.1.2', '1.1.1.2']);
  for (const r of p2) {
    assert.equal(r.down.mbps, 5);
    assert.equal(r.delay.median, Number(r.ip.split('.')[3]) * 10, 'the phase-1 delay travels with the row');
    assert.equal(r.up, null, 'not ticked');
    assert.ok(r.score > 0);
  }
  // the TCP test goes straight to ip:port, not through the core
  assert.ok(rig.log.some(e => e[0] === 'tcp' && e[1] === '1.1.1.3' && e[2] === 443));

  assert.equal(out.cancelled, false);
  assert.equal(out.results.length, 10, 'one row per IP × engine, the newest phase');
  assert.equal(out.results.filter(r => r.phase === 2).length, 4);
  for (let i = 1; i < out.results.length; i++) assert.ok(out.results[i - 1].score >= out.results[i].score);
  assert.equal(progress.at(-1).stage, 'done');
});

test('engines run side by side: up to coresInParallel cores alive at once, never more', async () => {
  const wide = fakeRig({ probeMs: 20 });
  await run(wide, { engines: ['xray', 'xray-pattn'], opts: { batch: 5, coresInParallel: 2, speedTop: 0 } }).promise;
  assert.equal(wide.peak.core, 2);
  assert.equal(wide.live(), 0, 'none left alive');

  const narrow = fakeRig({ probeMs: 20 });
  await run(narrow, { engines: ['xray', 'xray-pattn'], opts: { batch: 5, coresInParallel: 1, speedTop: 0 } }).promise;
  assert.equal(narrow.peak.core, 1);

  const three = fakeRig({ probeMs: 20 });
  await run(three, { engines: ['xray', 'xray-pattn'], opts: { batch: 2, coresInParallel: 3, speedTop: 0 } }).promise;
  assert.equal(three.peak.core, 3, 'three of the six batch cores at once');
  assert.equal(three.calls.length, 6);
});

test('never more than filterConcurrency probes in flight inside a batch; the v2.0 name `concurrency` still means that', async () => {
  const rig = fakeRig({ probeMs: 15 });
  await run(rig, { opts: { batch: 20, filterConcurrency: 2, speedTop: 0 } }).promise;
  assert.equal(rig.peak.filter, 2);

  const legacy = fakeRig({ probeMs: 15 });
  await runScan({
    server: F.VLESS_WS_TLS, ips: IPS, engines: ['xray'], tests: { tcp: true, delay: true, down: false, up: false },
    opts: { batch: 20, concurrency: 3, probes: legacy.probes, getFreePorts: legacy.getFreePorts },
    xray: legacy.xray
  });
  assert.equal(legacy.peak.filter, 3, 'a caller that only knows `concurrency` gets it, not the 16 default');
});

test('phase 2 takes exactly the top speedTop live rows of each engine, downloads speedConcurrency at a time across engines, and 0 skips it', async () => {
  const dead = (ip) => (ip === '1.1.1.5' ? { ok: false, ms: -1, error: 'timeout' } : { ok: true, ms: 12 });
  const rig = fakeRig({ delay: delayByOctet, tcp: dead, downMs: 20 });
  const { promise, progress } = run(rig, { engines: ['xray', 'xray-pattn'], opts: { batch: 20, speedTop: 2, speedConcurrency: 1 } });
  await promise;
  assert.deepEqual(downs(rig).map(e => e[1]).sort(), ['1.1.1.1', '1.1.1.1', '1.1.1.2', '1.1.1.2']);
  assert.equal(rig.peak.down, 1, 'one transfer at a time, even with two cores alive');
  assert.equal(rig.peak.core, 2, 'both speed cores were up together');
  const speedCores = rig.cores.slice(2);
  assert.deepEqual(speedCores.map(c => c.ips), [['1.1.1.1', '1.1.1.2'], ['1.1.1.1', '1.1.1.2']]);
  assert.equal(progress.find(p => p.stage === 'speed').speedTotal, 4);
  assert.equal(progress.at(-1).alive, 8, 'the dead IP did not pass phase 1 on either engine');

  const two = fakeRig({ delay: delayByOctet, downMs: 20 });
  await run(two, { engines: ['xray', 'xray-pattn'], opts: { batch: 20, speedTop: 2, speedConcurrency: 2 } }).promise;
  assert.equal(two.peak.down, 2);

  const none = fakeRig({ delay: delayByOctet });
  const r0 = run(none, { opts: { batch: 20, speedTop: 0 } });
  await r0.promise;
  assert.equal(downs(none).length, 0);
  assert.equal(none.calls.length, 1, 'no speed core');
  assert.ok(r0.results.every(r => r.phase === 1));
  assert.ok(!r0.progress.some(p => p.stage === 'speed'));

  const capped = fakeRig({ delay: delayByOctet });
  await run(capped, { opts: { batch: 3, speedTop: 99 } }).promise;
  assert.deepEqual(downs(capped).map(e => e[1]).sort(), ['1.1.1.1', '1.1.1.2', '1.1.1.3'], 'speedTop cannot exceed the batch');

  const delayOnly = fakeRig({ delay: delayByOctet });
  await run(delayOnly, { tests: { tcp: true, delay: true, down: false, up: false }, opts: { batch: 20, speedTop: 5 } }).promise;
  assert.equal(delayOnly.calls.length, 1, 'nothing to measure in phase 2 when neither transfer is ticked');
});

test('speedRounds repeats the download and keeps the fastest round; an ok round beats a failed one; the upload runs once after', async () => {
  const rig = fakeRig({ mbps: (ip, n) => [3, 9, 6][n - 1] });
  const { promise, results } = run(rig, { tests: { tcp: true, delay: true, down: true, up: true }, opts: { batch: 20, speedTop: 1, speedRounds: 3 } });
  await promise;
  assert.equal(downs(rig).length, 3);
  const row = results.find(r => r.phase === 2);
  assert.equal(row.down.mbps, 9);
  assert.equal(rig.log.filter(e => e[0] === 'up').length, 1);
  assert.equal(row.up.mbps, 2);
  const d = downs(rig)[0][2];
  assert.deepEqual([d.host, d.path, d.bytes, d.maxMs, d.warmupMs, d.tls], ['speed.cloudflare.com', '/__down?bytes=10000000', 10e6, 6000, 300, true]);

  const flaky = fakeRig({ mbps: () => 4, down: (ip, n) => (n === 1 ? { ok: false, bytes: 0, ms: -1, ttfb: -1, mbps: 0, mbpsRaw: 0, warm: false, error: 'timeout' } : null) });
  const f = run(flaky, { opts: { batch: 20, speedTop: 1, speedRounds: 2 } });
  await f.promise;
  const kept = f.results.find(r => r.phase === 2).down;
  assert.deepEqual([kept.ok, kept.mbps], [true, 4]);

  const broken = fakeRig({ down: () => ({ ok: false, bytes: 0, ms: -1, ttfb: -1, mbps: 0, mbpsRaw: 0, warm: false, error: 'timeout' }) });
  const b = run(broken, { opts: { batch: 20, speedTop: 1, speedRounds: 2 } });
  await b.promise;
  const failed = b.results.find(r => r.phase === 2);
  assert.equal(failed.down.error, 'timeout');
  assert.equal(failed.score, 0, 'a download that failed in every round must not outrank a row that never got one');
});

test('the tests object decides what runs; the download path follows downBytes unless given', async () => {
  const rig = fakeRig();
  const { promise, results } = run(rig, {
    tests: { tcp: false, delay: true, down: true, up: true },
    opts: { batch: 20, delaySamples: 5, downBytes: 5e6, upBytes: 1e6, speedTop: 5 }
  });
  await promise;
  assert.equal(results[0].tcp, null);
  assert.ok(results.find(r => r.phase === 2).up.ok);
  assert.ok(!rig.log.some(e => e[0] === 'tcp'));
  const delayCall = rig.log.find(e => e[0] === 'delay');
  assert.equal(delayCall[2].n, 5);
  assert.equal(delayCall[2].host, 'cp.cloudflare.com');
  assert.equal(delayCall[2].timeout, 4000);
  const downCall = downs(rig)[0];
  assert.equal(downCall[2].path, '/__down?bytes=5000000');
  assert.equal(downCall[2].bytes, 5e6);
  assert.equal(rig.log.find(e => e[0] === 'up')[2].bytes, 1e6);

  const rig2 = fakeRig();
  await run(rig2, { opts: { batch: 20, speedTop: 5, downPath: '/custom?x=1', downHost: 'my.host', downTls: false, downPort: 8080, warmupMs: 0 } }).promise;
  const d = downs(rig2)[0][2];
  assert.deepEqual([d.path, d.host, d.tls, d.port, d.warmupMs], ['/custom?x=1', 'my.host', false, 8080, 0]);
});

test('a failed TCP connect ends the row; a tunnel that never answers is alive to nobody and gets no download', async () => {
  const rig = fakeRig({
    tcp: (ip) => (ip === '1.1.1.2' ? { ok: false, ms: -1, error: 'timeout' } : { ok: true, ms: 12 }),
    delay: (ip) => (ip === '1.1.1.4' ? delayStats([-1, -1, -1]) : delayStats([40, 40, 40]))
  });
  const { promise, results, progress } = run(rig, { opts: { batch: 20, speedTop: 5 } });
  await promise;
  const byIp = Object.fromEntries(results.filter(r => r.phase === 1).map(r => [r.ip, r]));
  assert.equal(byIp['1.1.1.2'].tcp.ok, false);
  assert.equal(byIp['1.1.1.2'].delay, null);
  assert.equal(byIp['1.1.1.2'].score, 0);
  assert.equal(byIp['1.1.1.2'].error, null, 'a failed probe is a measurement, not an error');
  assert.ok(!rig.log.some(e => e[0] === 'delay' && e[1] === '1.1.1.2'));
  assert.equal(byIp['1.1.1.4'].delay.loss, 1);
  assert.equal(byIp['1.1.1.4'].score, 0);
  assert.deepEqual(downs(rig).map(e => e[1]).sort(), ['1.1.1.1', '1.1.1.3', '1.1.1.5']);
  assert.equal(results.filter(r => r.phase === 1).length, 5, 'every IP still gets its row');
  assert.equal(progress.at(-1).alive, 3);
});

test('results are sorted by score desc, then median delay asc', async () => {
  const mbps = { '1.1.1.1': 1, '1.1.1.2': 9, '1.1.1.3': 9, '1.1.1.4': 3, '1.1.1.5': 0.5 };
  const rig = fakeRig({
    mbps: (ip) => mbps[ip],
    delay: (ip) => (ip === '1.1.1.3' ? delayStats([20, 20, 20]) : delayStats([80, 80, 80]))
  });
  const { promise } = run(rig, { opts: { batch: 20, speedTop: 5 } });
  const { results } = await promise;
  assert.deepEqual(results.map(r => r.ip), ['1.1.1.3', '1.1.1.2', '1.1.1.4', '1.1.1.1', '1.1.1.5']);
  for (let i = 1; i < results.length; i++) assert.ok(results[i - 1].score >= results[i].score);
  const a = { score: 5, delay: { loss: 0, median: 30 } }, b = { score: 5, delay: { loss: 0, median: 20 } };
  assert.ok(byRank(a, b) > 0, 'equal score: the lower median first');
  assert.ok(byRank({ score: 5, delay: null }, b) > 0, 'no delay sorts after one');
});

/* ----------------------------- progress ----------------------------- */

test('progress: stage filter → speed → done, the counters, and an ETA once two rows of the stage are in', async () => {
  const dead = (ip) => (ip === '1.1.1.5' ? { ok: false, ms: -1, error: 'timeout' } : { ok: true, ms: 12 });
  const rig = fakeRig({ delay: delayByOctet, tcp: dead, probeMs: 8 });
  const { promise, progress } = run(rig, { opts: { batch: 20, speedTop: 2 } });
  await promise;
  for (const p of progress) assert.deepEqual(Object.keys(p).sort(), PROGRESS_KEYS, JSON.stringify(p));
  assert.equal(progress.length, 5 + 1 + 2 + 1, 'five filter rows, the stage change, two speed rows, done');

  const filter = progress.slice(0, 5);
  filter.forEach((p, i) => {
    assert.equal(p.stage, 'filter');
    assert.deepEqual([p.done, p.total, p.speedDone, p.speedTotal], [i + 1, 5, 0, 0]);
  });
  assert.equal(filter[0].etaMs, null, 'no rate from one row');
  for (const p of filter.slice(1)) assert.ok(Number.isInteger(p.etaMs) && p.etaMs >= 0, JSON.stringify(p));
  assert.equal(filter[4].etaMs, 0, 'nothing left in the stage');
  assert.equal(filter[4].alive, 4);

  assert.deepEqual(progress[5], { stage: 'speed', done: 5, total: 5, alive: 4, speedDone: 0, speedTotal: 2, etaMs: null });
  assert.deepEqual([progress[6].stage, progress[6].speedDone, progress[6].etaMs], ['speed', 1, null]);
  assert.deepEqual([progress[7].stage, progress[7].speedDone, progress[7].speedTotal, progress[7].etaMs], ['speed', 2, 2, 0]);
  assert.deepEqual(progress[8], { stage: 'done', done: 5, total: 5, alive: 4, speedDone: 2, speedTotal: 2, etaMs: 0 });
});

/* ----------------------------- stop ----------------------------- */

test('Stop in phase 1: no more scheduling, the batch core is killed, the run resolves cancelled with what it has', async () => {
  const rig = fakeRig();
  let cancelAt;
  const { promise, results, progress, token } = run(rig, {
    engines: ['xray', 'xray-pattn'],
    opts: { batch: 20, filterConcurrency: 1, coresInParallel: 1 },
    onResult: (r) => { results.push(r); if (results.length === 3) { token.cancelled = true; cancelAt = Date.now(); } }
  });
  const out = await promise;
  assert.equal(results.length, 3);
  assert.equal(out.cancelled, true);
  assert.equal(out.results.length, 3);
  assert.equal(rig.calls.length, 1, 'the second engine never started');
  assert.equal(rig.cores[0].cleaned, 1);
  assert.equal(downs(rig).length, 0, 'no phase 2 after a stop');
  assert.deepEqual([progress.at(-1).stage, progress.at(-1).done], ['done', 3]);
  assert.ok(Date.now() - cancelAt < 1000);
});

test('Stop in phase 2: no more transfers, every live core dies, the phase-1 rows and the finished speed rows stay', async () => {
  const rig = fakeRig({ delay: delayByOctet, downMs: 30 });
  const { promise, results, progress, token } = run(rig, {
    engines: ['xray', 'xray-pattn'],
    opts: { batch: 20, speedTop: 2, speedConcurrency: 1, coresInParallel: 2 },
    onResult: (r) => { results.push(r); if (r.phase === 2) token.cancelled = true; }
  });
  const out = await promise;
  assert.equal(results.filter(r => r.phase === 1).length, 10);
  assert.equal(results.filter(r => r.phase === 2).length, 1);
  assert.equal(downs(rig).length, 1, 'the queued transfers never started');
  assert.equal(out.cancelled, true);
  assert.equal(rig.cores.length, 4);
  for (const c of rig.cores) assert.equal(c.cleaned, 1);
  assert.equal(rig.live(), 0);
  assert.deepEqual([progress.at(-1).stage, progress.at(-1).speedDone, progress.at(-1).speedTotal], ['done', 1, 4]);
});

test('Stop mid-probe kills the core early instead of waiting for the probes\' timeouts', async () => {
  const rig = fakeRig({ probeMs: 1500 });
  const { promise, results, token } = run(rig, { opts: { batch: 20 } });
  const t0 = Date.now();
  await until(() => rig.cores.length === 1, 2000, 'core started');
  token.cancelled = true;
  await until(() => rig.cores[0].cleaned === 1, 1500, 'early cleanup');
  assert.ok(Date.now() - t0 < 1200, 'the core died before the probes finished');
  const out = await promise;
  assert.equal(out.cancelled, true);
  assert.deepEqual(results, [], 'nothing measured against a killed core is reported');
  assert.equal(rig.cores[0].cleaned, 1, 'cleanup runs once');
});

/* ----------------------------- failures ----------------------------- */

test('a core that fails to start in phase 1 marks that batch `error` and the run goes on', async () => {
  const rig = fakeRig({ failStart: (engine, n, cfg) => engine === 'xray' && ipsOf(cfg)[0] === '1.1.1.3' });
  const { promise, results, progress } = run(rig, { engines: ['xray', 'xray-pattn'], opts: { speedTop: 0 } });
  const out = await promise;
  assert.equal(results.length, 10, 'every IP × engine is reported');
  const failed = results.filter(r => r.error);
  assert.deepEqual(failed.map(r => [r.ip, r.engine]).sort(), [['1.1.1.3', 'xray'], ['1.1.1.4', 'xray']]);
  for (const r of failed) {
    assert.equal(r.error, 'spawn failed');
    assert.deepEqual([r.phase, r.tcp, r.delay, r.down, r.up, r.score], [1, null, null, null, null, 0]);
  }
  assert.equal(results.filter(r => r.engine === 'xray-pattn' && !r.error).length, 5);
  assert.deepEqual(progress.at(-1), { stage: 'done', done: 10, total: 10, alive: 8, speedDone: 0, speedTotal: 0, etaMs: 0 });
  assert.equal(out.results.at(-1).error, 'spawn failed', 'errors sort last');
});

test('a core that fails to start in phase 2 re-emits its rows with phase 2, the error and score 0; the other engine is unaffected', async () => {
  const rig = fakeRig({ delay: delayByOctet, failStart: (engine, n, cfg) => engine === 'xray-pattn' && ipsOf(cfg).length === 2 });
  const { promise, results } = run(rig, { engines: ['xray', 'xray-pattn'], opts: { batch: 20, speedTop: 2 } });
  const out = await promise;
  const p2 = results.filter(r => r.phase === 2);
  assert.equal(p2.length, 4);
  const broken = p2.filter(r => r.engine === 'xray-pattn');
  assert.deepEqual(broken.map(r => [r.ip, r.error, r.score, r.down]).sort(), [['1.1.1.1', 'spawn failed', 0, null], ['1.1.1.2', 'spawn failed', 0, null]]);
  assert.equal(broken[0].delay.median, Number(broken[0].ip.split('.')[3]) * 10, 'the phase-1 numbers stay on the row');
  assert.ok(p2.filter(r => r.engine === 'xray').every(r => r.down.ok && !r.error));
  assert.equal(out.cancelled, false);
});

test('a config the substitution refuses marks every batch without spawning a core', async () => {
  const rig = fakeRig();
  const { promise, results } = run(rig, { server: F.WG_BAD_MASK, ips: ['1.1.1.1', '1.1.1.2'] });
  await promise;
  assert.equal(rig.calls.length, 0);
  assert.deepEqual(results.map(r => r.error), ['unsupported protocol', 'unsupported protocol']);
});

test('no IPs or no engines is an empty, finished run', async () => {
  const rig = fakeRig();
  assert.deepEqual(await run(rig, { ips: [] }).promise, { results: [], cancelled: false });
  assert.deepEqual(await run(rig, { engines: [] }).promise, { results: [], cancelled: false });
  assert.equal(rig.calls.length, 0);
});

/* ----------------------------- runSpeed (re-test) ----------------------------- */

test('runSpeed: phase 2 alone on the rows given, in the speed stage from the start; a delay passed along is rebuilt from its samples', async () => {
  const rig = fakeRig();
  const results = [], progress = [];
  const out = await runSpeed({
    server: F.VLESS_WS_TLS,
    rows: [
      { ip: '1.1.1.1', engine: 'xray', tcp: { ok: true, ms: 12 }, delay: { samples: [40, 50, 60], median: 1, loss: 0 } },
      { ip: '1.1.1.2', engine: 'xray-pattn' },
      { ip: '1.1.1.1', engine: 'xray' },
      { ip: '', engine: 'xray' }
    ],
    tests: { down: true, up: false },
    opts: { probes: rig.probes, getFreePorts: rig.getFreePorts },
    xray: rig.xray, token: { cancelled: false },
    onResult: (r) => results.push(r), onProgress: (p) => progress.push(p)
  });
  assert.equal(results.length, 2, 'the duplicate and the bad row are dropped');
  assert.ok(results.every(r => r.phase === 2));
  assert.ok(!rig.log.some(e => e[0] === 'tcp' || e[0] === 'delay'), 'no filter probes');
  assert.deepEqual(rig.cores.map(c => [c.engine, c.ips]).sort(), [['xray', ['1.1.1.1']], ['xray-pattn', ['1.1.1.2']]]);
  const a = results.find(r => r.ip === '1.1.1.1');
  assert.deepEqual(a.tcp, { ok: true, ms: 12 });
  assert.equal(a.delay.median, 50, 'rebuilt from the samples, not taken from the row');
  assert.equal(a.down.mbps, 5);
  const b = results.find(r => r.ip === '1.1.1.2');
  assert.deepEqual([b.tcp, b.delay, b.down.mbps], [null, null, 5]);
  assert.equal(b.score, 500, 'download alone is the base when no delay came along');
  assert.ok(a.score < b.score && a.score > 0);
  assert.deepEqual(progress[0], { stage: 'speed', done: 2, total: 2, alive: 2, speedDone: 0, speedTotal: 2, etaMs: null });
  assert.deepEqual(progress.at(-1), { stage: 'done', done: 2, total: 2, alive: 2, speedDone: 2, speedTotal: 2, etaMs: 0 });
  assert.equal(out.results.length, 2);
  assert.equal(out.cancelled, false);
});

/* ----------------------------- createScan(ctx) ----------------------------- */

function fakeCtx(rig, { servers = [] } = {}) {
  const handlers = {}, events = [], logs = [], data = {}, added = [];
  const ctx = {
    handle: (ch, fn) => { handlers[ch] = fn; },
    send: (ch, payload) => events.push({ ch, payload: JSON.parse(JSON.stringify(payload)) }),
    notify: () => {},
    store: {
      get: (k, d) => (k in data ? data[k] : d),
      set: (k, v) => { data[k] = v; return true; },
      setLazy: (k, v) => { data[k] = v; return true; }
    },
    dataDir: os.tmpdir(),
    getSettings: () => ({ defaultEngine: 'xray' }),
    xray: rig.xray,
    getServers: () => servers,
    addServer: (rec) => { added.push(rec); servers.push(rec); return rec; },
    resolveTarget: (id) => { const s = servers.find(x => x.id === id); return s ? { server: s, chain: null } : { server: null, chain: null }; },
    log: (line, level) => logs.push({ line, level }),
    platform: process.platform, isElectron: false
  };
  return { ctx, handlers, events, logs, data, added, servers };
}

function setup(spec = {}, extra = {}) {
  const rig = fakeRig(spec);
  const c = fakeCtx(rig, extra);
  const scan = createScan(c.ctx, { probes: rig.probes, getFreePorts: rig.getFreePorts, runScan: extra.runScan });
  scan.register();
  return Object.assign({ rig, scan }, c);
}

const progressOf = (events) => events.filter(e => e.ch === 'scan-progress').map(e => e.payload);
const EVENT_KEYS = ['alive', 'done', 'etaMs', 'runId', 'speedDone', 'speedTotal', 'stage', 'total'];

test('register() puts exactly the six scan channels on the context', () => {
  const s = setup();
  assert.deepEqual(Object.keys(s.handlers).sort(), ['scan:apply', 'scan:export', 'scan:presets', 'scan:retest', 'scan:start', 'scan:stop']);
  assert.equal(s.scan.busy(), false);
});

test('scan:presets — the Cloudflare ranges, the exact defaults, the three presets as full opts objects, the engines, and no last request yet', async () => {
  const s = setup({ installed: ['xray'] });
  const p = await s.handlers['scan:presets']();
  assert.equal(p.cfRanges.length, 15);
  const balanced = {
    batch: 20, filterConcurrency: 16, coresInParallel: 2, delaySamples: 2,
    tcpTimeout: 2000, delayTimeout: 4000,
    speedTop: 10, speedConcurrency: 1, speedRounds: 1, warmupMs: 300,
    downBytes: 10e6, downMaxMs: 6000, downTimeout: 8000,
    downHost: 'speed.cloudflare.com', downPath: '/__down?bytes=10000000', downPort: 443, downTls: true,
    upBytes: 2e6, upTimeout: 20000,
    upHost: 'speed.cloudflare.com', upPath: '/__up', upPort: 443, upTls: true
  };
  assert.deepEqual(p.defaults, balanced);
  assert.deepEqual(p.presets.balanced, balanced, 'balanced is the defaults');
  assert.deepEqual(p.presets.fast, Object.assign({}, balanced, { delaySamples: 1, tcpTimeout: 1500, delayTimeout: 3000, filterConcurrency: 32, coresInParallel: 3, speedTop: 5 }));
  assert.deepEqual(p.presets.accurate, Object.assign({}, balanced, { delaySamples: 4, filterConcurrency: 8, speedTop: 20, speedRounds: 2, speedConcurrency: 1 }));
  for (const [name, preset] of Object.entries(p.presets)) assert.deepEqual(sanitizeOpts(preset), preset, name + ' is a full, in-range opts object');
  assert.deepEqual(PRESET_DEFAULTS, balanced);
  assert.equal(p.last, null);
  assert.deepEqual(p.engines, [
    { id: 'xray', label: 'Xray (official)', installed: true },
    { id: 'xray-pattn', label: 'Xray-PattN (patterniha)', installed: false }
  ]);
  assert.deepEqual(Object.keys(p).sort(), ['cfRanges', 'defaults', 'engines', 'last', 'presets']);
});

test('scan:start refuses what it cannot run, with the agreed reasons', async () => {
  const s = setup({ installed: ['xray'] }, { servers: [F.VLESS_WS_TLS, F.WG_BAD_MASK] });
  const start = s.handlers['scan:start'];
  assert.deepEqual(await start({ ipsText: '1.1.1.1' }), { error: 'no server' });
  assert.deepEqual(await start({ serverId: 'nope', ipsText: '1.1.1.1' }), { error: 'server not found' });
  assert.match((await start({ link: 'garbage', ipsText: '1.1.1.1' })).error, /Unsupported or invalid link/);
  assert.deepEqual(await start({ serverId: 'sv-wg', ipsText: '1.1.1.1' }), { error: 'unsupported protocol' });
  assert.deepEqual(await start({ link: 'socks://1.2.3.4:1080', ipsText: '1.1.1.1' }), { error: 'unsupported protocol' });
  const none = await start({ serverId: 'sv-vless', ipsText: '# nothing\nbad-line' });
  assert.equal(none.error, 'no targets');
  assert.deepEqual(none.errors.map(e => e.line), [2]);
  assert.deepEqual(await start({ serverId: 'sv-vless', ipsText: '1.1.1.1', engines: ['xray-pattn'] }), { error: 'no engine' });
  assert.deepEqual(await start({ serverId: 'sv-vless', ipsText: '1.1.1.1', engines: ['sing-box'] }), { error: 'no engine' });
  assert.deepEqual(await start({ serverId: 'sv-vless', ipsText: '1.1.1.1', tests: { tcp: false, delay: false, down: false, up: false } }), { error: 'no tests' });
  assert.equal(s.rig.calls.length, 0);
  assert.equal(s.scan.busy(), false);
});

test('scan:start runs in the background and streams scan-progress: one event per result with the stage counters, then a finished one', async () => {
  const s = setup({ installed: ['xray', 'xray-pattn'] }, { servers: [F.VLESS_WS_TLS] });
  const req = { serverId: 'sv-vless', ipsText: '1.1.1.1\n1.1.1.2, 1.1.1.3\n1.1.1.1', engines: ['xray', 'xray-pattn', 'sing-box'], tests: { tcp: true, delay: true, down: false, up: false }, opts: { batch: 2, concurrency: 3 } };
  const reply = await s.handlers['scan:start'](req);
  assert.match(reply.runId, /^scan-/);
  assert.equal(reply.total, 6, '3 unique IPs × 2 installed engines');
  assert.equal(reply.truncated, false);
  assert.deepEqual(reply.errors, []);
  assert.equal(s.scan.busy(), true);
  assert.deepEqual(await s.handlers['scan:start'](req), { error: 'busy' });
  assert.deepEqual(await s.handlers['scan:retest']({ serverId: 'sv-vless', rows: [{ ip: '1.1.1.1', engine: 'xray' }] }), { error: 'busy' });

  await until(() => progressOf(s.events).some(p => p.finished), 5000, 'finished event');
  const ev = progressOf(s.events);
  assert.equal(ev.length, 7, 'no speed stage when no transfer is ticked');
  ev.slice(0, 6).forEach((p, i) => {
    assert.equal(p.runId, reply.runId);
    assert.deepEqual(Object.keys(p).sort(), [...EVENT_KEYS, 'result'].sort());
    assert.deepEqual([p.stage, p.done, p.total, p.alive, p.speedDone, p.speedTotal], ['filter', i + 1, 6, i + 1, 0, 0]);
    assert.deepEqual(Object.keys(p.result).sort(), RESULT_KEYS);
    assert.equal(p.result.phase, 1);
    assert.equal(p.finished, undefined);
  });
  assert.deepEqual(ev[6], { runId: reply.runId, stage: 'done', done: 6, total: 6, alive: 6, speedDone: 0, speedTotal: 0, etaMs: 0, finished: true, cancelled: false });
  assert.equal(s.scan.busy(), false);
  assert.deepEqual(s.rig.calls.map(c => c.engine).sort(), ['xray', 'xray', 'xray-pattn', 'xray-pattn']);

  // the last request is remembered without results, with the engines it actually ran and the v2.1 option names
  const last = s.data.scan;
  assert.deepEqual(Object.keys(last).sort(), ['engines', 'ipsText', 'link', 'opts', 'serverId', 'tests']);
  assert.equal(last.serverId, 'sv-vless');
  assert.equal(last.ipsText, req.ipsText);
  assert.deepEqual(last.engines, ['xray', 'xray-pattn']);
  assert.deepEqual(last.tests, { tcp: true, delay: true, down: false, up: false });
  assert.equal(last.opts.batch, 2);
  assert.equal(last.opts.filterConcurrency, 3, 'the v2.0 name is read as the filter concurrency');
  assert.equal(last.opts.concurrency, undefined);
  assert.equal(last.opts.downBytes, 10e6, 'omitted options are filled with the defaults');
  assert.deepEqual(Object.keys(last.opts).sort(), Object.keys(PRESET_DEFAULTS).sort());
  assert.equal((await s.handlers['scan:presets']()).last.serverId, 'sv-vless');
  assert.ok(s.logs.some(l => /scan/i.test(l.line)));
});

test('scan:start with a download ticked: a stage event without a result when phase 2 begins, then the phase-2 rows, then finished', async () => {
  const s = setup({ installed: ['xray'], delay: delayByOctet }, { servers: [F.VLESS_WS_TLS] });
  const reply = await s.handlers['scan:start']({ serverId: 'sv-vless', ipsText: '1.1.1.1-1.1.1.4', opts: { batch: 20, speedTop: 2 } });
  assert.equal(reply.total, 4);
  await until(() => progressOf(s.events).some(p => p.finished), 5000, 'finished');
  const ev = progressOf(s.events);
  assert.deepEqual(ev.map(p => [p.stage, p.result ? p.result.phase : null, !!p.finished]), [
    ['filter', 1, false], ['filter', 1, false], ['filter', 1, false], ['filter', 1, false],
    ['speed', null, false],
    ['speed', 2, false], ['speed', 2, false],
    ['done', null, true]
  ]);
  assert.deepEqual(ev[4], { runId: reply.runId, stage: 'speed', done: 4, total: 4, alive: 4, speedDone: 0, speedTotal: 2, etaMs: null });
  assert.deepEqual(ev[5].result.ip, '1.1.1.1');
  assert.ok(ev[5].result.down.ok);
  assert.deepEqual(ev[7], { runId: reply.runId, stage: 'done', done: 4, total: 4, alive: 4, speedDone: 2, speedTotal: 2, etaMs: 0, finished: true, cancelled: false });
});

test('scan:start with a pasted link and no engines list runs on every installed core; out-of-range options are clamped', async () => {
  const s = setup({ installed: ['xray-pattn'] });
  const link = buildShareLink(F.TROJAN_TCP_TLS);
  const reply = await s.handlers['scan:start']({ link, ipsText: '9.9.9.9', opts: { concurrency: 999, batch: 0, delaySamples: 'x', speedTop: 500, coresInParallel: 0, speedConcurrency: 9, speedRounds: 0, warmupMs: 5000, tcpTimeout: 1, delayTimeout: 1e9 } });
  assert.equal(reply.total, 1);
  await until(() => progressOf(s.events).some(p => p.finished), 5000, 'finished');
  assert.deepEqual(s.rig.calls.map(c => c.engine), ['xray-pattn', 'xray-pattn']);
  assert.equal(s.rig.cores[0].ips[0], '9.9.9.9');
  assert.equal(s.rig.calls[0].cfg.outbounds[0].settings.servers[0].password, 'pw');
  assert.equal(s.data.scan.link, link);
  assert.equal(s.data.scan.serverId, null);
  const o = s.data.scan.opts;
  assert.deepEqual(
    [o.filterConcurrency, o.batch, o.delaySamples, o.speedTop, o.coresInParallel, o.speedConcurrency, o.speedRounds, o.warmupMs, o.tcpTimeout, o.delayTimeout],
    [64, 1, 2, 50, 1, 4, 1, 2000, 500, 60000]
  );
  const rows = progressOf(s.events).filter(p => p.result).map(p => p.result);
  assert.deepEqual(rows.map(r => r.phase), [1, 2], 'tests default to tcp+delay+down');
  assert.ok(rows[1].down.ok);
  assert.equal(rows[1].up, null);
});

test('scan:stop ends the run with cancelled: true; stop() waits for it', async () => {
  const s = setup({ installed: ['xray'], probeMs: 40 }, { servers: [F.VLESS_WS_TLS] });
  assert.deepEqual(await s.handlers['scan:stop'](), { ok: true, running: false });
  const reply = await s.handlers['scan:start']({ serverId: 'sv-vless', ipsText: '10.0.0.0/28', opts: { filterConcurrency: 1, batch: 20 } });
  assert.equal(reply.total, 16);
  await until(() => progressOf(s.events).length >= 2, 5000, 'two results');
  assert.deepEqual(await s.handlers['scan:stop'](), { ok: true, running: true, runId: reply.runId });
  await s.scan.stop();
  assert.equal(s.scan.busy(), false);
  const ev = progressOf(s.events);
  const last = ev.at(-1);
  assert.equal(last.finished, true);
  assert.equal(last.cancelled, true);
  assert.equal(last.stage, 'done');
  assert.ok(last.done < 16 && last.done >= 2, String(last.done));
  assert.equal(s.rig.cores[0].cleaned, 1);
  assert.equal(await s.scan.stop(), undefined, 'idle stop is a no-op');
});

test('a run that blows up ends with finished + error instead of a stuck busy flag', async () => {
  const s = setup({ installed: ['xray'] }, { servers: [F.VLESS_WS_TLS], runScan: async () => { await tick(5); throw new Error('boom'); } });
  const reply = await s.handlers['scan:start']({ serverId: 'sv-vless', ipsText: '1.1.1.1' });
  assert.ok(reply.runId);
  await until(() => !s.scan.busy(), 2000, 'not busy');
  const last = progressOf(s.events).at(-1);
  assert.deepEqual(last, { runId: reply.runId, stage: 'filter', done: 0, total: 1, alive: 0, speedDone: 0, speedTotal: 0, etaMs: null, finished: true, cancelled: false, error: 'boom' });
  assert.ok(s.logs.some(l => l.level === 'error' && /boom/.test(l.line)));
});

test('scan:retest runs phase 2 alone on the rows given, in the speed stage from the first event; it refuses what it cannot run', async () => {
  const s = setup({ installed: ['xray', 'xray-pattn'] }, { servers: [F.VLESS_WS_TLS, F.WG_BAD_MASK] });
  const retest = s.handlers['scan:retest'];
  assert.deepEqual(await retest({ rows: [{ ip: '1.1.1.1', engine: 'xray' }] }), { error: 'no server' });
  assert.deepEqual(await retest({ serverId: 'sv-wg', rows: [{ ip: '1.1.1.1', engine: 'xray' }] }), { error: 'unsupported protocol' });
  assert.deepEqual(await retest({ serverId: 'sv-vless' }), { error: 'no rows' });
  assert.deepEqual(await retest({ serverId: 'sv-vless', rows: [{ ip: 'nope', engine: 'xray' }, { ip: '1.1.1.1', engine: 'sing-box' }, null] }), { error: 'no rows' });
  assert.deepEqual(await retest({ serverId: 'sv-vless', rows: [{ ip: '1.1.1.1', engine: 'xray' }], tests: { down: false, up: false } }), { error: 'no tests' });
  assert.equal(s.rig.calls.length, 0);

  const reply = await retest({
    serverId: 'sv-vless',
    rows: [{ ip: '1.1.1.1', engine: 'xray', delay: { samples: [30, 40, 50] } }, { ip: '1.1.1.2', engine: 'xray-pattn' }, { ip: '1.1.1.1', engine: 'xray' }],
    tests: { down: true, up: true },
    opts: { speedRounds: 2 }
  });
  assert.match(reply.runId, /^scan-/);
  assert.deepEqual(Object.keys(reply).sort(), ['runId', 'total']);
  assert.equal(reply.total, 2);
  assert.equal(s.scan.busy(), true);
  await until(() => progressOf(s.events).some(p => p.finished), 5000, 'finished');
  const ev = progressOf(s.events);
  assert.equal(ev.length, 3, 'two rows, then finished — no stage change to report');
  ev.slice(0, 2).forEach((p) => {
    assert.equal(p.runId, reply.runId);
    assert.equal(p.stage, 'speed');
    assert.deepEqual([p.done, p.total, p.alive, p.speedTotal], [2, 2, 2, 2]);
    assert.equal(p.result.phase, 2);
    assert.ok(p.result.down.ok && p.result.up.ok);
  });
  assert.deepEqual(ev[2], { runId: reply.runId, stage: 'done', done: 2, total: 2, alive: 2, speedDone: 2, speedTotal: 2, etaMs: 0, finished: true, cancelled: false });
  const a = ev.find(p => p.result && p.result.ip === '1.1.1.1').result;
  assert.equal(a.delay.median, 40);
  assert.equal(downs(s.rig).length, 4, 'two rounds per row');
  assert.deepEqual(s.rig.cores.map(c => c.engine).sort(), ['xray', 'xray-pattn']);
  assert.equal(s.data.scan, undefined, 'a re-test is not remembered as the last request');
  assert.equal(s.scan.busy(), false);
});

test('scan:apply stores a clone that dials the IP under "<name> [ip]" with a fresh id and a rebuilt link', async () => {
  const s = setup({ installed: ['xray'] }, { servers: [F.VLESS_WS_TLS] });
  const rec = await s.handlers['scan:apply']({ serverId: 'sv-vless', ip: '104.16.2.3' });
  assert.match(rec.id, /^sv-[0-9a-f]{12}$/);
  assert.notEqual(rec.id, 'sv-vless');
  assert.equal(rec.name, 'VLESS WS [104.16.2.3]');
  assert.equal(rec.address, '104.16.2.3');
  assert.equal(rec.port, 443);
  assert.equal(rec.protocol, 'vless');
  assert.equal(rec.outbound.settings.vnext[0].address, '104.16.2.3');
  assert.equal(rec.outbound.streamSettings.tlsSettings.serverName, 'a.example.com');
  assert.equal(rec.outbound.streamSettings.wsSettings.headers.Host, 'a.example.com');
  assert.equal(rec.engine, undefined);
  const back = parseLink(rec.raw);
  assert.equal(back.address, '104.16.2.3');
  assert.equal(back.outbound.streamSettings.tlsSettings.serverName, 'a.example.com');
  assert.equal(back.outbound.settings.vnext[0].users[0].id, 'uuid-a');
  assert.equal(s.added[0], rec, 'went through ctx.addServer');
  assert.equal(F.VLESS_WS_TLS.address, 'a.example.com', 'the source is untouched');

  const named = await s.handlers['scan:apply']({ serverId: 'sv-vless', ip: '104.16.2.4', name: 'CF edge', engine: 'xray-pattn' });
  assert.equal(named.name, 'CF edge [104.16.2.4]');
  assert.equal(named.engine, 'xray-pattn');
  assert.match(named.raw, /engine=xray-pattn/);

  const fromLink = await s.handlers['scan:apply']({ link: buildShareLink(F.SS_TCP), ip: '5.5.5.5' });
  assert.equal(fromLink.name, 'Shadowsocks [5.5.5.5]');
  assert.equal(fromLink.outbound.settings.servers[0].address, '5.5.5.5');
  assert.equal(s.added.length, 3);
});

test('scan:apply refuses a bad IP, a missing server and an unsupported protocol', async () => {
  const s = setup({ installed: ['xray'] }, { servers: [F.WG_BAD_MASK] });
  assert.deepEqual(await s.handlers['scan:apply']({ serverId: 'sv-wg', ip: 'not-an-ip' }), { error: 'invalid ip' });
  assert.deepEqual(await s.handlers['scan:apply']({ serverId: 'gone', ip: '1.1.1.1' }), { error: 'server not found' });
  assert.deepEqual(await s.handlers['scan:apply']({ serverId: 'sv-wg', ip: '1.1.1.1' }), { error: 'unsupported protocol' });
  assert.deepEqual(await s.handlers['scan:apply']({ ip: '1.1.1.1' }), { error: 'no server' });
  assert.equal(s.added.length, 0);
});

test('scan:export — CSV with the exact header, the phase and the median, empty cells for what was not measured; JSON round-trips', async () => {
  const s = setup();
  const results = [
    { ip: '1.1.1.1', engine: 'xray', phase: 2, tcp: { ok: true, ms: 12 }, delay: { min: 40, median: 45, avg: 45.5, jitter: 2.5, loss: 0, samples: [40, 51] }, down: { ok: true, bytes: 1, ms: 1, ttfb: 1, mbps: 12.34, mbpsRaw: 11, warm: true, error: null }, up: null, score: 987.6, error: null },
    { ip: '1.1.1.2', engine: 'xray-pattn', tcp: { ok: false, ms: -1, error: 'timeout' }, delay: null, down: null, up: null, score: 0, error: null },
    { ip: '1.1.1.3', engine: 'xray', phase: 1, tcp: null, delay: { min: 0, median: 0, avg: 0, jitter: 0, loss: 1, samples: [-1] }, down: { ok: false, bytes: 0, ms: -1, ttfb: -1, mbps: 0, mbpsRaw: 0, warm: false, error: 'timeout' }, up: { ok: true, bytes: 2, ms: 2, ttfb: 2, mbps: 1.5, error: null }, score: 0, error: 'spawn failed, "quoted"' }
  ];
  const csv = await s.handlers['scan:export']({ format: 'csv', results });
  const lines = csv.split('\r\n');
  assert.equal(lines[0], 'ip,engine,phase,tcp_ms,delay_min,delay_median,delay_avg,jitter,loss,down_mbps,up_mbps,score,error');
  assert.equal(lines[1], '1.1.1.1,xray,2,12,40,45,45.5,2.5,0,12.34,,987.6,');
  assert.equal(lines[2], '1.1.1.2,xray-pattn,1,,,,,,,,,0,', 'a row without a phase is a phase-1 row');
  assert.equal(lines[3], '1.1.1.3,xray,1,,,,,,1,,1.5,0,"spawn failed, ""quoted"""');
  assert.equal(lines[4], '');
  assert.equal(lines.length, 5);

  const json = await s.handlers['scan:export']({ format: 'json', results });
  assert.deepEqual(JSON.parse(json), results);
  assert.equal(await s.handlers['scan:export']({ format: 'csv', results: [] }), lines[0] + '\r\n');
  assert.deepEqual(await s.handlers['scan:export']({ format: 'xml', results }), { error: 'unknown format' });
});
