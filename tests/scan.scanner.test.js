'use strict';
/**
 * IP-scan runner and channels, with a fake core and fake probes.
 *
 * What matters: one throwaway core per engine per batch and nothing else
 * spawned, every IP×engine reported exactly once the moment it is done,
 * progress that only goes up, a Stop that halts scheduling and kills the
 * batch core, a core that fails to start marking its batch and not the run,
 * a result shape R2 can render, and channel replies/events that match the
 * plan's interface block to the letter.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');

const { runScan } = require('../src/main/scan/scanner');
const { createScan } = require('../src/main/scan/index');
const { delayStats } = require('../src/main/scan/score');
const { parseLink, buildShareLink } = require('../src/main/parser');
const F = require('./fixtures');

const tick = (ms = 2) => new Promise((r) => setTimeout(r, ms));
const until = async (pred, ms = 5000, what = 'condition') => {
  const t0 = Date.now();
  while (!pred()) { if (Date.now() - t0 > ms) throw new Error(`${what} not met within ${ms}ms`); await tick(5); }
};
const RESULT_KEYS = ['delay', 'down', 'engine', 'error', 'ip', 'score', 'tcp', 'up'];

/* ----------------------------- the fake rig ----------------------------- */

/** Address a test config dials for its k-th inbound (the real buildMultiTestConfig shapes). */
function dialAddress(out) {
  const s = out.settings || {};
  return (s.vnext && s.vnext[0] && s.vnext[0].address) || (s.servers && s.servers[0] && s.servers[0].address) || null;
}

function fakeRig(spec = {}) {
  const calls = [], cores = [], portToIp = new Map(), log = [];
  let active = 0, peak = 0;
  const busy = async (ms) => { active++; peak = Math.max(peak, active); await tick(ms); active--; };
  const ipOf = (port) => portToIp.get(port);
  const xray = {
    binExists: (id) => (spec.installed || ['xray', 'xray-pattn']).includes(id),
    startTest: async (cfg, engine) => {
      calls.push({ cfg, engine });
      if (spec.failStart && spec.failStart(engine, calls.length)) throw new Error('spawn failed');
      cfg.inbounds.forEach((inb, k) => portToIp.set(inb.port, dialAddress(cfg.outbounds[k])));
      const core = { engine, ips: cfg.inbounds.map((inb, k) => dialAddress(cfg.outbounds[k])), cleaned: 0 };
      cores.push(core);
      return { proc: null, cleanup: () => { core.cleaned++; } };
    }
  };
  const getFreePorts = async (n) => Array.from({ length: n }, (_, k) => 40000 + k);   // numbers only, never bound
  const probeMs = spec.probeMs || 3;
  const probes = {
    tcpPing: async (host, port, timeout) => {
      log.push(['tcp', host, port, timeout]);
      await busy(probeMs);
      return spec.tcp ? spec.tcp(host) : { ok: true, ms: 10 };
    },
    delaySeries: async (port, o) => {
      log.push(['delay', ipOf(port), o]);
      await busy(probeMs);
      return spec.delay ? spec.delay(ipOf(port)) : delayStats([50, 60, 70]);
    },
    downloadThroughProxy: async (port, o) => {
      log.push(['down', ipOf(port), o]);
      await busy(probeMs);
      const mbps = spec.mbps ? spec.mbps(ipOf(port)) : 5;
      return { ok: true, bytes: o.bytes, ms: 100, ttfb: 10, mbps, error: null };
    },
    uploadThroughProxy: async (port, o) => {
      log.push(['up', ipOf(port), o]);
      await busy(probeMs);
      return { ok: true, bytes: o.bytes, ms: 50, ttfb: 50, mbps: 2, error: null };
    }
  };
  return { xray, getFreePorts, probes, calls, cores, log, peak: () => peak };
}

const IPS = ['1.1.1.1', '1.1.1.2', '1.1.1.3', '1.1.1.4', '1.1.1.5'];

function run(rig, over = {}) {
  const results = [], progress = [];
  const args = Object.assign({
    server: F.VLESS_WS_TLS, ips: IPS, engines: ['xray'], tests: { tcp: true, delay: true, down: true, up: false },
    opts: { batch: 2, concurrency: 8, probes: rig.probes, getFreePorts: rig.getFreePorts },
    xray: rig.xray, token: { cancelled: false },
    onResult: (r) => results.push(r), onProgress: (p) => progress.push(Object.assign({}, p))
  }, over);
  return { promise: runScan(args), results, progress, token: args.token };
}

/* ----------------------------- runScan ----------------------------- */

test('one core per engine per batch, dialling exactly the batch\'s IPs with the SNI still on the name', async () => {
  const rig = fakeRig();
  const { promise, results, progress } = run(rig, { engines: ['xray', 'xray-pattn'] });
  const out = await promise;

  assert.equal(rig.calls.length, 6, '3 batches × 2 engines');
  assert.deepEqual(rig.calls.map(c => c.engine), ['xray', 'xray', 'xray', 'xray-pattn', 'xray-pattn', 'xray-pattn']);
  assert.deepEqual(rig.cores.map(c => c.ips), [['1.1.1.1', '1.1.1.2'], ['1.1.1.3', '1.1.1.4'], ['1.1.1.5'], ['1.1.1.1', '1.1.1.2'], ['1.1.1.3', '1.1.1.4'], ['1.1.1.5']]);
  for (const c of rig.cores) assert.equal(c.cleaned, 1, 'every core is cleaned up exactly once');
  const cfg = rig.calls[0].cfg;
  assert.equal(cfg.inbounds.length, 2);
  assert.deepEqual(cfg.inbounds.map(i => i.port), [40000, 40001]);
  assert.equal(cfg.outbounds[0].streamSettings.tlsSettings.serverName, 'a.example.com');
  assert.equal(cfg.outbounds[0].settings.vnext[0].address, '1.1.1.1');

  assert.equal(results.length, 10);
  for (const r of results) {
    assert.deepEqual(Object.keys(r).sort(), RESULT_KEYS, JSON.stringify(r));
    assert.deepEqual(r.tcp, { ok: true, ms: 10 });
    assert.equal(r.delay.avg, 60);
    assert.equal(r.down.mbps, 5);
    assert.equal(r.up, null, 'not ticked');
    assert.equal(r.error, null);
    assert.ok(r.score > 0);
  }
  assert.equal(results.filter(r => r.engine === 'xray-pattn').length, 5);
  // the TCP test goes straight to ip:port, not through the core
  assert.ok(rig.log.some(e => e[0] === 'tcp' && e[1] === '1.1.1.3' && e[2] === 443));

  assert.equal(progress.length, 10);
  progress.forEach((p, i) => assert.deepEqual(p, { done: i + 1, total: 10 }));
  assert.equal(out.cancelled, false);
  assert.equal(out.results.length, 10);
});

test('results are sorted by score desc, then delay avg asc', async () => {
  const mbps = { '1.1.1.1': 1, '1.1.1.2': 9, '1.1.1.3': 9, '1.1.1.4': 3, '1.1.1.5': 0.5 };
  const rig = fakeRig({
    mbps: (ip) => mbps[ip],
    delay: (ip) => (ip === '1.1.1.3' ? delayStats([20, 20, 20]) : delayStats([80, 80, 80]))
  });
  const { promise } = run(rig);
  const { results } = await promise;
  assert.deepEqual(results.map(r => r.ip), ['1.1.1.3', '1.1.1.2', '1.1.1.4', '1.1.1.1', '1.1.1.5']);
  for (let i = 1; i < results.length; i++) assert.ok(results[i - 1].score >= results[i].score);
});

test('never more than `concurrency` probes in flight', async () => {
  const rig = fakeRig({ probeMs: 15 });
  const { promise } = run(rig, { opts: { batch: 20, concurrency: 2, probes: rig.probes, getFreePorts: rig.getFreePorts } });
  await promise;
  assert.equal(rig.peak(), 2);
});

test('a failed TCP connect skips the tunnel tests; a dead tunnel skips the download', async () => {
  const rig = fakeRig({
    tcp: (ip) => (ip === '1.1.1.2' ? { ok: false, ms: -1, error: 'timeout' } : { ok: true, ms: 12 }),
    delay: (ip) => (ip === '1.1.1.4' ? delayStats([-1, -1, -1]) : delayStats([40, 40, 40]))
  });
  const { promise, results } = run(rig, { opts: { batch: 20, concurrency: 8, probes: rig.probes, getFreePorts: rig.getFreePorts } });
  await promise;
  const byIp = Object.fromEntries(results.map(r => [r.ip, r]));
  assert.equal(byIp['1.1.1.2'].tcp.ok, false);
  assert.equal(byIp['1.1.1.2'].delay, null);
  assert.equal(byIp['1.1.1.2'].down, null);
  assert.equal(byIp['1.1.1.2'].score, 0);
  assert.equal(byIp['1.1.1.2'].error, null, 'a failed probe is a measurement, not an error');
  assert.ok(!rig.log.some(e => e[0] === 'delay' && e[1] === '1.1.1.2'));

  assert.equal(byIp['1.1.1.4'].delay.loss, 1);
  assert.equal(byIp['1.1.1.4'].down, null);
  assert.equal(byIp['1.1.1.4'].score, 0);
  assert.ok(!rig.log.some(e => e[0] === 'down' && e[1] === '1.1.1.4'));
  assert.ok(byIp['1.1.1.1'].down.ok);
  assert.equal(results.length, 5, 'every IP still gets its row');
});

test('the tests object decides what runs; the download path follows downBytes unless given', async () => {
  const rig = fakeRig();
  const { promise, results } = run(rig, {
    tests: { tcp: false, delay: true, down: true, up: true },
    opts: { batch: 20, concurrency: 8, delaySamples: 5, downBytes: 5e6, upBytes: 1e6, probes: rig.probes, getFreePorts: rig.getFreePorts }
  });
  await promise;
  assert.equal(results[0].tcp, null);
  assert.ok(results[0].up.ok);
  assert.ok(!rig.log.some(e => e[0] === 'tcp'));
  const delayCall = rig.log.find(e => e[0] === 'delay');
  assert.equal(delayCall[2].n, 5);
  assert.equal(delayCall[2].host, 'cp.cloudflare.com');
  const downCall = rig.log.find(e => e[0] === 'down');
  assert.equal(downCall[2].path, '/__down?bytes=5000000');
  assert.equal(downCall[2].bytes, 5e6);
  assert.equal(downCall[2].host, 'speed.cloudflare.com');
  assert.equal(downCall[2].tls, true);
  assert.equal(rig.log.find(e => e[0] === 'up')[2].bytes, 1e6);

  const rig2 = fakeRig();
  await run(rig2, { opts: { batch: 20, downPath: '/custom?x=1', downHost: 'my.host', downTls: false, downPort: 8080, probes: rig2.probes, getFreePorts: rig2.getFreePorts } }).promise;
  const d = rig2.log.find(e => e[0] === 'down')[2];
  assert.deepEqual([d.path, d.host, d.tls, d.port], ['/custom?x=1', 'my.host', false, 8080]);
});

test('Stop: no more scheduling, the batch core is killed, the run resolves cancelled with what it has', async () => {
  const rig = fakeRig();
  let cancelAt;
  const { promise, results, progress, token } = run(rig, {
    engines: ['xray', 'xray-pattn'],
    opts: { batch: 20, concurrency: 1, probes: rig.probes, getFreePorts: rig.getFreePorts },
    onResult: (r) => { results.push(r); if (results.length === 3) { token.cancelled = true; cancelAt = Date.now(); } }
  });
  const out = await promise;
  assert.equal(results.length, 3);
  assert.equal(out.cancelled, true);
  assert.equal(out.results.length, 3);
  assert.equal(rig.calls.length, 1, 'the second engine never started');
  assert.equal(rig.cores[0].cleaned, 1);
  assert.equal(progress.at(-1).done, 3);
  assert.ok(Date.now() - cancelAt < 1000);
});

test('Stop mid-probe kills the core early instead of waiting for the probes\' timeouts', async () => {
  const rig = fakeRig({ probeMs: 1500 });
  const { promise, results, token } = run(rig, { opts: { batch: 20, concurrency: 8, probes: rig.probes, getFreePorts: rig.getFreePorts } });
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

test('a core that fails to start marks that batch `error` and the run goes on', async () => {
  const rig = fakeRig({ failStart: (engine, n) => engine === 'xray' && n === 2 });
  const { promise, results, progress } = run(rig, { engines: ['xray', 'xray-pattn'] });
  const out = await promise;
  assert.equal(results.length, 10, 'every IP × engine is reported');
  const failed = results.filter(r => r.error);
  assert.deepEqual(failed.map(r => [r.ip, r.engine]).sort(), [['1.1.1.3', 'xray'], ['1.1.1.4', 'xray']]);
  for (const r of failed) {
    assert.equal(r.error, 'spawn failed');
    assert.deepEqual([r.tcp, r.delay, r.down, r.up, r.score], [null, null, null, null, 0]);
  }
  assert.equal(results.filter(r => r.engine === 'xray-pattn' && !r.error).length, 5);
  assert.deepEqual(progress.at(-1), { done: 10, total: 10 });
  assert.equal(out.results.at(-1).error, 'spawn failed', 'errors sort last');
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

test('register() puts exactly the five scan channels on the context', () => {
  const s = setup();
  assert.deepEqual(Object.keys(s.handlers).sort(), ['scan:apply', 'scan:export', 'scan:presets', 'scan:start', 'scan:stop']);
  assert.equal(s.scan.busy(), false);
});

test('scan:presets — the Cloudflare ranges, the exact defaults, the engines with their install state, and no last request yet', async () => {
  const s = setup({ installed: ['xray'] });
  const p = await s.handlers['scan:presets']();
  assert.equal(p.cfRanges.length, 15);
  assert.deepEqual(p.defaults, {
    concurrency: 8, batch: 20, delaySamples: 3, downBytes: 10e6, downMaxMs: 8000,
    downHost: 'speed.cloudflare.com', downPath: '/__down?bytes=10000000',
    upHost: 'speed.cloudflare.com', upPath: '/__up', upBytes: 2e6
  });
  assert.equal(p.last, null);
  assert.deepEqual(p.engines, [
    { id: 'xray', label: 'Xray (official)', installed: true },
    { id: 'xray-pattn', label: 'Xray-PattN (patterniha)', installed: false }
  ]);
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

test('scan:start runs in the background and streams scan-progress: one event per result, then a finished one', async () => {
  const s = setup({ installed: ['xray', 'xray-pattn'] }, { servers: [F.VLESS_WS_TLS] });
  const req = { serverId: 'sv-vless', ipsText: '1.1.1.1\n1.1.1.2, 1.1.1.3\n1.1.1.1', engines: ['xray', 'xray-pattn', 'sing-box'], tests: { tcp: true, delay: true, down: false, up: false }, opts: { batch: 2, concurrency: 3 } };
  const reply = await s.handlers['scan:start'](req);
  assert.match(reply.runId, /^scan-/);
  assert.equal(reply.total, 6, '3 unique IPs × 2 installed engines');
  assert.equal(reply.truncated, false);
  assert.deepEqual(reply.errors, []);
  assert.equal(s.scan.busy(), true);
  assert.deepEqual(await s.handlers['scan:start'](req), { error: 'busy' });

  await until(() => progressOf(s.events).some(p => p.finished), 5000, 'finished event');
  const ev = progressOf(s.events);
  assert.equal(ev.length, 7);
  ev.slice(0, 6).forEach((p, i) => {
    assert.equal(p.runId, reply.runId);
    assert.deepEqual([p.done, p.total], [i + 1, 6]);
    assert.deepEqual(Object.keys(p.result).sort(), RESULT_KEYS);
    assert.equal(p.finished, undefined);
  });
  assert.deepEqual(ev[6], { runId: reply.runId, done: 6, total: 6, finished: true, cancelled: false });
  assert.equal(s.scan.busy(), false);
  assert.deepEqual(s.rig.calls.map(c => c.engine), ['xray', 'xray', 'xray-pattn', 'xray-pattn']);

  // the last request is remembered without results, with the engines it actually ran
  const last = s.data.scan;
  assert.deepEqual(Object.keys(last).sort(), ['engines', 'ipsText', 'link', 'opts', 'serverId', 'tests']);
  assert.equal(last.serverId, 'sv-vless');
  assert.equal(last.ipsText, req.ipsText);
  assert.deepEqual(last.engines, ['xray', 'xray-pattn']);
  assert.deepEqual(last.tests, { tcp: true, delay: true, down: false, up: false });
  assert.equal(last.opts.batch, 2);
  assert.equal(last.opts.concurrency, 3);
  assert.equal(last.opts.downBytes, 10e6, 'omitted options are filled with the defaults');
  assert.equal((await s.handlers['scan:presets']()).last.serverId, 'sv-vless');
  assert.ok(s.logs.some(l => /scan/i.test(l.line)));
});

test('scan:start with a pasted link and no engines list runs on every installed core; out-of-range options are clamped', async () => {
  const s = setup({ installed: ['xray-pattn'] });
  const link = buildShareLink(F.TROJAN_TCP_TLS);
  const reply = await s.handlers['scan:start']({ link, ipsText: '9.9.9.9', opts: { concurrency: 999, batch: 0, delaySamples: 'x' } });
  assert.equal(reply.total, 1);
  await until(() => progressOf(s.events).some(p => p.finished), 5000, 'finished');
  assert.deepEqual(s.rig.calls.map(c => c.engine), ['xray-pattn']);
  assert.equal(s.rig.cores[0].ips[0], '9.9.9.9');
  assert.equal(s.rig.calls[0].cfg.outbounds[0].settings.servers[0].password, 'pw');
  assert.equal(s.data.scan.link, link);
  assert.equal(s.data.scan.serverId, null);
  assert.deepEqual([s.data.scan.opts.concurrency, s.data.scan.opts.batch, s.data.scan.opts.delaySamples], [64, 1, 3]);
  const r = progressOf(s.events)[0].result;
  assert.ok(r.down.ok, 'tests default to tcp+delay+down');
  assert.equal(r.up, null);
});

test('scan:stop ends the run with cancelled: true; stop() waits for it', async () => {
  const s = setup({ installed: ['xray'], probeMs: 40 }, { servers: [F.VLESS_WS_TLS] });
  assert.deepEqual(await s.handlers['scan:stop'](), { ok: true, running: false });
  const reply = await s.handlers['scan:start']({ serverId: 'sv-vless', ipsText: '10.0.0.0/28', opts: { concurrency: 1, batch: 20 } });
  assert.equal(reply.total, 16);
  await until(() => progressOf(s.events).length >= 2, 5000, 'two results');
  assert.deepEqual(await s.handlers['scan:stop'](), { ok: true, running: true, runId: reply.runId });
  await s.scan.stop();
  assert.equal(s.scan.busy(), false);
  const ev = progressOf(s.events);
  const last = ev.at(-1);
  assert.equal(last.finished, true);
  assert.equal(last.cancelled, true);
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
  assert.deepEqual(last, { runId: reply.runId, done: 0, total: 1, finished: true, cancelled: false, error: 'boom' });
  assert.ok(s.logs.some(l => l.level === 'error' && /boom/.test(l.line)));
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

test('scan:export — CSV with the exact header and empty cells for what was not measured; JSON round-trips', async () => {
  const s = setup();
  const results = [
    { ip: '1.1.1.1', engine: 'xray', tcp: { ok: true, ms: 12 }, delay: { min: 40, avg: 45.5, jitter: 2.5, loss: 0, samples: [40, 51] }, down: { ok: true, bytes: 1, ms: 1, ttfb: 1, mbps: 12.34, error: null }, up: null, score: 987.6, error: null },
    { ip: '1.1.1.2', engine: 'xray-pattn', tcp: { ok: false, ms: -1, error: 'timeout' }, delay: null, down: null, up: null, score: 0, error: null },
    { ip: '1.1.1.3', engine: 'xray', tcp: null, delay: { min: 0, avg: 0, jitter: 0, loss: 1, samples: [-1] }, down: { ok: false, bytes: 0, ms: -1, ttfb: -1, mbps: 0, error: 'timeout' }, up: { ok: true, bytes: 2, ms: 2, ttfb: 2, mbps: 1.5, error: null }, score: 0, error: 'spawn failed, "quoted"' }
  ];
  const csv = await s.handlers['scan:export']({ format: 'csv', results });
  const lines = csv.split('\r\n');
  assert.equal(lines[0], 'ip,engine,tcp_ms,delay_min,delay_avg,jitter,loss,down_mbps,up_mbps,score,error');
  assert.equal(lines[1], '1.1.1.1,xray,12,40,45.5,2.5,0,12.34,,987.6,');
  assert.equal(lines[2], '1.1.1.2,xray-pattn,,,,,,,,0,');
  assert.equal(lines[3], '1.1.1.3,xray,,,,,1,,1.5,0,"spawn failed, ""quoted"""');
  assert.equal(lines[4], '');
  assert.equal(lines.length, 5);

  const json = await s.handlers['scan:export']({ format: 'json', results });
  assert.deepEqual(JSON.parse(json), results);
  assert.equal(await s.handlers['scan:export']({ format: 'csv', results: [] }), lines[0] + '\r\n');
  assert.deepEqual(await s.handlers['scan:export']({ format: 'xml', results }), { error: 'unknown format' });
});
