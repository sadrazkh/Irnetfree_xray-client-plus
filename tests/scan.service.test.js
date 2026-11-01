'use strict';
/**
 * The Scan page's service (src/main/scan/index.js) on 2026-11-01's ground:
 * the parameter matrix end to end (built, gated to its cores, planned against
 * the limit, every row naming its variant), the live plan the summary line
 * reads (counts only — a /8 is counted, never listed), the address picks with
 * no cap, the base gate the synced v1.41.0 xrayManager asks for (TUIC/AnyTLS
 * refused, dialMode/merge on Xray-PattN 26.10.27+, finalmask on PattN when
 * it is there), one row copied as a link or as JSON, the saved parameter
 * sets, and a run too big to list streaming only what passed.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');

const { createScan, STREAM_ALL } = require('../src/main/scan/index');
const { delayStats } = require('../src/main/scan/score');
const { parseLink } = require('../src/main/parser');
const { importJson } = require('../src/main/jsonImport');
const F = require('./fixtures');

const tick = (ms = 1) => new Promise((r) => setTimeout(r, ms));
const until = async (pred, ms = 8000, what = 'condition') => {
  const t0 = Date.now();
  while (!pred()) { if (Date.now() - t0 > ms) throw new Error(`${what} not met within ${ms}ms`); await tick(5); }
};

function dialAddress(out) {
  const s = (out && out.settings) || {};
  return (s.vnext && s.vnext[0] && s.vnext[0].address) || (s.servers && s.servers[0] && s.servers[0].address) || s.address || null;
}

function setup(spec = {}, servers = []) {
  const cores = [], log = [], portTo = new Map();
  const xray = {
    binExists: (id) => (spec.installed || ['xray', 'xray-pattn']).includes(id),
    version: async (id) => (spec.versions && spec.versions[id]) || '26.11.1',
    startTest: async (cfg, engine) => {
      const outs = cfg.inbounds.map((inb, k) => cfg.outbounds.find((o) => o.tag === `test-out-${k}`));
      cfg.inbounds.forEach((inb, k) => portTo.set(inb.port, outs[k]));
      cores.push({ engine, cfg, addrs: outs.map(dialAddress) });
      return { proc: null, cleanup: () => {} };
    }
  };
  let base = 43000;
  const probes = {
    tcpPing: async (host) => { log.push(['tcp', host]); await tick(spec.preMs || 1); return spec.tcp ? spec.tcp(host) : { ok: true, ms: 7 }; },
    tlsPing: async (host) => { log.push(['tls', host]); return { ok: true, ms: 9, reason: '' }; },
    delaySeries: async (port, o) => { log.push(['delay', portTo.get(port), o]); await tick(); return spec.delay ? spec.delay(portTo.get(port)) : delayStats([40, 50, 60]); },
    downloadThroughProxy: async () => ({ ok: true, bytes: 1, ms: 1, ttfb: 5, mbps: 3, mbpsRaw: 3, warm: true, error: null }),
    uploadThroughProxy: async () => ({ ok: true, bytes: 1, ms: 1, ttfb: 1, mbps: 1, error: null })
  };
  const handlers = {}, events = [], logs = [], data = {}, added = [];
  const ctx = {
    handle: (ch, fn) => { handlers[ch] = fn; },
    send: (ch, payload) => events.push({ ch, payload: JSON.parse(JSON.stringify(payload)) }),
    notify: () => {},
    store: { get: (k, d) => (k in data ? data[k] : d), set: (k, v) => { data[k] = v; return true; }, setLazy: (k, v) => { data[k] = v; return true; } },
    dataDir: os.tmpdir(), getSettings: () => ({}), xray,
    getServers: () => servers,
    addServer: (rec) => { added.push(rec); servers.push(rec); return rec; },
    resolveTarget: (id) => { const s = servers.find((x) => x.id === id); return s ? { server: s, chain: null } : { server: null, chain: null }; },
    log: (line, level) => logs.push({ line, level }), platform: process.platform, isElectron: false
  };
  const scan = createScan(ctx, { probes, getFreePorts: async (n) => { const b = base; base += 100; return Array.from({ length: n }, (_, k) => b + k); }, waitReady: async () => true });
  scan.register();
  const progress = () => events.filter((e) => e.ch === 'scan-progress').map((e) => e.payload);
  const finished = (n = 1) => until(() => progress().filter((p) => p.finished).length >= n, 15000, 'finished');
  return { handlers, events, logs, data, added, cores, log, progress, finished, scan };
}

const VLESS = () => Object.assign(JSON.parse(JSON.stringify(F.VLESS_WS_TLS)), { id: 'sv-vless' });
const FILTER = { tcp: true, delay: true, down: false, up: false };

/* ------------------------------- the matrix, end to end ------------------------------- */

test('scan:start with parameters: variants × targets, every row naming its variant, the dialMode variant on Xray-PattN alone', async () => {
  const s = setup({}, [VLESS()]);
  const reply = await s.handlers['scan:start']({
    serverId: 'sv-vless', ipsText: '1.1.1.1\n1.1.1.2', tests: FILTER, opts: { batch: 20 },
    variants: { dims: { fingerprint: ['chrome', 'firefox'], dialMode: ['none', 'oob.0'] } }
  });
  assert.equal(reply.error, undefined, JSON.stringify(reply));
  assert.equal(reply.variants.count, 4);
  assert.equal(reply.tests, 8, '4 variants × 2 targets');
  assert.equal(reply.total, 2 * (2 + 2 + 1 + 1), 'dialMode variants on one core, the others on two');
  assert.deepEqual(reply.variants.list.map((v) => [v.label, v.engines]), [
    ['fp=chrome · dm=none', ['xray', 'xray-pattn']], ['fp=chrome · oob.0', ['xray-pattn']],
    ['fp=firefox · dm=none', ['xray', 'xray-pattn']], ['fp=firefox · oob.0', ['xray-pattn']]
  ]);
  await s.finished();
  const rows = s.progress().filter((p) => p.result).map((p) => p.result);
  assert.equal(rows.length, 12);
  assert.ok(rows.every((r) => r.variant && r.variantLabel && r.key.includes('#' + r.variant)));
  assert.ok(rows.filter((r) => /oob\.0/.test(r.variantLabel)).every((r) => r.engine === 'xray-pattn'));
  const official = s.cores.filter((c) => c.engine === 'xray').flatMap((c) => c.cfg.outbounds);
  assert.ok(official.every((o) => !(o.streamSettings && o.streamSettings.sockopt && o.streamSettings.sockopt.dialMode)), 'never on the official core');
  assert.equal(s.log.filter((e) => e[0] === 'tcp').length, 2, 'one pre-check per address');
  assert.deepEqual(s.progress().at(-1).variantStats, {
    'fp=chrome~dm=none': [4, 4], 'fp=chrome~dm=oob.0': [2, 2], 'fp=firefox~dm=none': [4, 4], 'fp=firefox~dm=oob.0': [2, 2]
  });
  assert.deepEqual(s.data.scan.variants, { dims: { fingerprint: ['chrome', 'firefox'], dialMode: ['none', 'oob.0'] }, limit: 300 }, 'remembered as the page sent it');
});

test('a variant only Xray-PattN runs is left out, with the reason, when PattN is missing or too old — never run on the official core', async () => {
  const old = setup({ versions: { 'xray-pattn': '26.9.9' } }, [VLESS()]);
  const r = await old.handlers['scan:start']({
    serverId: 'sv-vless', ipsText: '1.1.1.1', tests: FILTER,
    variants: { dims: { dialMode: ['none', 'oob.0'], finalMask: ['none', 'tlshello'] } }
  });
  assert.equal(r.variants.count, 2, 'the finalmask runs on any PattN; the dialMode does not');
  assert.deepEqual(r.variants.skipped.map((x) => x.label), ['fm=none · oob.0', 'fm=tlshello · oob.0']);
  assert.match(r.variants.skipped[0].reason, /Xray-PattN 26\.9\.9 does not know dialMode oob \(26\.10\.27 and newer do\)/);
  await old.finished();
  assert.ok(old.logs.some((l) => l.level === 'warn' && /variant fm=none · oob\.0 left out/.test(l.line)));

  const none = setup({ installed: ['xray'] }, [VLESS()]);
  const r2 = await none.handlers['scan:start']({ serverId: 'sv-vless', ipsText: '1.1.1.1', tests: FILTER, variants: { dims: { dialMode: ['oob.0'] } } });
  assert.equal(r2.error, 'no variant runs');
  assert.match(r2.variants.skipped[0].reason, /not installed/);
});

test('past the limit an even sample; the product past MAX_VARIANTS is refused before anything runs', async () => {
  const s = setup({}, [VLESS()]);
  const r = await s.handlers['scan:start']({
    serverId: 'sv-vless', ipsText: '10.0.0.0/24', tests: FILTER, engines: ['xray'],
    variants: { dims: { fingerprint: ['chrome', 'firefox', 'safari'] }, limit: 30 }
  });
  assert.deepEqual([r.tests, r.variants.sampled, r.total], [30, true, 30]);
  await s.finished();
  const rows = s.progress().filter((p) => p.result).map((p) => p.result);
  const per = {};
  for (const x of rows) per[x.variant] = (per[x.variant] || 0) + 1;
  assert.deepEqual(Object.values(per), [10, 10, 10]);
  assert.equal(new Set(rows.map((x) => x.addr)).size, 30, 'thirty different addresses');

  const big = await s.handlers['scan:start']({
    serverId: 'sv-vless', ipsText: '1.1.1.1', tests: FILTER,
    variants: { dims: { fingerprint: ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', '360', 'qq', 'random', 'randomized', 'unsafe', 'hellochrome_120'], alpn: ['h2', 'http/1.1', 'none'], fragment: ['off', '1-1,1-2,1-2', '1-2,1-3,1-3', '1-3,1-4,1-4'], finalMask: ['none', 'tlshello', 'tlshello-0-len', 'merge'], mux: ['off', 'on'], dialMode: ['none', 'oob.0', 'oob.1'], cipherSuites: ['none', 'real-firefox', 'semi-python'] } }
  });
  assert.equal(big.error, 'too many variants');
  assert.equal(big.max, 5000);
});

test('scan:plan: the live counts — addresses X of Y, targets, variants and tests — without drawing or starting anything', async () => {
  const s = setup({}, [VLESS()]);
  const t0 = Date.now();
  const all = await s.handlers['scan:plan']({ serverId: 'sv-vless', ipsText: '10.0.0.0/8', portsText: '443, 2053', pick: { mode: 'all' } });
  assert.ok(Date.now() - t0 < 1000, 'a /8 is counted, not listed');
  assert.deepEqual([all.addresses.total, all.addresses.taken, all.ports, all.snis, all.targets, all.tests], [16777216, 16777216, 2, 1, 33554432, 33554432]);
  const sample = await s.handlers['scan:plan']({ serverId: 'sv-vless', ipsText: '10.0.0.0/8', portsText: '443, 2053', pick: { mode: 'sample', count: 500 } });
  assert.deepEqual([sample.addresses.taken, sample.targets], [500, 1000]);
  const per = await s.handlers['scan:plan']({ serverId: 'sv-vless', ipsText: '10.0.0.0/24\n10.1.0.0/30', pick: { mode: 'random', perRange: 10 } });
  assert.deepEqual([per.addresses.total, per.addresses.taken], [260, 14]);
  const v = await s.handlers['scan:plan']({
    serverId: 'sv-vless', ipsText: '1.1.1.0/30', snisText: 'a.example.org',
    variants: { dims: { fingerprint: ['chrome', 'firefox', 'ios', 'edge'], finalMask: ['none', 'tlshello'] }, limit: 20 }
  });
  assert.deepEqual([v.targets, v.variants.count, v.tests, v.variants.sampled], [4, 8, 20, true]);
  assert.deepEqual(v.variants.dims, [{ id: 'fingerprint', n: 4 }, { id: 'finalMask', n: 2 }]);
  assert.equal(s.cores.length, 0, 'nothing started');
  assert.equal(s.data.scan, undefined, 'nothing remembered');
  const hy = setup({}, [Object.assign(parseLink('hy2://pw@h.example:443?sni=h.example#h'), { id: 'sv-hy2' })]);
  const skip = await hy.handlers['scan:plan']({ serverId: 'sv-hy2', variants: { dims: { fingerprint: ['chrome'] } } });
  assert.deepEqual(skip.variants.skippedDims.map((d) => d.dim), ['fingerprint']);
  assert.equal(skip.tests, 1, 'nothing applied: the plain run');
});

test('no address cap: a /16 is walked whole; past STREAM_ALL rows only the passing ones are sent, the dead counted by reason', async () => {
  assert.equal(STREAM_ALL, 20000);
  const s = setup({ installed: ['xray'], tcp: (host) => (host === '10.7.3.3' ? { ok: true, ms: 4 } : { ok: false, ms: -1, error: 'timeout' }), preMs: 0 }, [VLESS()]);
  const r = await s.handlers['scan:start']({ serverId: 'sv-vless', ipsText: '10.7.0.0/17', tests: FILTER, opts: { prefilterConcurrency: 512 } });
  assert.deepEqual([r.targets, r.total, r.streamAll, r.addresses], [32768, 32768, false, { total: 32768, taken: 32768 }]);
  await s.finished();
  const ev = s.progress();
  const rows = ev.filter((p) => p.result).map((p) => p.result);
  assert.deepEqual(rows.map((x) => x.addr), ['10.7.3.3'], 'the one that passed');
  assert.ok(ev.length < 2000, 'not one event per dead row: ' + ev.length);
  const last = ev.at(-1);
  assert.deepEqual([last.done, last.total, last.alive, last.reasons], [32768, 32768, 1, { 'no-tcp': 32767 }]);
  assert.equal(s.cores.length, 1, 'only the live address reached a core');
  assert.equal((s.data.scanTested || []).length, 32768, 'under the history cap: every address is remembered');
});

test('the address picks: N random from all the ranges together, N from each range — remembered with the rest', async () => {
  const s = setup({ installed: ['xray'] }, [VLESS()]);
  const r = await s.handlers['scan:start']({ serverId: 'sv-vless', ipsText: '10.0.0.0/16\n10.9.9.0/24', tests: FILTER, pick: { mode: 'sample', count: 64 } });
  assert.deepEqual([r.targets, r.addresses], [64, { total: 65792, taken: 64 }]);
  await s.finished();
  assert.deepEqual(s.data.scan.pick, { mode: 'sample', perRange: 20, count: 64, fresh: true });
  assert.ok(s.logs.some((l) => /64 of 65792 address\(es\), a random sample of all the ranges together/.test(l.line)));
});

/* ------------------------------- the base gate (v1.41.0) ------------------------------- */

test('the base gate: TUIC/AnyTLS refused; a dialMode config on Xray-PattN 26.10.27+ only; a finalmask config on PattN when it is there', async () => {
  const tuic = Object.assign(parseLink('tuic://11111111-2222-3333-4444-555555555555:pw@t.example.com:443?sni=t.example.com#t'), { id: 'sv-tuic' });
  const dmServer = VLESS(); dmServer.id = 'sv-dm'; dmServer.outbound.streamSettings.sockopt = { dialMode: 'oob.0' };
  const fmServer = VLESS(); fmServer.id = 'sv-fm'; fmServer.outbound.streamSettings.finalmask = { tcp: [{ type: 'fragment', settings: { packets: 'tlshello', lengths: ['3-5'], delays: ['1'] } }] };
  const s = setup({}, [tuic, dmServer, fmServer]);
  assert.deepEqual(await s.handlers['scan:start']({ serverId: 'sv-tuic', tests: FILTER }), { error: 'singbox only' });
  assert.equal((await s.handlers['scan:suggest']({ serverId: 'sv-tuic' })).unsupported, 'singbox only');

  const dm = await s.handlers['scan:start']({ serverId: 'sv-dm', ipsText: '1.1.1.1', tests: FILTER });
  assert.deepEqual(dm.engines, ['xray-pattn']);
  assert.match(dm.skipped[0].reason, /Xray \(official\) ignores dialMode oob/);
  await s.finished(1);
  const fm = await s.handlers['scan:start']({ serverId: 'sv-fm', ipsText: '1.1.1.1', tests: FILTER });
  assert.deepEqual(fm.engines, ['xray-pattn']);
  assert.match(fm.skipped[0].reason, /finalmask config runs on Xray-PattN/);
  await s.finished(2);

  const oldPattn = setup({ versions: { 'xray-pattn': '26.9.9' } }, [dmServer]);
  const r = await oldPattn.handlers['scan:start']({ serverId: 'sv-dm', ipsText: '1.1.1.1', tests: FILTER });
  assert.equal(r.error, 'core too old');
  assert.ok(r.skipped.some((x) => /26\.9\.9 does not know dialMode oob/.test(x.reason)));
  const onlyOfficial = setup({ installed: ['xray'] }, [fmServer]);
  const r2 = await onlyOfficial.handlers['scan:start']({ serverId: 'sv-fm', ipsText: '1.1.1.1', tests: FILTER });
  assert.deepEqual(r2.engines, ['xray'], 'no PattN: the official core runs a finalmask, as the app does');
});

/* ------------------------------- copying, saving ------------------------------- */

test('scan:copy: one row as a share link and as JSON — a dialMode or mux variant only as JSON; scan:links counts what a link cannot carry', async () => {
  const s = setup({}, [VLESS()]);
  const c = await s.handlers['scan:copy']({ serverId: 'sv-vless', addr: '104.16.0.9', port: 2053, variant: { fingerprint: 'firefox', alpn: 'h2' } });
  const back = parseLink(c.link);
  assert.deepEqual([back.address, back.port, back.outbound.streamSettings.tlsSettings.fingerprint, back.outbound.streamSettings.tlsSettings.alpn], ['104.16.0.9', 2053, 'firefox', ['h2']]);
  const json = JSON.parse(c.json);
  assert.ok(json.remarks.includes('fp=firefox · alpn=h2'));
  assert.equal(json.outbounds[0].settings.vnext[0].address, '104.16.0.9');
  assert.equal(json.outbounds[0].streamSettings.tlsSettings.fingerprint, 'firefox');
  const imported = importJson(c.json);
  assert.equal(imported.servers.length, 1, 'IRNetFree reads the JSON back');

  const dm = await s.handlers['scan:copy']({ serverId: 'sv-vless', addr: '104.16.0.9', variant: { dialMode: 'oob.0', fragment: 'off' } });
  assert.deepEqual([dm.link, dm.loses], ['', ['dialMode']]);
  assert.equal(JSON.parse(dm.json).outbounds[0].streamSettings.sockopt.dialMode, 'oob.0');
  const frag = await s.handlers['scan:copy']({ serverId: 'sv-vless', addr: '104.16.0.9', variant: { fragment: 'tlshello,100-200,10-20' } });
  const fj = JSON.parse(frag.json);
  const dialer = fj.outbounds.find((o) => o.tag === fj.outbounds[0].streamSettings.sockopt.dialerProxy);
  assert.deepEqual(dialer.settings.fragment, { packets: 'tlshello', length: '100-200', interval: '10-20' }, 'the JSON carries the real dialer, not the app’s marker');
  assert.equal(parseLink(frag.link).outbound._fragment, 'tlshello,100-200,10-20', 'the link carries the fragment parameter');
  assert.match((await s.handlers['scan:copy']({ serverId: 'sv-vless', addr: '1.1.1.1', variant: { dialMode: 'oob.999' } })).error, /dialMode/);

  const l = await s.handlers['scan:links']({ serverId: 'sv-vless', rows: [{ addr: '1.1.1.1', variant: { fingerprint: 'ios' } }, { addr: '1.1.1.2', variant: { mux: 'on' } }, { addr: '1.1.1.3' }] });
  assert.equal(l.links.length, 2);
  assert.equal(l.lossy, 1);

  const saved = await s.handlers['scan:apply']({ serverId: 'sv-vless', addr: '1.1.1.4', engine: 'xray-pattn', variant: { mux: 'on', fingerprint: 'edge' } });
  assert.ok(saved.name.endsWith('[1.1.1.4 · fp=edge · mux=on]'), saved.name);
  assert.deepEqual([saved.engine, saved.mux, saved.outbound.mux.enabled, saved.outbound.streamSettings.tlsSettings.fingerprint], ['xray-pattn', 'on', true, 'edge']);
});

test('scan:retest writes a row’s variant again, read value by value', async () => {
  const s = setup({}, [VLESS()]);
  const r = await s.handlers['scan:retest']({ serverId: 'sv-vless', rows: [{ addr: '1.1.1.1', engine: 'xray', variant: { fingerprint: 'safari' } }, { addr: '1.1.1.2', engine: 'xray', variant: { dialMode: 'bogus' } }], tests: { down: true } });
  assert.equal(r.total, 1, 'a variant that does not read is not run');
  await s.finished();
  assert.equal(s.cores[0].cfg.outbounds[0].streamSettings.tlsSettings.fingerprint, 'safari');
  assert.equal(s.progress().find((p) => p.result).result.variant, 'fp=safari');
});

test('scan:sets: a named selection saved, listed, replaced, deleted — the values kept as they read', async () => {
  const s = setup();
  assert.deepEqual(await s.handlers['scan:sets']({ action: 'list' }), { sets: [] });
  const a = await s.handlers['scan:sets']({ action: 'save', name: ' DPI ', set: { dims: { fragment: ['off', 'tlshello,100-200,10-20', 'nonsense'], dialMode: ['oob.0'] }, limit: 50 } });
  assert.equal(a.sets.length, 1);
  assert.deepEqual([a.sets[0].name, a.sets[0].dims, a.sets[0].limit], ['DPI', { fragment: ['off', 'tlshello,100-200,10-20'], dialMode: ['oob.0'] }, 50]);
  await s.handlers['scan:sets']({ action: 'save', name: 'TLS', set: { dims: { fingerprint: ['chrome'] } } });
  const b = await s.handlers['scan:sets']({ action: 'save', name: 'DPI', set: { dims: { fragment: ['off'] } } });
  assert.deepEqual(b.sets.map((x) => x.name), ['DPI', 'TLS'], 'the newest first, a name once');
  assert.deepEqual(b.sets[0].dims, { fragment: ['off'] });
  assert.deepEqual((await s.handlers['scan:sets']({ action: 'delete', name: 'TLS' })).sets.map((x) => x.name), ['DPI']);
  assert.deepEqual(s.data.scanSets.map((x) => x.name), ['DPI'], 'kept in the store');
  assert.deepEqual((await s.handlers['scan:presets']()).sets.map((x) => x.name), ['DPI']);
  assert.equal((await s.handlers['scan:sets']({ action: 'save', name: '', set: {} })).error, 'no name');
  assert.equal((await s.handlers['scan:sets']({ action: 'save', name: 'x', set: { dims: { fingerprint: ['bogus'] } } })).error, 'empty set');
});

test('scan:suggest tells the page which dimensions this config takes and its own values', async () => {
  const s = setup({}, [VLESS()]);
  const f = await s.handlers['scan:suggest']({ serverId: 'sv-vless' });
  assert.equal(f.variants.fingerprint.ok, true);
  assert.equal(f.variants.fingerprint.current, 'chrome');
  assert.equal(f.variants.xhttpMode.ok, false);
});
