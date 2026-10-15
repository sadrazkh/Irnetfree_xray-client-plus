'use strict';
/**
 * plus: the Scan page — one config tried through many targets (address × port
 * × SNI) on every installed Xray-format core (spec 2026-10-15 §4; v2.1 §1 for
 * the two phases, v2.2 for the random pick). `ctx` is the service's context
 * (src/main/plus/service.js); a handler gets its one argument unwrapped.
 *
 * Channels: scan:start, scan:retest, scan:stop, scan:presets, scan:suggest,
 * scan:apply, scan:links, scan:export, scan:forget. Event: scan-progress
 * { runId, stage, done, total, alive, speedDone, speedTotal, etaMs, result }
 * per result, the same without a result when the stage changes, then
 * { ..., finished: true, cancelled } (plus `error` when the run itself failed).
 * One run at a time. The last request is remembered under `scan`, never the
 * results — only the addresses tested, under `scanTested`, so a random draw
 * can skip them.
 *
 * Before a run (prepare): the config is checked to be one a target can be put
 * into; an SNI list is refused for a config whose SNI cannot change; a core
 * too old for the config is left out (MASQUE, a WARP account, ECH); and an
 * ECH config that is a DNS query is fetched ONCE here and handed to every
 * core as the list itself.
 */
const crypto = require('crypto');
const { parseLink, parseMany, buildShareLink } = require('../parser');
const { buildMultiTestConfig, echQueryOf } = require('../configBuilder');
const { usesMasque, usesMasqueWarp, usesEch, versionBelow, MASQUE_SINCE, MASQUE_WARP_SINCE, ECH_SINCE } = require('../xrayManager');
const { xrayEngines, engineLabel } = require('../engines');
const T = require('./targets');
const { applyTarget, dialOf, transportOf, sniSupport } = require('./substitute');
const { fetchEchConfig: defaultFetchEch } = require('./ech');
const { runScan: defaultRunScan, runSpeed: defaultRunSpeed } = require('./scanner');

const STORE_KEY = 'scan';
const MAX_TARGETS = 5000;
/** Every address a run has tested (phase 1), normalised strings, newest last — spec v2.2 §2.2. */
const TESTED_KEY = 'scanTested';
const TESTED_CAP = 50000;
const ECH_TIMEOUT_MS = 4000;
/** How the address box is read: every address, or a fresh draw of `perRange` per range that skips the tested. */
const PICK_DEFAULTS = { mode: 'all', perRange: 20, fresh: true };
/** What the page shows before the user changes anything: the balanced preset. */
const PRESET_DEFAULTS = {
  batch: 20, filterConcurrency: 16, coresInParallel: 2, delaySamples: 2,
  tcpTimeout: 2000, delayTimeout: 4000,
  delayHost: 'cp.cloudflare.com', delayPort: 80, delayPath: '/',
  speedTop: 10, speedConcurrency: 1, speedRounds: 1, warmupMs: 300,
  downBytes: 10e6, downMaxMs: 6000, downTimeout: 8000,
  downHost: 'speed.cloudflare.com', downPath: '/__down?bytes=10000000', downPort: 443, downTls: true,
  upBytes: 2e6, upTimeout: 20000,
  upHost: 'speed.cloudflare.com', upPath: '/__up', upPort: 443, upTls: true
};
/** The three presets; every one a full opts object. */
const PRESETS = {
  fast: Object.assign({}, PRESET_DEFAULTS, { delaySamples: 1, tcpTimeout: 1500, delayTimeout: 3000, filterConcurrency: 32, coresInParallel: 3, speedTop: 5 }),
  balanced: Object.assign({}, PRESET_DEFAULTS),
  accurate: Object.assign({}, PRESET_DEFAULTS, { delaySamples: 4, filterConcurrency: 8, speedTop: 20, speedRounds: 2, speedConcurrency: 1 })
};
const DEFAULT_TESTS = { tcp: true, delay: true, down: true, up: false };
const CSV_HEADER = 'addr,port,sni,engine,phase,tcp_ms,delay_min,delay_median,delay_avg,jitter,loss,down_mbps,up_mbps,score,error';

const num = (v, def, lo, hi) => {
  const n = Math.floor(Number(v));
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : def;
};
const str = (v, def) => (typeof v === 'string' && v.trim() ? v.trim() : def);
const hasTokens = (text) => String(text || '').split(/\r?\n/).some((l) => l.replace(/#.*/, '').trim());

/** The pick as sent, clamped; a request without one reads as `all`. */
function sanitizePick(raw) {
  const p = raw && typeof raw === 'object' ? raw : {};
  return {
    mode: p.mode === 'random' ? 'random' : 'all',
    perRange: num(p.perRange, PICK_DEFAULTS.perRange, 1, MAX_TARGETS),
    fresh: p.fresh === undefined ? PICK_DEFAULTS.fresh : !!p.fresh
  };
}

/** Clamp what the page sent; anything missing takes the default. */
function sanitizeOpts(raw) {
  const o = raw && typeof raw === 'object' ? raw : {};
  const D = PRESET_DEFAULTS;
  // v2.0 remembered one `concurrency`; it was the filter's
  const filterConcurrency = o.filterConcurrency !== undefined ? o.filterConcurrency : o.concurrency;
  return {
    batch: num(o.batch, D.batch, 1, 50),
    filterConcurrency: num(filterConcurrency, D.filterConcurrency, 1, 64),
    coresInParallel: num(o.coresInParallel, D.coresInParallel, 1, 6),
    delaySamples: num(o.delaySamples, D.delaySamples, 1, 10),
    tcpTimeout: num(o.tcpTimeout, D.tcpTimeout, 500, 30000),
    delayTimeout: num(o.delayTimeout, D.delayTimeout, 500, 60000),
    delayHost: str(o.delayHost, D.delayHost),
    delayPort: num(o.delayPort, D.delayPort, 1, 65535),
    delayPath: str(o.delayPath, D.delayPath),
    speedTop: num(o.speedTop, D.speedTop, 0, 50),
    speedConcurrency: num(o.speedConcurrency, D.speedConcurrency, 1, 4),
    speedRounds: num(o.speedRounds, D.speedRounds, 1, 3),
    warmupMs: num(o.warmupMs, D.warmupMs, 0, 2000),
    downBytes: num(o.downBytes, D.downBytes, 1e5, 1e9),
    downMaxMs: num(o.downMaxMs, D.downMaxMs, 1000, 60000),
    downTimeout: num(o.downTimeout, D.downTimeout, 500, 60000),
    downHost: str(o.downHost, D.downHost),
    downPath: str(o.downPath, ''),
    downPort: num(o.downPort, D.downPort, 1, 65535),
    downTls: o.downTls !== false,
    upBytes: num(o.upBytes, D.upBytes, 1e4, 1e8),
    upTimeout: num(o.upTimeout, D.upTimeout, 500, 120000),
    upHost: str(o.upHost, D.upHost),
    upPath: str(o.upPath, D.upPath),
    upPort: num(o.upPort, D.upPort, 1, 65535),
    upTls: o.upTls !== false
  };
}

function sanitizeTests(raw) {
  if (!raw || typeof raw !== 'object') return Object.assign({}, DEFAULT_TESTS);
  return { tcp: !!raw.tcp, delay: !!raw.delay, down: !!raw.down, up: !!raw.up };
}

function csvCell(v) {
  if (v === null || v === undefined || v === '') return '';
  const s = typeof v === 'number' ? String(Number.isInteger(v) ? v : Math.round(v * 1000) / 1000) : String(v);
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function csvRow(r) {
  const d = r.delay && r.delay.loss < 1 ? r.delay : null;
  return [
    r.addr || r.ip, r.port, r.sni, r.engine, r.phase || 1,
    r.tcp && r.tcp.ok ? r.tcp.ms : null,
    d ? d.min : null, d ? d.median : null, d ? d.avg : null, d ? d.jitter : null,
    r.delay ? r.delay.loss : null,
    r.down && r.down.ok ? r.down.mbps : null,
    r.up && r.up.ok ? r.up.mbps : null,
    r.score, r.error
  ].map(csvCell).join(',');
}

/** Why a config cannot take a target, as the page's error code; '' when it can. */
function refusalOf(err) {
  const code = err && err.code;
  if (code === 'json-chain') return 'json chain';
  if (code === 'reality' || code === 'ech' || code === 'notls') return 'sni';
  return 'unsupported protocol';
}

/** The TLS settings of a config's dialling outbound, or null. */
const tlsOf = (server) => (server && server.outbound && server.outbound.streamSettings && server.outbound.streamSettings.tlsSettings) || null;

/**
 * createScan(ctx, deps?) → { register(), stop(), busy() }
 * `deps` = { probes, getFreePorts, waitReady, runScan, runSpeed, fetchEchConfig } are the tests' seams.
 */
function createScan(ctx, deps = {}) {
  const runScan = deps.runScan || defaultRunScan;
  const runSpeed = deps.runSpeed || defaultRunSpeed;
  const fetchEch = deps.fetchEchConfig || defaultFetchEch;
  let run = null;                    // { runId, token, promise } while a scan is in flight

  function engineOffer() {
    return xrayEngines().map((id) => ({ id, label: engineLabel(id), installed: !!ctx.xray.binExists(id) }));
  }

  /** The stored config, or the pasted link or JSON. Throws with a reason the reply carries. */
  function resolveServer(req) {
    if (req.serverId) {
      const t = ctx.resolveTarget(req.serverId) || {};
      if (!t.server) throw new Error('server not found');
      return t.server;
    }
    if (req.link) {
      const text = String(req.link).trim();
      const many = (() => { try { return parseMany(text); } catch { return { servers: [] }; } })();
      if (many.servers && many.servers.length) return many.servers[0];
      return parseLink(text);   // throws, saying why
    }
    throw new Error('no server');
  }

  /** The engines a request may run on: installed, and wanted when it named any. */
  function chooseEngines(wanted) {
    const offered = engineOffer();
    const want = Array.isArray(wanted) && wanted.length ? wanted : offered.map((e) => e.id);
    return offered.filter((e) => e.installed && want.includes(e.id)).map((e) => e.id);
  }

  /** What a config allows a scan to do — for the page, before anything runs. */
  function factsOf(server) {
    const tls = tlsOf(server) || {};
    const ms = server.outbound && server.outbound.streamSettings && server.outbound.streamSettings.masqueSettings;
    let applies = '';
    try { applyTarget(server, {}); } catch (e) { applies = refusalOf(e); }
    const dial = dialOf(server);
    return {
      protocol: String(server.protocol || (server.outbound && server.outbound.protocol) || ''),
      name: server.name || '',
      address: dial.addr || '', port: dial.port || null, sniName: dial.sni || '',
      transport: transportOf(server),
      sni: sniSupport(server),
      ech: !!String(tls.echConfigList || '').trim(),
      echQuery: !!echQueryOf(tls.echConfigList),
      masque: (server.outbound && server.outbound.protocol) === 'masque',
      warp: !!(ms && ms.warp),
      preset: T.suggestPreset(server),
      unsupported: applies
    };
  }

  /** The cores a run can use: a core too old for this config is left out, with the reason. */
  async function gateEngines(server, engines) {
    let cfg;
    try { cfg = buildMultiTestConfig([applyTarget(server, {})], [1]); } catch { return { engines, skipped: [] }; }
    const need = usesMasqueWarp(cfg) ? MASQUE_WARP_SINCE : (usesMasque(cfg) ? MASQUE_SINCE : (usesEch(cfg) ? ECH_SINCE : ''));
    if (!need) return { engines, skipped: [] };
    const ok = [], skipped = [];
    for (const id of engines) {
      let v = '';
      try { v = String(await ctx.xray.version(id) || ''); } catch { /* unreadable: give it the run */ }
      if (/\d+\.\d+\.\d+/.test(v) && versionBelow(v, need)) {
        const what = need === MASQUE_WARP_SINCE ? 'MASQUE with a WARP account' : (need === MASQUE_SINCE ? 'MASQUE' : 'ECH');
        skipped.push({ engine: id, version: v, need, reason: `${engineLabel(id)} ${v} does not know ${what} (${need} and newer do)` });
      } else ok.push(id);
    }
    return { engines: ok, skipped };
  }

  /**
   * An ECH config given as a DNS query, fetched once: the config with the
   * list itself in it, and what the page says about it. Any failure keeps the
   * query form — each core then asks on its own, as a connect does.
   */
  async function withEch(server) {
    const tls = tlsOf(server);
    if (!tls || !echQueryOf(tls.echConfigList)) return { server, ech: null };
    let r;
    try { r = await fetchEch(tls.echConfigList, { serverName: tls.serverName || dialOf(server).sni || '', timeout: ECH_TIMEOUT_MS }); }
    catch (e) { r = { ok: false, error: (e && e.message) || String(e) }; }
    if (!r || !r.ok) {
      const msg = (r && r.error) || 'no answer';
      ctx.log(`Scan: the ECH config could not be fetched here (${msg}) — each core asks itself`, 'warn');
      return { server, ech: { ok: false, error: msg, via: (r && r.via) || '' } };
    }
    const copy = JSON.parse(JSON.stringify(server));
    tlsOf(copy).echConfigList = r.list;
    ctx.log(`Scan: ECH config fetched once over ${r.via}${r.publicName ? ' — public name ' + r.publicName : ''}`, 'info');
    return { server: copy, ech: { ok: true, publicName: r.publicName || '', via: r.via || '' } };
  }

  /* ----------------------------- the tested history ----------------------------- */

  let tested = null;        // Set<string>, read from the store on first use
  let testedDirty = false;
  const testedSet = () => {
    if (!tested) {
      const raw = ctx.store.get(TESTED_KEY, null);
      tested = new Set();
      for (const v of Array.isArray(raw) ? raw : []) {
        // v2.2 kept IPv4 integers; v3 keeps normalised strings of any kind
        const s = Number.isInteger(v) && v >= 0 && v <= 0xffffffff ? T.intToIp4(v) : (typeof v === 'string' ? T.normalizeAddr(v) : null);
        if (s) tested.add(s);
      }
    }
    return tested;
  };
  /** A Set keeps insertion order, so the cap drops the oldest. */
  function rememberTested(addr) {
    const n = T.normalizeAddr(addr);
    if (!n) return;
    const set = testedSet();
    if (set.has(n)) return;
    set.add(n);
    testedDirty = true;
    if (set.size > TESTED_CAP) for (const old of set) { set.delete(old); if (set.size <= TESTED_CAP) break; }
  }
  function persistTested() {
    if (!testedDirty) return;
    testedDirty = false;
    try { ctx.store.setLazy(TESTED_KEY, Array.from(testedSet())); } catch { /* the history is a convenience */ }
  }
  function forget() {
    tested = new Set();
    testedDirty = false;
    try { ctx.store.set(TESTED_KEY, []); } catch { /* same */ }
    return { ok: true, tested: 0 };
  }

  /* ----------------------------- runs ----------------------------- */

  /**
   * Put a run in flight: its events go out as scan-progress with the newest
   * progress merged in — one per result, one on a stage change, one at the end.
   */
  function launch({ server, total, stage, token, start }) {
    const runId = 'scan-' + Date.now().toString(36) + '-' + crypto.randomBytes(3).toString('hex');
    let progress = { stage, done: 0, total, alive: 0, speedDone: 0, speedTotal: 0, etaMs: null };
    let done = 0;
    const send = (payload) => {
      try { ctx.send('scan-progress', Object.assign({ runId }, progress, payload)); } catch { /* window gone */ }
    };
    const hooks = {
      onProgress: (p) => {
        const moved = p.stage !== progress.stage;
        progress = Object.assign({}, p);
        if (moved && p.stage !== 'done') send({});
      },
      onResult: (result) => {
        done++;
        if (result && result.phase === 1 && result.addr) rememberTested(result.addr);   // whatever the pick: it was tested
        send({ result });
      }
    };
    const promise = start(hooks).then(
      ({ cancelled }) => {
        ctx.log(`Scan ${runId}: ${cancelled ? 'stopped' : 'finished'} — ${done} row(s)`, 'info');
        send({ finished: true, cancelled: !!cancelled });
      },
      (err) => {
        const msg = (err && err.message) || String(err);
        ctx.log(`Scan ${runId} failed: ${msg}`, 'error');
        send({ finished: true, cancelled: token.cancelled, error: msg });
      }
    ).finally(() => { run = null; persistTested(); });
    run = { runId, token, promise };
    return { runId, label: server.name || server.address };
  }

  /** What every run needs first: the config, its cores, its ECH. A refusal is `{ error }`. */
  async function prepare(req) {
    let server;
    try { server = resolveServer(req); } catch (e) { return { error: e.message }; }
    try { applyTarget(server, {}); } catch (e) { return { error: refusalOf(e) }; }
    const engines = chooseEngines(req.engines);
    if (!engines.length) return { error: 'no engine' };
    const gate = await gateEngines(server, engines);
    if (!gate.engines.length) return { error: 'core too old', skipped: gate.skipped };
    const e = await withEch(server);
    return { server: e.server, original: server, engines: gate.engines, skipped: gate.skipped, ech: e.ech };
  }

  async function start(raw) {
    const req = raw && typeof raw === 'object' ? raw : {};
    if (run) return { error: 'busy' };

    // the targets first: a typo is answered without waiting on a core or DNS
    let server;
    try { server = resolveServer(req); } catch (e) { return { error: e.message }; }
    try { applyTarget(server, {}); } catch (e) { return { error: refusalOf(e) }; }
    const pick = sanitizePick(req.pick);
    const dial = dialOf(server);
    const addrText = String(req.ipsText || '');
    let drawn = { addrs: [], errors: [], ranges: 0, exhausted: 0, truncated: false };
    if (hasTokens(addrText)) {
      drawn = pick.mode === 'random'
        ? T.drawTargets(addrText, { perRange: pick.perRange, max: MAX_TARGETS, exclude: pick.fresh ? testedSet() : undefined })
        : Object.assign({ ranges: 0, exhausted: 0 }, T.expandTargets(addrText, { max: MAX_TARGETS }));
      if (!drawn.addrs.length) return { error: 'no targets', errors: drawn.errors };
    }
    const ports = T.parsePorts(String(req.portsText || ''));
    const snis = T.parseSnis(String(req.snisText || ''));
    if (snis.snis.length) {
      const s = sniSupport(server);
      if (!s.ok) return { error: 'sni', code: s.code, reason: s.reason };
    }
    const built = T.buildTargets({ addrs: drawn.addrs, ports: ports.ports, snis: snis.snis, defaultAddr: dial.addr, defaultPort: dial.port, max: MAX_TARGETS });
    if (!built.targets.length) return { error: 'no targets', errors: drawn.errors };

    const tests = sanitizeTests(req.tests);
    const transport = transportOf(server);
    const measures = tests.delay || tests.down || tests.up || (tests.tcp && transport === 'tcp');
    if (!measures) return { error: 'no tests' };
    const opts = sanitizeOpts(req.opts);

    const prep = await prepare(req);
    if (prep.error) return prep;
    if (run) return { error: 'busy' };   // another start won while this one asked DNS

    const remembered = {
      serverId: req.serverId || null, link: req.serverId ? null : (req.link || null),
      ipsText: addrText, portsText: String(req.portsText || ''), snisText: String(req.snisText || ''),
      pick, engines: prep.engines, tests, opts
    };
    try { ctx.store.setLazy(STORE_KEY, remembered); } catch { /* the run matters more than the memory of it */ }

    const targets = built.targets;
    const total = targets.length * prep.engines.length;
    const token = { cancelled: false };
    const { runId, label } = launch({
      server: prep.server, total, stage: 'filter', token,
      start: (hooks) => runScan(Object.assign({
        server: prep.server, targets, engines: prep.engines, tests, transport,
        opts: Object.assign({}, opts, { probes: deps.probes, getFreePorts: deps.getFreePorts, waitReady: deps.waitReady }),
        xray: ctx.xray, token
      }, hooks))
    });
    const how = pick.mode !== 'random' ? '' :
      ` — a fresh draw of ${pick.perRange} per range from ${drawn.ranges} range(s)` +
      (pick.fresh ? `, ${testedSet().size} tested before skipped` : '') +
      (drawn.exhausted ? `, ${drawn.exhausted} range(s) had to repeat` : '');
    ctx.log(`Scan ${runId}: ${targets.length} target(s) × ${prep.engines.join(', ')} through "${label}"${how}`, 'info');
    for (const s of prep.skipped) ctx.log('Scan: ' + s.reason, 'warn');
    return {
      runId, total, targets: targets.length, truncated: !!(drawn.truncated || built.truncated),
      errors: drawn.errors, portErrors: ports.errors, sniErrors: snis.errors,
      pick, ranges: drawn.ranges || 0, exhausted: drawn.exhausted || 0,
      transport, ech: prep.ech, skipped: prep.skipped, engines: prep.engines
    };
  }

  /** Phase 2 alone on rows the table chose; every row names its engine. */
  async function retest(raw) {
    const req = raw && typeof raw === 'object' ? raw : {};
    if (run) return { error: 'busy' };
    const prep = await prepare(Object.assign({}, req, { engines: null }));
    if (prep.error) return prep;
    if (run) return { error: 'busy' };
    const seen = new Set();
    const rows = [];
    for (const r of Array.isArray(req.rows) ? req.rows : []) {
      if (!r || typeof r !== 'object' || !prep.engines.includes(r.engine)) continue;
      const addr = T.normalizeAddr(r.addr || r.ip);
      if (!addr) continue;
      const port = Number.isInteger(Number(r.port)) && r.port >= 1 && r.port <= 65535 ? Number(r.port) : null;
      const sni = r.sni ? (T.parseSnis(String(r.sni)).snis[0] || null) : null;
      if (r.sni && !sni) continue;
      const key = T.addrPort(addr, port) + '|' + (sni || '');
      if (seen.has(`${key}|${r.engine}`)) continue;
      seen.add(`${key}|${r.engine}`);
      rows.push({ key, addr, port, sni, engine: r.engine, tcp: r.tcp, delay: r.delay });
    }
    if (!rows.length) return { error: 'no rows' };

    const t = req.tests && typeof req.tests === 'object' ? req.tests : { down: true, up: false };
    const tests = { tcp: false, delay: false, down: !!t.down, up: !!t.up };
    if (!tests.down && !tests.up) return { error: 'no tests' };
    const opts = sanitizeOpts(req.opts);

    const token = { cancelled: false };
    const { runId, label } = launch({
      server: prep.server, total: rows.length, stage: 'speed', token,
      start: (hooks) => runSpeed(Object.assign({
        server: prep.server, rows, tests,
        opts: Object.assign({}, opts, { probes: deps.probes, getFreePorts: deps.getFreePorts, waitReady: deps.waitReady }),
        xray: ctx.xray, token
      }, hooks))
    });
    ctx.log(`Scan ${runId}: speed test of ${rows.length} row(s) through "${label}"`, 'info');
    return { runId, total: rows.length };
  }

  function stop() {
    if (!run) return { ok: true, running: false };
    run.token.cancelled = true;
    return { ok: true, running: true, runId: run.runId };
  }

  function presets() {
    return {
      cfRanges: T.CF_IPV4_RANGES.slice(),
      ranges: JSON.parse(JSON.stringify(T.PRESETS)),
      defaults: Object.assign({}, PRESET_DEFAULTS),
      presets: { fast: Object.assign({}, PRESETS.fast), balanced: Object.assign({}, PRESETS.balanced), accurate: Object.assign({}, PRESETS.accurate) },
      last: ctx.store.get(STORE_KEY, null) || null,
      engines: engineOffer(),
      tested: testedSet().size
    };
  }

  /** What the chosen config allows (page hints and the suggested addresses). */
  function suggest(raw) {
    const req = raw && typeof raw === 'object' ? raw : {};
    let server;
    try { server = resolveServer(req); } catch (e) { return { error: e.message }; }
    return factsOf(server);
  }

  /** The config with one target in it: a new record named after the target, its share link rebuilt. */
  function recordFor(req) {
    const server = resolveServer(req);
    const addr = T.normalizeAddr(req.addr || req.ip);
    if (!addr) throw new Error('invalid ip');
    const port = req.port != null && req.port !== '' ? Number(req.port) : null;
    const sni = req.sni ? String(req.sni) : null;
    const record = applyTarget(server, { addr, port, sni });
    record.id = 'sv-' + crypto.randomBytes(6).toString('hex');
    const label = T.addrPort(addr, port) + (sni ? ' ' + sni : '');
    record.name = `${str(req.name, '') || server.name || server.address} [${label}]`;
    delete record.importedFrom; delete record.importedId; delete record.importedSub;
    if (req.engine && xrayEngines().includes(req.engine)) {
      // the engine the winning row ran on; the official core is the unmarked default
      if (req.engine === 'xray') delete record.engine; else record.engine = req.engine;
    }
    let link = '';
    try { link = buildShareLink(record); } catch { link = ''; }
    if (!link && record.source === 'json' && record.json) link = JSON.stringify(record.json);
    record.raw = link || record.raw || '';
    return { record, link };
  }

  function apply(raw) {
    const req = raw && typeof raw === 'object' ? raw : {};
    let made;
    try { made = recordFor(req); } catch (e) { return { error: e.code ? refusalOf(e) : e.message }; }
    const saved = ctx.addServer(made.record);
    return Object.assign({}, saved, { link: made.link, servers: ctx.getServers() });
  }

  /** Share links for rows — "copy the best N", ready to paste into IRNetFree. */
  function links(raw) {
    const req = raw && typeof raw === 'object' ? raw : {};
    const out = [];
    for (const r of Array.isArray(req.rows) ? req.rows.slice(0, 500) : []) {
      try { const { link } = recordFor(Object.assign({}, req, r, { rows: undefined })); if (link) out.push(link); } catch { /* a row that no longer fits is left out */ }
    }
    return { links: out };
  }

  function exportText(raw) {
    const req = raw && typeof raw === 'object' ? raw : {};
    const results = (Array.isArray(req.results) ? req.results : []).filter(Boolean);
    const format = req.format || 'csv';
    if (format === 'json') return JSON.stringify(results, null, 2);
    if (format === 'csv') return [CSV_HEADER, ...results.map(csvRow)].join('\r\n') + '\r\n';
    return { error: 'unknown format' };
  }

  const handlers = {
    'scan:start': start,
    'scan:retest': retest,
    'scan:stop': stop,
    'scan:presets': presets,
    'scan:suggest': suggest,
    'scan:apply': apply,
    'scan:links': links,
    'scan:export': exportText,
    'scan:forget': forget
  };

  return {
    register() { for (const [channel, fn] of Object.entries(handlers)) ctx.handle(channel, fn); },
    async stop() {
      if (!run) return;
      run.token.cancelled = true;
      try { await run.promise; } catch { /* reported through scan-progress */ }
    },
    busy: () => !!run
  };
}

module.exports = { createScan, PRESET_DEFAULTS, PRESETS, PICK_DEFAULTS, CSV_HEADER, sanitizeOpts, sanitizeTests, sanitizePick };
