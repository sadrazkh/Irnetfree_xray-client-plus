'use strict';
/**
 * plus: the IP-scan tab — a config tested through many addresses on every
 * installed xray-format core (spec section 3 of v2.0, section 1 of v2.1).
 * One module for both mirrors: `ctx` is the normalised context main.js and
 * service.js build the same way, and a handler gets its one argument already
 * unwrapped.
 *
 * Channels: scan:start, scan:retest, scan:stop, scan:presets, scan:apply,
 * scan:export, scan:forget. Event: scan-progress { runId, stage, done, total, alive,
 * speedDone, speedTotal, etaMs, result } per result, the same without a
 * result when the stage changes, then { ..., finished: true, cancelled } (plus
 * `error` when the run itself failed). One run at a time; the last request is
 * remembered in the store under `scan`, never the results — only the addresses
 * that were tested, under `scanTested`, so a random draw can skip them (v2.2).
 */
const crypto = require('crypto');
const { isIPv4 } = require('net');
const { parseLink, buildShareLink } = require('../parser');
const { xrayEngines, engineLabel } = require('../engines');
const { expandTargets, drawTargets, CF_IPV4_RANGES, ip4ToInt } = require('./targets');
const { withAddress } = require('./substitute');
const { runScan: defaultRunScan, runSpeed: defaultRunSpeed } = require('./scanner');

const STORE_KEY = 'scan';
const MAX_TARGETS = 5000;
/** Every address a run has tested (phase 1), as integers, newest last — spec v2.2 §2.2. */
const TESTED_KEY = 'scanTested';
const TESTED_CAP = 50000;
/** How the box is read: every address, or a fresh draw of `perRange` per range that skips the tested. */
const PICK_DEFAULTS = { mode: 'all', perRange: 20, fresh: true };
/** What the tab shows before the user changes anything: the balanced preset. */
const PRESET_DEFAULTS = {
  batch: 20, filterConcurrency: 16, coresInParallel: 2, delaySamples: 2,
  tcpTimeout: 2000, delayTimeout: 4000,
  speedTop: 10, speedConcurrency: 1, speedRounds: 1, warmupMs: 300,
  downBytes: 10e6, downMaxMs: 6000, downTimeout: 8000,
  downHost: 'speed.cloudflare.com', downPath: '/__down?bytes=10000000', downPort: 443, downTls: true,
  upBytes: 2e6, upTimeout: 20000,
  upHost: 'speed.cloudflare.com', upPath: '/__up', upPort: 443, upTls: true
};
/** The three presets of spec section 1.2; every one a full opts object. */
const PRESETS = {
  fast: Object.assign({}, PRESET_DEFAULTS, { delaySamples: 1, tcpTimeout: 1500, delayTimeout: 3000, filterConcurrency: 32, coresInParallel: 3, speedTop: 5 }),
  balanced: Object.assign({}, PRESET_DEFAULTS),
  accurate: Object.assign({}, PRESET_DEFAULTS, { delaySamples: 4, filterConcurrency: 8, speedTop: 20, speedRounds: 2, speedConcurrency: 1 })
};
const DEFAULT_TESTS = { tcp: true, delay: true, down: true, up: false };
const CSV_HEADER = 'ip,engine,phase,tcp_ms,delay_min,delay_median,delay_avg,jitter,loss,down_mbps,up_mbps,score,error';

const num = (v, def, lo, hi) => {
  const n = Math.floor(Number(v));
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : def;
};
const str = (v, def) => (typeof v === 'string' && v.trim() ? v.trim() : def);

/** The pick as sent, clamped; a v2.1 request without one reads as `all`. */
function sanitizePick(raw) {
  const p = raw && typeof raw === 'object' ? raw : {};
  return {
    mode: p.mode === 'random' ? 'random' : 'all',
    perRange: num(p.perRange, PICK_DEFAULTS.perRange, 1, MAX_TARGETS),
    fresh: p.fresh === undefined ? PICK_DEFAULTS.fresh : !!p.fresh
  };
}

/** Clamp what the renderer sent; anything missing takes the default. */
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
    r.ip, r.engine, r.phase || 1,
    r.tcp && r.tcp.ok ? r.tcp.ms : null,
    d ? d.min : null, d ? d.median : null, d ? d.avg : null, d ? d.jitter : null,
    r.delay ? r.delay.loss : null,
    r.down && r.down.ok ? r.down.mbps : null,
    r.up && r.up.ok ? r.up.mbps : null,
    r.score, r.error
  ].map(csvCell).join(',');
}

/**
 * createScan(ctx, deps?) → { register(), stop(), busy() }
 * `deps` = { probes, getFreePorts, runScan, runSpeed } are injection points for tests.
 */
function createScan(ctx, deps = {}) {
  const runScan = deps.runScan || defaultRunScan;
  const runSpeed = deps.runSpeed || defaultRunSpeed;
  let run = null;                    // { runId, token, promise } while a scan is in flight

  function engineOffer() {
    return xrayEngines().map((id) => ({ id, label: engineLabel(id), installed: !!ctx.xray.binExists(id) }));
  }

  /** The stored server or the pasted link. Throws with a reason the reply carries. */
  function resolveServer(req) {
    if (req.serverId) {
      const t = ctx.resolveTarget(req.serverId) || {};
      if (!t.server) throw new Error('server not found');
      return t.server;
    }
    if (req.link) return parseLink(req.link);
    throw new Error('no server');
  }

  /** The engines a request may run on: installed, and wanted when it named any. */
  function chooseEngines(wanted) {
    const offered = engineOffer();
    const want = Array.isArray(wanted) && wanted.length ? wanted : offered.map((e) => e.id);
    return offered.filter((e) => e.installed && want.includes(e.id)).map((e) => e.id);
  }

  /* ----------------------------- the tested history ----------------------------- */

  let tested = null;        // Set<int>, read from the store on first use
  let testedDirty = false;  // something was added since the last write
  const testedSet = () => {
    if (!tested) {
      const raw = ctx.store.get(TESTED_KEY, null);
      tested = new Set(Array.isArray(raw) ? raw.filter(n => Number.isInteger(n) && n >= 0 && n <= 0xffffffff) : []);
    }
    return tested;
  };
  /** A Set keeps insertion order, so the cap drops the oldest; an address seen again keeps its old place. */
  function rememberTested(ip) {
    const n = ip4ToInt(ip);
    if (n === null) return;
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
        if (result && result.phase === 1 && result.ip) rememberTested(result.ip);   // whatever mode: it was tested
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
    const label = server.name || server.address;
    return { runId, label };
  }

  async function start(raw) {
    const req = raw && typeof raw === 'object' ? raw : {};
    if (run) return { error: 'busy' };
    let server;
    try { server = resolveServer(req); } catch (e) { return { error: e.message }; }
    try { withAddress(server, '127.0.0.1'); } catch { return { error: 'unsupported protocol' }; }

    // the box, read the way the pick says: every address, or a fresh draw per range
    const pick = sanitizePick(req.pick);
    const drawn = pick.mode === 'random'
      ? drawTargets(req.ipsText, { perRange: pick.perRange, max: MAX_TARGETS, exclude: pick.fresh ? testedSet() : undefined })
      : expandTargets(req.ipsText, { max: MAX_TARGETS });
    const { ips, errors, truncated } = drawn;
    if (!ips.length) return { error: 'no targets', errors };

    const engines = chooseEngines(req.engines);
    if (!engines.length) return { error: 'no engine' };

    const tests = sanitizeTests(req.tests);
    if (!tests.tcp && !tests.delay && !tests.down && !tests.up) return { error: 'no tests' };
    const opts = sanitizeOpts(req.opts);

    const remembered = {
      serverId: req.serverId || null, link: req.serverId ? null : (req.link || null),
      ipsText: String(req.ipsText || ''), pick, engines, tests, opts
    };
    try { ctx.store.setLazy(STORE_KEY, remembered); } catch { /* the run matters more than the memory of it */ }

    const total = ips.length * engines.length;
    const token = { cancelled: false };
    const { runId, label } = launch({
      server, total, stage: 'filter', token,
      start: (hooks) => runScan(Object.assign({
        server, ips, engines, tests,
        opts: Object.assign({}, opts, { probes: deps.probes, getFreePorts: deps.getFreePorts }),
        xray: ctx.xray, token
      }, hooks))
    });
    const how = pick.mode !== 'random' ? '' :
      ` — a fresh draw of ${pick.perRange} per range from ${drawn.ranges} range(s)` +
      (pick.fresh ? `, ${testedSet().size} tested before skipped` : '') +
      (drawn.exhausted ? `, ${drawn.exhausted} range(s) had to repeat` : '');
    ctx.log(`Scan ${runId}: ${ips.length} target(s) × ${engines.join(', ')} through "${label}"${how}`, 'info');
    return { runId, total, truncated, errors, pick, ranges: drawn.ranges || 0, exhausted: drawn.exhausted || 0 };
  }

  /** Phase 2 alone on rows the table chose; every row names its engine. */
  async function retest(raw) {
    const req = raw && typeof raw === 'object' ? raw : {};
    if (run) return { error: 'busy' };
    let server;
    try { server = resolveServer(req); } catch (e) { return { error: e.message }; }
    try { withAddress(server, '127.0.0.1'); } catch { return { error: 'unsupported protocol' }; }

    const installed = chooseEngines(null);
    const seen = new Set();
    const rows = [];
    for (const r of Array.isArray(req.rows) ? req.rows : []) {
      if (!r || typeof r !== 'object') continue;
      const ip = String(r.ip || '').trim();
      if (!isIPv4(ip) || !installed.includes(r.engine) || seen.has(`${ip}|${r.engine}`)) continue;
      seen.add(`${ip}|${r.engine}`);
      rows.push({ ip, engine: r.engine, tcp: r.tcp, delay: r.delay });
    }
    if (!rows.length) return { error: 'no rows' };

    const t = req.tests && typeof req.tests === 'object' ? req.tests : { down: true, up: false };
    const tests = { tcp: false, delay: false, down: !!t.down, up: !!t.up };
    if (!tests.down && !tests.up) return { error: 'no tests' };
    const opts = sanitizeOpts(req.opts);

    const token = { cancelled: false };
    const { runId, label } = launch({
      server, total: rows.length, stage: 'speed', token,
      start: (hooks) => runSpeed(Object.assign({
        server, rows, tests,
        opts: Object.assign({}, opts, { probes: deps.probes, getFreePorts: deps.getFreePorts }),
        xray: ctx.xray, token
      }, hooks))
    });
    ctx.log(`Scan ${runId}: re-test of ${rows.length} row(s) through "${label}"`, 'info');
    return { runId, total: rows.length };
  }

  function stop() {
    if (!run) return { ok: true, running: false };
    run.token.cancelled = true;
    return { ok: true, running: true, runId: run.runId };
  }

  function presets() {
    return {
      cfRanges: CF_IPV4_RANGES.slice(),
      defaults: Object.assign({}, PRESET_DEFAULTS),
      presets: { fast: Object.assign({}, PRESETS.fast), balanced: Object.assign({}, PRESETS.balanced), accurate: Object.assign({}, PRESETS.accurate) },
      last: ctx.store.get(STORE_KEY, null) || null,
      engines: engineOffer(),
      tested: testedSet().size
    };
  }

  function apply(raw) {
    const req = raw && typeof raw === 'object' ? raw : {};
    const ip = String(req.ip || '').trim();
    if (!isIPv4(ip)) return { error: 'invalid ip' };
    let server, record;
    try { server = resolveServer(req); } catch (e) { return { error: e.message }; }
    try { record = withAddress(server, ip); } catch (e) { return { error: e.message }; }
    record.id = 'sv-' + crypto.randomBytes(6).toString('hex');
    record.name = `${str(req.name, '') || server.name || server.address} [${ip}]`;
    if (req.engine && xrayEngines().includes(req.engine)) {
      // the engine the winning row ran on; the official core is the unmarked default
      if (req.engine === 'xray') delete record.engine; else record.engine = req.engine;
    }
    record.raw = buildShareLink(record);
    ctx.addServer(record);
    return record;
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
    'scan:apply': apply,
    'scan:export': exportText,
    'scan:forget': forget
  };

  return {
    register() { for (const [channel, fn] of Object.entries(handlers)) ctx.handle(channel, fn); },
    /** Quit path: cancel a run in flight and wait for its core to be cleaned up. */
    stop: async () => {
      if (!run) return;
      run.token.cancelled = true;
      try { await run.promise; } catch { /* reported through the event */ }
    },
    busy: () => !!run
  };
}

module.exports = { createScan, PRESET_DEFAULTS, PRESETS, PICK_DEFAULTS, CSV_HEADER, sanitizeOpts, sanitizeTests, sanitizePick };
