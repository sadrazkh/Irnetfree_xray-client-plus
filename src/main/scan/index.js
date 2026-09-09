'use strict';
/**
 * plus: the IP-scan tab — a config tested through many addresses on every
 * installed xray-format core (spec section 3). One module for both mirrors:
 * `ctx` is the normalised context main.js and service.js build the same way
 * (spec section 4), and a handler gets its one argument already unwrapped.
 *
 * Channels: scan:start, scan:stop, scan:presets, scan:apply, scan:export.
 * Event: scan-progress { runId, done, total, result } per result, then
 * { runId, done, total, finished: true, cancelled } (plus `error` when the
 * run itself failed). One run at a time; the last request is remembered in
 * the store under `scan`, never the results.
 */
const crypto = require('crypto');
const { isIPv4 } = require('net');
const { parseLink, buildShareLink } = require('../parser');
const { xrayEngines, engineLabel } = require('../engines');
const { expandTargets, CF_IPV4_RANGES } = require('./targets');
const { withAddress } = require('./substitute');
const { runScan: defaultRunScan } = require('./scanner');

const STORE_KEY = 'scan';
const MAX_TARGETS = 5000;
/** What the tab shows before the user changes anything. */
const PRESET_DEFAULTS = {
  concurrency: 8, batch: 20, delaySamples: 3,
  downBytes: 10e6, downMaxMs: 8000, downHost: 'speed.cloudflare.com', downPath: '/__down?bytes=10000000',
  upHost: 'speed.cloudflare.com', upPath: '/__up', upBytes: 2e6
};
const DEFAULT_TESTS = { tcp: true, delay: true, down: true, up: false };
const CSV_HEADER = 'ip,engine,tcp_ms,delay_min,delay_avg,jitter,loss,down_mbps,up_mbps,score,error';

const num = (v, def, lo, hi) => {
  const n = Math.floor(Number(v));
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : def;
};
const str = (v, def) => (typeof v === 'string' && v.trim() ? v.trim() : def);

/** Clamp what the renderer sent; anything missing takes the default. */
function sanitizeOpts(raw) {
  const o = raw && typeof raw === 'object' ? raw : {};
  return {
    concurrency: num(o.concurrency, 8, 1, 64),
    batch: num(o.batch, 20, 1, 50),
    delaySamples: num(o.delaySamples, 3, 1, 10),
    tcpTimeout: num(o.tcpTimeout, 3000, 500, 30000),
    delayTimeout: num(o.delayTimeout, 8000, 500, 60000),
    downBytes: num(o.downBytes, 10e6, 1e5, 1e9),
    downMaxMs: num(o.downMaxMs, 8000, 1000, 60000),
    downTimeout: num(o.downTimeout, 8000, 500, 60000),
    downHost: str(o.downHost, PRESET_DEFAULTS.downHost),
    downPath: str(o.downPath, ''),
    downPort: num(o.downPort, 443, 1, 65535),
    downTls: o.downTls !== false,
    upBytes: num(o.upBytes, 2e6, 1e4, 1e8),
    upTimeout: num(o.upTimeout, 20000, 500, 120000),
    upHost: str(o.upHost, PRESET_DEFAULTS.upHost),
    upPath: str(o.upPath, PRESET_DEFAULTS.upPath),
    upPort: num(o.upPort, 443, 1, 65535),
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
    r.ip, r.engine,
    r.tcp && r.tcp.ok ? r.tcp.ms : null,
    d ? d.min : null, d ? d.avg : null, d ? d.jitter : null,
    r.delay ? r.delay.loss : null,
    r.down && r.down.ok ? r.down.mbps : null,
    r.up && r.up.ok ? r.up.mbps : null,
    r.score, r.error
  ].map(csvCell).join(',');
}

/**
 * createScan(ctx, deps?) → { register(), stop(), busy() }
 * `deps` = { probes, getFreePorts, runScan } are injection points for tests.
 */
function createScan(ctx, deps = {}) {
  const runScan = deps.runScan || defaultRunScan;
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

  async function start(raw) {
    const req = raw && typeof raw === 'object' ? raw : {};
    if (run) return { error: 'busy' };
    let server;
    try { server = resolveServer(req); } catch (e) { return { error: e.message }; }
    try { withAddress(server, '127.0.0.1'); } catch { return { error: 'unsupported protocol' }; }

    const { ips, errors, truncated } = expandTargets(req.ipsText, { max: MAX_TARGETS });
    if (!ips.length) return { error: 'no targets', errors };

    const offered = engineOffer();
    const wanted = Array.isArray(req.engines) && req.engines.length ? req.engines : offered.map((e) => e.id);
    const engines = offered.filter((e) => e.installed && wanted.includes(e.id)).map((e) => e.id);
    if (!engines.length) return { error: 'no engine' };

    const tests = sanitizeTests(req.tests);
    if (!tests.tcp && !tests.delay && !tests.down && !tests.up) return { error: 'no tests' };
    const opts = sanitizeOpts(req.opts);

    const remembered = {
      serverId: req.serverId || null, link: req.serverId ? null : (req.link || null),
      ipsText: String(req.ipsText || ''), engines, tests, opts
    };
    try { ctx.store.setLazy(STORE_KEY, remembered); } catch { /* the run matters more than the memory of it */ }

    const runId = 'scan-' + Date.now().toString(36) + '-' + crypto.randomBytes(3).toString('hex');
    const total = ips.length * engines.length;
    const token = { cancelled: false };
    let done = 0;
    const send = (payload) => {
      try { ctx.send('scan-progress', Object.assign({ runId, done, total }, payload)); } catch { /* window gone */ }
    };
    const label = server.name || server.address;
    ctx.log(`Scan ${runId}: ${ips.length} target(s) × ${engines.join(', ')} through "${label}"`, 'info');

    const promise = runScan({
      server, ips, engines, tests,
      opts: Object.assign({}, opts, { probes: deps.probes, getFreePorts: deps.getFreePorts }),
      xray: ctx.xray, token,
      onResult: (result) => { done++; send({ result }); }
    }).then(
      ({ cancelled }) => {
        ctx.log(`Scan ${runId}: ${cancelled ? 'stopped' : 'finished'} — ${done}/${total}`, 'info');
        send({ finished: true, cancelled: !!cancelled });
      },
      (err) => {
        const msg = (err && err.message) || String(err);
        ctx.log(`Scan ${runId} failed: ${msg}`, 'error');
        send({ finished: true, cancelled: token.cancelled, error: msg });
      }
    ).finally(() => { run = null; });
    run = { runId, token, promise };
    return { runId, total, truncated, errors };
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
      last: ctx.store.get(STORE_KEY, null) || null,
      engines: engineOffer()
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
    'scan:stop': stop,
    'scan:presets': presets,
    'scan:apply': apply,
    'scan:export': exportText
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

module.exports = { createScan, PRESET_DEFAULTS, CSV_HEADER, sanitizeOpts, sanitizeTests };
