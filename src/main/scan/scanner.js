'use strict';
/**
 * plus: the scan runner — two phases, each with its own concurrency
 * (spec v2.1 §1, v3 §4).
 *
 * A run tests TARGETS — `{ addr, port, sni, key }`, an address × port × SNI
 * (targets.js buildTargets) — each through a copy of the config that dials it
 * (substitute.js applyTarget).
 *
 * Phase 1 (filter): every target on every engine gets a direct TCP connect to
 * addr:port — only when the config runs over TCP (`transport`: a Hysteria2, a
 * WireGuard, an mKCP or a MASQUE-over-HTTP/3 config has nothing a TCP connect
 * could tell) — and a short delay series through a throw-away core. Cheap, so
 * it runs wide: one core per (engine × batch), scheduled through one
 * pLimit(coresInParallel) shared by every engine so the engines run side by
 * side, and pLimit(filterConcurrency) probes in flight inside a batch. A dead
 * TCP ends the row. Each row leaves through onResult with phase: 1 at once.
 *
 * A core is probed only once it listens: its first inbound is polled (100 ms
 * steps, up to 4 s) — a busy machine starting several cores took longer than
 * the fixed half second startTest waits, and their first rows died for it.
 *
 * Phase 2 (speed): only the best `speedTop` rows of each engine get the
 * download (and the upload when ticked), at most `speedConcurrency` transfers
 * in flight across all engines together — a download sharing the link with
 * another measures the share, not the target. `speedRounds` repeats it; the
 * best round is kept. The row comes again with phase: 2 and a new score.
 *
 * Stop is a flag on the token, read before every batch, target and round;
 * while a core is alive a short poll kills it as soon as the flag is set.
 */
const net = require('net');
const { buildMultiTestConfig } = require('../configBuilder');
const { getFreePorts: realGetFreePorts } = require('../xrayManager');
const { tcpPing, pLimit } = require('../netutils');
const { applyTarget } = require('./substitute');
const { scoreResult, delayStats } = require('./score');
const probesMod = require('./probes');

const SCAN_DEFAULTS = {
  batch: 20, filterConcurrency: 16, coresInParallel: 2, delaySamples: 2,
  tcpTimeout: 2000,
  delayHost: 'cp.cloudflare.com', delayPort: 80, delayPath: '/', delayTimeout: 4000,
  speedTop: 10, speedConcurrency: 1, speedRounds: 1, warmupMs: 300,
  downHost: 'speed.cloudflare.com', downPort: 443, downPath: '', downTls: true, downBytes: 10e6, downMaxMs: 6000, downTimeout: 8000,
  upHost: 'speed.cloudflare.com', upPort: 443, upPath: '/__up', upTls: true, upBytes: 2e6, upTimeout: 20000,
  readyTimeout: 4000
};
const DEFAULT_TESTS = { tcp: true, delay: true, down: false, up: false };
const DEFAULT_PROBES = {
  tcpPing,
  delaySeries: probesMod.delaySeries,
  downloadThroughProxy: probesMod.downloadThroughProxy,
  uploadThroughProxy: probesMod.uploadThroughProxy
};
const CANCEL_POLL_MS = 250;
const READY_STEP_MS = 100;

const posInt = (v, def, lo = 1) => {
  const n = Math.floor(Number(v));
  return Math.max(lo, Number.isFinite(n) ? n : def);
};

/** A target as rows carry it; `ip` stays as an alias of addr for older readers. */
function emptyResult(target, engine, phase = 1) {
  const tg = target || {};
  return {
    key: tg.key || String(tg.addr || ''), addr: tg.addr || '', port: tg.port == null ? null : tg.port, sni: tg.sni || null,
    ip: tg.addr || '', engine, phase, tcp: null, delay: null, down: null, up: null, score: 0, error: null
  };
}

const keyOf = (r) => `${r.key}|${r.engine}`;

/** Score desc, then median delay asc; rows with no usable delay sort after those with one. */
const medianOf = (r) => (r.delay && r.delay.loss < 1 ? r.delay.median : Number.MAX_SAFE_INTEGER);
function byRank(a, b) {
  return (b.score - a.score) || (medianOf(a) - medianOf(b)) || 0;
}

/** A row that passed phase 1: it answered whatever phase 1 asked of it. */
function isAlive(r, tests) {
  if (r.error) return false;
  if (tests.delay) return !!(r.delay && r.delay.loss < 1);
  if (tests.tcp && r.tcp && !r.tcp.skipped) return !!r.tcp.ok;
  return true;
}

/**
 * The progress the UI paints: the stage, its counters and an ETA from the
 * measured rate of the stage in flight — null until two rows are in.
 */
function progressTracker(onProgress, init) {
  const p = Object.assign({ stage: 'filter', done: 0, total: 0, alive: 0, speedDone: 0, speedTotal: 0, etaMs: null }, init);
  let t0 = Date.now(), n = 0, size = p.total;
  const eta = () => (n < 2 ? null : Math.max(0, Math.round((size - n) * (Date.now() - t0) / n)));
  const emit = () => { if (onProgress) onProgress(Object.assign({}, p)); };
  return {
    stage(next, stageTotal) {
      p.stage = next;
      t0 = Date.now(); n = 0; size = stageTotal;
      if (next === 'speed') p.speedTotal = stageTotal;
      p.etaMs = next === 'done' ? 0 : null;
      emit();
    },
    row(r, tests) {
      n++;
      if (r.phase === 2) p.speedDone++;
      else { p.done++; if (isAlive(r, tests)) p.alive++; }
      p.etaMs = eta();
      emit();
    },
    snapshot: () => Object.assign({}, p)
  };
}

/** Resolves true once 127.0.0.1:port takes a connection, false at the deadline or when cancelled. */
function waitListening(port, ms, token) {
  const deadline = Date.now() + ms;
  const once = () => new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port });
    const done = (ok) => { s.removeAllListeners(); s.destroy(); resolve(ok); };
    s.once('connect', () => done(true));
    s.once('error', () => done(false));
    s.setTimeout(500, () => done(false));
  });
  return (async () => {
    for (;;) {
      if (token && token.cancelled) return false;
      if (await once()) return true;
      if (Date.now() >= deadline) return false;
      await new Promise((r) => setTimeout(r, READY_STEP_MS));
    }
  })();
}

/** Everything the phases share, built once per run. */
function makeContext(args) {
  const given = args.opts && typeof args.opts === 'object' ? args.opts : {};
  const o = Object.assign({}, SCAN_DEFAULTS, given);
  if (given.filterConcurrency === undefined && given.concurrency !== undefined) o.filterConcurrency = given.concurrency;
  const tests = Object.assign({}, DEFAULT_TESTS, args.tests);
  const batchSize = posInt(o.batch, SCAN_DEFAULTS.batch);
  const ctx = {
    server: args.server, xray: args.xray, tests, o,
    transport: args.transport === 'udp' ? 'udp' : 'tcp',
    token: args.token || { cancelled: false },
    probes: Object.assign({}, DEFAULT_PROBES, o.probes),
    getFreePorts: o.getFreePorts || realGetFreePorts,
    waitReady: o.waitReady || waitListening,
    batchSize,
    filterConcurrency: posInt(o.filterConcurrency, SCAN_DEFAULTS.filterConcurrency),
    coreLimit: pLimit(posInt(o.coresInParallel, SCAN_DEFAULTS.coresInParallel)),
    speedLimit: pLimit(posInt(o.speedConcurrency, SCAN_DEFAULTS.speedConcurrency)),
    speedRounds: posInt(o.speedRounds, SCAN_DEFAULTS.speedRounds),
    speedTop: Math.min(batchSize, posInt(o.speedTop, SCAN_DEFAULTS.speedTop, 0)),
    latest: new Map(),               // key|engine → the newest row, whichever phase
    progress: null,
    onResult: args.onResult
  };
  ctx.emit = (r) => {
    r.score = r.error ? 0 : scoreResult(r);
    ctx.latest.set(keyOf(r), r);
    ctx.progress.row(r, tests);
    if (ctx.onResult) ctx.onResult(r);
  };
  return ctx;
}

/**
 * One throw-away core for `targets` on `engine`; `work(ports)` runs once it
 * listens, and the core dies in `finally`, or earlier when the token is
 * cancelled. Rejects when the config cannot take a target or the core cannot
 * start.
 */
async function withCore(ctx, engine, targets, work) {
  const servers = targets.map((tg) => applyTarget(ctx.server, tg));
  const ports = await ctx.getFreePorts(targets.length);
  const test = await ctx.xray.startTest(buildMultiTestConfig(servers, ports), engine);
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    try { test.cleanup(); } catch { /* already gone */ }
  };
  const watch = setInterval(() => { if (ctx.token.cancelled) cleanup(); }, CANCEL_POLL_MS);
  if (watch.unref) watch.unref();
  try {
    if (ports.length && !(await ctx.waitReady(ports[0], ctx.o.readyTimeout, ctx.token)) && !ctx.token.cancelled) {
      throw new Error('the core did not start listening');
    }
    await work(ports);
  } finally { clearInterval(watch); cleanup(); }
}

/* ----------------------------- phase 1 ----------------------------- */

/**
 * One target on one engine. A failed TCP connect ends the row early — the
 * delay probes would only burn their timeouts. Over UDP there is no TCP
 * connect to make: the row says so (`skipped`) and the delay decides.
 */
async function filterOne(ctx, target, engine, port) {
  const { tests, o, probes, token } = ctx;
  const r = emptyResult(target, engine, 1);
  if (tests.tcp && ctx.transport === 'tcp') {
    r.tcp = await probes.tcpPing(target.addr, target.port || ctx.server.port, o.tcpTimeout);
    if (!r.tcp.ok) return r;
  } else if (tests.tcp) {
    r.tcp = { ok: false, skipped: true, ms: 0 };
  }
  if (token.cancelled) return r;
  if (tests.delay) {
    r.delay = await probes.delaySeries(port, { n: o.delaySamples, host: o.delayHost, port: o.delayPort, path: o.delayPath, timeout: o.delayTimeout });
  }
  return r;
}

async function filterBatch(ctx, engine, batch) {
  if (ctx.token.cancelled) return;
  const emitted = new Set();
  try {
    await withCore(ctx, engine, batch, async (ports) => {
      const limit = pLimit(ctx.filterConcurrency);
      await Promise.all(batch.map((tg, k) => limit(async () => {
        if (ctx.token.cancelled) return;
        const r = await filterOne(ctx, tg, engine, ports[k]);
        if (ctx.token.cancelled) return;
        emitted.add(tg.key);
        ctx.emit(r);
      })));
    });
  } catch (err) {
    if (ctx.token.cancelled) return;
    for (const tg of batch) {
      if (emitted.has(tg.key)) continue;
      const r = emptyResult(tg, engine, 1);
      r.error = (err && err.message) || String(err);
      emitted.add(tg.key);
      ctx.emit(r);
    }
  }
}

async function filterPhase(ctx, targets, engines) {
  const jobs = [];
  for (const engine of engines) {
    for (let i = 0; i < targets.length; i += ctx.batchSize) {
      const batch = targets.slice(i, i + ctx.batchSize);
      jobs.push(ctx.coreLimit(() => filterBatch(ctx, engine, batch)));
    }
  }
  await Promise.all(jobs);
}

/* ----------------------------- phase 2 ----------------------------- */

/** An ok round beats a failed one; among ok rounds the faster wins. */
const betterRound = (a, b) => (!b || (a.ok !== b.ok ? a.ok : a.mbps > b.mbps));

async function speedOne(ctx, row, port) {
  const { tests, o, probes, token } = ctx;
  const r = Object.assign({}, row, { phase: 2, down: null, up: null, error: null });
  if (tests.down) {
    for (let i = 0; i < ctx.speedRounds; i++) {
      if (token.cancelled) break;
      const d = await probes.downloadThroughProxy(port, {
        host: o.downHost, port: o.downPort, path: o.downPath || `/__down?bytes=${o.downBytes}`,
        tls: o.downTls, bytes: o.downBytes, maxMs: o.downMaxMs, timeout: o.downTimeout, warmupMs: o.warmupMs
      });
      if (betterRound(d, r.down)) r.down = d;
    }
  }
  if (token.cancelled) return r;
  if (tests.up) {
    r.up = await probes.uploadThroughProxy(port, {
      host: o.upHost, port: o.upPort, path: o.upPath, tls: o.upTls, bytes: o.upBytes, timeout: o.upTimeout
    });
  }
  return r;
}

const targetOf = (row) => ({ addr: row.addr, port: row.port, sni: row.sni, key: row.key });

async function speedBatch(ctx, engine, rows) {
  if (ctx.token.cancelled || !rows.length) return;
  const emitted = new Set();
  try {
    await withCore(ctx, engine, rows.map(targetOf), async (ports) => {
      await Promise.all(rows.map((row, k) => ctx.speedLimit(async () => {
        if (ctx.token.cancelled) return;
        const r = await speedOne(ctx, row, ports[k]);
        if (ctx.token.cancelled) return;
        emitted.add(row.key);
        ctx.emit(r);
      })));
    });
  } catch (err) {
    if (ctx.token.cancelled) return;
    for (const row of rows) {
      if (emitted.has(row.key)) continue;
      emitted.add(row.key);
      ctx.emit(Object.assign({}, row, { phase: 2, down: null, up: null, error: (err && err.message) || String(err) }));
    }
  }
}

/** rowsByEngine: Map engine → rows. One core per engine per batch of rows, cores through the shared limiter. */
async function speedPhase(ctx, rowsByEngine) {
  const jobs = [];
  for (const [engine, rows] of rowsByEngine) {
    for (let i = 0; i < rows.length; i += ctx.batchSize) {
      const chunk = rows.slice(i, i + ctx.batchSize);
      jobs.push(ctx.coreLimit(() => speedBatch(ctx, engine, chunk)));
    }
  }
  await Promise.all(jobs);
}

/** The top `speedTop` live phase-1 rows of every engine, in rank order. */
function pickTop(ctx, engines) {
  const out = new Map();
  if (!ctx.speedTop) return out;
  for (const engine of engines) {
    const rows = [...ctx.latest.values()].filter((r) => r.engine === engine && isAlive(r, ctx.tests)).sort(byRank);
    if (rows.length) out.set(engine, rows.slice(0, ctx.speedTop));
  }
  return out;
}

function finish(ctx) {
  const results = [...ctx.latest.values()].sort(byRank);
  return { results, cancelled: !!ctx.token.cancelled };
}

/** A target from what a caller handed in: `{ addr, port?, sni?, key? }`, or a bare `ip` (v2.x callers). */
function normalizeTarget(t) {
  if (typeof t === 'string') return { addr: t, port: null, sni: null, key: t };
  const addr = String((t && (t.addr || t.ip)) || '');
  const port = t && t.port != null && t.port !== '' ? Number(t.port) : null;
  const sni = t && t.sni ? String(t.sni) : null;
  return { addr, port, sni, key: (t && t.key) || addr };
}

/**
 * runScan({ server, targets, engines, tests, opts, transport, xray, onResult, onProgress, token })
 *   → Promise<{ results, cancelled }>
 * `results` holds one row per target×engine, the newest phase of each, ranked.
 * `ips` is still read when `targets` is absent. `opts.probes`,
 * `opts.getFreePorts` and `opts.waitReady` are injection points for tests.
 */
async function runScan(args) {
  const list = Array.isArray(args.targets) ? args.targets : (Array.isArray(args.ips) ? args.ips : []);
  const targets = list.map(normalizeTarget).filter(t => t.addr);
  const engines = Array.isArray(args.engines) ? args.engines : [];
  const ctx = makeContext(args);
  ctx.progress = progressTracker(args.onProgress, { stage: 'filter', total: targets.length * engines.length });

  await filterPhase(ctx, targets, engines);

  const wantSpeed = ctx.tests.down || ctx.tests.up;
  if (wantSpeed && !ctx.token.cancelled) {
    const top = pickTop(ctx, engines);
    const speedTotal = [...top.values()].reduce((s, rows) => s + rows.length, 0);
    if (speedTotal) {
      ctx.progress.stage('speed', speedTotal);
      await speedPhase(ctx, top);
    }
  }
  ctx.progress.stage('done', 0);
  return finish(ctx);
}

/**
 * runSpeed({ server, rows: [{ key, addr, port, sni, engine, tcp?, delay? }], tests, opts, xray, onResult, onProgress, token })
 *   → Promise<{ results, cancelled }>
 * Phase 2 alone, for "speed-test again": the rows come from the table, with
 * the delay they measured before when the caller passes it along (rebuilt
 * from its samples, so a row from the renderer cannot smuggle a number in).
 */
async function runSpeed(args) {
  const ctx = makeContext(args);
  const tests = ctx.tests;
  tests.tcp = false; tests.delay = false;
  const rowsByEngine = new Map();
  for (const raw of Array.isArray(args.rows) ? args.rows : []) {
    if (!raw || !(raw.addr || raw.ip) || !raw.engine) continue;
    const row = emptyResult(normalizeTarget(raw), String(raw.engine), 1);
    if (raw.tcp && typeof raw.tcp === 'object') row.tcp = { ok: !!raw.tcp.ok, ms: Number(raw.tcp.ms) || 0, ...(raw.tcp.skipped ? { skipped: true } : {}) };
    if (raw.delay && Array.isArray(raw.delay.samples)) row.delay = delayStats(raw.delay.samples);
    if (ctx.latest.has(keyOf(row))) continue;
    ctx.latest.set(keyOf(row), row);
    if (!rowsByEngine.has(row.engine)) rowsByEngine.set(row.engine, []);
    rowsByEngine.get(row.engine).push(row);
  }
  const total = ctx.latest.size;
  ctx.progress = progressTracker(args.onProgress, { stage: 'speed', total, done: total, alive: total });
  ctx.progress.stage('speed', total);
  if (total && (tests.down || tests.up) && !ctx.token.cancelled) await speedPhase(ctx, rowsByEngine);
  ctx.progress.stage('done', 0);
  return finish(ctx);
}

module.exports = { runScan, runSpeed, SCAN_DEFAULTS, DEFAULT_TESTS, emptyResult, byRank, isAlive, waitListening, normalizeTarget };
