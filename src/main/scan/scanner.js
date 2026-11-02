'use strict';
/**
 * plus: the scan runner — a pre-check and two phases, each with its own
 * concurrency (spec v2.1 §1, v3 §4; 2026-11-01 for the space, the pre-check,
 * the variants and what a pass means).
 *
 * A run tests ITEMS — `{ addr, port, sni, key, variant?, engines? }`: a
 * target (targets.js: address × port × SNI), and when the page asked for a
 * parameter matrix one variant of the config (variants.js) and the cores that
 * variant may run on — each through a copy of the config that dials it
 * (substitute.applyTarget, then variants.applyVariant). The items come as an
 * array or as a SPACE `{ size, at(i) }`, walked in chunks: a /8 × six ports
 * is a hundred million items and none of them is held longer than its chunk.
 *
 * Pre-check (when the TCP test is ticked and the config runs over TCP): a
 * direct TCP connect to addr:port — or, `prefilterTls`, a TLS handshake under
 * the SNI — for each address of a chunk, once however many variants and
 * cores share it, `prefilterConcurrency` at a time; no core is involved. An
 * address that fails is reported dead at once (reason `no-tcp` / `tls`), on
 * every core it would have run on, and never reaches a core: a big range costs
 * the cores only its live part. A Hysteria2, WireGuard, mKCP or
 * MASQUE-over-HTTP/3 config has nothing a TCP connect could tell; its rows say
 * so (`tcp.skipped`) and the delay decides.
 *
 * Phase 1 (filter): what survived gets a delay series (probes.delaySeries:
 * the expected answer from the probe page through the tunnel, passRatio of
 * the samples to pass) through a throw-away core: one core per (engine ×
 * batch), through one pLimit(coresInParallel) shared by every engine so the
 * engines run side by side, and at most `filterConcurrency` series in flight
 * across ALL the cores together — v3.0 allowed that many per core, so two
 * cores ran twice the number the page showed, and a starved machine reads as
 * dead targets. A batch may carry several variants; when such a core does not
 * start (a value this core refuses: an unknown fingerprint, a mask it cannot
 * read) the batch is run again variant by variant, so one bad value marks its
 * own rows and no other — and those rows say what the core said when it can
 * say (xray.validate). Each row leaves through onResult with phase: 1 at once.
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
 * Memory: with `keepRows` false (the service's choice for a run too big to
 * list) only rows that passed are kept, and of those the best KEEP_ALIVE per
 * engine — what phase 2 and the final ranking need; every row still leaves
 * through onResult.
 *
 * Stop is a flag on the token, read before every chunk, batch, target and
 * round; while a core is alive a short poll kills it as soon as the flag is
 * set.
 */
const net = require('net');
const { buildMultiTestConfig } = require('../configBuilder');
const { withUpstream, dialVia } = require('./upstream');
const { getFreePorts: realGetFreePorts } = require('../xrayManager');
const { tcpPing, pLimit } = require('../netutils');
const { applyTarget } = require('./substitute');
const { applyVariant } = require('./variants');
const { scoreResult, delayStats, passes, reasonOf, PASS_RATIO } = require('./score');
const probesMod = require('./probes');

const SCAN_DEFAULTS = {
  batch: 20, filterConcurrency: 16, prefilterConcurrency: 128, coresInParallel: 2, delaySamples: 3, passRatio: PASS_RATIO,
  tcpTimeout: 2000, prefilterTls: false,
  delayHost: 'cp.cloudflare.com', delayPort: 80, delayPath: '/', delayTimeout: 4000, delayExpect: '204',
  speedTop: 10, speedConcurrency: 1, speedRounds: 1, warmupMs: 300,
  downHost: 'speed.cloudflare.com', downPort: 443, downPath: '', downTls: true, downBytes: 10e6, downMaxMs: 6000, downTimeout: 8000,
  upHost: 'speed.cloudflare.com', upPort: 443, upPath: '/__up', upTls: true, upBytes: 2e6, upTimeout: 20000,
  readyTimeout: 4000
};
const DEFAULT_TESTS = { tcp: true, delay: true, down: false, up: false };
const DEFAULT_PROBES = {
  tcpPing,
  tlsPing: probesMod.tlsPing,
  delaySeries: probesMod.delaySeries,
  downloadThroughProxy: probesMod.downloadThroughProxy,
  uploadThroughProxy: probesMod.uploadThroughProxy
};
const CANCEL_POLL_MS = 250;
const READY_STEP_MS = 100;
/** With keepRows false: the passing rows kept per engine (pruned to this when twice as many are in). */
const KEEP_ALIVE = 1000;

const posInt = (v, def, lo = 1) => {
  const n = Math.floor(Number(v));
  return Math.max(lo, Number.isFinite(n) ? n : def);
};

/** A target as rows carry it; `ip` stays as an alias of addr for older readers. A variant names itself on the row. */
function emptyResult(target, engine, phase = 1) {
  const tg = target || {};
  const r = {
    key: tg.key || String(tg.addr || ''), addr: tg.addr || '', port: tg.port == null ? null : tg.port, sni: tg.sni || null,
    ip: tg.addr || '', engine, phase, tcp: null, delay: null, down: null, up: null, score: 0, error: null, reason: ''
  };
  if (tg.variant && tg.variant.key) { r.variant = tg.variant.key; r.variantLabel = tg.variant.label || tg.variant.key; }
  return r;
}

const keyOf = (r) => `${r.key}|${r.engine}`;

/**
 * The owner's order (score.js): the success step first (score / 100, whole),
 * then the median delay, then the jitter, then whatever is left of the score;
 * a row with no usable delay sorts after one with it.
 */
const medianOf = (r) => (r.delay && r.delay.loss < 1 ? r.delay.median : Number.MAX_SAFE_INTEGER);
const jitterOf = (r) => (r.delay && r.delay.loss < 1 ? r.delay.jitter || 0 : Number.MAX_SAFE_INTEGER);
const stepOf = (r) => Math.floor((Number(r.score) || 0) / 100);
function byRank(a, b) {
  return (stepOf(b) - stepOf(a)) || (medianOf(a) - medianOf(b)) || (jitterOf(a) - jitterOf(b)) || ((b.score || 0) - (a.score || 0)) || 0;
}

/** A row that passed phase 1: it answered whatever phase 1 asked of it — a delay series, passRatio of it. */
function isAlive(r, tests, passRatio) {
  if (r.error) return false;
  if (tests.delay) return passes(r.delay, passRatio);
  if (tests.tcp && r.tcp && !r.tcp.skipped) return !!r.tcp.ok;
  return true;
}

/**
 * The progress the UI paints: the stage, its counters, an ETA from the
 * measured rate of the stage in flight — null until two rows are in — and
 * the failures by reason (`reasons`), what a run too big to list shows
 * instead of its dead rows.
 */
function progressTracker(onProgress, init, passRatio) {
  const p = Object.assign({ stage: 'filter', done: 0, total: 0, alive: 0, speedDone: 0, speedTotal: 0, etaMs: null, reasons: {} }, init);
  let t0 = Date.now(), n = 0, size = p.total;
  const eta = () => (n < 2 ? null : Math.max(0, Math.round((size - n) * (Date.now() - t0) / n)));
  const snap = () => Object.assign({}, p, { reasons: Object.assign({}, p.reasons) });
  const emit = () => { if (onProgress) onProgress(snap()); };
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
      else {
        p.done++;
        if (isAlive(r, tests, passRatio)) p.alive++;
        else if (r.reason) p.reasons[r.reason] = (p.reasons[r.reason] || 0) + 1;
      }
      p.etaMs = eta();
      emit();
    },
    snapshot: snap
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
    upstream: args.upstream || null,
    // through a port only a TLS handshake says anything (upstream.js); without one, no pre-check
    noPrecheck: !!args.upstream && !o.prefilterTls,
    transport: args.transport === 'udp' ? 'udp' : 'tcp',
    sni: typeof args.sni === 'string' ? args.sni : '',
    token: args.token || { cancelled: false },
    probes: Object.assign({}, DEFAULT_PROBES, o.probes),
    getFreePorts: o.getFreePorts || realGetFreePorts,
    waitReady: o.waitReady || waitListening,
    batchSize,
    probeLimit: pLimit(posInt(o.filterConcurrency, SCAN_DEFAULTS.filterConcurrency)),
    preLimit: pLimit(posInt(o.prefilterConcurrency, SCAN_DEFAULTS.prefilterConcurrency)),
    coresInParallel: posInt(o.coresInParallel, SCAN_DEFAULTS.coresInParallel),
    coreLimit: pLimit(posInt(o.coresInParallel, SCAN_DEFAULTS.coresInParallel)),
    speedLimit: pLimit(posInt(o.speedConcurrency, SCAN_DEFAULTS.speedConcurrency)),
    speedRounds: posInt(o.speedRounds, SCAN_DEFAULTS.speedRounds),
    speedTop: Math.min(batchSize, posInt(o.speedTop, SCAN_DEFAULTS.speedTop, 0)),
    passRatio: Number(o.passRatio) > 0 ? Math.min(1, Number(o.passRatio)) : PASS_RATIO,
    keepRows: args.keepRows !== false,
    latest: new Map(),               // key|engine → the newest row, whichever phase
    kept: new Map(),                 // keepRows false: engine → count of rows kept since the last prune
    variants: new Map(),             // variant key → the variant, for phase 2 to write it again
    progress: null,
    onResult: args.onResult
  };
  ctx.emit = (r) => {
    r.score = r.error ? 0 : scoreResult(r, { passRatio: ctx.passRatio });
    r.reason = r.score > 0 ? '' : (r.reason || reasonOf(r, { passRatio: ctx.passRatio }) || (r.error ? 'core' : ''));
    remember(ctx, r);
    ctx.progress.row(r, tests);
    if (ctx.onResult) ctx.onResult(r);
  };
  return ctx;
}

/** A row into `latest`: every row with keepRows, else only rows that passed, the best KEEP_ALIVE of each engine. */
function remember(ctx, r) {
  const k = keyOf(r);
  if (ctx.keepRows) { ctx.latest.set(k, r); return; }
  if (!isAlive(r, ctx.tests, ctx.passRatio) || r.error) { ctx.latest.delete(k); return; }
  ctx.latest.set(k, r);
  const n = (ctx.kept.get(r.engine) || 0) + 1;
  ctx.kept.set(r.engine, n);
  if (n < KEEP_ALIVE * 2) return;
  ctx.kept.set(r.engine, 0);
  const mine = [...ctx.latest.values()].filter((x) => x.engine === r.engine).sort(byRank);
  for (const x of mine.slice(KEEP_ALIVE)) ctx.latest.delete(keyOf(x));
}

/** The record one item dials: the target, then its variant. */
function recordOf(ctx, tg) {
  const rec = applyTarget(ctx.server, tg);
  return tg.variant && tg.variant.set ? applyVariant(rec, tg.variant) : rec;
}

/**
 * One throw-away core for `targets` on `engine`; `work(ports)` runs once it
 * listens, and the core dies in `finally`, or earlier when the token is
 * cancelled. Rejects when the config cannot take a target or the core cannot
 * start; `err.built` is the config, for whoever wants the core to say why.
 */
async function withCore(ctx, engine, targets, work) {
  const servers = targets.map((tg) => recordOf(ctx, tg));
  const ports = await ctx.getFreePorts(targets.length);
  const cfg = withUpstream(buildMultiTestConfig(servers, ports), ctx.upstream);
  let test;
  try { test = await ctx.xray.startTest(cfg, engine); } catch (e) { throw Object.assign(e instanceof Error ? e : new Error(String(e)), { built: cfg }); }
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
      throw Object.assign(new Error('the core did not start listening'), { built: cfg });
    }
    await work(ports);
  } finally { clearInterval(watch); cleanup(); }
}

/* ----------------------------- the pre-check ----------------------------- */

/** Does the pre-check (and the TCP column) apply: the TCP test ticked, a config over TCP. */
const prechecks = (ctx) => ctx.tests.tcp && ctx.transport === 'tcp' && !ctx.noPrecheck;

/**
 * The pre-check of one chunk: every distinct address:port (with its SNI for
 * the TLS form) once; the items that failed leave as dead rows on each of
 * their cores, the others come back carrying the connect (`tcp`).
 */
async function precheck(ctx, items, enginesOf) {
  const { o, probes, token } = ctx;
  const tlsForm = !!o.prefilterTls;
  const probe = new Map();
  const keyFor = (it) => `${it.addr}|${it.port || ctx.server.port}${tlsForm ? '|' + (it.sni || ctx.sni) : ''}`;
  for (const it of items) {
    const k = keyFor(it);
    if (probe.has(k)) continue;
    const port = it.port || ctx.server.port;
    probe.set(k, ctx.preLimit(async () => {
      if (token.cancelled) return null;
      if (tlsForm) {
        const r = await probes.tlsPing(it.addr, port, Object.assign({ servername: it.sni || ctx.sni, timeout: o.tcpTimeout }, ctx.upstream ? { dial: dialVia(ctx.upstream) } : {}));
        return { ok: !!r.ok, ms: r.ok ? r.ms : -1, error: r.error || null, reason: r.ok ? '' : (r.reason || 'tls') };
      }
      const r = await probes.tcpPing(it.addr, port, o.tcpTimeout);
      return { ok: !!r.ok, ms: r.ok ? r.ms : -1, error: r.ok ? null : (r.error || 'no answer'), reason: r.ok ? '' : 'no-tcp' };
    }));
  }
  const answers = new Map();
  await Promise.all([...probe].map(async ([k, p]) => { answers.set(k, await p); }));
  if (token.cancelled) return [];
  const alive = [];
  for (const it of items) {
    const a = answers.get(keyFor(it));
    if (!a) continue;
    if (a.ok) { alive.push(Object.assign({}, it, { tcp: { ok: true, ms: a.ms } })); continue; }
    for (const engine of enginesOf(it)) {
      const r = emptyResult(it, engine, 1);
      r.tcp = { ok: false, ms: -1, error: a.error };
      r.reason = a.reason;
      ctx.emit(r);
    }
  }
  return alive;
}

/* ----------------------------- phase 1 ----------------------------- */

/**
 * One item on one engine: its pre-check's connect (or `skipped` over UDP),
 * then the delay series — inside the run-wide probe limit.
 */
async function filterOne(ctx, item, engine, port) {
  const { tests, o, probes, token } = ctx;
  const r = emptyResult(item, engine, 1);
  if (item.tcp) r.tcp = Object.assign({}, item.tcp);
  else if (prechecks(ctx)) {
    // an item that skipped the pre-check (a caller's own list): the connect is made here, as before
    r.tcp = await probes.tcpPing(item.addr, item.port || ctx.server.port, o.tcpTimeout);
    if (!r.tcp.ok) { r.reason = 'no-tcp'; return r; }
  } else if (tests.tcp) r.tcp = { ok: false, skipped: true, ms: 0 };
  if (token.cancelled) return r;
  if (tests.delay) {
    r.delay = await ctx.probeLimit(() => (token.cancelled ? null : probes.delaySeries(port, {
      n: o.delaySamples, host: o.delayHost, port: o.delayPort, path: o.delayPath, timeout: o.delayTimeout,
      expect: o.delayExpect, passRatio: ctx.passRatio
    })));
  }
  return r;
}

/** What the core said about a config it would not start, when it can say; '' otherwise. */
async function coreSays(ctx, err, engine) {
  if (!err || !err.built || !ctx.xray || typeof ctx.xray.validate !== 'function') return '';
  try {
    const v = await ctx.xray.validate(err.built, engine);
    return v && !v.ok && v.error ? String(v.error).split(/\r?\n/).filter(Boolean).slice(-1)[0] : '';
  } catch { return ''; }
}

async function filterBatch(ctx, engine, batch) {
  if (ctx.token.cancelled || !batch.length) return;
  const emitted = new Set();
  try {
    await withCore(ctx, engine, batch, async (ports) => {
      await Promise.all(batch.map(async (tg, k) => {
        if (ctx.token.cancelled) return;
        const r = await filterOne(ctx, tg, engine, ports[k]);
        if (ctx.token.cancelled) return;
        emitted.add(tg.key);
        ctx.emit(r);
      }));
    });
  } catch (err) {
    if (ctx.token.cancelled) return;
    // several variants in a core that would not start: each on its own, so a bad value marks only its rows
    const groups = new Map();
    for (const tg of batch) {
      const k = tg.variant ? tg.variant.key : '';
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(tg);
    }
    if (!emitted.size && groups.size > 1) {
      for (const g of groups.values()) await filterBatch(ctx, engine, g);
      return;
    }
    let msg = (err && err.message) || String(err);
    if (batch.some((tg) => tg.variant)) {
      const said = await coreSays(ctx, err, engine);
      if (said) msg = `${msg} — ${said}`;
    }
    for (const tg of batch) {
      if (emitted.has(tg.key)) continue;
      const r = emptyResult(tg, engine, 1);
      if (tg.tcp) r.tcp = Object.assign({}, tg.tcp);
      r.error = msg;
      r.reason = 'core';
      emitted.add(tg.key);
      ctx.emit(r);
    }
  }
}

/** The items of [from, to) of a list or a space, normalized; the variants remembered for phase 2. */
function chunkOf(ctx, source, from, to) {
  const out = [];
  for (let i = from; i < to; i++) {
    const raw = source.at(i);
    if (!raw) continue;
    const it = normalizeTarget(raw);
    if (!it.addr) continue;
    if (it.variant && it.variant.key && !ctx.variants.has(it.variant.key)) ctx.variants.set(it.variant.key, it.variant);
    out.push(it);
  }
  return out;
}

/**
 * Phase 1 over the whole source, a chunk at a time: the chunk's pre-check,
 * then its batches per engine into the shared core limit. Up to PRE_AHEAD
 * chunks are pre-checked at once — one chunk waits for its slowest connect
 * (a dead address costs the whole TCP timeout), and the next ones fill the
 * pre-check limit meanwhile — but their batches go to the cores in the order
 * of the source, and never more than a few batches ahead of the cores: what
 * is held at once is bounded, whatever the size.
 */
const PRE_AHEAD = 4;
async function filterPhase(ctx, source, engines) {
  const enginesOf = (it) => (Array.isArray(it.engines) ? engines.filter((e) => it.engines.includes(e)) : engines);
  const chunkSize = Math.max(64, ctx.batchSize * ctx.coresInParallel * 2, posInt(ctx.o.prefilterConcurrency, 64));
  const pending = new Set();
  const ahead = ctx.coresInParallel * 3;
  const checks = [];
  let next = 0;
  const readAhead = () => {
    while (checks.length < (prechecks(ctx) ? PRE_AHEAD : 1) && next < source.size && !ctx.token.cancelled) {
      const items = chunkOf(ctx, source, next, Math.min(source.size, next + chunkSize));
      next += chunkSize;
      checks.push(prechecks(ctx) ? precheck(ctx, items, enginesOf) : Promise.resolve(items));
    }
  };
  for (readAhead(); checks.length; readAhead()) {
    if (ctx.token.cancelled) break;
    const items = await checks.shift();
    if (ctx.token.cancelled) break;
    for (const engine of engines) {
      const mine = items.filter((it) => enginesOf(it).includes(engine));
      for (let j = 0; j < mine.length; j += ctx.batchSize) {
        const batch = mine.slice(j, j + ctx.batchSize);
        const job = ctx.coreLimit(() => filterBatch(ctx, engine, batch)).finally(() => pending.delete(job));
        pending.add(job);
      }
    }
    while (pending.size > ahead) await Promise.race(pending);
  }
  await Promise.all(checks);     // a stop: the pre-checks in flight end on their own (they read the token), then the run does
  await Promise.all(pending);
}

/* ----------------------------- phase 2 ----------------------------- */

/** An ok round beats a failed one; among ok rounds the faster wins. */
const betterRound = (a, b) => (!b || (a.ok !== b.ok ? a.ok : a.mbps > b.mbps));

async function speedOne(ctx, row, port) {
  const { tests, o, probes, token } = ctx;
  const r = Object.assign({}, row, { phase: 2, down: null, up: null, error: null, reason: '' });
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

const targetOf = (ctx, row) => ({ addr: row.addr, port: row.port, sni: row.sni, key: row.key, variant: row.variant ? ctx.variants.get(row.variant) || null : null });

async function speedBatch(ctx, engine, rows) {
  if (ctx.token.cancelled || !rows.length) return;
  const emitted = new Set();
  try {
    await withCore(ctx, engine, rows.map((r) => targetOf(ctx, r)), async (ports) => {
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
      ctx.emit(Object.assign({}, row, { phase: 2, down: null, up: null, error: (err && err.message) || String(err), reason: 'core' }));
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
    const rows = [...ctx.latest.values()].filter((r) => r.engine === engine && isAlive(r, ctx.tests, ctx.passRatio)).sort(byRank);
    if (rows.length) out.set(engine, rows.slice(0, ctx.speedTop));
  }
  return out;
}

function finish(ctx) {
  const results = [...ctx.latest.values()].sort(byRank);
  return { results, cancelled: !!ctx.token.cancelled };
}

/**
 * An item from what a caller handed in: `{ addr, port?, sni?, key?, variant?, engines?, tcp? }`,
 * or a bare `ip` (v2.x callers).
 */
function normalizeTarget(t) {
  if (typeof t === 'string') return { addr: t, port: null, sni: null, key: t };
  const addr = String((t && (t.addr || t.ip)) || '');
  const port = t && t.port != null && t.port !== '' ? Number(t.port) : null;
  const sni = t && t.sni ? String(t.sni) : null;
  const out = { addr, port, sni, key: (t && t.key) || addr };
  if (t && t.variant && typeof t.variant === 'object') out.variant = t.variant;
  if (t && Array.isArray(t.engines)) out.engines = t.engines;
  if (t && t.tcp && typeof t.tcp === 'object' && t.tcp.ok) out.tcp = { ok: true, ms: Number(t.tcp.ms) || 0 };
  return out;
}

/** An array or a space, as a space. */
function sourceOf(args) {
  const t = args.targets;
  if (t && !Array.isArray(t) && typeof t.at === 'function' && Number.isFinite(t.size)) return t;
  const list = Array.isArray(t) ? t : (Array.isArray(args.ips) ? args.ips : []);
  return { size: list.length, at: (i) => list[i] };
}

/**
 * runScan({ server, targets, engines, tests, opts, transport, sni, total, keepRows, xray, onResult, onProgress, token })
 *   → Promise<{ results, cancelled }>
 * `targets` is a list or a space of items (see the header). `results` holds
 * one row per item × engine, the newest phase of each, ranked (with keepRows
 * false only the best passing ones). `total` is the number of rows phase 1
 * will make, when the caller knows it better (items with their own engines);
 * otherwise items × engines. `ips` is still read when `targets` is absent.
 * `opts.probes`, `opts.getFreePorts` and `opts.waitReady` are injection
 * points for tests.
 */
async function runScan(args) {
  const source = sourceOf(args);
  const engines = Array.isArray(args.engines) ? args.engines : [];
  const ctx = makeContext(args);
  const total = Number.isFinite(args.total) ? args.total : source.size * engines.length;
  ctx.progress = progressTracker(args.onProgress, { stage: 'filter', total }, ctx.passRatio);

  if (engines.length) await filterPhase(ctx, source, engines);

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
 * runSpeed({ server, rows: [{ key, addr, port, sni, engine, tcp?, delay?, variant? }], tests, opts, xray, onResult, onProgress, token })
 *   → Promise<{ results, cancelled }>
 * Phase 2 alone, for "speed-test again": the rows come from the table, with
 * the delay they measured before when the caller passes it along (rebuilt
 * from its samples, so a row from the renderer cannot smuggle a number in),
 * and their variant as the service read it again (a variant object).
 */
async function runSpeed(args) {
  const ctx = makeContext(args);
  const tests = ctx.tests;
  tests.tcp = false; tests.delay = false;
  const rowsByEngine = new Map();
  for (const raw of Array.isArray(args.rows) ? args.rows : []) {
    if (!raw || !(raw.addr || raw.ip) || !raw.engine) continue;
    const item = normalizeTarget(raw);
    if (item.variant && item.variant.key) ctx.variants.set(item.variant.key, item.variant);
    const row = emptyResult(item, String(raw.engine), 1);
    if (raw.tcp && typeof raw.tcp === 'object') row.tcp = { ok: !!raw.tcp.ok, ms: Number(raw.tcp.ms) || 0, ...(raw.tcp.skipped ? { skipped: true } : {}) };
    if (raw.delay && Array.isArray(raw.delay.samples)) row.delay = delayStats(raw.delay.samples);
    if (ctx.latest.has(keyOf(row))) continue;
    ctx.latest.set(keyOf(row), row);
    if (!rowsByEngine.has(row.engine)) rowsByEngine.set(row.engine, []);
    rowsByEngine.get(row.engine).push(row);
  }
  const total = ctx.latest.size;
  ctx.progress = progressTracker(args.onProgress, { stage: 'speed', total, done: total, alive: total }, ctx.passRatio);
  ctx.progress.stage('speed', total);
  if (total && (tests.down || tests.up) && !ctx.token.cancelled) await speedPhase(ctx, rowsByEngine);
  ctx.progress.stage('done', 0);
  return finish(ctx);
}

module.exports = { runScan, runSpeed, SCAN_DEFAULTS, DEFAULT_TESTS, emptyResult, byRank, isAlive, waitListening, normalizeTarget, KEEP_ALIVE };
