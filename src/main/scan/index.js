'use strict';
/**
 * plus: the Scan page — one config tried through many targets (address × port
 * × SNI) and, when the page asks, many variants of its parameters (variants.js)
 * on every installed Xray-format core (spec 2026-10-15 §4; v2.1 §1 for the two
 * phases, v2.2 for the random pick, 2026-11-01 for the matrix, the address
 * picks without a cap and what a pass means). `ctx` is the service's context
 * (src/main/plus/service.js); a handler gets its one argument unwrapped.
 *
 * Channels: scan:start, scan:retest, scan:stop, scan:presets, scan:suggest,
 * scan:plan, scan:apply, scan:links, scan:copy, scan:export, scan:forget,
 * scan:sets, scan:cdnUpdate, scan:pathCheck. Event: scan-progress { runId, stage, done, total, alive,
 * speedDone, speedTotal, etaMs, reasons, result } per result, the same
 * without a result when the stage changes, then { ..., finished: true,
 * cancelled } (plus `error` when the run itself failed). One run at a time.
 * The last request is remembered under `scan`, never the results — only the
 * addresses tested, under `scanTested`, so a random draw can skip them; the
 * saved parameter sets under `scanSets`.
 *
 * A run too big to list (more than STREAM_ALL rows) sends only the rows that
 * passed; the dead ones are counted by reason in every event's `reasons`
 * (and per variant in `variantStats`), and an event without a row goes out at
 * most every PROGRESS_MS, so a /8 is not sixteen million messages to the
 * page.
 *
 * Before a run (prepare): the config is checked to be one a target can be put
 * into (a TUIC or AnyTLS one runs on sing-box only — the scan runs Xray); an
 * SNI list is refused for a config whose SNI cannot change; a core too old
 * for the config is left out (MASQUE, a WARP account, ECH, the ECH outbound),
 * and so is one the app would not run it on (a dialMode or the merge mask:
 * Xray-PattN 26.10.27 and newer; a finalmask: Xray-PattN when it is there);
 * an ECH config that is a DNS query is fetched ONCE here and handed to every
 * core as the list itself.
 */
const crypto = require('crypto');
const { parseLink, parseMany, buildShareLink } = require('../parser');
const { buildMultiTestConfig, buildTestConfig, echQueryOf } = require('../configBuilder');
const XM = require('../xrayManager');
const { isSingboxOnly } = require('../engineChoice');
const { xrayEngines, engineLabel } = require('../engines');
const T = require('./targets');
const V = require('./variants');
const C = require('./cdnRanges');
const U = require('./upstream');
const { readExpect } = require('./probes');
const { applyTarget, dialOf, transportOf, sniSupport } = require('./substitute');
const { fetchEchConfig: defaultFetchEch } = require('./ech');
const { runScan: defaultRunScan, runSpeed: defaultRunSpeed } = require('./scanner');

const STORE_KEY = 'scan';
const SETS_KEY = 'scanSets';
const MAX_SETS = 50;
/** Every address a run has tested (phase 1), normalised strings, newest last — spec v2.2 §2.2. */
const TESTED_KEY = 'scanTested';
const TESTED_CAP = 50000;
const ECH_TIMEOUT_MS = 4000;
/** Past this many rows a run sends only the rows that passed (see the header). */
const STREAM_ALL = 20000;
const PROGRESS_MS = 250;
/**
 * How the address box is read: `all` (every address of every range, no cap),
 * `sample` (`count` random from all the ranges together), `random`
 * (`perRange` from each range) or `block` (`perBlock` from every /`block` of
 * the ranges, so a share follows a range's size); `fresh` skips what was tested before.
 */
const PICK_DEFAULTS = { mode: 'all', perRange: 20, count: 1000, perBlock: 5, block: 24, fresh: true };
/** A block holds at most 65536 addresses (/16). */
const PER_BLOCK_MAX = 65536;
/** What the page shows before the user changes anything: the balanced preset. */
const PRESET_DEFAULTS = {
  batch: 20, filterConcurrency: 16, prefilterConcurrency: 128, coresInParallel: 2, delaySamples: 3, passRatio: 0.66,
  tcpTimeout: 2000, delayTimeout: 4000, prefilterTls: false,
  delayHost: 'cp.cloudflare.com', delayPort: 80, delayPath: '/', delayExpect: '204',
  speedTop: 10, speedConcurrency: 1, speedRounds: 1, warmupMs: 300,
  downBytes: 10e6, downMaxMs: 6000, downTimeout: 8000,
  downHost: 'speed.cloudflare.com', downPath: '/__down?bytes=10000000', downPort: 443, downTls: true,
  upBytes: 2e6, upTimeout: 20000,
  upHost: 'speed.cloudflare.com', upPath: '/__up', upPort: 443, upTls: true
};
/** The three presets; every one a full opts object. Two samples is the least a pass can mean. */
const PRESETS = {
  fast: Object.assign({}, PRESET_DEFAULTS, { delaySamples: 2, tcpTimeout: 1500, delayTimeout: 3000, filterConcurrency: 24, prefilterConcurrency: 256, coresInParallel: 3, speedTop: 5 }),
  balanced: Object.assign({}, PRESET_DEFAULTS),
  accurate: Object.assign({}, PRESET_DEFAULTS, { delaySamples: 5, filterConcurrency: 8, prefilterConcurrency: 64, tcpTimeout: 3000, speedTop: 20, speedRounds: 2, speedConcurrency: 1 })
};
const DEFAULT_TESTS = { tcp: true, delay: true, down: true, up: false };
const CSV_HEADER = 'addr,port,sni,engine,phase,tcp_ms,delay_min,delay_median,delay_avg,jitter,loss,down_mbps,up_mbps,score,error,variant,reason';

const num = (v, def, lo, hi) => {
  const n = Math.floor(Number(v));
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : def;
};
const str = (v, def) => (typeof v === 'string' && v.trim() ? v.trim() : def);
const hasTokens = (text) => String(text || '').split(/\r?\n/).some((l) => l.replace(/#.*/, '').trim());
const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

/** The pick as sent, clamped; a request without one reads as `all`. */
function sanitizePick(raw) {
  const p = raw && typeof raw === 'object' ? raw : {};
  return {
    mode: p.mode === 'random' || p.mode === 'sample' || p.mode === 'block' ? p.mode : 'all',
    perRange: num(p.perRange, PICK_DEFAULTS.perRange, 1, T.MAX_SAMPLE),
    count: num(p.count, PICK_DEFAULTS.count, 1, T.MAX_SAMPLE),
    perBlock: num(p.perBlock, PICK_DEFAULTS.perBlock, 1, PER_BLOCK_MAX),
    block: T.BLOCK_PREFIXES.includes(Number(p.block)) ? Number(p.block) : PICK_DEFAULTS.block,
    fresh: p.fresh === undefined ? PICK_DEFAULTS.fresh : !!p.fresh
  };
}

/** Clamp what the page sent; anything missing takes the default. */
function sanitizeOpts(raw) {
  const o = raw && typeof raw === 'object' ? raw : {};
  const D = PRESET_DEFAULTS;
  // v2.0 remembered one `concurrency`; it was the filter's
  const filterConcurrency = o.filterConcurrency !== undefined ? o.filterConcurrency : o.concurrency;
  const delayHost = str(o.delayHost, D.delayHost);
  // the expected answer: as given when it reads; else 204 for the default page, any 2xx/3xx for another one
  const expect = typeof o.delayExpect === 'string' && readExpect(o.delayExpect) ? o.delayExpect.trim() : (delayHost === D.delayHost ? D.delayExpect : '');
  const ratio = Number(o.passRatio);
  return {
    batch: num(o.batch, D.batch, 1, 50),
    filterConcurrency: num(filterConcurrency, D.filterConcurrency, 1, 64),
    prefilterConcurrency: num(o.prefilterConcurrency, D.prefilterConcurrency, 1, 1024),
    coresInParallel: num(o.coresInParallel, D.coresInParallel, 1, 6),
    delaySamples: num(o.delaySamples, D.delaySamples, 1, 10),
    passRatio: Number.isFinite(ratio) && ratio > 0 ? Math.min(1, Math.max(0.3, ratio)) : D.passRatio,
    tcpTimeout: num(o.tcpTimeout, D.tcpTimeout, 500, 30000),
    delayTimeout: num(o.delayTimeout, D.delayTimeout, 500, 60000),
    prefilterTls: o.prefilterTls === true,
    delayHost,
    delayPort: num(o.delayPort, D.delayPort, 1, 65535),
    delayPath: str(o.delayPath, D.delayPath),
    delayExpect: expect,
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

/** The parameter dimensions the page sent, as the store keeps them: the raw values that read, and the limit. */
function storableSpec(raw) {
  const s = V.sanitizeSpec(raw);
  const dims = {};
  for (const d of s.dims) dims[d.id] = d.values.map((v) => v.raw);
  return { dims, limit: s.limit };
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
    r.score, r.error, r.variantLabel || r.variant || null, r.reason || null
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
 * xrayManager.usesFinalmask, which the synced file does not export: a
 * non-empty finalmask on an outbound that is not Hysteria, mKCP or MASQUE —
 * theirs are the official core's own.
 */
function usesFinalmask(config) {
  return ((config && config.outbounds) || []).some((o) => {
    const ss = o && o.streamSettings;
    const fm = ss && ss.finalmask;
    if (/^(hysteria|kcp|mkcp|masque)$/i.test(String((ss && ss.network) || ''))) return false;
    return !!fm && typeof fm === 'object' && Object.keys(fm).length > 0;
  });
}

/** A config's own anti-DPI tricks — the plain TLS handshake of the pre-check may be what a DPI box cuts. */
function hasDpiTricks(server) {
  const ob = (server && server.outbound) || {};
  const st = ob.streamSettings || {};
  return !!(ob._fragment || ob._noise || (st.finalmask && Object.keys(st.finalmask).length) || (st.sockopt && st.sockopt.dialMode));
}

/**
 * createScan(ctx, deps?) → { register(), stop(), busy() }
 * `deps` = { probes, getFreePorts, waitReady, runScan, runSpeed, fetchEchConfig } are the tests' seams.
 */
function createScan(ctx, deps = {}) {
  const runScan = deps.runScan || defaultRunScan;
  const runSpeed = deps.runSpeed || defaultRunSpeed;
  const fetchEch = deps.fetchEchConfig || defaultFetchEch;
  const checkPath = deps.checkPath || U.checkPath;
  let cdnStored = null;     // the store's updated lists, read once
  let cdnUpdating = null;   // the update under way: a second click joins it
  let run = null;                    // { runId, token, promise } while a scan is in flight

  function engineOffer() {
    return xrayEngines().map((id) => ({ id, label: engineLabel(id), installed: !!ctx.xray.binExists(id) }));
  }

  const versionOf = async (id) => { try { return String((await ctx.xray.version(id)) || ''); } catch { return ''; } };

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

  /** A config the scan cannot dial at all: '' when it can, else the page's error code. */
  function refusal(server) {
    if (isSingboxOnly(server)) return 'singbox only';
    try { applyTarget(server, {}); } catch (e) { return refusalOf(e); }
    return '';
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
      preset: T.suggestPreset(server, C.presetsOf(cdnLists())),
      unsupported: refusal(server),
      variants: V.applicability(server)
    };
  }

  /**
   * The cores a run can use: a core too old for this config, or one the app
   * would not run it on, is left out with the reason (see the header).
   */
  async function gateEngines(server, engines) {
    let cfg;
    try { cfg = buildMultiTestConfig([applyTarget(server, {})], [1]); } catch { return { engines, skipped: [] }; }
    const ok = [], skipped = [];
    const PATTN = 'xray-pattn';
    const oob = XM.pattnOobNeeds(cfg);
    const fm = !oob.length && usesFinalmask(cfg);
    const need = XM.usesMasqueWarp(cfg) ? XM.MASQUE_WARP_SINCE : (XM.usesMasque(cfg) ? XM.MASQUE_SINCE : '');
    const echOut = XM.usesEchOutbound(cfg);
    const ech = XM.usesEch(cfg);
    for (const id of engines) {
      const v = await versionOf(id);
      const known = /\d+\.\d+\.\d+/.test(v);
      const below = (min) => known && XM.versionBelow(v, min);
      const skip = (reason) => skipped.push({ engine: id, version: v, reason });
      if (oob.length && id !== PATTN) { skip(`${engineLabel(id)} ignores ${XM.pattnOobWhat(oob)} — this config runs on Xray-PattN ${XM.PATTN_OOB_SINCE}+ only`); continue; }
      if (oob.length && below(XM.PATTN_OOB_SINCE)) { skip(`${engineLabel(id)} ${v} does not know ${XM.pattnOobWhat(oob)} (${XM.PATTN_OOB_SINCE} and newer do)`); continue; }
      if (fm && id !== PATTN && engines.includes(PATTN)) { skip(`a finalmask config runs on Xray-PattN in the app — ${engineLabel(id)} is left out`); continue; }
      if (fm && id !== PATTN && below(XM.FINALMASK_SINCE)) { skip(`${engineLabel(id)} ${v} does not know finalmask (${XM.FINALMASK_SINCE} and newer do) — it would run unmasked`); continue; }
      if (need && below(need)) { skip(`${engineLabel(id)} ${v} does not know ${need === XM.MASQUE_WARP_SINCE ? 'MASQUE with a WARP account' : 'MASQUE'} (${need} and newer do)`); continue; }
      if (echOut && below(XM.ECH_OUTBOUND_SINCE)) { skip(`${engineLabel(id)} ${v} cannot dial the ECH query through its own outbound (${XM.ECH_OUTBOUND_SINCE} and newer can)`); continue; }
      if (ech && !need && below(XM.ECH_SINCE)) { skip(`${engineLabel(id)} ${v} does not know ECH (${XM.ECH_SINCE} and newer do)`); continue; }
      ok.push(id);
    }
    // a dialMode / merge config with no PattN in the run: say what it needs
    if (oob.length && !ok.length && !engines.includes(PATTN)) {
      skipped.push({ engine: PATTN, version: '', reason: `this config's ${XM.pattnOobWhat(oob)} needs Xray-PattN ${XM.PATTN_OOB_SINCE}+ — ${ctx.xray.binExists(PATTN) ? 'tick it under Cores' : 'install it under Settings → Cores'}` });
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

  /* ----------------------------- the shape of a run ----------------------------- */

  /**
   * The address box, counted (for the page's live line) or drawn (for a run):
   * { space?, total, taken, ranges, errors, exhausted, repeated }. Counting
   * never draws a sample — "N random" of a /8 is a million numbers, not
   * something to make on every key press.
   */
  function addressesOf(text, pick, draw) {
    if (draw) {
      const exclude = pick.fresh && pick.mode !== 'all' ? testedSet() : undefined;
      return T.pickAddresses(text, { mode: pick.mode, count: pick.count, perRange: pick.perRange, perBlock: pick.perBlock, block: pick.block }, { exclude });
    }
    const all = T.addressSpace(text);
    let taken = all.size;
    if (pick.mode === 'sample') taken = Math.min(pick.count, all.size, T.MAX_SAMPLE);
    else if (pick.mode === 'random') {
      taken = Math.min(T.MAX_SAMPLE, T.parseTargetText(text).ranges.reduce((s, r) => s + Math.min(pick.perRange, r.size), 0));
    } else if (pick.mode === 'block') {
      taken = T.countPerBlock(text, pick);
    }
    return { space: all, total: all.size, taken, ranges: all.ranges, errors: all.errors, exhausted: 0, repeated: 0 };
  }

  /** Which of the run's cores each variant may use; the others left out with the reason. */
  async function gateVariants(server, variants, engines) {
    const pv = ctx.xray.binExists('xray-pattn') ? await versionOf('xray-pattn') : '';
    const offer = { engines, installed: (id) => !!ctx.xray.binExists(id), version: (id) => (id === 'xray-pattn' ? pv : '') };
    const base = applyTarget(server, {});
    const kept = [], keptEngines = [], skipped = [];
    for (const v of variants) {
      const e = V.enginesFor(V.engineNeed(V.applyVariant(base, v), v), offer);
      if (e.reason) skipped.push({ key: v.key, label: v.label, reason: e.reason });
      else { kept.push(v); keptEngines.push(e.engines); }
    }
    return { kept, keptEngines, skipped };
  }

  /**
   * shape(req, server, { draw, engines }) → the run's make-up, or { error }:
   * the addresses (counted or drawn), the targets (a space), the variants
   * (built, gated to their cores, planned against the limit) and the items
   * the runner walks, with how many rows phase 1 will make.
   */
  async function shape(req, server, { draw, engines }) {
    const pick = sanitizePick(req.pick);
    const dial = dialOf(server);
    const text = String(req.ipsText || '');
    let addr = { space: null, total: 0, taken: 0, ranges: 0, errors: [], exhausted: 0, repeated: 0 };
    if (hasTokens(text)) {
      addr = addressesOf(text, pick, draw);
      if (!addr.taken) return { error: 'no targets', errors: addr.errors, pick };
    }
    const ports = T.parsePorts(String(req.portsText || ''));
    const snis = T.parseSnis(String(req.snisText || ''));
    if (snis.snis.length) {
      const s = sniSupport(server);
      if (!s.ok) return { error: 'sni', code: s.code, reason: s.reason };
    }
    const all = T.targetSpace({ space: addr.space, ports: ports.ports, snis: snis.snis, defaultAddr: dial.addr, defaultPort: dial.port });
    // counted, not drawn: the targets a draw would give, by the box's own address-to-target ratio
    const targetsN = draw || !addr.space || addr.taken === addr.total ? all.size : Math.round(all.size * (addr.taken / Math.max(1, addr.total)));
    const out = {
      pick, addr, targets: all, targetsN, ports: ports.ports.length || 1, snis: snis.snis.length || 1,
      portErrors: ports.errors, sniErrors: snis.errors, engines,
      items: all, total: all.size * engines.length, tests: targetsN, variants: null
    };
    const spec = V.sanitizeSpec(req.variants);
    if (!spec.dims.length) return out;
    const built = V.buildVariants(server, spec);
    const vinfo = {
      total: built.total, limit: spec.limit, errors: spec.errors,
      dims: built.dims.map((d) => ({ id: d.id, n: d.values.length })), skippedDims: built.skippedDims,
      skippedValues: built.skippedValues, dropped: built.dropped, count: 0, tests: 0, sampled: false, list: [], skipped: []
    };
    out.variants = vinfo;
    if (built.error) return Object.assign(out, { error: built.error, max: V.MAX_VARIANTS });
    if (!built.variants.length) return out;   // nothing applied: the plain run, the page says why
    const gate = await gateVariants(server, built.variants, engines);
    vinfo.skipped = gate.skipped;
    vinfo.count = gate.kept.length;
    vinfo.list = gate.kept.map((v, k) => ({ key: v.key, label: v.label, raw: v.raw, engines: gate.keptEngines[k] }));
    if (!gate.kept.length) return Object.assign(out, { error: 'no variant runs', tests: 0 });
    const plan = V.planTests(gate.kept.length, draw ? all.size : targetsN, spec.limit, gate.kept);
    vinfo.tests = plan.size;
    vinfo.sampled = plan.sampled;
    out.tests = plan.size;
    if (!draw) return out;
    const { kept, keptEngines } = gate;
    out.items = {
      size: plan.size,
      at: (i) => {
        const p = plan.at(i);
        const tg = all.at(p.t);
        const v = kept[p.v];
        return Object.assign({}, tg, { key: tg.key + '#' + v.key, variant: v, engines: keptEngines[p.v] });
      }
    };
    let rows = 0;
    if (plan.sampled) for (let i = 0; i < plan.size; i++) rows += keptEngines[plan.at(i).v].length;
    else rows = all.size * keptEngines.reduce((s, e) => s + e.length, 0);
    out.total = rows;
    return out;
  }

  /* ----------------------------- runs ----------------------------- */

  /**
   * Put a run in flight: its events go out as scan-progress with the newest
   * progress merged in — one per result (a run too big to list: one per
   * PASSING result), one on a stage change, one at the end, and between them
   * at most one every PROGRESS_MS.
   */
  function launch({ server, total, stage, token, start, streamAll = true, variants = false }) {
    const runId = 'scan-' + Date.now().toString(36) + '-' + crypto.randomBytes(3).toString('hex');
    let progress = { stage, done: 0, total, alive: 0, speedDone: 0, speedTotal: 0, etaMs: null };
    let done = 0, lastSent = 0;
    const perVariant = variants ? new Map() : null;
    const remember = total <= TESTED_CAP;
    const extra = () => (perVariant && !streamAll ? { variantStats: Object.fromEntries(perVariant) } : {});
    const send = (payload) => {
      lastSent = Date.now();
      try { ctx.send('scan-progress', Object.assign({ runId }, progress, extra(), payload)); } catch { /* window gone */ }
    };
    const hooks = {
      onProgress: (p) => {
        const moved = p.stage !== progress.stage;
        progress = Object.assign({}, p);
        if (moved && p.stage !== 'done') send({});
      },
      onResult: (result) => {
        done++;
        if (result && result.phase === 1 && result.addr && remember) rememberTested(result.addr);   // whatever the pick: it was tested
        if (perVariant && result && result.phase === 1 && result.variant) {
          const s = perVariant.get(result.variant) || [0, 0];
          s[0]++; if (result.score > 0) s[1]++;
          perVariant.set(result.variant, s);
        }
        if (streamAll || (result && (result.score > 0 || result.phase === 2))) send({ result });
        else if (Date.now() - lastSent >= PROGRESS_MS) send({});
      }
    };
    const promise = start(hooks).then(
      ({ cancelled }) => {
        ctx.log(`Scan ${runId}: ${cancelled ? 'stopped' : 'finished'} — ${done} row(s)`, 'info');
        send(Object.assign({ finished: true, cancelled: !!cancelled }, perVariant ? { variantStats: Object.fromEntries(perVariant) } : {}));
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
    const no = refusal(server);
    if (no) return { error: no };
    const engines = chooseEngines(req.engines);
    if (!engines.length) return { error: 'no engine' };
    const gate = await gateEngines(server, engines);
    if (!gate.engines.length) return { error: 'core too old', skipped: gate.skipped };
    const e = await withEch(server);
    return { server: e.server, original: server, engines: gate.engines, skipped: gate.skipped, ech: e.ech };
  }

  /** The counts the page's summary line shows, before anything runs: nothing is drawn, nothing starts. */
  async function plan(raw) {
    const req = isObj(raw) ? raw : {};
    let server;
    try { server = resolveServer(req); } catch (e) { return { error: e.message }; }
    const no = refusal(server);
    if (no) return { error: no };
    const chosen = chooseEngines(req.engines);
    const gate = chosen.length ? await gateEngines(server, chosen) : { engines: [], skipped: [] };
    const s = await shape(req, server, { draw: false, engines: gate.engines });
    if (s.error && !s.addr) return { error: s.error, errors: s.errors || [] };
    return {
      error: s.error || '', max: s.max || 0,
      addresses: s.addr ? { total: s.addr.total, taken: s.addr.taken, ranges: s.addr.ranges, errors: (s.addr.errors || []).length } : null,
      pick: s.pick, ports: s.ports, snis: s.snis, targets: s.targetsN, tests: s.tests,
      engines: gate.engines, enginesSkipped: gate.skipped,
      variants: s.variants ? Object.assign({}, s.variants, { list: undefined, keys: s.variants.list.map((v) => v.key) }) : null
    };
  }

  async function start(raw) {
    const req = raw && typeof raw === 'object' ? raw : {};
    if (run) return { error: 'busy' };

    // the config and the boxes first: a typo is answered without waiting on a core or DNS
    let server;
    try { server = resolveServer(req); } catch (e) { return { error: e.message }; }
    const no = refusal(server);
    if (no) return { error: no };
    const quick = await shape(Object.assign({}, req, { variants: null }), server, { draw: false, engines: ['xray'] });
    if (quick.error === 'no targets' || quick.error === 'sni') return quick;
    if (!quick.targets.size) return { error: 'no targets', errors: (quick.addr && quick.addr.errors) || [] };

    const tests = sanitizeTests(req.tests);
    const transport = transportOf(server);
    const measures = tests.delay || tests.down || tests.up || (tests.tcp && transport === 'tcp');
    if (!measures) return { error: 'no tests' };
    const opts = sanitizeOpts(req.opts);

    // the way out, and whether it tells the truth (upstream.js): asked beside the cores, not after them
    const up = U.upstreamOf(req.upstream);
    if (up && up.error) return { error: up.error };
    if (up && transport === 'udp') return { error: 'proxy-udp' };
    const pathAnswer = checkPath(up);

    const prep = await prepare(req);
    if (prep.error) return prep;
    if (run) return { error: 'busy' };   // another start won while this one asked DNS
    const path = await pathAnswer;
    if (/^proxy-/.test(path.state)) return { error: path.state, path };
    if (run) return { error: 'busy' };   // …or while this one asked the way out

    const s = await shape(req, prep.server, { draw: true, engines: prep.engines });
    if (s.error) return Object.assign({ error: s.error, skipped: prep.skipped }, s.variants ? { variants: s.variants } : {}, s.max ? { max: s.max, total: s.variants && s.variants.total } : {});
    // the TLS pre-check only where a plain handshake says something: TLS, no ECH, no anti-DPI trick anywhere
    const trick = (v, id, none) => !!v.raw[id] && v.raw[id] !== none;
    const variantTricks = !!(s.variants && s.variants.list.some((v) => trick(v, 'fragment', 'off') || trick(v, 'finalMask', 'none') || trick(v, 'dialMode', 'none')));
    // through a port: always, it is the only pre-check that says anything; no trick of the config's reaches the line there anyway
    const tlsCheck = up ? sniSupport(server).ok : (opts.prefilterTls && sniSupport(server).ok && !hasDpiTricks(server) && !variantTricks);

    const remembered = {
      serverId: req.serverId || null, link: req.serverId ? null : (req.link || null),
      ipsText: String(req.ipsText || ''), portsText: String(req.portsText || ''), snisText: String(req.snisText || ''),
      pick: s.pick, engines: prep.engines, tests, opts, variants: storableSpec(req.variants), upstream: U.sanitizeUpstream(req.upstream)
    };
    try { ctx.store.setLazy(STORE_KEY, remembered); } catch { /* the run matters more than the memory of it */ }

    const total = s.total;
    const streamAll = total <= STREAM_ALL;
    const token = { cancelled: false };
    const dial = dialOf(prep.server);
    const { runId, label } = launch({
      server: prep.server, total, stage: 'filter', token, streamAll, variants: !!(s.variants && s.variants.count),
      start: (hooks) => runScan(Object.assign({
        server: prep.server, targets: s.items, total, engines: prep.engines, tests, transport, sni: dial.sni, keepRows: streamAll, upstream: up,
        opts: Object.assign({}, opts, { prefilterTls: tlsCheck, probes: deps.probes, getFreePorts: deps.getFreePorts, waitReady: deps.waitReady }),
        xray: ctx.xray, token
      }, hooks))
    });
    const a = s.addr;
    const how = !a.total ? '' : ` — ${a.taken} of ${a.total} address(es)` + (s.pick.mode === 'sample' ? ', a random sample of all the ranges together' : (s.pick.mode === 'random' ? `, ${s.pick.perRange} from each of ${a.ranges} range(s)` : (s.pick.mode === 'block' ? `, ${s.pick.perBlock} from every /${s.pick.block}` : ''))) +
      (s.pick.mode !== 'all' && s.pick.fresh ? `, ${testedSet().size} tested before skipped` : '') + (a.exhausted ? `, ${a.exhausted} range(s) had to repeat` : '');
    const vs = s.variants && s.variants.count ? ` × ${s.variants.count} variant(s)${s.variants.sampled ? ` (${s.variants.tests} of ${s.variants.count * s.targets.size} tests, an even sample)` : ''}` : '';
    ctx.log(`Scan ${runId}: ${s.targets.size} target(s)${vs} × ${prep.engines.join(', ')} through "${label}"${how}${tlsCheck ? '; TLS pre-check' : ''}${up ? `; through ${up.host}:${up.port}` : ''}`, 'info');
    if (path.state === 'lying') ctx.log(up ? 'Scan: this port answers for an address that cannot exist: it goes through a VPN or a sniffing proxy, and the results will not be real' : 'Scan: something on this machine answers for an address that cannot exist (a VPN in TUN mode?): the results will not be real', 'warn');
    for (const x of prep.skipped) ctx.log('Scan: ' + x.reason, 'warn');
    for (const x of (s.variants && s.variants.skipped) || []) ctx.log(`Scan: variant ${x.label} left out — ${x.reason}`, 'warn');
    return {
      runId, total, targets: s.targets.size, tests: s.tests, truncated: !!(a.truncated),
      errors: a.errors || [], portErrors: s.portErrors, sniErrors: s.sniErrors,
      pick: s.pick, ranges: a.ranges || 0, exhausted: a.exhausted || 0,
      addresses: a.total ? { total: a.total, taken: a.taken } : null,
      streamAll, transport, ech: prep.ech, skipped: prep.skipped, engines: prep.engines,
      variants: s.variants, prefilter: tests.tcp && transport === 'tcp' && (tlsCheck || !up) ? (tlsCheck ? 'tls' : 'tcp') : '',
      path, proxyTricks: !!up && (hasDpiTricks(server) || variantTricks)
    };
  }

  /** A row's variant, read again from what the page sent: null without one, `{ error }` when it does not read. */
  function rowVariant(raw) {
    if (!raw || !isObj(raw) || !Object.keys(raw).length) return null;
    return V.variantFromRaw(raw);
  }

  /** Phase 2 alone on rows the table chose; every row names its engine (and its variant, when it has one). */
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
      const variant = rowVariant(r.variant);
      if (variant && variant.error) continue;
      const key = T.addrPort(addr, port) + '|' + (sni || '') + (variant ? '#' + variant.key : '');
      if (seen.has(`${key}|${r.engine}`)) continue;
      seen.add(`${key}|${r.engine}`);
      rows.push(Object.assign({ key, addr, port, sni, engine: r.engine, tcp: r.tcp, delay: r.delay }, variant ? { variant } : {}));
    }
    if (!rows.length) return { error: 'no rows' };

    const t = req.tests && typeof req.tests === 'object' ? req.tests : { down: true, up: false };
    const tests = { tcp: false, delay: false, down: !!t.down, up: !!t.up };
    if (!tests.down && !tests.up) return { error: 'no tests' };
    const opts = sanitizeOpts(req.opts);
    const up = U.upstreamOf(req.upstream);
    if (up && up.error) return { error: up.error };
    if (up && transportOf(prep.server) === 'udp') return { error: 'proxy-udp' };

    const token = { cancelled: false };
    const { runId, label } = launch({
      server: prep.server, total: rows.length, stage: 'speed', token,
      start: (hooks) => runSpeed(Object.assign({
        server: prep.server, rows, tests, upstream: up,
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

  /** The CDN lists the update button has brought; what the store holds that still reads. */
  function cdnLists() {
    if (!cdnStored) cdnStored = C.readStored(ctx.store.get(C.STORE_KEY, null));
    return cdnStored;
  }

  /**
   * scan:cdnUpdate { ids?, upstream? } → { results, ranges }: every CDN's list (or
   * `ids`'), asked from the CDN itself, through the scan's port when it has one.
   * `results` is one row per CDN (cdnRanges.updateLists); `ranges` is every list as
   * it now stands. A list that failed stays as it was.
   */
  function cdnUpdate(raw) {
    if (cdnUpdating) return cdnUpdating;
    const ids = raw && Array.isArray(raw.ids) ? raw.ids : null;
    const up = U.upstreamOf(raw && raw.upstream);
    if (up && up.error) return { error: up.error };
    cdnUpdating = (async () => {
      const u = await C.updateLists(ids, cdnLists(), { get: deps.fetchText || (up ? (url) => C.fetchText(url, { via: up }) : undefined) });
      cdnStored = u.stored;
      try { ctx.store.set(C.STORE_KEY, u.stored); } catch (e) { ctx.log('Scan: the updated lists were not saved: ' + ((e && e.message) || e), 'warn'); }
      for (const r of u.results) {
        if (r.ok) ctx.log(`Scan: ${r.name} list updated — ${r.count} range(s), ${r.added} new, ${r.removed} gone`, 'info');
        else ctx.log(`Scan: ${r.name} list not updated (${r.error}); the one it had stays`, 'warn');
      }
      return { results: u.results, ranges: C.presetsOf(u.stored) };
    })().finally(() => { cdnUpdating = null; });
    return cdnUpdating;
  }

  /** scan:pathCheck { upstream? } → { via, state, error? }: is the way out honest? (upstream.js) */
  async function pathCheck(raw) {
    const up = U.upstreamOf(raw && raw.upstream);
    if (up && up.error) return { via: 'proxy', state: 'proxy-addr' };
    return checkPath(up);
  }

  function presets() {
    return {
      cfRanges: T.CF_IPV4_RANGES.slice(),
      ranges: Object.assign(JSON.parse(JSON.stringify(T.PRESETS)), C.presetsOf(cdnLists())),
      defaults: Object.assign({}, PRESET_DEFAULTS),
      presets: { fast: Object.assign({}, PRESETS.fast), balanced: Object.assign({}, PRESETS.balanced), accurate: Object.assign({}, PRESETS.accurate) },
      last: ctx.store.get(STORE_KEY, null) || null,
      engines: engineOffer(),
      tested: testedSet().size,
      dimensions: V.catalog(),
      limits: { variants: V.DEFAULT_LIMIT, variantsMax: V.MAX_LIMIT, sampleMax: T.MAX_SAMPLE, maxVariants: V.MAX_VARIANTS, pick: Object.assign({}, PICK_DEFAULTS) },
      sets: listSets()
    };
  }

  /** What the chosen config allows (page hints and the suggested addresses). */
  function suggest(raw) {
    const req = raw && typeof raw === 'object' ? raw : {};
    let server;
    try { server = resolveServer(req); } catch (e) { return { error: e.message }; }
    return factsOf(server);
  }

  /**
   * The config with one target — and the row's variant, when it has one — in
   * it: a new record named after both, its share link rebuilt. `loses` lists
   * what of the variant a link cannot carry (dialMode, mux: the record's own
   * fields) — such a row is copied as JSON.
   */
  function recordFor(req) {
    const server = resolveServer(req);
    const addr = T.normalizeAddr(req.addr || req.ip);
    if (!addr) throw new Error('invalid ip');
    const port = req.port != null && req.port !== '' ? Number(req.port) : null;
    const sni = req.sni ? String(req.sni) : null;
    const variant = rowVariant(req.variant);
    if (variant && variant.error) throw new Error(variant.error);
    let record = applyTarget(server, { addr, port, sni });
    if (variant) record = V.applyVariant(record, variant);
    record.id = 'sv-' + crypto.randomBytes(6).toString('hex');
    const label = T.addrPort(addr, port) + (sni ? ' ' + sni : '') + (variant ? ' · ' + variant.label : '');
    record.name = `${str(req.name, '') || server.name || server.address} [${label}]`;
    delete record.importedFrom; delete record.importedId; delete record.importedSub;
    if (req.engine && xrayEngines().includes(req.engine)) {
      // the engine the winning row ran on; the official core is the unmarked default
      if (req.engine === 'xray') delete record.engine; else record.engine = req.engine;
    }
    if (variant && variant.set && variant.set.mux === 'on') record.mux = 'on';
    const loses = variant ? V.linkLoses(variant) : [];
    let link = '';
    try { link = buildShareLink(record); } catch { link = ''; }
    if (!link && record.source === 'json' && record.json) link = JSON.stringify(record.json);
    record.raw = (loses.length ? '' : link) || record.raw || '';
    return { record, link: loses.length ? '' : link, loses };
  }

  /** A record as an Xray client config IRNetFree imports: its outbound and the helpers it dials through, as the scan ran them. */
  function jsonOf(record) {
    const cfg = buildTestConfig(record, 1080);
    return JSON.stringify({ remarks: record.name, outbounds: cfg.outbounds }, null, 2);
  }

  function apply(raw) {
    const req = raw && typeof raw === 'object' ? raw : {};
    let made;
    try { made = recordFor(req); } catch (e) { return { error: e.code ? refusalOf(e) : e.message }; }
    const saved = ctx.addServer(made.record);
    return Object.assign({}, saved, { link: made.link, servers: ctx.getServers() });
  }

  /** Share links for rows — "copy the best N", ready to paste into IRNetFree; a row a link cannot carry is counted, not copied. */
  function links(raw) {
    const req = raw && typeof raw === 'object' ? raw : {};
    const out = [];
    let lossy = 0;
    for (const r of Array.isArray(req.rows) ? req.rows.slice(0, 500) : []) {
      try {
        const made = recordFor(Object.assign({}, req, r, { rows: undefined }));
        if (made.loses.length) lossy++;
        else if (made.link) out.push(made.link);
      } catch { /* a row that no longer fits is left out */ }
    }
    return { links: out, lossy };
  }

  /** One row as a link and as JSON — "copy as link" / "copy JSON". */
  function copy(raw) {
    const req = raw && typeof raw === 'object' ? raw : {};
    let made;
    try { made = recordFor(req); } catch (e) { return { error: e.code ? refusalOf(e) : e.message }; }
    let json = '';
    try { json = jsonOf(made.record); } catch (e) { json = ''; }
    return { link: made.link, json, loses: made.loses, name: made.record.name };
  }

  function exportText(raw) {
    const req = raw && typeof raw === 'object' ? raw : {};
    const results = (Array.isArray(req.results) ? req.results : []).filter(Boolean);
    const format = req.format || 'csv';
    if (format === 'json') return JSON.stringify(results, null, 2);
    if (format === 'csv') return [CSV_HEADER, ...results.map(csvRow)].join('\r\n') + '\r\n';
    return { error: 'unknown format' };
  }

  /* ----------------------------- saved parameter sets ----------------------------- */

  function listSets() {
    const raw = ctx.store.get(SETS_KEY, null);
    return (Array.isArray(raw) ? raw : []).filter((s) => isObj(s) && typeof s.name === 'string' && s.name.trim());
  }

  /**
   * scan:sets { action: 'list' | 'save' | 'delete', name, set } → { sets }:
   * a named selection of dimensions and values (and the limit), kept as the
   * raw values that read — a save under an existing name replaces it.
   */
  function sets(raw) {
    const req = isObj(raw) ? raw : {};
    const action = req.action || 'list';
    if (action === 'list') return { sets: listSets() };
    const name = String(req.name || '').trim().slice(0, 60);
    if (!name) return { error: 'no name' };
    let all = listSets().filter((s) => s.name !== name);
    if (action === 'save') {
      const set = storableSpec(isObj(req.set) ? req.set : {});
      if (!Object.keys(set.dims).length) return { error: 'empty set' };
      all = [Object.assign({ name, savedAt: Date.now() }, set)].concat(all).slice(0, MAX_SETS);
    } else if (action !== 'delete') return { error: 'unknown action' };
    try { ctx.store.set(SETS_KEY, all); } catch { /* reported by what the page reads back */ }
    return { sets: all };
  }

  const handlers = {
    'scan:start': start,
    'scan:retest': retest,
    'scan:stop': stop,
    'scan:presets': presets,
    'scan:suggest': suggest,
    'scan:plan': plan,
    'scan:apply': apply,
    'scan:links': links,
    'scan:copy': copy,
    'scan:export': exportText,
    'scan:forget': forget,
    'scan:sets': sets,
    'scan:cdnUpdate': cdnUpdate,
    'scan:pathCheck': pathCheck
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

module.exports = { createScan, PRESET_DEFAULTS, PRESETS, PICK_DEFAULTS, CSV_HEADER, STREAM_ALL, sanitizeOpts, sanitizeTests, sanitizePick };
