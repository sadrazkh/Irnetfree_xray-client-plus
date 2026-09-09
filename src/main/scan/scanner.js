'use strict';
/**
 * plus: the IP-scan runner — `ping:realMany` generalised.
 *
 * Per engine, per batch of IPs: one throwaway core whose inbound k is routed
 * to the config dialled through IP k (buildMultiTestConfig), the probes of
 * the batch at most `concurrency` in flight, the core killed in `finally`.
 * A result leaves through onResult the moment its IP is done, so the table
 * fills live. A core that fails to start marks its batch and the run moves
 * on; nothing here rejects for one bad IP.
 *
 * Stop is a flag on the token, read before each batch and each IP. While a
 * batch is in flight a short poll kills its core as soon as the flag is set,
 * so the probes fail now rather than at their timeouts; whatever those
 * probes return afterwards was measured against a dead core and is dropped.
 */
const { buildMultiTestConfig } = require('../configBuilder');
const { getFreePorts: realGetFreePorts } = require('../xrayManager');
const { tcpPing, pLimit } = require('../netutils');
const { withAddress } = require('./substitute');
const { scoreResult } = require('./score');
const probesMod = require('./probes');

const SCAN_DEFAULTS = {
  concurrency: 8, batch: 20, delaySamples: 3,
  tcpTimeout: 3000,
  delayHost: 'cp.cloudflare.com', delayPort: 80, delayPath: '/', delayTimeout: 8000,
  downHost: 'speed.cloudflare.com', downPort: 443, downPath: '', downTls: true, downBytes: 10e6, downMaxMs: 8000, downTimeout: 8000,
  upHost: 'speed.cloudflare.com', upPort: 443, upPath: '/__up', upTls: true, upBytes: 2e6, upTimeout: 20000
};
const DEFAULT_TESTS = { tcp: true, delay: true, down: false, up: false };
const DEFAULT_PROBES = {
  tcpPing,
  delaySeries: probesMod.delaySeries,
  downloadThroughProxy: probesMod.downloadThroughProxy,
  uploadThroughProxy: probesMod.uploadThroughProxy
};
const CANCEL_POLL_MS = 250;

function emptyResult(ip, engine) {
  return { ip, engine, tcp: null, delay: null, down: null, up: null, score: 0, error: null };
}

/** Score desc, then delay avg asc; rows with no usable delay sort after those with one. */
const avgOf = (r) => (r.delay && r.delay.loss < 1 ? r.delay.avg : Number.MAX_SAFE_INTEGER);
function byRank(a, b) {
  return (b.score - a.score) || (avgOf(a) - avgOf(b)) || 0;
}

/**
 * One IP on one engine. A failed TCP connect or a tunnel that never answers
 * ends the row early — the remaining probes would only burn their timeouts.
 */
async function probeOne(ip, engine, port, { server, tests, o, probes, token }) {
  const r = emptyResult(ip, engine);
  if (tests.tcp) {
    r.tcp = await probes.tcpPing(ip, server.port, o.tcpTimeout);
    if (!r.tcp.ok) return r;
  }
  if (token.cancelled) return r;
  if (tests.delay) {
    r.delay = await probes.delaySeries(port, { n: o.delaySamples, host: o.delayHost, port: o.delayPort, path: o.delayPath, timeout: o.delayTimeout });
    if (r.delay.loss >= 1) return r;
  }
  if (token.cancelled) return r;
  if (tests.down) {
    r.down = await probes.downloadThroughProxy(port, {
      host: o.downHost, port: o.downPort, path: o.downPath || `/__down?bytes=${o.downBytes}`,
      tls: o.downTls, bytes: o.downBytes, maxMs: o.downMaxMs, timeout: o.downTimeout
    });
  }
  if (token.cancelled) return r;
  if (tests.up) {
    r.up = await probes.uploadThroughProxy(port, {
      host: o.upHost, port: o.upPort, path: o.upPath, tls: o.upTls, bytes: o.upBytes, timeout: o.upTimeout
    });
  }
  return r;
}

/**
 * runScan({ server, ips, engines, tests, opts, xray, onResult, onProgress, token })
 *   → Promise<{ results, cancelled }>
 * `opts.probes` and `opts.getFreePorts` are injection points for tests.
 */
async function runScan(args) {
  const { server, xray, onResult, onProgress } = args;
  const ips = Array.isArray(args.ips) ? args.ips : [];
  const engines = Array.isArray(args.engines) ? args.engines : [];
  const token = args.token || { cancelled: false };
  const tests = Object.assign({}, DEFAULT_TESTS, args.tests);
  const o = Object.assign({}, SCAN_DEFAULTS, args.opts);
  const probes = Object.assign({}, DEFAULT_PROBES, o.probes);
  const getFreePorts = o.getFreePorts || realGetFreePorts;
  const batchSize = Math.max(1, Math.floor(o.batch) || SCAN_DEFAULTS.batch);
  const concurrency = Math.max(1, Math.floor(o.concurrency) || SCAN_DEFAULTS.concurrency);

  const results = [];
  const total = ips.length * engines.length;
  let done = 0;
  let cancelled = false;
  const emit = (r) => {
    r.score = scoreResult(r);
    results.push(r);
    done++;
    if (onResult) onResult(r);
    if (onProgress) onProgress({ done, total });
  };

  outer: for (const engine of engines) {
    for (let i = 0; i < ips.length; i += batchSize) {
      if (token.cancelled) { cancelled = true; break outer; }
      const batch = ips.slice(i, i + batchSize);
      const emitted = new Set();
      let test = null, cleaned = false, watch = null;
      const cleanup = () => {
        if (cleaned || !test) return;
        cleaned = true;
        try { test.cleanup(); } catch { /* already gone */ }
      };
      try {
        const servers = batch.map((ip) => withAddress(server, ip));
        const ports = await getFreePorts(batch.length);
        test = await xray.startTest(buildMultiTestConfig(servers, ports), engine);
        watch = setInterval(() => { if (token.cancelled) cleanup(); }, CANCEL_POLL_MS);
        if (watch.unref) watch.unref();
        const limit = pLimit(concurrency);
        await Promise.all(batch.map((ip, k) => limit(async () => {
          if (token.cancelled) return;
          const r = await probeOne(ip, engine, ports[k], { server, tests, o, probes, token });
          if (token.cancelled) return;
          emitted.add(ip);
          emit(r);
        })));
      } catch (err) {
        for (const ip of batch) {
          if (emitted.has(ip)) continue;
          const r = emptyResult(ip, engine);
          r.error = (err && err.message) || String(err);
          emitted.add(ip);
          emit(r);
        }
      } finally {
        if (watch) clearInterval(watch);
        cleanup();
      }
      if (token.cancelled) { cancelled = true; break outer; }
    }
  }

  results.sort(byRank);
  return { results, cancelled };
}

module.exports = { runScan, SCAN_DEFAULTS, DEFAULT_TESTS, emptyResult, byRank };
