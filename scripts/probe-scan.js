#!/usr/bin/env node
'use strict';
/**
 * plus: a live, local-only proof of the scanner (spec 2026-10-15 §5).
 *
 * A VLESS server core on 127.0.0.1 (built by the Server tab's own code) and a
 * local web page; then a real scan through the Scan page's own handlers
 * (createScan) on every installed Xray-format core: four targets — the
 * server's address and port, the same address on a port nobody listens on,
 * and 127.0.0.2 on both ports (the server listens on 127.0.0.1 only). Exactly
 * the first must come out alive, with a delay measured through the tunnel and
 * a download speed from phase 2; the others must die at TCP.
 *
 * The latency and download targets are the local page, so no internet is
 * needed — except on cores that do not carry a scan to a loopback destination
 * through the server's exit (the 26.9+ policy probe-reverse.js meets too):
 * there the same scan is repeated against public pages (cp.cloudflare.com,
 * speed.cloudflare.com) and the probe says so. Every row is printed when a
 * scan does not pass, so a failure in CI reads from the log. Nothing binds
 * 0.0.0.0, nothing touches the system; every process is killed and the temp
 * dir removed at the end.
 *
 *   node scripts/probe-scan.js       (IRNF_ENGINES=xray,xray-pattn to choose)
 */
const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { XrayManager, getFreePorts } = require('../src/main/xrayManager');
const X = require('../src/main/xserver/config');
const { createScan } = require('../src/main/scan');

const ENGINES = (process.env.IRNF_ENGINES || 'xray,xray-pattn').split(',').map(s => s.trim()).filter(Boolean);
const delay = (ms) => new Promise(r => setTimeout(r, ms));
/** In GitHub Actions a line also becomes an annotation — readable from the API without logging in. */
const annotate = (level, text) => { if (process.env.GITHUB_ACTIONS) console.log(`::${level} title=probe-scan::${String(text).replace(/%/g, '%25').replace(/\r?\n/g, '%0A')}`); };

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-plus-scanprobe-'));
  const xray = new XrayManager({ dataDir: tmp });
  const engines = ENGINES.filter(e => xray.binExists(e));
  if (!engines.length) { console.log('no core installed — skipped'); return 0; }

  // the page: a 204 for the latency probe, bytes for the download
  const web = http.createServer((req, res) => {
    const m = /bytes=(\d+)/.exec(req.url || '');
    if (m) {
      const n = Math.min(Number(m[1]) || 0, 20e6);
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': n });
      const chunk = Buffer.alloc(64 * 1024, 7);
      let left = n;
      const pump = () => {
        while (left > 0) {
          const k = Math.min(left, chunk.length);
          left -= k;
          if (!res.write(k === chunk.length ? chunk : chunk.subarray(0, k))) return res.once('drain', pump);
        }
        return res.end();
      };
      return pump();
    }
    res.writeHead(204);
    return res.end();
  });
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const webPort = web.address().port;

  const [pIn, pDead, apiPort] = await getFreePorts(3);
  const inbound = X.newInbound('vless', { remark: 'probe', listen: '127.0.0.1', port: pIn, network: 'ws', path: '/scan', security: 'none' });
  const client = X.newClient('vless', { email: 'probe' });
  inbound.clients = [client];
  const model = X.normalizeModel({ schema: 2, publicAddress: '127.0.0.1', inbounds: [inbound], outbounds: [X.newOutbound('freedom', { tag: 'direct' })] });
  const link = X.clientLink(inbound, client, model, { address: '127.0.0.1' });

  const store = new Map();
  const events = [];
  const handlers = {};
  const ctx = {
    handle: (ch, fn) => { handlers[ch] = fn; },
    send: (ch, p) => { if (ch === 'scan-progress') events.push(p); },
    notify: () => {}, log: () => {},
    store: { get: (k, d) => (store.has(k) ? store.get(k) : d), set: (k, v) => { store.set(k, v); return true; }, setLazy: (k, v) => { store.set(k, v); return true; } },
    dataDir: tmp, xray, platform: process.platform,
    getSettings: () => ({}), getServers: () => [], addServer: (r) => r, resolveTarget: () => ({ server: null })
  };
  const scan = createScan(ctx);
  scan.register();

  const LOCAL = { delayHost: '127.0.0.1', delayPort: webPort, delayPath: '/', downHost: '127.0.0.1', downPort: webPort, downTls: false, downBytes: 2e6, downPath: '/__down?bytes=2000000' };
  const PUBLIC = { delayHost: 'cp.cloudflare.com', delayPort: 80, delayPath: '/', downHost: 'speed.cloudflare.com', downPort: 443, downTls: true, downBytes: 2e6, downPath: '/__down?bytes=2000000' };

  async function scanWith(engine, targetsOpts) {
    events.length = 0;
    const reply = await handlers['scan:start']({
      link, engines: [engine],
      ipsText: '127.0.0.1\n127.0.0.2', portsText: `${pIn}, ${pDead}`,
      tests: { tcp: true, delay: true, down: true, up: false },
      opts: Object.assign({ batch: 10, delaySamples: 2, tcpTimeout: 1500, delayTimeout: 6000, speedTop: 3 }, targetsOpts)
    });
    if (reply.error) return { reply, rows: null };
    const t0 = Date.now();
    while (!events.some(e => e.finished) && Date.now() - t0 < 90000) await delay(100);
    const rows = new Map();
    for (const e of events) if (e.result) rows.set(e.result.key, e.result);
    return { reply, rows };
  }

  function verdict(rows) {
    const good = rows.get(`127.0.0.1:${pIn}|`);
    const dead = [rows.get(`127.0.0.1:${pDead}|`), rows.get(`127.0.0.2:${pIn}|`), rows.get(`127.0.0.2:${pDead}|`)];
    const ok = !!(good && good.score > 0 && good.delay && good.delay.loss < 1 && good.phase === 2 && good.down && good.down.ok
      && dead.every(r => r && r.tcp && !r.tcp.ok && !(r.score > 0)));
    return { good, dead, ok, tunnelUp: !!(good && good.tcp && good.tcp.ok) };
  }

  function show(engine, rows) {
    for (const r of rows.values()) {
      const d = r.delay;
      const tcp = r.tcp ? (r.tcp.ok ? r.tcp.ms + ' ms' : 'fail ' + (r.tcp.error || '')) : '-';
      const lat = d ? (d.loss < 1 ? d.median + ' ms' : 'lost ' + JSON.stringify(d.samples)) : '-';
      const down = r.down ? (r.down.ok ? r.down.mbps + ' Mbps' : 'fail ' + (r.down.error || '')) : '-';
      const line = `${engine} ${r.key} phase ${r.phase}: tcp ${tcp}; delay ${lat}; down ${down}; score ${r.score}${r.error ? '; error ' + r.error : ''}`;
      console.log('  ' + line);
      annotate('warning', line);
    }
  }

  let failed = 0;
  let server;
  try {
    const serverCfg = X.buildServerConfig(model, { apiPort, servers: [], geoAvailable: false });
    // the exit lets every destination through, the local page included (older cores ignore the field)
    for (const o of serverCfg.outbounds) if (o.protocol === 'freedom') o.settings = Object.assign({}, o.settings, { finalRules: [{ action: 'allow' }] });
    server = await xray.startTest(serverCfg, engines[0]);
    await delay(300);
    for (const engine of engines) {
      let run = await scanWith(engine, LOCAL);
      if (run.reply.error) { console.log(`${engine}: refused — ${run.reply.error}`); failed++; continue; }
      let v = verdict(run.rows);
      let where = 'the local page';
      if (!v.ok && v.tunnelUp) {
        show(engine, run.rows);
        console.log(`  ${engine}: the local page was not reached through the server core — repeating against public pages`);
        run = await scanWith(engine, PUBLIC);
        if (run.rows) v = verdict(run.rows);
        where = 'public pages';
      }
      const g = v.good, d = g && g.delay;
      const good = g ? `tcp ${g.tcp && g.tcp.ms} ms, delay ${d ? d.median : '?'} ms, down ${g.down && g.down.ok ? g.down.mbps + ' Mbps' : 'none'}, score ${g.score}` : 'missing';
      const dead = v.dead.map(r => (r && r.tcp && !r.tcp.ok ? 'tcp ×' : 'WRONG')).join(', ');
      console.log(`${engine} via ${where}: ${run.reply.targets} targets — good ${good}; dead ${dead} → ${v.ok ? 'PASS' : 'FAIL'}`);
      if (!v.ok) { if (run.rows) show(engine, run.rows); annotate('error', `${engine} via ${where}: FAIL — good ${good}; dead ${dead}`); failed++; }
    }
  } finally {
    try { await scan.stop(); } catch { /* none running */ }
    if (server) { try { server.cleanup(); } catch { /* gone */ } }
    await new Promise((r) => web.close(r));
    await delay(300);
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* a core still closing */ }
  }
  console.log(`scan probe: ${engines.length - failed} pass, ${failed} fail`);
  return failed ? 1 : 0;
}

main().then((code) => process.exit(code), (e) => { console.error(e); process.exit(1); });
