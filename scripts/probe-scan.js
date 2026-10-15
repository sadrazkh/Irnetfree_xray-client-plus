#!/usr/bin/env node
'use strict';
/**
 * plus: a live, local-only proof of the scanner (spec 2026-10-15 §5).
 *
 * A VLESS server core on 127.0.0.1 (built by the Server tab's own code) and a
 * local web page; then a real scan through the Scan page's own handlers
 * (createScan) on every installed Xray-format core: three targets — the
 * server's address and port, the same address on a port nobody listens on,
 * and 127.0.0.2 on the right port (the server listens on 127.0.0.1 only).
 * Exactly the first must come out alive, with a delay measured through the
 * tunnel and a download speed from phase 2; the other two must die at TCP.
 * The latency and download targets are the local page, so no internet is
 * needed. Nothing binds 0.0.0.0, nothing touches the system; every process is
 * killed and the temp dir removed at the end.
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
      const pump = () => { while (left > 0) { const k = Math.min(left, chunk.length); left -= k; if (!res.write(k === chunk.length ? chunk : chunk.subarray(0, k))) return res.once('drain', pump); } return res.end(); };
      return pump();
    }
    res.writeHead(204); return res.end();
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

  let failed = 0;
  let server;
  try {
    server = await xray.startTest(X.buildServerConfig(model, { apiPort, servers: [], geoAvailable: false }), engines[0]);
    await delay(300);
    for (const engine of engines) {
      events.length = 0;
      const reply = await handlers['scan:start']({
        link, engines: [engine],
        ipsText: '127.0.0.1\n127.0.0.2', portsText: `${pIn}, ${pDead}`,
        tests: { tcp: true, delay: true, down: true, up: false },
        opts: { batch: 10, delaySamples: 2, delayHost: '127.0.0.1', delayPort: webPort, delayPath: '/', tcpTimeout: 1500, delayTimeout: 4000, speedTop: 3, downHost: '127.0.0.1', downPort: webPort, downTls: false, downBytes: 2e6, downPath: '/__down?bytes=2000000' }
      });
      if (reply.error) { console.log(`${engine}: refused — ${reply.error}`); failed++; continue; }
      const t0 = Date.now();
      while (!events.some(e => e.finished) && Date.now() - t0 < 60000) await delay(100);
      const rows = new Map();
      for (const e of events) if (e.result) rows.set(e.result.key, e.result);
      const good = rows.get(`127.0.0.1:${pIn}|`);
      const dead = [rows.get(`127.0.0.1:${pDead}|`), rows.get(`127.0.0.2:${pIn}|`)];
      const ok = !!(good && good.score > 0 && good.delay && good.delay.loss < 1 && good.phase === 2 && good.down && good.down.ok
        && dead.every(r => r && r.tcp && !r.tcp.ok && !(r.score > 0)));
      const d = good && good.delay;
      console.log(`${engine}: ${reply.targets} targets — good ${good ? `tcp ${good.tcp && good.tcp.ms} ms, delay ${d ? d.median : '?'} ms, down ${good.down && good.down.ok ? good.down.mbps + ' Mbps' : 'none'}, score ${good.score}` : 'missing'}; dead ${dead.map(r => (r && r.tcp && !r.tcp.ok ? 'tcp ×' : 'WRONG')).join(', ')} → ${ok ? 'PASS' : 'FAIL'}`);
      if (!ok) failed++;
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
