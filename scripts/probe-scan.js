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
const net = require('net');
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
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

  const [pIn, pDead, apiPort, pTls] = await getFreePorts(4);
  const inbound = X.newInbound('vless', { remark: 'probe', listen: '127.0.0.1', port: pIn, network: 'ws', path: '/scan', security: 'none' });
  const client = X.newClient('vless', { email: 'probe' });
  inbound.clients = [client];
  // the parameter matrix's server: raw TCP + TLS that speaks http/1.1 only, under a certificate the client pins
  const pem = mintCert(xray, engines[0], tmp);
  const tlsInbound = X.newInbound('vless', { remark: 'probe-tls', listen: '127.0.0.1', port: pTls, network: 'tcp', security: 'tls', tls: { certFile: pem.certFile, keyFile: pem.keyFile, serverName: 'localhost', alpn: ['http/1.1'] } });
  const tlsClient = X.newClient('vless', { email: 'probe-tls' });
  tlsInbound.clients = [tlsClient];
  const model = X.normalizeModel({ schema: 2, publicAddress: '127.0.0.1', inbounds: [inbound, tlsInbound], outbounds: [X.newOutbound('freedom', { tag: 'direct' })] });
  const link = X.clientLink(inbound, client, model, { address: '127.0.0.1' });
  const tlsLink = X.clientLink(model.inbounds[1], model.inbounds[1].clients[0], model, { address: '127.0.0.1' }).replace('#', `&pcs=${pem.pin}#`);

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

    // the parameter matrix: fingerprint × ALPN × dialMode on the TLS server, every core at once
    const vr = await variantRun(LOCAL);
    let vres = vr;
    if (!vr.ok && vr.tunnelUp) {
      console.log('  variants: the local page was not reached through the server core — repeating against public pages');
      vres = await variantRun(PUBLIC);
    }
    if (!vres.ok) failed++;

    // through a SOCKS port: real cores dial by way of it, and the port that is down stops the run
    const ur = await upstreamRun(LOCAL);
    if (!ur.ok && ur.tunnelUp) {
      console.log('  through a port: the local page was not reached through the server core — repeating against public pages');
      if (!(await upstreamRun(PUBLIC)).ok) failed++;
    } else if (!ur.ok) failed++;
  } finally {
    try { await scan.stop(); } catch { /* none running */ }
    if (server) { try { server.cleanup(); } catch { /* gone */ } }
    await new Promise((r) => web.close(r));
    await delay(300);
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* a core still closing */ }
  }
  console.log(`scan probe: ${engines.length + 2 - failed} pass, ${failed} fail (one run per core, the parameter matrix, then through a port)`);
  return failed ? 1 : 0;

  /**
   * Through a port (upstream.js), on every core: a little SOCKS5 server here that
   * only forwards and counts, on loopback. What must hold: the live port passes and
   * the port saw it, so the core really dialed by way of it; the dead port does not
   * pass, whatever the SOCKS reply said; a ws config with no TLS skips the pre-check
   * and still passes on the core's own answer; a port that is down stops the run.
   */
  async function upstreamRun(targetsOpts) {
    const seen = [];
    const proxy = net.createServer((c) => {
      let buf = Buffer.alloc(0), stage = 0;
      c.on('error', () => {});
      c.on('data', function onData(d) {
        buf = Buffer.concat([buf, d]);
        if (stage === 0 && buf.length >= 2 + buf[1]) { buf = buf.subarray(2 + buf[1]); c.write(Buffer.from([5, 0])); stage = 1; }
        if (stage !== 1 || buf.length < 5) return;
        const atyp = buf[3], hlen = atyp === 1 ? 4 : atyp === 4 ? 16 : 1 + buf[4];
        if (buf.length < 4 + hlen + 2) return;
        const host = atyp === 1 ? [...buf.subarray(4, 8)].join('.') : atyp === 3 ? buf.subarray(5, 4 + hlen).toString() : '::1';
        const port = buf.readUInt16BE(4 + hlen);
        const rest = buf.subarray(4 + hlen + 2);
        stage = 2;
        seen.push(port);
        c.removeListener('data', onData);
        c.pause();   // what the core sends next waits for the pipe, or it is lost
        // success at once, as Xray's inbound answers; what is dead simply closes after
        c.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
        const up = net.connect(port, host, () => { if (rest.length) up.write(rest); c.pipe(up); up.pipe(c); });
        up.on('error', () => c.destroy());
        up.on('close', () => c.destroy());
        c.on('close', () => up.destroy());
      });
    });
    await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
    const upstream = { on: true, addr: `127.0.0.1:${proxy.address().port}` };
    const problems = [];
    let tunnelUp = false;
    const once = async (engine, startLink, livePort, wantPrefilter) => {
      events.length = 0;
      seen.length = 0;
      const reply = await handlers['scan:start']({
        link: startLink, engines: [engine], ipsText: '127.0.0.1', portsText: `${livePort}, ${pDead}`,
        tests: { tcp: true, delay: true, down: false, up: false },
        opts: Object.assign({ batch: 10, delaySamples: 2, tcpTimeout: 1500, delayTimeout: 6000, speedTop: 0 }, targetsOpts), upstream
      });
      if (reply.error) { problems.push(`${engine}: refused — ${reply.error}`); return; }
      if (reply.prefilter !== wantPrefilter) problems.push(`${engine}: pre-check "${reply.prefilter}", not "${wantPrefilter}"`);
      const t0 = Date.now();
      while (!events.some(e => e.finished) && Date.now() - t0 < 60000) await delay(100);
      const rows = new Map();
      for (const e of events) if (e.result) rows.set(e.result.port, e.result);
      const live = rows.get(livePort), dead = rows.get(pDead);
      const say = (r) => (r ? `score ${r.score}, ${r.reason || 'no reason'}` : 'no row');
      console.log(`  ${engine} through a port (${wantPrefilter || 'no pre-check'}): live ${say(live)}; dead ${say(dead)}; the port saw ${seen.length} connection(s)`);
      if (seen.includes(livePort)) tunnelUp = true;
      if (!live || !(live.score > 0)) problems.push(`${engine}: the live port did not pass (${say(live)})`);
      if (!seen.includes(livePort)) problems.push(`${engine}: the port never saw the live address`);
      if (!dead || dead.score > 0) problems.push(`${engine}: the dead port passed (${say(dead)})`);
    };
    for (const engine of engines) {
      await once(engine, tlsLink, pTls, 'tls');
      await once(engine, link, pIn, '');
    }
    await new Promise((r) => proxy.close(r));
    const down = await handlers['scan:start']({ link, engines: [engines[0]], ipsText: '127.0.0.1', tests: { tcp: true, delay: true, down: false, up: false }, opts: targetsOpts, upstream });
    if (down.error !== 'proxy-down') problems.push(`a port that is down gave "${down.error || 'a run'}", not proxy-down`);
    const ok = !problems.length;
    console.log(`through a port: ${ok ? 'PASS' : 'FAIL — ' + problems.join('; ')}`);
    if (!ok) annotate('error', 'through a port: ' + problems.join('; '));
    return { ok, tunnelUp };
  }

  /**
   * The matrix on the TLS server (raw TCP + TLS, http/1.1 only, a pinned
   * certificate): fingerprint {chrome, firefox} × ALPN {http/1.1, h2} ×
   * dialMode {none, oob.0}, on the server's port and on a port nobody
   * listens on, every installed core in ONE run — the gate decides which
   * core each variant may use. What must hold:
   *  - a dialMode variant never runs on the official core: on Xray-PattN
   *    26.10.27+ it runs there alone, on an older PattN (or none) it is left
   *    out with the reason in the reply — never measured somewhere it would
   *    be ignored;
   *  - the dead port fails every variant at the pre-check (no-tcp), so no core
   *    ever dials it;
   *  - the config's own combination (fp chrome, ALPN http/1.1, no dialMode)
   *    passes on every core that ran it — through the expected 204, two
   *    samples of three at least;
   *  - every row that failed says why.
   * What ALPN h2 does against an http/1.1-only server is printed, not judged:
   * whether uTLS offers the configured ALPN is the core's business.
   */
  async function variantRun(targetsOpts) {
    events.length = 0;
    const reply = await handlers['scan:start']({
      link: tlsLink, engines,
      ipsText: '127.0.0.1', portsText: `${pTls}, ${pDead}`,
      tests: { tcp: true, delay: true, down: false, up: false },
      opts: Object.assign({ batch: 10, delaySamples: 3, tcpTimeout: 1500, delayTimeout: 6000, speedTop: 0 }, targetsOpts),
      variants: { dims: { fingerprint: ['chrome', 'firefox'], alpn: ['http/1.1', 'h2'], dialMode: ['none', 'oob.0'] } }
    });
    if (reply.error) { console.log(`variants: refused — ${reply.error}`, JSON.stringify(reply.variants || {}).slice(0, 400)); return { ok: false }; }
    const t0 = Date.now();
    while (!events.some(e => e.finished) && Date.now() - t0 < 120000) await delay(100);
    const rows = events.filter(e => e.result).map(e => e.result);
    const list = reply.variants.list, skipped = reply.variants.skipped;
    const problems = [];
    const pv = await xray.version('xray-pattn').catch(() => '');
    // the dialMode variants: on PattN only, or left out with the reason
    const oob = rows.filter(r => /oob\.0/.test(r.variantLabel || ''));
    if (oob.some(r => r.engine !== 'xray-pattn')) problems.push('a dialMode variant ran on ' + [...new Set(oob.map(r => r.engine))].join(', '));
    const oobListed = list.filter(v => /oob\.0/.test(v.label));
    const oobSkipped = skipped.filter(v => /oob\.0/.test(v.label));
    // half of the 2 × 2 × 2 product carries oob.0: four, run or left out
    if (oobListed.length + oobSkipped.length !== 4) problems.push(`dialMode variants: ${oobListed.length} run + ${oobSkipped.length} left out, not 4`);
    if (list.length + skipped.length !== 8) problems.push(`${list.length + skipped.length} variants, not 8`);
    if (oobListed.some(v => v.engines.join() !== 'xray-pattn')) problems.push('a dialMode variant was given a core other than Xray-PattN');
    // the dead port: every variant × core it was given, failed at the pre-check
    const dead = rows.filter(r => r.port === pDead);
    const expectDead = list.reduce((s, v) => s + v.engines.length, 0);
    if (dead.length !== expectDead) problems.push(`dead port: ${dead.length} rows, not ${expectDead}`);
    if (dead.some(r => r.reason !== 'no-tcp' || r.score > 0)) problems.push('a dead-port row is not a no-tcp failure');
    // the config's own combination passes on every core it ran on
    const own = rows.filter(r => r.port === pTls && r.variantLabel === 'fp=chrome · alpn=http/1.1 · dm=none');
    const ownEngines = (list.find(v => v.label === 'fp=chrome · alpn=http/1.1 · dm=none') || { engines: [] }).engines;
    if (own.length !== ownEngines.length || own.some(r => !(r.score > 0))) problems.push(`the config's own combination: ${own.map(r => r.engine + ' ' + r.score + ' ' + (r.reason || '')).join(', ') || 'no rows'}`);
    if (rows.some(r => !(r.score > 0) && !r.reason)) problems.push('a failed row without a reason');
    // the table: what each variant did on the live port
    console.log(`variants (${list.length} run, ${skipped.length} left out; Xray-PattN ${pv || 'missing'}):`);
    for (const v of list) {
      const mine = rows.filter(r => r.port === pTls && r.variant === v.key);
      const cells = mine.map(r => `${r.engine} ${r.score > 0 ? (r.score / 100).toFixed(2) + ' (' + r.delay.median + ' ms)' : '× ' + r.reason}`).join(' · ');
      console.log(`  ${v.label.padEnd(36)} ${cells}`);
    }
    for (const s of skipped) console.log(`  ${s.label.padEnd(36)} left out — ${s.reason}`);
    const tunnelUp = own.some(r => r.tcp && r.tcp.ok);
    const ok = !problems.length;
    console.log(`variants via ${targetsOpts === LOCAL ? 'the local page' : 'public pages'}: ${ok ? 'PASS' : 'FAIL — ' + problems.join('; ')}`);
    if (!ok) annotate('error', 'variants: ' + problems.join('; '));
    return { ok, tunnelUp };
  }
}

/**
 * A certificate for localhost, fresh from the core itself (`xray tls cert`,
 * two days), and its pin — the SHA-256 of the leaf the client is told to
 * accept (pcs). The fixture pair in tests/ has expired; it is the fallback
 * when the core cannot mint one.
 */
function mintCert(xray, engine, dir) {
  let pair;
  try {
    const bin = xray.resolveEngine(engine, { quiet: true }).bin;
    pair = JSON.parse(execFileSync(bin, ['tls', 'cert', '--domain=localhost', '--expire=48h'], { encoding: 'utf8', windowsHide: true, timeout: 15000 }));
  } catch {
    pair = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'tests', 'fixtures', 'selfsigned.json'), 'utf8'));
  }
  const cert = pair.certificate.join('\n') + '\n';
  const certFile = path.join(dir, 'probe.crt'), keyFile = path.join(dir, 'probe.key');
  fs.writeFileSync(certFile, cert);
  fs.writeFileSync(keyFile, pair.key.join('\n') + '\n');
  const pin = new crypto.X509Certificate(cert).fingerprint256.replace(/:/g, '').toLowerCase();
  return { certFile, keyFile, pin };
}

main().then((code) => process.exit(code), (e) => { console.error(e); process.exit(1); });
