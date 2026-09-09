#!/usr/bin/env node
'use strict';
/**
 * plus: a live, local-only proof of the Server tab's reverse proxy.
 *
 * Two server cores on 127.0.0.1 built from the same models the tab saves — a
 * PORTAL (an interconn inbound the bridge dials in on, a user inbound people
 * connect to) and a BRIDGE (no public side; it dials the portal and carries
 * the users' traffic out through its own exit) — plus a throwaway client that
 * connects to the portal's user inbound and fetches a page from a local web
 * server. The page can only arrive through the bridge: the portal's own exit
 * must stay at zero bytes while the bridge's exit carries the request.
 *
 * Nothing binds 0.0.0.0, nothing touches the system; every process is killed
 * and the temp dir removed at the end. Runs on every installed xray-format core
 * (IRNF_ENGINES=xray,xray-pattn to choose).
 *
 *   npm run probe:reverse
 */
const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { XrayManager, getFreePorts } = require('../src/main/xrayManager');
const X = require('../src/main/xserver/config');
const { parseLink } = require('../src/main/parser');
const { buildTestConfig } = require('../src/main/configBuilder');
const { httpThroughProxy } = require('../src/main/netutils');

const ENGINES = (process.env.IRNF_ENGINES || 'xray,xray-pattn').split(',').map(s => s.trim()).filter(Boolean);

const delay = (ms) => new Promise(r => setTimeout(r, ms));

/** The core's /debug/vars as an object, or null while it is not up yet. */
function metrics(port) {
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port, path: '/debug/vars', timeout: 1500 }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; });
      res.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

async function waitFor(fn, ms, step = 250) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    const v = await fn();
    if (v) return v;
    await delay(step);
  }
  return null;
}

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
function outboundBytes(vars, tag) {
  const o = vars && vars.stats && vars.stats.outbound && vars.stats.outbound[tag];
  return { up: num(o && o.uplink), down: num(o && o.downlink) };
}

const TARGETS = [
  { name: 'local page', host: '127.0.0.1', port: 0, path: '/' },            // port: the local web server's
  { name: 'cp.cloudflare.com', host: 'cp.cloudflare.com', port: 80, path: '/' }
];

/** One whole scenario — fresh cores, one fetch of `target` — so a core's penalty on a refused destination cannot leak into the next attempt. */
async function runOn(engineId, target) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-plus-reverse-'));
  const xray = new XrayManager({ dataDir: tmp });
  if (!xray.binExists(engineId)) { console.log(`${engineId}: not installed — skipped`); return 'skip'; }

  // The page the client must reach THROUGH the bridge.
  const web = http.createServer((req, res) => { res.setHeader('Content-Type', 'text/plain'); res.end('hello-through-bridge'); });
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const webPort = web.address().port;

  const [pInterconn, pUsers, pSocks, apiPortal, apiBridge, pUnused] = await getFreePorts(6);

  // The portal: the bridge dials `interconn`; people connect to `users`.
  const interconn = X.newInbound('vless', { remark: 'interconn', listen: '127.0.0.1', port: pInterconn, network: 'tcp', security: 'none' });
  const bridgeClient = X.newClient('vless', { email: 'bridge' });
  interconn.clients = [bridgeClient];
  const users = X.newInbound('vless', { remark: 'users', listen: '127.0.0.1', port: pUsers, network: 'ws', security: 'none', path: '/rev' });
  const alice = X.newClient('vless', { email: 'alice' });
  users.clients = [alice];
  const portal = X.normalizeModel({
    publicAddress: '127.0.0.1', blockPrivate: false,
    inbounds: [interconn, users],
    reverse: { role: 'portal', portal: { interconnInboundId: interconn.id, userInboundIds: [users.id] } }
  });
  const interconnLink = X.clientLink(interconn, bridgeClient, portal, { address: '127.0.0.1' });

  // The bridge: reaches the portal with the interconn client's own link; its
  // one inbound is unused (a core wants at least one).
  const unused = X.newInbound('vless', { remark: 'unused', listen: '127.0.0.1', port: pUnused, network: 'tcp', security: 'none' });
  unused.clients = [X.newClient('vless', { email: 'nobody' })];
  const bridge = X.normalizeModel({
    publicAddress: '127.0.0.1', blockPrivate: false,
    inbounds: [unused],
    reverse: { role: 'bridge', bridge: { via: 'link', link: interconnLink } }
  });

  for (const [name, m] of [['portal', portal], ['bridge', bridge]]) {
    const v = X.validateModel(m, { servers: [] });
    if (!v.ok) throw new Error(`${name} model: ` + v.errors.map(e => `${e.path}: ${e.msg}`).join('; '));
  }
  const portalCfg = X.buildServerConfig(portal, { apiPort: apiPortal, servers: [], geoAvailable: false });
  const bridgeCfg = X.buildServerConfig(bridge, { apiPort: apiBridge, servers: [], geoAvailable: false });
  // IRNF_VERBOSE=1: the cores' own log lines, at debug level, prefixed by role
  const verbose = !!process.env.IRNF_VERBOSE;
  if (verbose) { portalCfg.log = { loglevel: 'debug' }; bridgeCfg.log = { loglevel: 'debug' }; }
  const tap = (t, role) => {
    if (!verbose || !t.proc) return t;
    for (const s of [t.proc.stdout, t.proc.stderr]) {
      if (s) s.on('data', (d) => process.stdout.write(String(d).split(/\r?\n/).filter(Boolean).map(l => `[${role}] ${l}` + os.EOL).join('')));
    }
    return t;
  };
  if (process.env.IRNF_DUMP) {
    fs.writeFileSync(path.join(tmp, 'portal.json'), JSON.stringify(portalCfg, null, 2));
    fs.writeFileSync(path.join(tmp, 'bridge.json'), JSON.stringify(bridgeCfg, null, 2));
    console.log(`configs written under ${tmp}`);
  }

  const procs = [];
  try {
    procs.push(tap(await xray.startTest(portalCfg, engineId), 'portal'));
    if (!(await waitFor(() => metrics(apiPortal), 6000))) throw new Error('the portal core did not come up');
    procs.push(tap(await xray.startTest(bridgeCfg, engineId), 'bridge'));
    if (!(await waitFor(() => metrics(apiBridge), 6000))) throw new Error('the bridge core did not come up');
    // The bridge dials the portal on its own schedule (about two seconds after
    // it starts); the portal's `portal` outbound only exists once that session
    // is up, and its user counter for the bridge appears at the same moment.
    const linked = await waitFor(() => metrics(apiPortal).then((v) => !!(v && v.stats && v.stats.user && v.stats.user[bridgeClient.email])), 10000);
    if (!linked) throw new Error('the bridge never reached the portal');
    await delay(300);

    // A client on the portal's user inbound, from the link the tab would show.
    const userLink = X.clientLink(users, alice, portal, { address: '127.0.0.1' });
    procs.push(tap(await xray.startTest(buildTestConfig(parseLink(userLink), pSocks), engineId), 'client'));

    const host = target.host, port = target.port || webPort;
    const r = await httpThroughProxy(pSocks, { host, port, path: target.path, timeout: 8000 });
    await delay(300);   // let the counters settle
    const b = await metrics(apiBridge);
    const p = await metrics(apiPortal);
    const bExit = outboundBytes(b, 'exit');
    const pExit = outboundBytes(p, 'exit');
    const ok = !!(r.ok && r.status > 0 && r.status < 500 && bExit.down > 0 && pExit.up === 0 && pExit.down === 0);
    console.log(`${engineId} via ${target.name}: fetch ${r.ok ? `ok ${r.status} in ${r.ms} ms` : `FAILED (${r.error})`}; ` +
      `bridge exit ${bExit.up}/${bExit.down} B, portal exit ${pExit.up}/${pExit.down} B → ${ok ? 'PASS' : 'FAIL'}`);
    return ok ? 'pass' : 'fail';
  } finally {
    for (const t of procs) { try { t.cleanup(); } catch { /* already gone */ } }
    await new Promise((r) => web.close(r));
    if (!process.env.IRNF_DUMP) { await delay(300); try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* a core still closing its config */ } }
  }
}

(async () => {
  let failed = 0, passed = 0;
  for (const e of ENGINES) {
    // The local page first. Cores from 26.9 on refuse a loopback target that
    // arrives through a reverse ("proxy/freedom: blocked target") and penalise
    // the source for a while — a policy on private destinations, not a fault
    // in the tunnel — so on those the proof is repeated from scratch against a
    // public page, through the owner's own internet.
    let res = 'fail';
    for (const target of TARGETS) {
      try { res = await runOn(e, target); }
      catch (err) { res = 'error'; console.log(`${e} via ${target.name}: ERROR ${err.message}`); }
      if (res !== 'fail') break;
    }
    if (res === 'pass') passed++;
    else if (res !== 'skip') failed++;
  }
  console.log(`reverse proxy: ${passed} pass, ${failed} fail`);
  process.exit(failed ? 1 : 0);
})();
