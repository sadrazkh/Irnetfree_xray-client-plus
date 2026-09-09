'use strict';
/**
 * plus: the Server tab — a local Xray server with inbounds, clients and a
 * reverse-proxy role (spec section 2). One module for both mirrors: `ctx`
 * is the normalised context main.js and service.js build the same way
 * (spec section 4), and a handler gets its one argument already unwrapped.
 * The model lives in the store under `xserver`; the renderer never writes
 * it, every change goes through xserver:set.
 *
 * Channels: xserver:get, set, start, stop, restart, status, log, genKeys,
 * genId, clientLink, preview, otherSide, firewall. Events: xserver-status
 * (the status payload) and xserver-log ({ line, level }). No handler
 * throws to the bridge: a failure is { ok:false, error }, or { error }
 * where the reply is a value.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile: nodeExecFile } = require('child_process');
const { xrayEngines, engineLabel } = require('../engines');
const { ServerCore, firewallArgs } = require('./core');
const X = require('./config');

const STORE_KEY = 'xserver';
/** The preview's metrics port while nothing runs: the real one is picked from the free pool at start. */
const PREVIEW_API_PORT = 10099;
const FIREWALL_PREFIX = 'IRNetFree Plus ';
const EXEC_TIMEOUT_MS = 10000;

/**
 * createXServer(ctx, deps?) → { register(), stop(), autoStart(), status() }
 * `deps` = { execFile, setTimeout, core: { spawn, now, setTimeout, … } } are
 * injection points for the tests.
 */
function createXServer(ctx, deps = {}) {
  const execFile = deps.execFile || nodeExecFile;
  const setTimeoutFn = deps.setTimeout || setTimeout;

  const getModel = () => X.normalizeModel(ctx.store.get(STORE_KEY));
  const setModel = (model) => { ctx.store.setLazy(STORE_KEY, model); };
  // The private block wants geoip.dat; without it the config carries the literal list.
  const geoAvailable = () => {
    try {
      const dir = ctx.xray.assetDir();
      return !!dir && fs.existsSync(path.join(dir, 'geoip.dat'));
    } catch { return false; }
  };

  const core = new ServerCore(Object.assign({
    dataDir: ctx.dataDir, xray: ctx.xray, getModel, setModel,
    send: ctx.send, log: ctx.log, notify: ctx.notify,
    getServers: ctx.getServers, geoAvailable, platform: ctx.platform
  }, deps.core || {}));

  /** One command, its output, no throw. */
  const run = (bin, args) => new Promise((resolve) => {
    try {
      execFile(bin, args, { windowsHide: true, timeout: EXEC_TIMEOUT_MS }, (err, stdout, stderr) => {
        resolve({ err, stdout: String(stdout || ''), stderr: String(stderr || '') });
      });
    } catch (e) { resolve({ err: e, stdout: '', stderr: '' }); }
  });

  const find = (model, inboundId, clientId) => {
    const inbound = model.inbounds.find(i => i.id === inboundId) || null;
    const client = inbound && clientId !== undefined ? (inbound.clients.find(c => c.id === clientId) || null) : null;
    return { inbound, client };
  };
  const engines = () => xrayEngines().map((id) => ({ id, label: engineLabel(id), installed: !!ctx.xray.binExists(id) }));
  const withStatus = (r) => Object.assign({ ok: !!r.ok, error: r.error || '' }, core.status());

  const handlers = {
    'xserver:get': () => ({ model: getModel(), status: core.status(), engines: engines() }),

    'xserver:set': async (model) => {
      const r = await core.applyModel(model);
      return Object.assign(r, { status: core.status() });
    },

    'xserver:start': async () => withStatus(await core.start()),
    'xserver:stop': async () => { await core.stop(); return core.status(); },
    'xserver:restart': async () => withStatus(await core.restart()),
    'xserver:status': () => core.status(),
    'xserver:log': () => core.logLines(),

    'xserver:genKeys': async () => {
      const { bin } = ctx.xray.resolveEngine(getModel().engine, { quiet: true });
      if (!bin) return { error: 'core binary not found' };
      const r = await run(bin, ['x25519']);
      if (r.err) return { error: r.err.message || String(r.err) };
      return X.parseX25519(r.stdout) || { error: 'could not read the key pair from the core output' };
    },

    'xserver:genId': (kind) => {
      const k = String(kind || '');
      if (k === 'uuid') return { value: crypto.randomUUID() };
      if (k === 'password') return { value: crypto.randomBytes(16).toString('base64url') };
      if (k === 'shortId') return { value: X.randomShortId() };
      if (k.startsWith('ss2022:')) {
        const method = k.slice('ss2022:'.length);
        if (!X.SS_METHODS.includes(method)) return { error: `unknown method "${method}"` };
        return { value: X.randomKeyFor(method) };
      }
      return { error: `unknown kind "${k}"` };
    },

    'xserver:clientLink': (arg) => {
      const a = arg && typeof arg === 'object' ? arg : {};
      const model = getModel();
      const { inbound, client } = find(model, a.inboundId, a.clientId);
      if (!inbound) return { error: 'inbound not found' };
      if (!client) return { error: 'client not found' };
      try {
        return { link: X.clientLink(inbound, client, model), record: X.clientServerRecord(inbound, client, model) };
      } catch (e) { return { error: e.message }; }
    },

    'xserver:preview': () => {
      const model = getModel();
      const st = core.status();
      const live = st.apiPort && (st.state === 'running' || st.state === 'starting');
      return { config: X.buildServerConfig(model, { apiPort: live ? st.apiPort : PREVIEW_API_PORT, servers: ctx.getServers(), geoAvailable: geoAvailable() }) };
    },

    'xserver:otherSide': () => {
      const model = getModel();
      try { return X.otherSideSnippet(model, { servers: ctx.getServers(), address: model.publicAddress }); } catch (e) { return { error: e.message }; }
    },

    'xserver:firewall': async (arg) => {
      if (ctx.platform !== 'win32') return { ok: false, error: 'unsupported' };
      const a = arg && typeof arg === 'object' ? arg : {};
      const { inbound } = find(getModel(), a.inboundId);
      if (!inbound) return { ok: false, error: 'inbound not found' };
      const r = await run('netsh', firewallArgs(FIREWALL_PREFIX + inbound.tag, inbound.port, !!a.allow));
      if (r.err) return { ok: false, error: (r.stderr || r.stdout || r.err.message || String(r.err)).trim() };
      ctx.log(`Server: firewall rule ${a.allow ? 'added' : 'removed'} for ${inbound.tag} (tcp ${inbound.port})`, 'info');
      return { ok: true };
    }
  };

  const guard = (fn) => async (arg) => {
    try { return await fn(arg); } catch (e) { return { ok: false, error: (e && e.message) || String(e) }; }
  };

  return {
    register() { for (const [channel, fn] of Object.entries(handlers)) ctx.handle(channel, guard(fn)); },
    /** Quit path: the server core goes down after the client core. */
    stop: () => core.stop(),
    /** After the client auto-connect, so the two cores do not race for the same free-port pool. */
    autoStart() {
      let model;
      try { model = getModel(); } catch { return; }
      if (!model.autoStart) return;
      setTimeoutFn(() => { core.start().catch(() => { /* reported through the status */ }); }, 1500);
    },
    status: () => core.status()
  };
}

module.exports = { createXServer, STORE_KEY, PREVIEW_API_PORT };
