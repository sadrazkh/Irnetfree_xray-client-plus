'use strict';
/**
 * plus: the app behind both front ends — the Electron window (src/main/main.js)
 * and the headless server (src/server/server.js) — as ONE module, so nothing is
 * mirrored any more (spec 2026-10-15 §3). Every handler takes one argument and
 * answers a value; events go out through `send(channel, payload)`.
 *
 * What it holds: the store (`store.json` in the data folder, the file Plus v2
 * wrote — its configs, server model and scan memory carry over), the cores
 * (XrayManager, the downloader and upstream's version picker), the configs
 * list, a log ring, and the two tools, which register their own channels.
 */
const fs = require('fs');
const path = require('path');
const { Store } = require('../store');
const { XrayManager } = require('../xrayManager');
const { Downloader } = require('../downloader');
const { createCoreVersionsApi, CORE_IDS } = require('../coreVersions');
const { assetStatus } = require('../assets');
const { xrayEngines, engineLabel } = require('../engines');
const { createXServer } = require('../xserver');
const { createScan } = require('../scan');
const { createConfigs } = require('./configs');
const { createRunAdmin } = require('./elevate');

const APP_REPO = 'sadrazkh/Irnetfree_xray-client-plus';
const DEFAULT_SETTINGS = { lang: 'fa', theme: 'system', skin: 'console', openAtLogin: false };
const SETTINGS_KEYS = {
  lang: (v) => (v === 'en' ? 'en' : 'fa'),
  theme: (v) => (['system', 'dark', 'light'].includes(v) ? v : 'system'),
  skin: (v) => (['console', 'cockpit', 'legacy'].includes(v) ? v : 'console'),
  openAtLogin: (v) => !!v
};
const LOG_KEEP = 500;

/** '2.10.1' > '2.9.0'; anything unreadable is 0.0.0. */
function cmpVersion(a, b) {
  const p = (v) => String(v || '').replace(/^v/i, '').split(/[.-]/).slice(0, 3).map(n => parseInt(n, 10) || 0);
  const x = p(a), y = p(b);
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] > y[i] ? 1 : -1;
  return 0;
}

/**
 * createPlusService({ dataDir, version, platform, isElectron, send, deps })
 *   → { invoke(channel, arg), has(channel), channels(), settings(), shutdown(), store, xray, log }
 * `deps` = { downloader, runAdmin, readFile, xserverDeps, scanDeps } are the tests' seams.
 */
function createPlusService(opts = {}) {
  const dataDir = opts.dataDir;
  if (!dataDir) throw new Error('createPlusService: dataDir is required');
  fs.mkdirSync(dataDir, { recursive: true });
  const platform = opts.platform || process.platform;
  const isElectron = !!opts.isElectron;
  const version = opts.version || '0.0.0';
  const deps = opts.deps || {};
  const send = typeof opts.send === 'function' ? opts.send : () => {};
  const emit = (channel, payload) => { try { send(channel, payload); } catch { /* the front end is gone */ } };

  /* ----------------------------- log ----------------------------- */
  const lines = [];
  function log(line, level = 'info') {
    const entry = { at: Date.now(), line: String(line), level: level || 'info' };
    lines.push(entry);
    if (lines.length > LOG_KEEP) lines.splice(0, lines.length - LOG_KEEP);
    emit('log', entry);
  }

  /* ----------------------------- store & settings ----------------------------- */
  const store = new Store(path.join(dataDir, 'store.json'), { servers: [], settings: Object.assign({}, DEFAULT_SETTINGS) }, {
    onError: (kind, info) => log(`The store could not be read (${kind}): ${(info && info.message) || ''} — a copy was kept`, 'error')
  });
  function settings() {
    const s = store.get('settings', {}) || {};
    const out = {};
    for (const [k, clean] of Object.entries(SETTINGS_KEYS)) out[k] = k in s ? clean(s[k]) : DEFAULT_SETTINGS[k];
    return out;
  }
  function setSettings(patch) {
    const p = patch && typeof patch === 'object' ? patch : {};
    // the rest of a v2 store's settings (the client's) stays in the file, untouched
    const next = Object.assign({}, store.get('settings', {}) || {});
    for (const [k, clean] of Object.entries(SETTINGS_KEYS)) if (k in p) next[k] = clean(p[k]);
    store.set('settings', next);
    return settings();
  }

  /* ----------------------------- cores ----------------------------- */
  const userBin = path.join(dataDir, 'bin');
  fs.mkdirSync(userBin, { recursive: true });
  const xray = deps.xray || new XrayManager({ dataDir, extraBinDirs: [userBin], onLog: log });
  const downloaderOpts = { destDir: userBin, onLog: log, onProgress: (component, pct) => emit('asset-progress', { component, pct }) };
  const downloader = deps.downloader ? deps.downloader(downloaderOpts) : new Downloader(downloaderOpts);
  const assets = () => {
    const st = assetStatus([userBin, ...xray.binDirs()], platform);
    return { xray: !!st.xray, 'xray-pattn': !!st['xray-pattn'], geoip: !!st.geoip, geosite: !!st.geosite };
  };
  const engines = () => xrayEngines().map((id) => ({ id, label: engineLabel(id), installed: !!xray.binExists(id) }));
  function afterCoreChanged(component) {
    if (component === 'xray') xray.binPath = null;
    xray.forgetVersions();
  }

  /* ----------------------------- the tools ----------------------------- */
  const handlers = {};
  const configs = createConfigs({ store, dataDir, log, readFile: deps.readFile });
  const ctx = {
    handle: (channel, fn) => { handlers[channel] = fn; },
    send: emit,
    notify: (title, body) => emit('notify', { title, body }),
    store, dataDir, xray, platform, isElectron,
    getSettings: settings,
    getServers: () => configs.all(),
    addServer: (rec) => configs.addServer(rec),
    resolveTarget: (id) => ({ server: configs.find(id), chain: null }),
    log,
    latestVersion: (id) => downloader.latestVersion(id),
    runAdmin: deps.runAdmin || createRunAdmin({ platform })
  };
  const xserver = createXServer(ctx, deps.xserverDeps);
  const scanner = createScan(ctx, deps.scanDeps);
  xserver.register();
  scanner.register();

  // a core file is not swapped while something runs on it
  const coreBusy = () => {
    if (scanner.busy()) return true;
    const st = xserver.status ? xserver.status() : null;
    return !!(st && (st.state === 'running' || st.state === 'starting'));
  };
  const coreVersions = createCoreVersionsApi({
    downloader,
    installedVersion: (id) => xray.version(id),
    busy: coreBusy,
    afterInstall: afterCoreChanged,
    result: () => ({ assets: assets(), xrayReady: xray.binExists() }),
    onLog: log
  });

  /* ----------------------------- the app's own channels ----------------------------- */
  Object.assign(handlers, {
    'app:init': async () => ({
      version, platform, isElectron, repo: APP_REPO, dataDir,
      settings: settings(), servers: configs.list(), assets: assets(), engines: engines(), xrayReady: !!xray.binExists()
    }),
    'settings:get': () => settings(),
    'settings:set': (patch) => setSettings(patch),

    'configs:list': () => configs.list(),
    'configs:add': (text) => Object.assign(configs.add(text), { servers: configs.list() }),
    'configs:remove': (ids) => Object.assign(configs.remove(ids), { servers: configs.list() }),
    'configs:import': (arg) => Object.assign(configs.importIrnetfree(arg && typeof arg === 'object' ? arg : {}), { servers: configs.list() }),

    'assets:status': () => ({ assets: assets(), engines: engines() }),
    'assets:download': async (component) => {
      const id = String(component || '');
      if (!['xray', 'xray-pattn', 'geo'].includes(id)) return { ok: false, error: 'unknown component: ' + id };
      if (id !== 'geo' && coreBusy()) return { ok: false, error: 'busy', assets: assets() };
      try {
        const res = await downloader.download(id);
        if (CORE_IDS.includes(id)) afterCoreChanged(id);
        return { ok: true, files: res.files, assets: assets(), engines: engines() };
      } catch (err) {
        log('Download failed (' + id + '): ' + err.message, 'error');
        return { ok: false, error: err.message, coreBusy: err.code === 'ECOREBUSY', assets: assets() };
      }
    },
    'assets:versions': async () => {
      const out = {};
      for (const id of xrayEngines()) { try { out[id] = xray.binExists(id) ? String(await xray.version(id) || '') : ''; } catch { out[id] = ''; } }
      return out;
    },
    'cores:versions': (arg) => coreVersions.versions(arg),
    'cores:install': (arg) => coreVersions.install(arg),

    'log:get': () => lines.slice(),
    'log:clear': () => { lines.length = 0; return { ok: true }; },

    /** The newest Plus release: a link to it — Plus never installs itself. */
    'app:checkUpdate': async () => {
      try {
        const rel = await downloader.fetchJSON(`https://api.github.com/repos/${APP_REPO}/releases/latest`);
        const latest = String((rel && rel.tag_name) || '').replace(/^v/i, '');
        if (!latest) return { ok: false, error: 'no release' };
        return { ok: true, current: version, latest, newer: cmpVersion(latest, version) > 0, url: rel.html_url || `https://github.com/${APP_REPO}/releases/latest` };
      } catch (e) { return { ok: false, error: (e && e.message) || String(e) }; }
    }
  });

  function invoke(channel, arg) {
    const fn = handlers[channel];
    if (!fn) return Promise.reject(new Error('unknown channel: ' + channel));
    try { return Promise.resolve(fn(arg)); } catch (e) { return Promise.reject(e); }
  }

  let shut = false;
  async function shutdown() {
    if (shut) return;
    shut = true;
    try { await scanner.stop(); } catch { /* nothing running */ }
    try { await xserver.stop(); } catch { /* nothing running */ }
    try { store.flush(); } catch { /* best effort */ }
  }

  // the server, when its model asks to start with the app
  try { xserver.autoStart(); } catch (e) { log('Server autostart: ' + e.message, 'error'); }

  return {
    invoke, has: (ch) => !!handlers[ch], channels: () => Object.keys(handlers).sort(),
    settings, setSettings, shutdown, store, xray, log, serverRunning: () => { const st = xserver.status ? xserver.status() : null; return !!(st && st.state === 'running'); }
  };
}

module.exports = { createPlusService, DEFAULT_SETTINGS, APP_REPO, cmpVersion };
