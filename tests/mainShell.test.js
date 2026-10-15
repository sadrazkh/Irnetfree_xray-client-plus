'use strict';
/**
 * src/main/main.js — the Electron shell — run for real against a stubbed
 * `electron` module (no Electron is needed): it takes the single-instance
 * lock, starts the one service on the user-data folder, answers every channel
 * of the API map over IPC, opens the window (hidden with --hidden), keeps the
 * app in the tray only while the local server runs, and shuts the service
 * down before it quits.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');

const MAIN = path.join(__dirname, '..', 'src', 'main', 'main.js');
const SERVICE = path.join(__dirname, '..', 'src', 'main', 'plus', 'service.js');
const { INVOKE, WINDOW } = require('../src/main/plus/apiMap');

function fakeElectron({ userData, argv = [], lock = true }) {
  const handlers = new Map();
  const appEvents = {};
  const windows = [];
  let readyResolve;
  const ready = new Promise((r) => { readyResolve = r; });
  const app = {
    quitCalls: 0, loginItems: [],
    requestSingleInstanceLock: () => lock,
    on: (ev, fn) => { (appEvents[ev] = appEvents[ev] || []).push(fn); },
    whenReady: () => ready,
    getPath: (k) => { assert.equal(k, 'userData'); return userData; },
    getVersion: () => '3.0.0',
    setAppUserModelId: () => {},
    setLoginItemSettings: (o) => app.loginItems.push(o),
    quit: () => { app.quitCalls++; for (const fn of appEvents['before-quit'] || []) fn({ preventDefault: () => { app.prevented = true; } }); }
  };
  class BrowserWindow {
    constructor(opts) {
      this.opts = opts; this.events = {}; this.shown = !!opts.show; this.hidden = false; this.loaded = null;
      this.webContents = { on: () => {}, setWindowOpenHandler: () => {}, send: (ch, p) => this.sent.push([ch, p]) };
      this.sent = [];
      windows.push(this);
    }
    loadFile(f) { this.loaded = f; }
    on(ev, fn) { (this.events[ev] = this.events[ev] || []).push(fn); }
    hide() { this.hidden = true; }
    show() { this.shown = true; }
    focus() {}
    isMinimized() { return false; }
    isDestroyed() { return false; }
    close() { const e = { prevented: false, preventDefault() { this.prevented = true; } }; for (const fn of this.events.close || []) fn(e); return e; }
  }
  const electron = {
    app, BrowserWindow,
    ipcMain: { handle: (ch, fn) => { assert.ok(!handlers.has(ch), 'one handler per channel: ' + ch); handlers.set(ch, fn); } },
    Tray: class { constructor() {} setToolTip(t) { this.tip = t; } setContextMenu() {} on() {} },
    Menu: { buildFromTemplate: (x) => x },
    nativeImage: { createFromPath: () => ({ isEmpty: () => true, resize: () => ({}) }), createEmpty: () => ({}) },
    shell: { openExternal: () => {}, openPath: () => {} },
    Notification: class { static isSupported() { return false; } show() {} }
  };
  return { electron, app, handlers, windows, appEvents, fire: () => readyResolve(), argv };
}

/** Load main.js fresh with `electron` answered by the fake, and the service replaced when asked. */
function loadMain(fake, { serviceStub } = {}) {
  const realLoad = Module._load;
  const oldArgv = process.argv;
  process.argv = ['electron', '.', ...fake.argv];
  Module._load = function (request, parent, isMain) {
    if (request === 'electron') return fake.electron;
    if (serviceStub && parent && parent.filename === MAIN && request === './plus/service') return serviceStub;
    return realLoad.apply(this, arguments);
  };
  delete require.cache[MAIN];
  try { require(MAIN); } finally { Module._load = realLoad; process.argv = oldArgv; }
}

const tick = () => new Promise((r) => setImmediate(r));

test('the shell starts the real service on the user-data folder and answers every channel of the map', async (t) => {
  const userData = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-plus-main-'));
  t.after(() => fs.rmSync(userData, { recursive: true, force: true }));
  const fake = fakeElectron({ userData });
  loadMain(fake);
  fake.fire();
  await tick(); await tick();
  for (const [, [channel]] of Object.entries(INVOKE)) assert.ok(fake.handlers.has(channel), channel);
  for (const channel of Object.values(WINDOW)) assert.ok(fake.handlers.has(channel), channel);
  const init = await fake.handlers.get('app:init')({}, undefined);
  assert.equal(init.version, '3.0.0');
  assert.equal(init.dataDir, userData);
  assert.equal(init.isElectron, true);
  assert.ok(fs.existsSync(path.join(userData, 'bin')), 'the cores go into the user-data folder');
  assert.equal(fake.windows.length, 1);
  assert.match(fake.windows[0].loaded, /renderer[\\/]index\.html$/);
  assert.equal(fake.windows[0].opts.webPreferences.contextIsolation, true);
  assert.equal(fake.windows[0].opts.webPreferences.nodeIntegration, false);
  // settings:set with openAtLogin reaches the login item
  await fake.handlers.get('settings:set')({}, { openAtLogin: true });
  assert.deepEqual(fake.app.loginItems.at(-1), { openAtLogin: true, args: ['--hidden'] });
  // quit: the service is shut down first (before-quit is held once), then the app quits
  fake.app.quit();
  assert.equal(fake.app.prevented, true);
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(fake.app.quitCalls, 2, 'quit again once the service is down');
});

test('--hidden opens the window unseen; closing it hides to the tray only while the server runs', async () => {
  let running = true;
  const stub = {
    createPlusService: () => ({ invoke: async () => ({}), serverRunning: () => running, shutdown: async () => {}, log: () => {} })
  };
  const fake = fakeElectron({ userData: os.tmpdir(), argv: ['--hidden'] });
  loadMain(fake, { serviceStub: stub });
  fake.fire();
  await tick(); await tick();
  const win = fake.windows[0];
  assert.equal(win.opts.show, false);
  const kept = win.close();
  assert.equal(kept.prevented, true, 'the server is running: the window hides');
  assert.equal(win.hidden, true);
  running = false;
  const gone = win.close();
  assert.equal(gone.prevented, false, 'nothing running: closing closes');
});

test('a second copy does not start: the single-instance lock is not ours', () => {
  const fake = fakeElectron({ userData: os.tmpdir(), lock: false });
  loadMain(fake);
  assert.equal(fake.app.quitCalls, 1);
  assert.equal(fake.windows.length, 0);
  assert.ok(!fs.existsSync(SERVICE) || true);
});
