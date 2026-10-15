'use strict';
/**
 * IRNetFree Plus — the Electron shell (spec 2026-10-15). A window, a tray and
 * the IPC bridge to the one service (src/main/plus/service.js); everything the
 * app does lives there, shared with the headless server.
 *
 * - No administrator rights: nothing here needs them (src/main/plus/elevate.js
 *   asks for them for the firewall rule alone).
 * - Closing the window while the local server runs hides it to the tray, so
 *   the server keeps serving; otherwise it quits.
 * - "Start with the OS": the login item, launched with `--hidden`.
 */
const path = require('path');
const { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage, shell, Notification } = require('electron');
const { createPlusService } = require('./plus/service');
const { INVOKE, WINDOW } = require('./plus/apiMap');

const APP_PAGE = path.join(__dirname, '..', 'renderer', 'index.html');
const ICON = path.join(__dirname, '..', '..', 'assets', 'icon.png');
const TRAY_ICON = path.join(__dirname, '..', '..', 'assets', 'tray.png');
/** Started by the login item: the window waits in the tray. */
const START_HIDDEN = process.argv.includes('--hidden');

let mainWindow = null;
let tray = null;
let service = null;
let quitting = false;

const isWebUrl = (u) => /^https?:\/\//i.test(String(u || ''));
const isAppPage = (u) => { try { return new URL(u).protocol === 'file:' && decodeURIComponent(new URL(u).pathname).replace(/\\/g, '/').endsWith('/renderer/index.html'); } catch { return false; } };

function send(channel, payload) {
  if (channel === 'notify' && payload && Notification.isSupported()) {
    try { new Notification({ title: payload.title || 'IRNetFree Plus', body: payload.body || '' }).show(); } catch { /* no notifier */ }
  }
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send(channel, payload);
  if (channel === 'xserver-status') refreshTray();
}

function show() {
  if (!mainWindow) return createWindow(false);
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
}

function quit() {
  quitting = true;
  app.quit();
}

function refreshTray() {
  if (!tray) return;
  const running = service && service.serverRunning();
  tray.setToolTip('IRNetFree Plus' + (running ? ' — server running' : ''));
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Open IRNetFree Plus', click: show },
    { type: 'separator' },
    { label: 'Quit', click: quit }
  ]));
}

function createTray() {
  let icon = nativeImage.createFromPath(TRAY_ICON);
  if (icon.isEmpty()) icon = nativeImage.createFromPath(ICON);
  tray = new Tray(icon.isEmpty() ? nativeImage.createEmpty() : icon.resize({ width: 16, height: 16 }));
  tray.on('click', show);
  refreshTray();
}

function createWindow(hidden) {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 760,
    minWidth: 900,
    minHeight: 600,
    show: !hidden,
    backgroundColor: '#0d1117',
    title: 'IRNetFree Plus',
    icon: ICON,
    frame: false,
    webPreferences: {
      preload: path.join(__dirname, '..', 'preload', 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });
  // our page and nothing else; a web link opens in the browser
  mainWindow.webContents.on('will-navigate', (e, url) => { if (!isAppPage(url)) e.preventDefault(); });
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (isWebUrl(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  mainWindow.loadFile(APP_PAGE);
  mainWindow.on('close', (e) => {
    if (quitting) return;
    // the local server keeps serving from the tray; with nothing running, closing quits
    if (service && service.serverRunning()) { e.preventDefault(); mainWindow.hide(); return; }
    quitting = true;
  });
  mainWindow.on('closed', () => { mainWindow = null; });
}

function registerIpc() {
  for (const [, [channel]] of Object.entries(INVOKE)) {
    ipcMain.handle(channel, async (e, arg) => {
      const r = await service.invoke(channel, arg);
      if (channel === 'settings:set' && arg && 'openAtLogin' in arg) applyLoginItem(r.openAtLogin);
      return r;
    });
  }
  ipcMain.handle(WINDOW.winMinimize, () => { if (mainWindow) mainWindow.minimize(); });
  ipcMain.handle(WINDOW.winMaximize, () => {
    if (!mainWindow) return;
    if (mainWindow.isMaximized()) mainWindow.unmaximize(); else mainWindow.maximize();
  });
  ipcMain.handle(WINDOW.winClose, () => { if (mainWindow) mainWindow.close(); });
  ipcMain.handle(WINDOW.openExternal, (e, url) => { if (isWebUrl(url)) shell.openExternal(String(url)); });
  ipcMain.handle(WINDOW.openDataDir, () => shell.openPath(app.getPath('userData')));
}

/** The login item: the app at logon, in the tray (`--hidden`). */
function applyLoginItem(on) {
  try {
    app.setLoginItemSettings({ openAtLogin: !!on, args: on ? ['--hidden'] : [] });
  } catch (e) { if (service) service.log('Start with the system: ' + e.message, 'error'); }
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', show);
  if (process.platform === 'win32') app.setAppUserModelId('com.irnetfree.plus');

  app.whenReady().then(() => {
    service = createPlusService({
      dataDir: app.getPath('userData'),
      version: app.getVersion(),
      platform: process.platform,
      isElectron: true,
      send
    });
    registerIpc();
    createTray();
    createWindow(START_HIDDEN);
  });

  app.on('activate', show);
  // macOS keeps an app without windows; here the tray is the way back on every OS
  app.on('window-all-closed', () => { if (quitting || !(service && service.serverRunning())) quit(); });

  let shutDown = false;
  app.on('before-quit', async (e) => {
    quitting = true;
    if (shutDown || !service) return;
    e.preventDefault();
    shutDown = true;
    try { await service.shutdown(); } catch { /* quitting anyway */ }
    app.quit();
  });
}
