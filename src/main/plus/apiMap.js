'use strict';
/**
 * plus: `window.api` in one place. The preload (Electron) and the headless
 * page's shim (src/server/web-api.js, handed this map by server.js) both build
 * the page's API from it, so the two front ends can never offer different
 * methods. Plain data: no Electron, no Node.
 *
 * INVOKE: method → [channel, how the call's arguments become the one argument
 * the service takes]. 'one' passes the first argument, 'none' nothing,
 * 'versions' and 'install' are the core picker's two-argument calls
 * (corePicker.js, upstream). EVENTS: method → event channel; the callback gets
 * the payload. WINDOW: the Electron window's own controls (a no-op headless).
 */
const INVOKE = {
  init: ['app:init', 'none'],
  getSettings: ['settings:get', 'none'],
  setSettings: ['settings:set', 'one'],
  checkUpdate: ['app:checkUpdate', 'none'],
  getLog: ['log:get', 'none'],
  clearLog: ['log:clear', 'none'],

  configsList: ['configs:list', 'none'],
  configsAdd: ['configs:add', 'one'],
  configsRemove: ['configs:remove', 'one'],
  configsImport: ['configs:import', 'one'],

  assetStatus: ['assets:status', 'none'],
  assetVersions: ['assets:versions', 'none'],
  downloadAsset: ['assets:download', 'one'],
  coreVersions: ['cores:versions', 'versions'],
  installCoreVersion: ['cores:install', 'install'],

  xserverGet: ['xserver:get', 'none'],
  xserverSet: ['xserver:set', 'one'],
  xserverStart: ['xserver:start', 'none'],
  xserverStop: ['xserver:stop', 'none'],
  xserverRestart: ['xserver:restart', 'none'],
  xserverStatus: ['xserver:status', 'none'],
  xserverLog: ['xserver:log', 'none'],
  xserverGenKeys: ['xserver:genKeys', 'none'],
  xserverGenId: ['xserver:genId', 'one'],
  xserverClientLink: ['xserver:clientLink', 'one'],
  xserverPreview: ['xserver:preview', 'none'],
  xserverOtherSide: ['xserver:otherSide', 'none'],
  xserverFirewall: ['xserver:firewall', 'one'],
  xserverWizard: ['xserver:wizard', 'one'],
  xserverCoreInfo: ['xserver:coreInfo', 'one'],

  scanStart: ['scan:start', 'one'],
  scanStop: ['scan:stop', 'none'],
  scanRetest: ['scan:retest', 'one'],
  scanPresets: ['scan:presets', 'none'],
  scanSuggest: ['scan:suggest', 'one'],
  scanPlan: ['scan:plan', 'one'],
  scanApply: ['scan:apply', 'one'],
  scanLinks: ['scan:links', 'one'],
  scanCopy: ['scan:copy', 'one'],
  scanExport: ['scan:export', 'one'],
  scanForget: ['scan:forget', 'none'],
  scanSets: ['scan:sets', 'one'],
  scanCdnUpdate: ['scan:cdnUpdate', 'one']
};

const EVENTS = {
  onLog: 'log',
  onNotify: 'notify',
  onAssetProgress: 'asset-progress',
  onXServerStatus: 'xserver-status',
  onXServerLog: 'xserver-log',
  onScanProgress: 'scan-progress'
};

const WINDOW = {
  winMinimize: 'win:minimize',
  winMaximize: 'win:maximize',
  winClose: 'win:close',
  openExternal: 'app:openExternal',
  openDataDir: 'app:openDataDir'
};

/** The one argument the service gets for a call made with `args`. */
function argOf(kind, args) {
  if (kind === 'none') return undefined;
  if (kind === 'versions') return Object.assign({}, args[1], { component: args[0] });
  if (kind === 'install') return { component: args[0], tag: args[1] };
  return args[0];
}

module.exports = { INVOKE, EVENTS, WINDOW, argOf };
