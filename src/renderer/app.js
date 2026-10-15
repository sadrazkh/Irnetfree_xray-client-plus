'use strict';
/**
 * IRNetFree Plus — the page shell (spec 2026-10-15). The rail, the title bar,
 * Settings and the Log; the tools (plus/scan.js, plus/xserver.js,
 * plus/configs.js) are classic scripts after this one and use its globals:
 * $, $$, t, state, toast, escapeHtml, copyText, fmtMs, fmtBytes, fmtDuration,
 * pingClass, makeSearchSelect, openCorePicker. They start from the
 * window.plusInit list once app:init has answered and the page has loaded.
 */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const t = (k) => window.i18n.t(k);
const fill = (s, map) => String(s).replace(/\{(\w+)\}/g, (m, k) => (Object.prototype.hasOwnProperty.call(map, k) ? map[k] : m));

const state = {
  servers: [],          // the configs list (whole records) — the tools read it
  settings: {},
  assets: {},
  engines: [],
  coreVersions: {},     // engine → installed version
  platform: 'win32',
  version: '',
  isElectron: true,
  headless: false,
  serverState: 'stopped',
  scanning: false
};

/* ----------------------------- helpers the tools use ----------------------------- */

function toast(msg, kind = '', ms = 2600) {
  const el = $('#toast');
  el.textContent = msg;
  el.className = 'toast show ' + kind;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.className = 'toast'; }, ms);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function pingClass(ms) {
  if (ms < 0) return 'ping-bad';
  if (ms < 200) return 'ping-good';
  if (ms < 600) return 'ping-mid';
  return 'ping-bad';
}

/** Compact latency: seconds for slow results, × for a failure. */
function fmtMs(ms) {
  if (!Number.isFinite(ms) || ms < 0) return '×';
  return ms >= 1000 ? (ms / 1000).toFixed(1) + 's' : String(ms);
}

function fmtBytes(n) {
  n = Number(n) || 0;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? Math.round(n) : n.toFixed(1)) + ' ' + units[i];
}

/** Human duration from seconds (days / hours / minutes). */
function fmtDuration(sec) {
  sec = Math.max(0, sec);
  const d = Math.floor(sec / 86400);
  if (d >= 1) return d + ' ' + t('sub.days');
  const h = Math.floor(sec / 3600);
  if (h >= 1) return h + ' ' + t('sub.hours');
  return Math.floor(sec / 60) + ' ' + t('sub.mins');
}

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); }
  catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
}

/** A searchable select: { options: [{ value, label }], value, onChange } → element with getValue(). */
function makeSearchSelect({ options, value, onChange }) {
  const wrap = document.createElement('div');
  wrap.className = 'ss';
  const cur = document.createElement('button');
  cur.type = 'button';
  cur.className = 'ss-current';
  const menu = document.createElement('div');
  menu.className = 'ss-menu';
  menu.hidden = true;
  const search = document.createElement('input');
  search.className = 'input ss-search';
  search.placeholder = t('ss.search');
  const list = document.createElement('div');
  list.className = 'ss-list';
  menu.appendChild(search); menu.appendChild(list);
  wrap.appendChild(cur); wrap.appendChild(menu);

  let current = value;
  const labelFor = (v) => { const o = options.find(x => x.value === v); return o ? o.label : '—'; };
  const renderCur = () => { cur.innerHTML = `<span class="ss-cur-label">${escapeHtml(labelFor(current))}</span><span class="ss-caret">▾</span>`; };
  const close = () => { menu.hidden = true; };
  const renderList = (f) => {
    f = (f || '').toLowerCase();
    list.innerHTML = '';
    const items = options.filter(o => o.label.toLowerCase().includes(f) || String(o.value).toLowerCase().includes(f));
    if (!items.length) { list.innerHTML = `<div class="ss-empty">${escapeHtml(t('ss.none'))}</div>`; return; }
    for (const o of items) {
      const it = document.createElement('div');
      it.className = 'ss-item' + (o.value === current ? ' active' : '');
      it.textContent = o.label;
      it.onclick = () => { current = o.value; renderCur(); close(); if (onChange) onChange(current); };
      list.appendChild(it);
    }
  };
  const open = () => { menu.hidden = false; search.value = ''; renderList(''); setTimeout(() => search.focus(), 0); };
  cur.onclick = (e) => { e.stopPropagation(); if (menu.hidden) open(); else close(); };
  search.oninput = () => renderList(search.value);
  search.onclick = (e) => e.stopPropagation();
  document.addEventListener('click', (e) => { if (!wrap.contains(e.target)) close(); });
  renderCur();
  wrap.getValue = () => current;
  return wrap;
}

/* ----------------------------- look ----------------------------- */

function applyTheme(pref) {
  const systemDark = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)').matches : true;
  const dark = pref === 'system' ? systemDark : pref !== 'light';
  const theme = dark ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', theme);
  try { localStorage.setItem('irnetfree.theme', theme); } catch { /* only costs a flash */ }
}

function applySkin(skin) {
  const s = ['cockpit', 'console', 'legacy'].includes(skin) ? skin : 'console';
  document.documentElement.setAttribute('data-skin', s);
  try { localStorage.setItem('irnetfree.skin', s); } catch { /* only costs a flash */ }
}

function applyLang(lang) {
  window.i18n.applyI18n(lang);
  $('#btnLang').textContent = lang === 'en' ? 'FA' : 'EN';
  paintTitle();
  renderComponents();
}

/* ----------------------------- navigation and title bar ----------------------------- */

function showView(view) {
  const btn = document.querySelector(`.nav-item[data-view="${view}"]`);
  if (!btn) return;
  $$('.nav-item').forEach(b => b.classList.toggle('active', b === btn));
  $$('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + view));
  const content = $('.content');
  if (content) content.scrollTop = 0;
}
window.plusShowView = showView;

/** The title bar says what runs: the local server (green), a scan (amber), or nothing. */
function paintTitle() {
  const bar = $('#titlebar');
  const on = state.serverState === 'running';
  const busy = state.scanning || state.serverState === 'starting';
  bar.classList.toggle('conn-on', on && !state.scanning);
  bar.classList.toggle('conn-wait', busy);
  bar.classList.toggle('conn-off', !on && !busy);
  const key = state.scanning ? 'app.scanning' : (on ? 'app.serverOn' : 'app.idle');
  const label = $('#tbState');
  label.setAttribute('data-i18n', key);
  label.textContent = t(key);
}

/* ----------------------------- the configs list, shared ----------------------------- */

/** The configs changed (added, removed, imported, a scan saved one): every page that lists them redraws. */
function setServers(list) {
  state.servers = Array.isArray(list) ? list : [];
  for (const fn of [window.plusConfigsRefresh, window.plusScanRefresh, window.plusXsRefresh]) {
    if (typeof fn === 'function') { try { fn(); } catch (e) { console.error(e); } }
  }
}

/* ----------------------------- Settings: the cores ----------------------------- */

const COMPONENTS = [
  { key: 'xray', label: 'comp.xray', pick: true },
  { key: 'xray-pattn', label: 'comp.xrayPattn', pick: true },
  { key: 'geo', label: 'comp.geo', has: (a) => a.geoip && a.geosite }
];

function renderComponents() {
  const list = $('#compList');
  if (!list) return;
  list.innerHTML = '';
  const a = state.assets || {};
  for (const c of COMPONENTS) {
    const present = c.has ? !!c.has(a) : !!a[c.key];
    const v = c.pick && present ? state.coreVersions[c.key] : '';
    const ver = v ? ` <span class="comp-ver">v${escapeHtml(v)}</span>` : '';
    const pick = c.pick ? `<button class="btn ghost comp-pick" type="button">${escapeHtml(t('cv.choose'))}</button>` : '';
    const row = document.createElement('div');
    row.className = 'comp-row';
    row.innerHTML = `
      <div class="comp-info">
        <span class="comp-dot ${present ? 'ok' : 'missing'}"></span>
        <span class="comp-name">${escapeHtml(t(c.label))}${ver}</span>
        <span class="comp-state ${present ? 'ok' : 'missing'}">${escapeHtml(present ? t('comp.installed') : t('comp.missing'))}</span>
      </div>
      <div class="comp-actions">${pick}<button class="btn ${present ? 'ghost' : 'primary'} comp-btn" type="button">${escapeHtml(present ? t('btn.update') : t('btn.download'))}</button></div>`;
    const btn = row.querySelector('.comp-btn');
    btn.onclick = () => downloadComponent(c.key, btn);
    const pickBtn = row.querySelector('.comp-pick');
    if (pickBtn) pickBtn.onclick = () => openCorePicker(c.key, pickBtn);
    list.appendChild(row);
  }
}

async function refreshCoreVersions() {
  try { state.coreVersions = (await window.api.assetVersions()) || {}; } catch { state.coreVersions = {}; }
  renderComponents();
}

async function refreshAssets() {
  try {
    const r = await window.api.assetStatus();
    if (r) { state.assets = r.assets || state.assets; state.engines = r.engines || state.engines; }
  } catch { /* the rows keep what they had */ }
  renderComponents();
  if (typeof window.plusEnginesChanged === 'function') window.plusEnginesChanged();
}

async function downloadComponent(key, btn) {
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = t('btn.downloading');
  let res;
  try { res = await window.api.downloadAsset(key); } catch (e) { res = { ok: false, error: (e && e.message) || String(e) }; }
  btn.disabled = false;
  btn.textContent = orig;
  if (res && res.assets) state.assets = res.assets;
  if (res && res.engines) state.engines = res.engines;
  if (res && res.ok) {
    toast(t('t.downloaded'), 'ok');
    refreshCoreVersions();
    if (typeof window.plusEnginesChanged === 'function') window.plusEnginesChanged();
  } else if (res && (res.coreBusy || res.error === 'busy')) toast(t('comp.coreBusy'), 'warn');
  else toast(t('t.downloadFailed') + ': ' + ((res && res.error) || ''), 'err');
  renderComponents();
}

/**
 * Any version of a core — upstream's picker (corePicker.js), here as in
 * IRNetFree. A core is not swapped while a scan or the server runs on it (the
 * service refuses too).
 */
function openCorePicker(key, opener) {
  if (!window.corePicker) return;
  window.corePicker.open(key, {
    opener,
    busy: () => state.scanning || state.serverState === 'running' || state.serverState === 'starting',
    toast,
    onInstalled: async (res) => {
      if (res && res.assets) state.assets = res.assets;
      await refreshAssets();
      refreshCoreVersions();
    }
  });
}

/* ----------------------------- Settings: the rest ----------------------------- */

async function saveSettings(patch) {
  let s;
  try { s = await window.api.setSettings(patch); } catch (e) { return toast((e && e.message) || String(e), 'err'); }
  state.settings = s || state.settings;
  return state.settings;
}

function wireSettings() {
  $('#setLang').onchange = async () => { const s = await saveSettings({ lang: $('#setLang').value }); if (s) applyLang(s.lang); };
  $('#setTheme').onchange = async () => { const s = await saveSettings({ theme: $('#setTheme').value }); if (s) applyTheme(s.theme); };
  $('#setSkin').onchange = async () => { const s = await saveSettings({ skin: $('#setSkin').value }); if (s) applySkin(s.skin); };
  $('#setOpenAtLogin').onchange = async () => { await saveSettings({ openAtLogin: $('#setOpenAtLogin').checked }); toast(t('set.saved'), 'ok'); };
  $('#btnLang').onclick = async () => {
    const next = (state.settings.lang || 'fa') === 'fa' ? 'en' : 'fa';
    const s = await saveSettings({ lang: next });
    if (s) { $('#setLang').value = s.lang; applyLang(s.lang); }
  };
  $('#btnOpenData').onclick = () => window.api.openDataDir();
  $('#btnCheckUpdate').onclick = async () => {
    const out = $('#updateStatus');
    out.textContent = '…';
    let r;
    try { r = await window.api.checkUpdate(); } catch (e) { r = { ok: false, error: e.message }; }
    out.innerHTML = '';
    if (!r || !r.ok) { out.textContent = t('app.updateFailed'); return; }
    if (!r.newer) { out.textContent = fill(t('app.upToDate'), { v: r.current }); return; }
    out.textContent = fill(t('app.newer'), { v: r.latest }) + ' — ';
    const a = document.createElement('button');
    a.type = 'button';
    a.className = 'btn small primary';
    a.textContent = t('app.openRelease');
    a.onclick = () => window.api.openExternal(r.url);
    out.appendChild(a);
  };
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { if ((state.settings.theme || 'system') === 'system') applyTheme('system'); });
  }
}

function paintSettings() {
  const s = state.settings || {};
  $('#setLang').value = s.lang || 'fa';
  $('#setTheme').value = s.theme || 'system';
  $('#setSkin').value = s.skin || 'console';
  $('#setOpenAtLogin').checked = !!s.openAtLogin;
  // the login item is the desktop app's; the headless server is started by its own service manager
  $('#setStartCard').hidden = !state.isElectron;
  $('#btnOpenData').hidden = !state.isElectron;
  $('#aboutVersion').textContent = state.version ? 'v' + state.version : '—';
  $('#aboutDataDir').textContent = state.dataDir || '—';
  $('#tbVersion').textContent = state.version ? 'v' + state.version : '';
}

/* ----------------------------- the log ----------------------------- */

const LOG_KEEP = 500;
const logLines = [];
function logText(e) {
  const d = new Date(e.at || Date.now());
  const hh = String(d.getHours()).padStart(2, '0'), mm = String(d.getMinutes()).padStart(2, '0'), ss = String(d.getSeconds()).padStart(2, '0');
  return `${hh}:${mm}:${ss} [${e.level || 'info'}] ${e.line}`;
}
function addLog(e) {
  if (!e) return;
  logLines.push(e);
  if (logLines.length > LOG_KEEP) logLines.splice(0, logLines.length - LOG_KEEP);
  const box = $('#logBox');
  const atEnd = box.scrollTop + box.clientHeight >= box.scrollHeight - 8;
  box.textContent = logLines.map(logText).join('\n');
  if (atEnd) box.scrollTop = box.scrollHeight;
}
function wireLog() {
  $('#btnLogCopy').onclick = async () => { await copyText(logLines.map(logText).join('\n')); toast(t('log.copied'), 'ok'); };
  $('#btnLogClear').onclick = async () => {
    try { await window.api.clearLog(); } catch { /* the page clears anyway */ }
    logLines.length = 0;
    $('#logBox').textContent = '';
  };
}

/* ----------------------------- start ----------------------------- */

async function init() {
  $$('.nav-item').forEach(btn => btn.addEventListener('click', () => showView(btn.dataset.view)));
  $('#btnMin').onclick = () => window.api.winMinimize();
  $('#btnMax').onclick = () => window.api.winMaximize();
  $('#btnClose').onclick = () => window.api.winClose();
  wireSettings();
  wireLog();
  // the share-link QR the Server tab opens
  $('#qrClose').onclick = () => { $('#qrModal').hidden = true; };
  $('#qrModal').onclick = (e) => { if (e.target === $('#qrModal')) $('#qrModal').hidden = true; };
  $('#qrCopy').onclick = async () => { await copyText($('#qrLink').value); toast(t('t.copied'), 'ok'); };

  let data = {};
  try { data = (await window.api.init()) || {}; } catch (e) { console.error(e); }
  state.version = data.version || '';
  state.platform = data.platform || 'win32';
  state.isElectron = !!data.isElectron;
  state.headless = !!window.api.headless;
  state.dataDir = data.dataDir || '';
  state.settings = data.settings || {};
  state.assets = data.assets || {};
  state.engines = data.engines || [];
  state.servers = Array.isArray(data.servers) ? data.servers : [];
  for (const b of ['#btnMin', '#btnMax', '#btnClose']) $(b).hidden = state.headless;

  applyTheme(state.settings.theme || 'system');
  applySkin(state.settings.skin || 'console');
  paintSettings();
  applyLang(state.settings.lang || 'fa');
  refreshCoreVersions();

  window.api.onLog(addLog);
  try { for (const e of (await window.api.getLog()) || []) addLog(e); } catch { /* the log fills from here on */ }
  window.api.onAssetProgress((d) => {
    if (window.corePicker && window.corePicker.progress(d)) return;
    toast(`${t('t.downloading')} ${d.component}: ${d.pct}%`);
  });
  window.api.onNotify((n) => { if (n && state.headless) toast((n.title ? n.title + ' — ' : '') + (n.body || ''), 'warn', 6000); });
  window.api.onXServerStatus((st) => { state.serverState = (st && st.state) || 'stopped'; paintTitle(); });
  window.api.onScanProgress((ev) => { state.scanning = !!ev && !ev.finished; paintTitle(); });
  try { const st = await window.api.xserverStatus(); state.serverState = (st && st.state) || 'stopped'; } catch { /* stays stopped */ }
  paintTitle();

  // the tools: once the page has loaded (over HTTP the scripts after this one can arrive later than app:init)
  if (document.readyState !== 'complete') await new Promise((r) => window.addEventListener('load', r, { once: true }));
  for (const fn of (window.plusInit || [])) { try { await fn(data); } catch (e) { console.error(e); } }
}

init();
