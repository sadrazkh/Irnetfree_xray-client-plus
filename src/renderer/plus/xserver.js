'use strict';
/**
 * plus: the Server tab — this machine as an Xray server, laid out the way
 * 3x-ui lays it out: sub-tabs, a table of inbounds folding open over their
 * users, a table of tagged outbounds, an ordered table of routing rules, two
 * reverse wizards that only write ordinary outbounds and rules, the core's
 * settings and its log. Shares app.js globals ($, $$, t, state, toast,
 * escapeHtml, fmtBytes, fmtDuration, makeSearchSelect, copyText, srvById).
 *
 * One rule shapes the whole file: the model is main's, not ours. Every edit
 * copies `xs.model`, mutates the copy and hands it to `xserver:set`; on `ok`
 * the reply's normalised model replaces ours (ids and tags are filled there),
 * on a refusal NOTHING was written and the errors say which path was wrong.
 * So there is no local "unsaved" state to keep in step, and a validation
 * message can always be pinned to the row it belongs to.
 *
 * The live status is the one thing that does not go through a re-render: it
 * arrives every five seconds while the core runs, and rebuilding every row
 * for two counters would throw away the scroll position and the open rows.
 * Rows carry `data-xs-inbound` / `data-xs-client` and are patched in place.
 */
(function () {
  const GB = 1024 * 1024 * 1024;
  const MAX_LOG = 300;
  const SS_2022 = ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm'];
  // what the core can dial as an outbound: the stored configs of these shapes
  const XRAY_PROTOS = ['vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'wireguard'];
  const DEFAULT_TAGS = { freedom: 'direct', blackhole: 'block', server: 'proxy', link: 'proxy' };
  const PRESETS = ['private', 'torrent', 'ads'];
  const TABS = {
    overview: '#xsTabOverview', inbounds: '#xsTabInbounds', outbounds: '#xsTabOutbounds',
    routing: '#xsTabRouting', reverse: '#xsTabReverse', settings: '#xsTabSettings', log: '#xsTabLog'
  };

  const xs = { model: null, status: null, engines: [], presets: {}, constants: {}, core: null };
  let ready = null;              // the boot promise — initXServer can be reached twice
  let errors = [];               // the last refusal's [{ path, msg }]
  let attempted = null;          // the model those paths index into
  let ticker = 0;                // the one-second uptime clock, only while running
  let tab = 'overview';
  const open = new Set();        // inbound ids folded open over their users
  let editIn = null;             // { id, draft } while the inbound modal is open
  let editCl = null;             // { inboundId, id, draft } while the client modal is open
  let editOut = null;            // { id, draft } while the outbound modal is open
  let editRule = null;           // { id, draft } while the rule modal is open
  let tagTouched = false;        // the inbound tag follows the port until typed into
  let outTagTouched = false;     // the outbound tag follows the kind until typed into
  let outSel = null;             // the outbound modal's config picker
  let bridgeSel = null;          // the bridge wizard's config picker
  // what the two wizards have been told so far — kept across re-renders
  const wiz = { inboundId: '', clientId: '', users: new Set(), link: '' };
  const bwiz = { via: 'link', serverId: '' };

  /* ----------------------------- small helpers ----------------------------- */

  const deep = (v) => JSON.parse(JSON.stringify(v));
  /** t() with `{name}` slots filled. */
  const tf = (key, vars) => String(t(key)).replace(/\{(\w+)\}/g, (m, k) => (vars && k in vars ? String(vars[k]) : m));
  const usesUuid = (i) => i.protocol === 'vless' || i.protocol === 'vmess';
  const secretOf = (i, c) => (usesUuid(i) ? c.uuid : c.password) || '';
  const is2022 = (method) => SS_2022.includes(method);
  const csv = (v) => String(v || '').split(',').map(s => s.trim()).filter(Boolean);
  const lines = (v) => String(v || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  const inboundLabel = (i) => (i.remark || i.tag) + ' — ' + i.listen + ':' + i.port;
  /** Enough of a secret to recognise it, never enough to read it over a shoulder. */
  const mask = (s) => (s.length > 6 ? '••••' + s.slice(-4) : s ? '••••' : '—');
  const attr = (s) => escapeHtml(String(s == null ? '' : s));
  const liveInbound = (id) => ((xs.status && xs.status.inbounds) || []).find(i => i.id === id) || null;
  const liveClient = (li, id) => (li && (li.clients || []).find(c => c.id === id)) || null;
  /** Vision only means something for vless over raw tcp with tls or reality. */
  const flowOk = (i) => i.protocol === 'vless' && i.network === 'tcp' && (i.security === 'tls' || i.security === 'reality');
  const engineLabel = (id) => { const e = xs.engines.find(x => x.id === id); return e ? (e.label || e.id) : id; };

  /** `2026-09-09` in the user's own timezone — the date input's format. */
  function toDateInput(ms) {
    const d = new Date(ms);
    const p = (n) => String(n).padStart(2, '0');
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
  }

  /** A chosen day is valid to its end, not to its midnight. */
  function fromDateInput(v) {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(v || ''));
    if (!m) return 0;
    return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 23, 59, 59, 999).getTime();
  }

  const gbOf = (bytes) => (bytes ? String(Math.round((bytes / GB) * 100) / 100) : '0');
  const bytesOf = (gb) => Math.max(0, Math.round((parseFloat(gb) || 0) * GB));

  /** Every tag the model knows, by what carries it. */
  function allTags(m) {
    const out = { inbounds: new Set(), outbounds: new Set(), clientReverse: new Set(), outboundReverse: new Set() };
    for (const i of m.inbounds) {
      out.inbounds.add(i.tag);
      for (const c of i.clients) if (c.reverseTag) out.clientReverse.add(c.reverseTag);
    }
    for (const o of m.outbounds) {
      out.outbounds.add(o.tag);
      if (o.reverseTag) out.outboundReverse.add(o.reverseTag);
    }
    return out;
  }

  /** `base`, or `base-2`, `base-3`… — the first one nothing in the model carries. */
  function freeTag(m, base) {
    const tags = allTags(m);
    const taken = new Set([...tags.inbounds, ...tags.outbounds, ...tags.clientReverse, ...tags.outboundReverse]);
    let tag = base;
    for (let n = 2; taken.has(tag); n++) tag = base + '-' + n;
    return tag;
  }

  /** The host:port a link dials, for the outbound table; vmess hides it in base64. */
  function linkTarget(link) {
    const s = String(link || '');
    if (/^vmess:/i.test(s)) return 'vmess://…';
    const m = /^[a-z0-9+.-]+:\/\/(?:[^@/?#]*@)?([^/?#]+)/i.exec(s);
    return m ? m[1] : s.slice(0, 24) + '…';
  }

  /** The stored configs an outbound may dial. */
  const dialable = () => (state.servers || []).filter(s => s && s.outbound && XRAY_PROTOS.includes(s.protocol));
  const serverOpt = (s) => ({ value: s.id, label: s.name + ' — ' + s.address + ':' + s.port });

  /* ----------------------------- talking to main ----------------------------- */

  /**
   * The only way anything is written. On success the reply's model is the
   * truth; on a refusal our copy is untouched, so the screen keeps showing what
   * is actually stored while the errors say what to fix.
   */
  async function apply(next) {
    let r;
    try { r = await window.api.xserverSet(next); }
    catch (e) { setErrors([{ path: '', msg: (e && e.message) || String(e) }], next); return false; }
    if (r && r.ok) {
      xs.model = r.model;
      if (r.status) xs.status = r.status;
      setErrors([], null);
      render();
      paintStatus();
      return true;
    }
    const list = (r && r.errors && r.errors.length) ? r.errors : [{ path: '', msg: (r && r.error) || t('xs.refused') }];
    setErrors(list, next);
    render();
    toast(t('xs.refused'), 'err');
    return false;
  }

  async function load() {
    let r;
    try { r = await window.api.xserverGet(); }
    catch (e) { console.error(e); return; }
    xs.model = r.model;
    xs.status = r.status;
    xs.engines = r.engines || [];
    xs.presets = r.presets || {};
    xs.constants = r.constants || {};
    render();
    paintStatus();
    try {
      const lines = await window.api.xserverLog();
      for (const line of (lines || [])) appendLog(line, levelOf(line));
    } catch { /* the backlog is a nicety, not a requirement */ }
    refreshCore(false);
  }

  /** What core is installed and, when asked, what GitHub has on each channel. */
  async function refreshCore(online) {
    let r = null;
    try { r = await window.api.xserverCoreInfo({ online: !!online }); } catch { /* shown as unknown */ }
    if (r && !r.error) xs.core = r;
    paintCore();
    return r;
  }

  /* ----------------------------- errors ----------------------------- */

  function errorItem(e) {
    const li = document.createElement('li');
    li.className = 'xs-error';
    const path = document.createElement('code');
    path.className = 'xs-error-path';
    path.textContent = e.path || '—';
    const msg = document.createElement('span');
    msg.className = 'xs-error-msg';
    msg.textContent = e.msg || '';
    li.appendChild(path);
    li.appendChild(msg);
    return li;
  }

  function setErrors(list, submitted) {
    errors = list || [];
    attempted = errors.length ? submitted : null;
    renderErrors();
    markInvalid();
  }

  /** The overview's list: the core's last error first, then why the last change was refused. */
  function renderErrors() {
    const box = $('#xsErrors');
    box.innerHTML = '';
    const st = xs.status || {};
    if (st.state === 'error' && st.error) box.appendChild(errorItem({ path: t('xs.coreError'), msg: st.error }));
    for (const e of errors) box.appendChild(errorItem(e));
    $('#xsErrorsCard').hidden = !box.childNodes.length;
  }

  /**
   * A red outline on the row a message is about, and a dot on its tab. The
   * indices in a path belong to the refused model, so the row is found by the
   * id that model holds at that index — a brand-new row has none and the
   * whole table is marked instead.
   */
  function markInvalid() {
    $$('.xs-invalid').forEach(el => el.classList.remove('xs-invalid'));
    $$('.xs-tab.has-err').forEach(el => el.classList.remove('has-err'));
    const byId = (attrName, id) => (id ? document.querySelector('[' + attrName + '="' + id + '"]') : null);
    for (const e of errors) {
      const p = String(e.path || '');
      let el = null, tabName = 'overview', m;
      if ((m = /^inbounds\[(\d+)\](?:\.clients\[(\d+)\])?/.exec(p))) {
        tabName = 'inbounds';
        const i = attempted ? attempted.inbounds[Number(m[1])] : null;
        const c = i && m[2] !== undefined ? i.clients[Number(m[2])] : null;
        el = (c && byId('data-xs-client', c.id)) || (i && byId('data-xs-inbound', i.id)) || $('#xsInboundsCard');
      } else if ((m = /^outbounds(?:\[(\d+)\])?/.exec(p))) {
        tabName = 'outbounds';
        const o = attempted && m[1] !== undefined ? attempted.outbounds[Number(m[1])] : null;
        el = (o && byId('data-xs-outbound', o.id)) || $('#xsOutboundsCard');
      } else if ((m = /^routing\.rules(?:\[(\d+)\])?/.exec(p))) {
        tabName = 'routing';
        const r = attempted && m[1] !== undefined ? attempted.routing.rules[Number(m[1])] : null;
        el = (r && byId('data-xs-rule', r.id)) || $('#xsRulesCard');
      } else if (p.startsWith('routing')) {
        tabName = 'routing';
        el = $('#xsRulesCard');
      } else el = $('#xsErrorsCard');
      if (el) el.classList.add('xs-invalid');
      const btn = document.querySelector('.xs-tab[data-xstab="' + tabName + '"]');
      if (btn) btn.classList.add('has-err');
    }
  }

  /**
   * A modal keeps its place when the refusal is about what it is editing;
   * otherwise the fix is elsewhere on the page and the modal is in the way.
   */
  function modalErrors(sel, prefix, close) {
    const mine = errors.filter(e => String(e.path || '').startsWith(prefix));
    const box = $(sel);
    box.innerHTML = '';
    if (!mine.length) return close();
    for (const e of mine) box.appendChild(errorItem(e));
    box.hidden = false;
  }

  /* ----------------------------- tabs ----------------------------- */

  function showTab(name) {
    if (!TABS[name]) name = 'overview';
    tab = name;
    $$('#xsTabs .xs-tab').forEach(b => b.classList.toggle('active', b.dataset.xstab === name));
    for (const [k, sel] of Object.entries(TABS)) $(sel).hidden = k !== name;
    if (name === 'log') { const box = $('#xsLog'); box.scrollTop = box.scrollHeight; }
  }

  /* ----------------------------- overview ----------------------------- */

  function paintStatus() {
    const st = xs.status || { state: 'stopped' };
    const pill = $('#xsState');
    pill.dataset.state = st.state || 'stopped';
    pill.textContent = t('xs.state.' + (st.state || 'stopped'));

    // the pid and the metrics port belong to a live core; after a stop they
    // are last time's numbers and only mislead
    const up = st.state === 'running' || st.state === 'starting';
    const bits = [];
    if (xs.model) bits.push(engineLabel(st.engine && up ? st.engine : xs.model.engine));
    if (up && st.pid) bits.push('pid ' + st.pid);
    if (up && st.apiPort) bits.push('api ' + st.apiPort);
    if (!up) bits.push(t('xs.notRunning'));
    $('#xsEngine').textContent = bits.join(' · ');

    $('#btnXsStart').disabled = up;
    $('#btnXsStop').disabled = st.state === 'stopped';
    $('#btnXsRestart').disabled = st.state === 'stopped';

    paintUptime();
    const run = st.state === 'running';
    if (run && !ticker) ticker = setInterval(paintUptime, 1000);
    if (!run && ticker) { clearInterval(ticker); ticker = 0; }

    // the totals: the status carries every inbound whether or not the core runs
    let upB = 0, downB = 0, online = 0, total = 0;
    const src = Array.isArray(st.inbounds) ? st.inbounds : [];
    for (const li of src) {
      upB += li.up || 0;
      downB += li.down || 0;
      for (const c of (li.clients || [])) { total++; if (c.online) online++; }
    }
    $('#xsTotalUp').textContent = fmtBytes(upB);
    $('#xsTotalDown').textContent = fmtBytes(downB);
    $('#xsClientsOnline').textContent = online + ' / ' + total;
    $('#xsInboundCount').textContent = xs.model ? String(xs.model.inbounds.length) : '';
    renderErrors();
  }

  function paintUptime() {
    const st = xs.status || {};
    const on = st.state === 'running' && st.since;
    $('#xsUptime').textContent = on ? fmtDuration(Math.floor((Date.now() - st.since) / 1000)) : '';
  }

  function paintCore() {
    const c = xs.core;
    const ver = c && c.version ? c.version : '';
    $('#xsCoreVersion').textContent = ver;
    $('#xsCoreVersion2').textContent = t('xs.coreVersion') + ': ' + (ver || t('xs.coreNotInstalled'));
    const out = [];
    if (c && c.latestStable) out.push(t('xs.coreStable') + ' ' + c.latestStable);
    if (c && c.latestAny) out.push(t('xs.coreAny') + ' ' + c.latestAny);
    $('#xsCoreCheckOut').textContent = out.join(' · ');
  }

  /* ----------------------------- inbounds ----------------------------- */

  // The class list is assembled first: the contract test reads every
  // `class="…"` literal in this file as class names, and an expression inside
  // the quotes is not a class name.
  const PRESET_BUTTON = { private: '#btnXsPresetPrivate', torrent: '#btnXsPresetTorrent', ads: '#btnXsPresetAds' };
  const iconBtn = (act, glyph, key, extra) => {
    const cls = extra ? 'icon-btn ' + extra : 'icon-btn';
    return '<button type="button" data-act="' + act + '" title="' + attr(t(key)) + '" class=' + JSON.stringify(cls) + '>' + glyph + '</button>';
  };
  const switchCell = (on, key) =>
    '<td class="xs-c-sw"><label class="switch" title="' + attr(t(key)) + '"><input type="checkbox" data-act="enable"' + (on ? ' checked' : '') + ' /><span class="slider"></span></label></td>';
  const flagText = (by) => (by === 'expired' ? t('xs.expired') : by === 'quota' ? t('xs.quotaOut') : '');

  /** Counters, the online count and the enforcer's badge — what a status tick owns. */
  function paintInbound(row, i, live) {
    const up = live ? live.up : i.used.up;
    const down = live ? live.down : i.used.down;
    const online = live ? (live.clients || []).filter(c => c.online).length : 0;
    row.querySelector('.xs-in-clients').textContent = tf('xs.clientsOnline', { n: i.clients.length, online });
    row.querySelector('.xs-in-traffic').textContent = '↑ ' + fmtBytes(up) + '  ↓ ' + fmtBytes(down);
    const limits = [];
    if (i.totalBytes > 0) limits.push(fmtBytes(up + down) + ' / ' + fmtBytes(i.totalBytes));
    if (i.expiresAt > 0) limits.push(toDateInput(i.expiresAt));
    row.querySelector('.xs-in-limits').textContent = limits.length ? limits.join(' · ') : '—';
    const by = live ? live.disabledBy : i.disabledBy;
    const flag = row.querySelector('.xs-in-flag');
    flag.hidden = !by;
    flag.textContent = flagText(by);
    const on = live ? live.enabled : i.enabled;
    row.querySelector('.xs-c-sw input').checked = !!on;
    row.classList.toggle('disabled', !on);
  }

  function paintClient(row, c, live) {
    const up = live ? live.up : c.used.up;
    const down = live ? live.down : c.used.down;
    const used = up + down;
    const bar = row.querySelector('.usage-bar');
    const fill = row.querySelector('.usage-fill');
    if (c.quotaBytes > 0) {
      const pct = Math.max(0, Math.min(100, (used / c.quotaBytes) * 100));
      bar.hidden = false;
      fill.style.inlineSize = pct.toFixed(1) + '%';
      fill.className = 'usage-fill' + (pct >= 100 ? ' bad' : pct >= 80 ? ' mid' : '');
      row.querySelector('.xs-used').textContent = fmtBytes(used) + ' / ' + fmtBytes(c.quotaBytes);
    } else {
      // no quota, no bar: an empty track would read as "nothing of nothing"
      bar.hidden = true;
      row.querySelector('.xs-used').textContent = fmtBytes(used);
    }
    row.querySelector('.xs-dot').dataset.online = live && live.online ? '1' : '0';
    const by = live ? live.disabledBy : c.disabledBy;
    const flag = row.querySelector('.xs-cl-flag');
    flag.hidden = !by;
    flag.textContent = flagText(by);
    const resetAt = live ? live.resetAt : c.resetAt;
    const reset = row.querySelector('.xs-cl-reset');
    if (c.resetDays > 0) {
      reset.textContent = tf('xs.resetEvery', { n: c.resetDays }) + (resetAt ? ' · ' + tf('xs.resetNext', { d: toDateInput(resetAt) }) : '');
    } else reset.textContent = '—';
    const on = live ? live.enabled : c.enabled;
    row.querySelector('.xs-c-sw input').checked = !!on;
    row.classList.toggle('disabled', !on);
  }

  function clientRow(inbound, c) {
    const tr = document.createElement('tr');
    tr.className = 'xs-row';
    tr.dataset.xsClient = c.id;
    tr.innerHTML =
      switchCell(c.enabled, 'xs.enableClient') +
      '<td class="xs-c-email"><span class="xs-dot" data-online="0" title="' + attr(t('xs.online')) + '"></span> ' +
        escapeHtml(c.email || '—') + '<span class="xs-flag xs-cl-flag" hidden></span></td>' +
      '<td><span class="xs-secret" data-act="secret" title="' + attr(t('xs.copySecret')) + '">' + escapeHtml(mask(secretOf(inbound, c))) + '</span></td>' +
      '<td class="xs-c-mono">' + escapeHtml(c.flow || '—') + '</td>' +
      '<td class="xs-c-num">' + (c.limitIp > 0 ? c.limitIp : '—') + '</td>' +
      '<td class="xs-c-quota"><div class="xs-quota-wrap"><span class="usage-bar" hidden><span class="usage-fill"></span></span><span class="xs-used"></span></div></td>' +
      '<td class="xs-c-mono">' + escapeHtml(c.expiresAt ? toDateInput(c.expiresAt) : t('xs.never')) + '</td>' +
      '<td class="xs-c-mono xs-cl-reset"></td>' +
      '<td class="xs-c-dim" title="' + attr(c.comment) + '">' + escapeHtml(c.comment || '') + '</td>' +
      '<td>' + (c.reverseTag ? '<span class="xs-tag reverse">' + escapeHtml(c.reverseTag) + '</span>' : '—') + '</td>' +
      '<td class="xs-c-acts">' +
        iconBtn('link', '🔗', 'xs.copyLink') + iconBtn('qr', '▦', 'xs.qr') +
        iconBtn('edit', '✎', 'xs.editClient') + iconBtn('del', '🗑', 'xs.delClient', 'danger') +
      '</td>';
    paintClient(tr, c, liveClient(liveInbound(inbound.id), c.id));
    return tr;
  }

  /** The row under an inbound: its users as a table of their own, and the button that adds one. */
  function subRow(i) {
    const tr = document.createElement('tr');
    tr.className = 'xs-sub';
    tr.dataset.xsSub = i.id;
    tr.hidden = !open.has(i.id);
    const td = document.createElement('td');
    td.colSpan = 9;
    const head = document.createElement('div');
    head.className = 'xs-sub-head';
    head.innerHTML =
      '<span class="xs-sub-title">' + escapeHtml(t('xs.col.clients')) + '</span>' +
      '<button type="button" class="btn primary small" data-act="addClient">' + escapeHtml(t('xs.addClient')) + '</button>';
    td.appendChild(head);
    if (!i.clients.length) {
      const none = document.createElement('div');
      none.className = 'xs-sub-empty';
      none.textContent = t('xs.noClients');
      td.appendChild(none);
    } else {
      const wrap = document.createElement('div');
      wrap.className = 'xs-clients-wrap';
      const table = document.createElement('table');
      table.className = 'xs-clients';
      const cols = ['xs.col.enable', 'xs.col.email', 'xs.col.secret', 'xs.col.flow', 'xs.col.limitIp', 'xs.col.quota',
        'xs.col.expiry', 'xs.col.reset', 'xs.col.comment', 'xs.col.reverse', 'xs.col.actions'];
      table.innerHTML = '<thead><tr>' + cols.map((k, n) =>
        '<th class=' + JSON.stringify('xs-th' + (n === 0 ? ' xs-th-sw' : n === cols.length - 1 ? ' xs-th-acts' : '')) + '>' + escapeHtml(t(k)) + '</th>').join('') + '</tr></thead>';
      const body = document.createElement('tbody');
      for (const c of i.clients) body.appendChild(clientRow(i, c));
      table.appendChild(body);
      wrap.appendChild(table);
      td.appendChild(wrap);
    }
    tr.appendChild(td);
    return tr;
  }

  function inboundRow(i) {
    const tr = document.createElement('tr');
    tr.className = 'xs-row' + (open.has(i.id) ? ' expanded' : '');
    tr.dataset.xsInbound = i.id;
    const win = state.platform === 'win32';
    tr.innerHTML =
      switchCell(i.enabled, 'xs.enableIn') +
      '<td class="xs-c-name" title="' + attr(i.remark) + '">' + escapeHtml(i.remark || i.tag) + '<span class="xs-flag xs-in-flag" hidden></span></td>' +
      '<td><span class=' + JSON.stringify('proto-badge proto-' + i.protocol) + '>' + escapeHtml(i.protocol) + '</span></td>' +
      '<td class="xs-c-addr">' + escapeHtml(i.listen + ':' + i.port) + '</td>' +
      '<td><span class="xs-tag">' + escapeHtml(i.tag) + '</span></td>' +
      '<td class="xs-c-num xs-in-clients"></td>' +
      '<td class="xs-c-num xs-in-traffic"></td>' +
      '<td class="xs-c-num xs-in-limits"></td>' +
      '<td class="xs-c-acts">' +
        iconBtn('expand', '👥', 'xs.expandIn') + iconBtn('edit', '✎', 'xs.editIn') +
        iconBtn('link', '🔗', 'xs.linksIn') + iconBtn('qr', '▦', 'xs.qr') +
        (win ? iconBtn('fw', '🛡', 'xs.firewall') : '') +
        iconBtn('del', '🗑', 'xs.delIn', 'danger') +
      '</td>';
    paintInbound(tr, i, liveInbound(i.id));
    return tr;
  }

  function renderInbounds() {
    const host = $('#xsInbounds');
    host.innerHTML = '';
    for (const i of xs.model.inbounds) { host.appendChild(inboundRow(i)); host.appendChild(subRow(i)); }
    $('#xsInboundWrap').hidden = !xs.model.inbounds.length;
    $('#xsInboundsEmpty').hidden = xs.model.inbounds.length > 0;
    $('#xsFirewallHint').hidden = state.platform !== 'win32' || !xs.model.inbounds.length;
  }

  function toggleOpen(id) {
    if (open.has(id)) open.delete(id); else open.add(id);
    const row = document.querySelector('[data-xs-inbound="' + id + '"]');
    const sub = document.querySelector('[data-xs-sub="' + id + '"]');
    if (row) row.classList.toggle('expanded', open.has(id));
    if (sub) sub.hidden = !open.has(id);
  }

  /* ----------------------------- outbounds ----------------------------- */

  function kindLabel(ob) {
    if (ob.kind === 'freedom' || ob.kind === 'blackhole') return t('xs.kind.' + ob.kind);
    if (ob.kind === 'server') {
      const s = srvById(ob.serverId);
      return t('xs.kind.server') + ': ' + (s ? s.name + ' — ' + s.address + ':' + s.port : t('xs.missingServer'));
    }
    return t('xs.kind.link') + ': ' + linkTarget(ob.link);
  }

  const orderCell = (idx, len) =>
    '<td class="xs-c-order">' +
      '<button type="button" class="icon-btn" data-act="up" title="' + attr(t('xs.moveUp')) + '"' + (idx === 0 ? ' disabled' : '') + '>▲</button>' +
      '<button type="button" class="icon-btn" data-act="down" title="' + attr(t('xs.moveDown')) + '"' + (idx === len - 1 ? ' disabled' : '') + '>▼</button>' +
    '</td>';

  function outboundRow(ob, idx, len, isDefault) {
    const tr = document.createElement('tr');
    tr.className = 'xs-row' + (ob.enabled ? '' : ' disabled');
    tr.dataset.xsOutbound = ob.id;
    tr.innerHTML =
      switchCell(ob.enabled, 'xs.out.enabled') +
      '<td><span class=' + JSON.stringify(isDefault ? 'xs-tag exit' : 'xs-tag') + '>' + escapeHtml(ob.tag) + '</span>' +
        (isDefault ? '<span class="xs-flag">' + escapeHtml(t('xs.defaultExit')) + '</span>' : '') + '</td>' +
      '<td class="xs-c-dim" title="' + attr(kindLabel(ob)) + '">' + escapeHtml(kindLabel(ob)) + '</td>' +
      '<td>' + (ob.reverseTag ? '<span class="xs-tag reverse">' + escapeHtml(ob.reverseTag) + '</span>' : '—') + '</td>' +
      orderCell(idx, len) +
      '<td class="xs-c-acts">' + iconBtn('edit', '✎', 'xs.editOut') + iconBtn('del', '🗑', 'xs.delOut', 'danger') + '</td>';
    return tr;
  }

  function renderOutbounds() {
    const host = $('#xsOutbounds');
    host.innerHTML = '';
    const list = xs.model.outbounds;
    const def = list.find(o => o.enabled);
    list.forEach((ob, n) => host.appendChild(outboundRow(ob, n, list.length, def === ob)));
    $('#xsOutboundsEmpty').hidden = list.length > 0;
  }

  /* ----------------------------- routing ----------------------------- */

  function chip(tag, cls) { return '<span class=' + JSON.stringify(cls ? 'xs-tag ' + cls : 'xs-tag') + '>' + escapeHtml(tag) + '</span>'; }

  function ruleRow(r, idx, len, tags) {
    const tr = document.createElement('tr');
    tr.className = 'xs-row' + (r.enabled ? '' : ' disabled');
    tr.dataset.xsRule = r.id;
    const ins = r.inboundTags.length
      ? r.inboundTags.map(x => chip(x, tags.outboundReverse.has(x) ? 'reverse' : '')).join('')
      : '<span class="xs-c-dim">' + escapeHtml(t('xs.anyIn')) + '</span>';
    const out = chip(r.outboundTag || '—', tags.clientReverse.has(r.outboundTag) ? 'reverse' : '');
    const list = (arr) => '<td class="xs-c-list" title="' + attr(arr.join(', ')) + '">' + escapeHtml(arr.join(', ') || '—') + '</td>';
    tr.innerHTML =
      switchCell(r.enabled, 'xs.rule.enabled') +
      '<td><div class="xs-chips">' + ins + '</div></td>' +
      '<td>' + out + '</td>' +
      list(r.domain) + list(r.ip) +
      '<td class="xs-c-mono">' + escapeHtml(r.port || '—') + '</td>' +
      '<td class="xs-c-mono">' + escapeHtml(r.protocol.join(',') || '—') + '</td>' +
      '<td class="xs-c-mono">' + escapeHtml(r.network || '—') + '</td>' +
      '<td class="xs-c-dim" title="' + attr(r.comment) + '">' + (r.preset ? '<span class="xs-preset">' + escapeHtml(r.preset) + '</span>' : '') + escapeHtml(r.comment || '') + '</td>' +
      orderCell(idx, len) +
      '<td class="xs-c-acts">' + iconBtn('edit', '✎', 'xs.editRule') + iconBtn('del', '🗑', 'xs.delRule', 'danger') + '</td>';
    return tr;
  }

  function renderRouting() {
    const m = xs.model;
    $('#xsDomainStrategy').value = m.routing.domainStrategy;
    const host = $('#xsRules');
    host.innerHTML = '';
    const tags = allTags(m);
    const list = m.routing.rules;
    list.forEach((r, n) => host.appendChild(ruleRow(r, n, list.length, tags)));
    $('#xsRulesEmpty').hidden = list.length > 0;
    for (const name of PRESETS) {
      const btn = $(PRESET_BUTTON[name]);
      btn.disabled = list.some(r => r.preset === name);
    }
  }

  /** One of the three block rules, once: it goes first so it wins over any catch-all, and needs a blackhole to send to. */
  async function addPreset(name) {
    const preset = xs.presets[name];
    if (!preset || xs.model.routing.rules.some(r => r.preset === name)) return;
    const next = deep(xs.model);
    let block = next.outbounds.find(o => o.kind === 'blackhole' && o.enabled);
    if (!block) {
      block = { kind: 'blackhole', tag: freeTag(next, 'block'), enabled: true };
      next.outbounds.push(block);
    }
    const rule = { enabled: true, preset: name, comment: preset.comment, outboundTag: block.tag, inboundTags: [] };
    for (const k of ['domain', 'ip', 'protocol']) if (preset[k]) rule[k] = preset[k].slice();
    next.routing.rules.unshift(rule);
    if (await apply(next)) toast(t('xs.presetAdded'), 'ok');
  }

  /* ----------------------------- reverse ----------------------------- */

  function checkItem(value, label, checked, cls) {
    const lab = document.createElement('label');
    lab.className = 'xs-check';
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.value = value;
    box.checked = !!checked;
    const text = document.createElement('span');
    text.className = 'xs-check-label' + (cls ? ' ' + cls : '');
    text.textContent = label;
    lab.appendChild(box);
    lab.appendChild(text);
    return lab;
  }

  function renderPortalWiz() {
    const m = xs.model;
    const vless = m.inbounds.filter(i => i.enabled && i.protocol === 'vless');
    if (!vless.some(i => i.id === wiz.inboundId)) wiz.inboundId = vless.length ? vless[0].id : '';
    const sel = $('#xwpInbound');
    sel.innerHTML = vless.map(i => '<option value="' + attr(i.id) + '">' + escapeHtml(inboundLabel(i)) + '</option>').join('');
    sel.value = wiz.inboundId;
    sel.disabled = !vless.length;

    const ic = vless.find(i => i.id === wiz.inboundId) || null;
    const clients = ic ? ic.clients.filter(c => c.enabled) : [];
    if (!clients.some(c => c.id === wiz.clientId)) wiz.clientId = clients.length ? clients[0].id : '';
    const csel = $('#xwpClient');
    csel.innerHTML = clients.length
      ? clients.map(c => '<option value="' + attr(c.id) + '">' + escapeHtml(c.email + (c.reverseTag ? ' · ' + c.reverseTag : '')) + '</option>').join('')
      : '<option value="">' + escapeHtml(ic ? t('xs.wiz.noClient') : '—') + '</option>';
    csel.value = wiz.clientId;
    csel.disabled = !clients.length;

    const users = m.inbounds.filter(i => i.enabled && i.id !== wiz.inboundId);
    for (const id of [...wiz.users]) if (!users.some(i => i.id === id)) wiz.users.delete(id);
    const host = $('#xwpUsers');
    host.innerHTML = '';
    for (const i of users) host.appendChild(checkItem(i.id, inboundLabel(i), wiz.users.has(i.id)));
    if (!users.length) {
      const none = document.createElement('span');
      none.className = 'xs-checks-empty';
      none.textContent = t('xs.noInbounds');
      host.appendChild(none);
    }
    $('#btnXwpRun').disabled = !ic || !wiz.clientId;
    const err = $('#xwpError');
    if (!vless.length) { err.textContent = t('xs.wiz.noVlessIn'); err.hidden = false; }
    else if (err.textContent === t('xs.wiz.noVlessIn')) { err.textContent = ''; err.hidden = true; }
    $('#xwpResult').hidden = !wiz.link;
    $('#xwpLink').value = wiz.link || '';
  }

  function renderBridgeWiz() {
    const m = xs.model;
    $$('#xwbVia .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.via === bwiz.via));
    $('#xwbLinkWrap').hidden = bwiz.via !== 'link';
    $('#xwbServerWrap').hidden = bwiz.via !== 'server';

    const mount = $('#xwbServerMount');
    mount.innerHTML = '';
    bridgeSel = null;
    // the reverse proxy rides VLESS: nothing else can be the portal
    const opts = dialable().filter(s => s.protocol === 'vless').map(serverOpt);
    if (!opts.length) {
      const note = document.createElement('p');
      note.className = 'hint warn';
      note.textContent = t('xs.noVless');
      mount.appendChild(note);
    } else {
      if (!opts.some(o => o.value === bwiz.serverId)) bwiz.serverId = opts[0].value;
      bridgeSel = makeSearchSelect({ options: opts, value: bwiz.serverId, onChange: (v) => { bwiz.serverId = v; } });
      mount.appendChild(bridgeSel);
    }

    const exit = $('#xwbExit');
    const was = exit.value;
    const exits = m.outbounds.filter(o => o.enabled && o.kind !== 'blackhole');
    exit.innerHTML = '<option value="">' + escapeHtml(t('xs.wiz.exitAuto')) + '</option>' +
      exits.map(o => '<option value="' + attr(o.tag) + '">' + escapeHtml(o.tag + ' — ' + kindLabel(o)) + '</option>').join('');
    exit.value = exits.some(o => o.tag === was) ? was : '';
  }

  /** Every reverse tag in the model, what carries it and the rules that name it. */
  function renderReverseList() {
    const m = xs.model;
    const host = $('#xsReverseList');
    host.innerHTML = '';
    const items = [];
    for (const i of m.inbounds) for (const c of i.clients) if (c.reverseTag) {
      items.push({ tag: c.reverseTag, where: tf('xs.rev.client', { email: c.email, tag: i.tag }), rules: m.routing.rules.filter(r => r.outboundTag === c.reverseTag) });
    }
    for (const o of m.outbounds) if (o.reverseTag) {
      items.push({ tag: o.reverseTag, where: tf('xs.rev.outbound', { tag: o.tag }), rules: m.routing.rules.filter(r => r.inboundTags.includes(o.reverseTag)) });
    }
    for (const it of items) {
      const div = document.createElement('div');
      div.className = 'xs-rev-item';
      const names = it.rules.map(r => '#' + (m.routing.rules.indexOf(r) + 1) + (r.comment ? ' ' + r.comment : ''));
      div.innerHTML =
        chip(it.tag, 'reverse') +
        '<span class="xs-rev-where">' + escapeHtml(it.where) + '</span>' +
        '<span class="xs-rev-rules">' + escapeHtml(names.length ? tf('xs.rev.rules', { list: names.join(' · ') }) : t('xs.rev.noRules')) + '</span>' +
        '<button type="button" class="btn ghost small" data-act="go">' + escapeHtml(t('xs.goRouting')) + '</button>';
      div.querySelector('[data-act="go"]').onclick = () => {
        showTab('routing');
        $$('#xsRules .highlight').forEach(el => el.classList.remove('highlight'));
        for (const r of it.rules) {
          const row = document.querySelector('[data-xs-rule="' + r.id + '"]');
          if (row) row.classList.add('highlight');
        }
        const first = it.rules[0] && document.querySelector('[data-xs-rule="' + it.rules[0].id + '"]');
        if (first) first.scrollIntoView({ block: 'center' });
      };
      host.appendChild(div);
    }
    $('#xsReverseEmpty').hidden = items.length > 0;
  }

  function renderReverse() {
    renderPortalWiz();
    renderBridgeWiz();
    renderReverseList();
  }

  /** The reply of a wizard, handled the way apply() handles a set. */
  async function runWizard(req, errBox) {
    const err = $(errBox);
    err.hidden = true;
    err.textContent = '';
    let r;
    try { r = await window.api.xserverWizard(req); }
    catch (e) { err.textContent = (e && e.message) || String(e); err.hidden = false; return null; }
    if (r && r.ok) {
      xs.model = r.model;
      if (r.status) xs.status = r.status;
      setErrors([], null);
      render();
      paintStatus();
      toast(t('xs.wiz.done'), 'ok');
      return r;
    }
    const list = (r && r.errors && r.errors.length) ? r.errors.map(e => e.path + ': ' + e.msg) : [(r && r.error) || t('xs.refused')];
    err.textContent = list.join(' · ');
    err.hidden = false;
    if (r && r.errors && r.errors.length) setErrors(r.errors, r.model || null);
    return null;
  }

  /* ----------------------------- settings ----------------------------- */

  function renderSettings() {
    const m = xs.model;
    const sel = $('#xsEngineSelect');
    sel.innerHTML = xs.engines
      .map(e => '<option value="' + attr(e.id) + '"' + (e.installed ? '' : ' disabled') + '>' + escapeHtml(e.label || e.id) + '</option>')
      .join('');
    sel.value = m.engine;
    $('#xsCoreChannel').value = (state.settings && state.settings.coreChannel) || 'stable';
    $('#xsLogLevel').value = m.logLevel;
    $('#xsPublicAddr').value = m.publicAddress;
    $('#xsAutoStart').checked = !!m.autoStart;
    paintCore();
  }

  function render() {
    if (!xs.model) return;
    renderInbounds();
    renderOutbounds();
    renderRouting();
    renderReverse();
    renderSettings();
    markInvalid();
  }

  /* ----------------------------- the log ----------------------------- */

  /** The core prefixes its own lines; anything else is an ordinary line. */
  function levelOf(line) {
    const s = String(line || '');
    if (/\[Error\]|\[Fatal\]/i.test(s)) return 'error';
    if (/\[Warning\]/i.test(s)) return 'warn';
    if (/\[Info\]/i.test(s)) return 'info';
    return 'log';
  }

  function appendLog(line, level) {
    const box = $('#xsLog');
    const div = document.createElement('div');
    div.className = 'log-' + (level || 'log');
    div.textContent = line;
    box.appendChild(div);
    while (box.childNodes.length > MAX_LOG) box.removeChild(box.firstChild);
    box.scrollTop = box.scrollHeight;
  }

  /* ----------------------------- live status ----------------------------- */

  /**
   * The enforcer can switch an inbound or a client off between our fetches,
   * so the status is also what keeps our copy of the model honest — otherwise
   * the next `set` would quietly switch it back on.
   */
  function absorb(st) {
    if (!xs.model || !st || !Array.isArray(st.inbounds)) return;
    for (const li of st.inbounds) {
      const mi = xs.model.inbounds.find(i => i.id === li.id);
      if (!mi) continue;
      mi.enabled = li.enabled;
      mi.disabledBy = li.disabledBy || '';
      mi.used = { up: li.up, down: li.down };
      for (const lc of (li.clients || [])) {
        const mc = mi.clients.find(c => c.id === lc.id);
        if (!mc) continue;
        mc.enabled = lc.enabled;
        mc.disabledBy = lc.disabledBy || '';
        mc.used = { up: lc.up, down: lc.down };
        mc.resetAt = lc.resetAt || 0;
      }
    }
  }

  function onStatus(st) {
    if (!st) return;
    xs.status = st;
    absorb(st);
    paintStatus();
    if (!xs.model) return;
    // in place: a re-render here would cost the scroll position every five seconds
    for (const li of (st.inbounds || [])) {
      const mi = xs.model.inbounds.find(i => i.id === li.id);
      const row = document.querySelector('[data-xs-inbound="' + li.id + '"]');
      if (row && mi) paintInbound(row, mi, li);
      for (const lc of (li.clients || [])) {
        const crow = document.querySelector('[data-xs-client="' + lc.id + '"]');
        const mc = mi && mi.clients.find(c => c.id === lc.id);
        if (crow && mc) paintClient(crow, mc, lc);
      }
    }
  }

  /* ----------------------------- references ----------------------------- */

  const ruleEmpty = (r) => !((r.inboundTags || []).length || (r.domain || []).length || (r.ip || []).length || r.port || (r.protocol || []).length || r.network);

  /** `tag` leaves every rule's sources; a rule that matched on nothing else goes with it. Returns how many rules changed. */
  function dropSource(next, tag) {
    let n = 0;
    next.routing.rules = next.routing.rules.filter(r => {
      if (!r.inboundTags.includes(tag)) return true;
      r.inboundTags = r.inboundTags.filter(x => x !== tag);
      n++;
      return !ruleEmpty(r);
    });
    return n;
  }

  /** Every rule that sends to `tag` goes: there is nowhere else it could send. Returns how many. */
  function dropTarget(next, tag) {
    const before = next.routing.rules.length;
    next.routing.rules = next.routing.rules.filter(r => r.outboundTag !== tag);
    return before - next.routing.rules.length;
  }

  /** A tag renamed on the thing that carries it is renamed in the rules that name it. */
  function renameSource(next, from, to) {
    if (!from || !to || from === to) return;
    for (const r of next.routing.rules) r.inboundTags = r.inboundTags.map(x => (x === from ? to : x));
  }
  function renameTarget(next, from, to) {
    if (!from || !to || from === to) return;
    for (const r of next.routing.rules) if (r.outboundTag === from) r.outboundTag = to;
  }

  /** Is `tag` still some client's reverse tag once `exceptId` is gone? */
  const otherClientCarries = (next, tag, exceptId) =>
    next.inbounds.some(i => i.clients.some(c => c.id !== exceptId && c.reverseTag === tag));

  function saidCleaned(n) { if (n > 0) toast(tf('xs.refsCleaned', { n }), 'warn'); }

  /* ----------------------------- inbound editor ----------------------------- */

  function blankInbound() {
    // Reality over raw tcp: the right default for a machine with no domain
    return {
      enabled: true, remark: 'VLESS Reality', tag: '', protocol: 'vless',
      listen: '0.0.0.0', port: 443, network: 'tcp', path: '/', host: '', serviceName: '',
      security: 'reality',
      tls: { certFile: '', keyFile: '', serverName: '', alpn: ['h2', 'http/1.1'] },
      reality: { dest: 'www.cloudflare.com:443', serverNames: ['www.cloudflare.com'], privateKey: '', publicKey: '', shortIds: [] },
      ss: { method: '2022-blake3-aes-128-gcm', password: '' },
      sniffing: true, totalBytes: 0, expiresAt: 0, used: { up: 0, down: 0 }, clients: []
    };
  }

  /** Which groups of fields the chosen protocol, transport and security actually have. */
  function syncInboundFields() {
    const proto = $('#xiProtocol').value;
    const ss = proto === 'shadowsocks';
    // an ss:// link carries no transport and no security; the core refuses anything else
    $('#xiTransportRow').hidden = ss;
    $('#xiSsRow').hidden = !ss;
    if (ss) { $('#xiNetwork').value = 'tcp'; $('#xiSecurity').value = 'none'; }

    const net = $('#xiNetwork').value;
    // both cores refuse reality over websocket, and a vmess:// link cannot carry it
    const realityOk = !ss && proto !== 'vmess' && net !== 'ws';
    const opt = [...$('#xiSecurity').options].find(o => o.value === 'reality');
    opt.hidden = !realityOk;
    opt.disabled = !realityOk;
    if (!realityOk && $('#xiSecurity').value === 'reality') $('#xiSecurity').value = 'none';

    const sec = $('#xiSecurity').value;
    $('#xiPathRow').hidden = ss || (net !== 'ws' && net !== 'xhttp');
    $('#xiServiceRow').hidden = ss || net !== 'grpc';
    $('#xiTlsRow').hidden = sec !== 'tls';
    $('#xiRealityRow').hidden = sec !== 'reality';
  }

  /** The 3x-ui default: `inbound-<port>`, following the port until the user types a tag of their own. */
  function syncInboundTag() {
    if (tagTouched) return;
    const port = parseInt($('#xiPort').value, 10) || 0;
    $('#xiTag').value = port ? 'inbound-' + port : '';
  }

  function openInbound(inbound) {
    editIn = { id: inbound ? inbound.id : '', draft: inbound ? deep(inbound) : blankInbound() };
    const d = editIn.draft;
    tagTouched = !!inbound && d.tag !== 'inbound-' + d.port;
    $('#xiRemark').value = d.remark;
    $('#xiTag').value = d.tag;
    $('#xiProtocol').value = d.protocol;
    $('#xiListen').value = d.listen;
    $('#xiPort').value = d.port;
    $('#xiNetwork').value = d.network;
    $('#xiSecurity').value = d.security;
    $('#xiPath').value = d.path;
    $('#xiHost').value = d.host;
    $('#xiService').value = d.serviceName;
    $('#xiCert').value = d.tls.certFile;
    $('#xiKey').value = d.tls.keyFile;
    $('#xiSni').value = d.tls.serverName;
    $('#xiRealityDest').value = d.reality.dest;
    $('#xiRealityNames').value = d.reality.serverNames.join(', ');
    $('#xiRealityPriv').value = d.reality.privateKey;
    $('#xiRealityPub').value = d.reality.publicKey;
    $('#xiRealityShort').value = d.reality.shortIds.join(', ');
    $('#xiSsMethod').value = d.ss.method;
    $('#xiSsPassword').value = d.ss.password;
    $('#xiSniffing').checked = !!d.sniffing;
    $('#xiTotalGb').value = gbOf(d.totalBytes);
    $('#xiExpiry').value = d.expiresAt ? toDateInput(d.expiresAt) : '';
    $('#xiErrors').hidden = true;
    $('#xiErrors').innerHTML = '';
    syncInboundFields();
    syncInboundTag();
    $('#xsInboundModal').hidden = false;
  }

  const closeInbound = () => { $('#xsInboundModal').hidden = true; editIn = null; };

  function readInbound() {
    const d = editIn.draft;
    d.remark = $('#xiRemark').value.trim();
    d.tag = $('#xiTag').value.trim();
    d.protocol = $('#xiProtocol').value;
    d.listen = $('#xiListen').value.trim() || '0.0.0.0';
    d.port = parseInt($('#xiPort').value, 10) || 0;
    d.network = $('#xiNetwork').value;
    d.security = $('#xiSecurity').value;
    d.path = $('#xiPath').value.trim() || '/';
    d.host = $('#xiHost').value.trim();
    d.serviceName = $('#xiService').value.trim();
    d.tls.certFile = $('#xiCert').value.trim();
    d.tls.keyFile = $('#xiKey').value.trim();
    d.tls.serverName = $('#xiSni').value.trim();
    d.reality.dest = $('#xiRealityDest').value.trim();
    d.reality.serverNames = csv($('#xiRealityNames').value);
    d.reality.privateKey = $('#xiRealityPriv').value.trim();
    d.reality.publicKey = $('#xiRealityPub').value.trim();
    d.reality.shortIds = csv($('#xiRealityShort').value).map(s => s.toLowerCase());
    d.ss.method = $('#xiSsMethod').value;
    d.ss.password = $('#xiSsPassword').value.trim();
    d.sniffing = $('#xiSniffing').checked;
    d.totalBytes = bytesOf($('#xiTotalGb').value);
    d.expiresAt = fromDateInput($('#xiExpiry').value);
    return d;
  }

  async function saveInbound() {
    const d = readInbound();
    const next = deep(xs.model);
    let idx;
    if (editIn.id) {
      idx = next.inbounds.findIndex(i => i.id === editIn.id);
      if (idx === -1) return closeInbound();
      // a renamed tag follows through the rules that name it
      renameSource(next, next.inbounds[idx].tag, d.tag);
      next.inbounds[idx] = d;
    } else {
      next.inbounds.push(d);
      idx = next.inbounds.length - 1;
    }
    const known = new Set(xs.model.inbounds.map(i => i.id));
    if (await apply(next)) {
      // a new inbound opens over its (empty) user list, where "+ user" is
      for (const i of xs.model.inbounds) if (!known.has(i.id)) { open.add(i.id); toggleOpen(i.id); toggleOpen(i.id); }
      return closeInbound();
    }
    modalErrors('#xiErrors', 'inbounds[' + idx + ']', closeInbound);
  }

  async function delInbound(inbound) {
    if (!window.confirm(t('xs.confirmDelIn'))) return;
    const next = deep(xs.model);
    next.inbounds = next.inbounds.filter(i => i.id !== inbound.id);
    // A rule that names the inbound loses that source; a rule that sent to
    // one of its bridge credentials goes — better than a refusal the user
    // has to undo by hand, and the toast says it happened.
    let n = dropSource(next, inbound.tag);
    for (const c of inbound.clients) if (c.reverseTag && !otherClientCarries(next, c.reverseTag, c.id)) n += dropTarget(next, c.reverseTag);
    open.delete(inbound.id);
    if (await apply(next)) saidCleaned(n);
  }

  async function firewall(inbound) {
    let r;
    try { r = await window.api.xserverFirewall({ inboundId: inbound.id, allow: true }); }
    catch (e) { return toast((e && e.message) || String(e), 'err'); }
    if (r && r.ok) toast(t('xs.fwDone'), 'ok');
    else toast((r && r.error) || t('xs.genFailed'), 'err');
  }

  /* ----------------------------- client editor ----------------------------- */

  /** The kind of secret this inbound's protocol needs, made by main. */
  async function genSecret(inbound) {
    let kind = 'password';
    if (usesUuid(inbound)) kind = 'uuid';
    else if (inbound.protocol === 'shadowsocks' && is2022(inbound.ss.method)) kind = 'ss2022:' + inbound.ss.method;
    try {
      const r = await window.api.xserverGenId(kind);
      return (r && r.value) || '';
    } catch { return ''; }
  }

  async function openClient(inbound, client) {
    const draft = client ? deep(client) : {
      enabled: true, email: '', uuid: '', password: '', flow: '', limitIp: 0,
      quotaBytes: 0, expiresAt: 0, resetDays: 0, resetAt: 0, comment: '', reverseTag: '',
      used: { up: 0, down: 0 }, disabledBy: '', lastSeenAt: 0
    };
    editCl = { inboundId: inbound.id, id: client ? client.id : '', draft };
    if (!client) {
      const value = await genSecret(inbound);
      if (usesUuid(inbound)) draft.uuid = value; else draft.password = value;
    }
    // the label is the protocol's word for the secret, and stays translatable
    const label = $('#xcSecretLabel');
    label.dataset.i18n = usesUuid(inbound) ? 'xs.cl.uuid' : 'xs.cl.password';
    label.textContent = t(label.dataset.i18n);
    $('#xcEmail').value = draft.email;
    $('#xcSecret').value = secretOf(inbound, draft);
    $('#xcFlowRow').hidden = !flowOk(inbound);
    $('#xcFlow').value = draft.flow || '';
    $('#xcLimitIp').value = String(draft.limitIp || 0);
    $('#xcQuotaGb').value = gbOf(draft.quotaBytes);
    $('#xcExpiry').value = draft.expiresAt ? toDateInput(draft.expiresAt) : '';
    $('#xcResetDays').value = String(draft.resetDays || 0);
    $('#xcComment').value = draft.comment || '';
    // the reverse proxy rides VLESS: only a vless client can be a bridge's credential
    $('#xcReverseRow').hidden = inbound.protocol !== 'vless';
    $('#xcReverseTag').value = draft.reverseTag || '';
    $('#xcEnabled').checked = draft.enabled !== false;
    $('#xcErrors').hidden = true;
    $('#xcErrors').innerHTML = '';
    $('#xsClientModal').hidden = false;
  }

  const closeClient = () => { $('#xsClientModal').hidden = true; editCl = null; };

  async function saveClient() {
    const next = deep(xs.model);
    const inIdx = next.inbounds.findIndex(i => i.id === editCl.inboundId);
    if (inIdx === -1) return closeClient();
    const inbound = next.inbounds[inIdx];
    const d = editCl.draft;
    d.email = $('#xcEmail').value.trim();
    if (usesUuid(inbound)) d.uuid = $('#xcSecret').value.trim();
    else d.password = $('#xcSecret').value.trim();
    d.flow = flowOk(inbound) ? $('#xcFlow').value : '';
    d.limitIp = Math.max(0, parseInt($('#xcLimitIp').value, 10) || 0);
    d.quotaBytes = bytesOf($('#xcQuotaGb').value);
    d.expiresAt = fromDateInput($('#xcExpiry').value);
    d.resetDays = Math.max(0, parseInt($('#xcResetDays').value, 10) || 0);
    d.comment = $('#xcComment').value;
    d.reverseTag = inbound.protocol === 'vless' ? $('#xcReverseTag').value.trim() : '';
    d.enabled = $('#xcEnabled').checked;
    if (d.enabled) d.disabledBy = '';

    let cIdx;
    if (editCl.id) {
      cIdx = inbound.clients.findIndex(c => c.id === editCl.id);
      if (cIdx === -1) return closeClient();
      const was = inbound.clients[cIdx].reverseTag;
      // a renamed reverse tag follows through the rules, unless another client still answers to the old one
      if (was && d.reverseTag && was !== d.reverseTag && !otherClientCarries(next, was, editCl.id)) renameTarget(next, was, d.reverseTag);
      inbound.clients[cIdx] = d;
    } else {
      inbound.clients.push(d);
      cIdx = inbound.clients.length - 1;
    }
    if (await apply(next)) return closeClient();
    modalErrors('#xcErrors', 'inbounds[' + inIdx + '].clients[' + cIdx + ']', closeClient);
  }

  async function delClient(inbound, client) {
    if (!window.confirm(t('xs.confirmDelClient'))) return;
    const next = deep(xs.model);
    const ni = next.inbounds.find(i => i.id === inbound.id);
    if (!ni) return;
    ni.clients = ni.clients.filter(c => c.id !== client.id);
    let n = 0;
    if (client.reverseTag && !otherClientCarries(next, client.reverseTag, client.id)) n = dropTarget(next, client.reverseTag);
    if (await apply(next)) saidCleaned(n);
  }

  /* ----------------------------- outbound editor ----------------------------- */

  /** The target's protocol, for the reverse-tag field: only a VLESS portal can carry one. */
  function outboundIsVless() {
    const kind = $('#xoKind').value;
    if (kind === 'server') { const s = outSel ? srvById(outSel.getValue()) : null; return !!s && s.protocol === 'vless'; }
    if (kind === 'link') return /^vless:\/\//i.test($('#xoLink').value.trim());
    return false;
  }

  function syncOutboundFields() {
    const kind = $('#xoKind').value;
    $('#xoServerRow').hidden = kind !== 'server';
    $('#xoLinkRow').hidden = kind !== 'link';
    $('#xoReverseRow').hidden = !outboundIsVless();
    if (!outTagTouched) $('#xoTag').value = editOut && editOut.id ? $('#xoTag').value : DEFAULT_TAGS[kind] || 'out';
  }

  function openOutbound(ob) {
    editOut = { id: ob ? ob.id : '', draft: ob ? deep(ob) : { enabled: true, kind: 'freedom', tag: '', serverId: '', link: '', reverseTag: '' } };
    const d = editOut.draft;
    outTagTouched = !!ob;
    $('#xoKind').value = d.kind;
    $('#xoTag').value = d.tag;
    $('#xoLink').value = d.link;
    $('#xoReverseTag').value = d.reverseTag;
    $('#xoEnabled').checked = d.enabled !== false;

    const mount = $('#xoServerMount');
    mount.innerHTML = '';
    outSel = null;
    const opts = dialable().map(serverOpt);
    if (!opts.length) {
      const note = document.createElement('p');
      note.className = 'hint warn';
      note.textContent = t('xs.noServers');
      mount.appendChild(note);
    } else {
      const value = opts.some(o => o.value === d.serverId) ? d.serverId : opts[0].value;
      outSel = makeSearchSelect({ options: opts, value, onChange: syncOutboundFields });
      mount.appendChild(outSel);
    }
    $('#xoErrors').hidden = true;
    $('#xoErrors').innerHTML = '';
    syncOutboundFields();
    $('#xsOutboundModal').hidden = false;
  }

  const closeOutbound = () => { $('#xsOutboundModal').hidden = true; editOut = null; };

  async function saveOutbound() {
    const d = editOut.draft;
    d.kind = $('#xoKind').value;
    d.tag = $('#xoTag').value.trim();
    d.serverId = d.kind === 'server' && outSel ? outSel.getValue() : '';
    d.link = d.kind === 'link' ? $('#xoLink').value.trim() : '';
    d.reverseTag = outboundIsVless() ? $('#xoReverseTag').value.trim() : '';
    d.enabled = $('#xoEnabled').checked;
    const next = deep(xs.model);
    let idx;
    if (editOut.id) {
      idx = next.outbounds.findIndex(o => o.id === editOut.id);
      if (idx === -1) return closeOutbound();
      const was = next.outbounds[idx];
      renameTarget(next, was.tag, d.tag);
      if (was.reverseTag && d.reverseTag) renameSource(next, was.reverseTag, d.reverseTag);
      next.outbounds[idx] = d;
    } else {
      next.outbounds.push(d);
      idx = next.outbounds.length - 1;
    }
    if (await apply(next)) return closeOutbound();
    modalErrors('#xoErrors', 'outbounds[' + idx + ']', closeOutbound);
  }

  async function delOutbound(ob) {
    if (!window.confirm(t('xs.confirmDelOut'))) return;
    const next = deep(xs.model);
    next.outbounds = next.outbounds.filter(o => o.id !== ob.id);
    let n = dropTarget(next, ob.tag);
    if (ob.reverseTag) n += dropSource(next, ob.reverseTag);
    if (await apply(next)) saidCleaned(n);
  }

  /* ----------------------------- rule editor ----------------------------- */

  function openRule(rule) {
    editRule = { id: rule ? rule.id : '', draft: rule ? deep(rule) : { enabled: true, comment: '', inboundTags: [], outboundTag: '', domain: [], ip: [], port: '', protocol: [], network: '', preset: '' } };
    const d = editRule.draft;
    const m = xs.model;
    const tags = allTags(m);

    // sources: every inbound tag, and the inbound a bridge outbound creates
    const host = $('#xrInbounds');
    host.innerHTML = '';
    for (const i of m.inbounds) host.appendChild(checkItem(i.tag, i.tag, d.inboundTags.includes(i.tag)));
    for (const tag of tags.outboundReverse) host.appendChild(checkItem(tag, tag + ' ↩', d.inboundTags.includes(tag), 'reverse'));
    if (!host.childNodes.length) {
      const none = document.createElement('span');
      none.className = 'xs-checks-empty';
      none.textContent = t('xs.anyIn');
      host.appendChild(none);
    }

    // targets: every outbound tag, and the outbound a bridge credential creates
    const sel = $('#xrOutbound');
    const opts = [];
    for (const o of m.outbounds) opts.push({ v: o.tag, label: o.tag + ' — ' + kindLabel(o) + (o.enabled ? '' : ' (off)') });
    for (const tag of tags.clientReverse) opts.push({ v: tag, label: tag + ' ↩' });
    sel.innerHTML = opts.length
      ? opts.map(o => '<option value="' + attr(o.v) + '">' + escapeHtml(o.label) + '</option>').join('')
      : '<option value="">' + escapeHtml(t('xs.rule.noTargets')) + '</option>';
    sel.value = opts.some(o => o.v === d.outboundTag) ? d.outboundTag : (opts[0] ? opts[0].v : '');

    $('#xrDomain').value = d.domain.join('\n');
    $('#xrIp').value = d.ip.join('\n');
    $('#xrPort').value = d.port;
    $$('#xrProtocol input').forEach(b => { b.checked = d.protocol.includes(b.value); });
    $('#xrNetwork').value = d.network;
    $('#xrComment').value = d.comment;
    $('#xrEnabled').checked = d.enabled !== false;
    $('#xrErrors').hidden = true;
    $('#xrErrors').innerHTML = '';
    $('#xsRuleModal').hidden = false;
  }

  const closeRule = () => { $('#xsRuleModal').hidden = true; editRule = null; };

  async function saveRule() {
    const d = editRule.draft;
    d.inboundTags = $$('#xrInbounds input:checked').map(b => b.value);
    d.outboundTag = $('#xrOutbound').value;
    d.domain = lines($('#xrDomain').value);
    d.ip = lines($('#xrIp').value);
    d.port = $('#xrPort').value.replace(/\s+/g, '');
    d.protocol = $$('#xrProtocol input:checked').map(b => b.value);
    d.network = $('#xrNetwork').value;
    d.comment = $('#xrComment').value;
    d.enabled = $('#xrEnabled').checked;
    const next = deep(xs.model);
    let idx;
    if (editRule.id) {
      idx = next.routing.rules.findIndex(r => r.id === editRule.id);
      if (idx === -1) return closeRule();
      next.routing.rules[idx] = d;
    } else {
      next.routing.rules.push(d);
      idx = next.routing.rules.length - 1;
    }
    if (await apply(next)) return closeRule();
    modalErrors('#xrErrors', 'routing.rules[' + idx + ']', closeRule);
  }

  async function delRule(rule) {
    if (!window.confirm(t('xs.confirmDelRule'))) return;
    const next = deep(xs.model);
    next.routing.rules = next.routing.rules.filter(r => r.id !== rule.id);
    await apply(next);
  }

  /** Swap with the neighbour: rule order and outbound order are both load-bearing. */
  async function move(listOf, id, dir) {
    const next = deep(xs.model);
    const list = listOf(next);
    const at = list.findIndex(x => x.id === id);
    const to = at + dir;
    if (at === -1 || to < 0 || to >= list.length) return;
    [list[at], list[to]] = [list[to], list[at]];
    await apply(next);
  }

  /* ----------------------------- links and QR ----------------------------- */

  async function linkFor(inbound, client) {
    let r;
    try { r = await window.api.xserverClientLink({ inboundId: inbound.id, clientId: client.id }); }
    catch (e) { toast((e && e.message) || String(e), 'err'); return ''; }
    if (!r || r.error || !r.link) { toast((r && r.error) || t('xs.genFailed'), 'err'); return ''; }
    return r.link;
  }

  /** The app's own QR modal, filled exactly the way showServerQr fills it. */
  function showQr(link) {
    const box = $('#qrImage');
    box.innerHTML = '';
    try {
      const qr = qrcode(0, 'L');
      qr.addData(link);
      qr.make();
      box.innerHTML = qr.createImgTag(4, 6);
    } catch {
      const p = document.createElement('p');
      p.className = 'hint xs-qr-fallback';
      p.textContent = t('qr.tooBig');
      box.appendChild(p);
    }
    $('#qrLink').value = link;
    $('#qrModal').hidden = false;
  }

  async function copyLink(inbound, client) {
    const link = await linkFor(inbound, client);
    if (!link) return;
    await copyText(link);
    toast(t('xs.copied'), 'ok');
  }

  /* ----------------------------- wiring: the tables ----------------------------- */

  function ctxOf(target) {
    const clRow = target.closest('[data-xs-client]');
    const inRow = target.closest('[data-xs-inbound], [data-xs-sub]');
    const inId = inRow ? (inRow.dataset.xsInbound || inRow.dataset.xsSub) : '';
    const inbound = inId ? xs.model.inbounds.find(i => i.id === inId) : null;
    const client = inbound && clRow ? inbound.clients.find(c => c.id === clRow.dataset.xsClient) : null;
    return { inbound, client };
  }

  async function onInboundsClick(e) {
    const { inbound, client } = ctxOf(e.target);
    if (!inbound) return;
    const btn = e.target.closest('[data-act]');
    if (!btn) return;
    const act = btn.dataset.act;
    if (client) {
      if (act === 'secret') { await copyText(secretOf(inbound, client)); return toast(t('xs.copied'), 'ok'); }
      if (act === 'edit') return openClient(inbound, client);
      if (act === 'del') return delClient(inbound, client);
      if (act === 'link') return copyLink(inbound, client);
      if (act === 'qr') { const link = await linkFor(inbound, client); if (link) showQr(link); }
      return;
    }
    if (act === 'expand') return toggleOpen(inbound.id);
    if (act === 'addClient') return openClient(inbound, null);
    if (act === 'edit') return openInbound(inbound);
    if (act === 'del') return delInbound(inbound);
    if (act === 'fw') return firewall(inbound);
    if (act === 'link' || act === 'qr') {
      const first = inbound.clients.find(c => c.enabled) || inbound.clients[0];
      if (!first) return toast(t('xs.noLinkClient'), 'err');
      if (act === 'link') return copyLink(inbound, first);
      const link = await linkFor(inbound, first);
      if (link) showQr(link);
    }
  }

  async function onInboundsChange(e) {
    if (!e.target.matches('input[data-act="enable"]')) return;
    const { inbound, client } = ctxOf(e.target);
    if (!inbound) return;
    const on = e.target.checked;
    const next = deep(xs.model);
    const ni = next.inbounds.find(i => i.id === inbound.id);
    if (client) {
      const nc = ni.clients.find(c => c.id === client.id);
      nc.enabled = on;
      if (on) nc.disabledBy = '';
    } else {
      ni.enabled = on;
      if (on) ni.disabledBy = '';
    }
    // a refusal leaves the store untouched, and apply's re-render puts the
    // switch back where the model says it belongs
    await apply(next);
  }

  function onOutboundsClick(e) {
    const row = e.target.closest('[data-xs-outbound]');
    const btn = e.target.closest('[data-act]');
    if (!row || !btn) return;
    const ob = xs.model.outbounds.find(o => o.id === row.dataset.xsOutbound);
    if (!ob) return;
    const act = btn.dataset.act;
    if (act === 'edit') return openOutbound(ob);
    if (act === 'del') return delOutbound(ob);
    if (act === 'up') return move(m => m.outbounds, ob.id, -1);
    if (act === 'down') return move(m => m.outbounds, ob.id, 1);
  }

  async function onOutboundsChange(e) {
    if (!e.target.matches('input[data-act="enable"]')) return;
    const row = e.target.closest('[data-xs-outbound]');
    if (!row) return;
    const next = deep(xs.model);
    const ob = next.outbounds.find(o => o.id === row.dataset.xsOutbound);
    if (!ob) return;
    ob.enabled = e.target.checked;
    await apply(next);
  }

  function onRulesClick(e) {
    const row = e.target.closest('[data-xs-rule]');
    const btn = e.target.closest('[data-act]');
    if (!row || !btn) return;
    const rule = xs.model.routing.rules.find(r => r.id === row.dataset.xsRule);
    if (!rule) return;
    const act = btn.dataset.act;
    if (act === 'edit') return openRule(rule);
    if (act === 'del') return delRule(rule);
    if (act === 'up') return move(m => m.routing.rules, rule.id, -1);
    if (act === 'down') return move(m => m.routing.rules, rule.id, 1);
  }

  async function onRulesChange(e) {
    if (!e.target.matches('input[data-act="enable"]')) return;
    const row = e.target.closest('[data-xs-rule]');
    if (!row) return;
    const next = deep(xs.model);
    const rule = next.routing.rules.find(r => r.id === row.dataset.xsRule);
    if (!rule) return;
    rule.enabled = e.target.checked;
    await apply(next);
  }

  /* ----------------------------- wiring ----------------------------- */

  const setField = (key, read) => () => {
    const next = deep(xs.model);
    read(next);
    apply(next);
  };

  function wire() {
    $('#xsTabs').onclick = (e) => {
      const b = e.target.closest('.xs-tab');
      if (b) showTab(b.dataset.xstab);
    };

    $('#btnXsStart').onclick = async () => {
      const st = await window.api.xserverStart();
      if (st) { xs.status = st; paintStatus(); }
      if (st && st.error) toast(st.error, 'err');
    };
    $('#btnXsStop').onclick = async () => {
      const st = await window.api.xserverStop();
      if (st) { xs.status = st; paintStatus(); }
    };
    $('#btnXsRestart').onclick = async () => {
      const st = await window.api.xserverRestart();
      if (st) { xs.status = st; paintStatus(); }
      if (st && st.error) toast(st.error, 'err');
    };

    /* inbounds */
    $('#btnXsAddInbound').onclick = () => openInbound(null);
    $('#xsInbounds').addEventListener('click', onInboundsClick);
    $('#xsInbounds').addEventListener('change', onInboundsChange);

    /* outbounds */
    $('#btnXsAddOutbound').onclick = () => openOutbound(null);
    $('#xsOutbounds').addEventListener('click', onOutboundsClick);
    $('#xsOutbounds').addEventListener('change', onOutboundsChange);

    /* routing */
    $('#btnXsAddRule').onclick = () => openRule(null);
    $('#xsRules').addEventListener('click', onRulesClick);
    $('#xsRules').addEventListener('change', onRulesChange);
    $('#xsDomainStrategy').onchange = setField('domainStrategy', (m) => { m.routing.domainStrategy = $('#xsDomainStrategy').value; });
    $('#btnXsPresetPrivate').onclick = () => addPreset('private');
    $('#btnXsPresetTorrent').onclick = () => addPreset('torrent');
    $('#btnXsPresetAds').onclick = () => addPreset('ads');

    /* the portal wizard */
    $('#xwpInbound').onchange = () => {
      wiz.inboundId = $('#xwpInbound').value;
      wiz.clientId = '';
      wiz.users.delete(wiz.inboundId);   // the interconn cannot also carry users through itself
      renderPortalWiz();
    };
    $('#xwpClient').onchange = () => { wiz.clientId = $('#xwpClient').value; };
    $('#xwpUsers').onchange = (e) => {
      if (!e.target.matches('input[type="checkbox"]')) return;
      if (e.target.checked) wiz.users.add(e.target.value); else wiz.users.delete(e.target.value);
    };
    $('#btnXwpRun').onclick = async () => {
      const r = await runWizard({
        kind: 'portal', inboundId: wiz.inboundId, clientId: wiz.clientId,
        userInboundIds: [...wiz.users], tag: $('#xwpTag').value.trim() || undefined
      }, '#xwpError');
      if (!r) return;
      wiz.link = r.link || '';
      $('#xwpResult').hidden = !wiz.link;
      $('#xwpLink').value = wiz.link;
      $('#xwpOther').hidden = true;
    };
    $('#btnXwpCopy').onclick = async () => {
      if (!$('#xwpLink').value) return;
      await copyText($('#xwpLink').value);
      toast(t('xs.copied'), 'ok');
    };
    $('#btnXwpQr').onclick = () => { if ($('#xwpLink').value) showQr($('#xwpLink').value); };
    $('#btnXwpOther').onclick = async () => {
      let r;
      try { r = await window.api.xserverOtherSide(); }
      catch (e) { return toast((e && e.message) || String(e), 'err'); }
      const items = (r && r.items) || [];
      // the bridge side of the credential chosen here, else the first one there is
      const client = xs.model.inbounds.flatMap(i => i.clients).find(c => c.id === wiz.clientId);
      const item = items.find(x => x.kind === 'bridge-side' && client && x.tag === client.reverseTag) || items.find(x => x.kind === 'bridge-side');
      if (!item) return toast((r && r.error) || t('xs.otherSideNone'), 'err');
      const json = JSON.stringify(item.snippet, null, 2);
      await copyText(json);
      toast(t('xs.otherSideCopied'), 'ok');
      $('#xwpOther').textContent = json;
      $('#xwpOther').hidden = false;
      if (item.link && !wiz.link) { wiz.link = item.link; $('#xwpResult').hidden = false; $('#xwpLink').value = item.link; }
    };

    /* the bridge wizard */
    $('#xwbVia').onclick = (e) => {
      const btn = e.target.closest('.seg-btn');
      if (!btn || btn.dataset.via === bwiz.via) return;
      bwiz.via = btn.dataset.via;
      renderBridgeWiz();
    };
    $('#btnXwbRun').onclick = async () => {
      const req = { kind: 'bridge', exitOutboundTag: $('#xwbExit').value || undefined, tag: $('#xwbTag').value.trim() || undefined, reverseTag: $('#xwbReverseTag').value.trim() || undefined };
      if (bwiz.via === 'link') req.link = $('#xwbLink').value.trim();
      else req.serverId = bridgeSel ? bridgeSel.getValue() : bwiz.serverId;
      await runWizard(req, '#xwbError');
    };

    /* settings */
    $('#xsEngineSelect').onchange = setField('engine', (m) => { m.engine = $('#xsEngineSelect').value; });
    $('#xsLogLevel').onchange = setField('logLevel', (m) => { m.logLevel = $('#xsLogLevel').value; });
    $('#xsPublicAddr').onchange = setField('publicAddress', (m) => { m.publicAddress = $('#xsPublicAddr').value.trim(); });
    $('#xsAutoStart').onchange = setField('autoStart', (m) => { m.autoStart = $('#xsAutoStart').checked; });
    $('#xsCoreChannel').onchange = async () => {
      // an ordinary app setting, not part of the server model
      const coreChannel = $('#xsCoreChannel').value === 'latest' ? 'latest' : 'stable';
      let res;
      try { res = await window.api.setSettings({ coreChannel }); }
      catch (e) { return toast((e && e.message) || String(e), 'err'); }
      if (res && res.settings) state.settings = res.settings;
      else if (state.settings) state.settings.coreChannel = coreChannel;
      refreshCore(false);
    };
    $('#btnXsCoreCheck').onclick = async () => {
      const btn = $('#btnXsCoreCheck');
      btn.disabled = true;
      const r = await refreshCore(true);
      btn.disabled = false;
      if (!r || (!r.latestStable && !r.latestAny)) $('#xsCoreCheckOut').textContent = t('xs.coreOffline');
    };
    $('#btnXsCoreLatest').onclick = async () => {
      const btn = $('#btnXsCoreLatest');
      btn.disabled = true;
      let res;
      try { res = await window.api.downloadAsset(xs.model.engine || 'xray'); }
      catch (e) { res = { ok: false, error: (e && e.message) || String(e) }; }
      btn.disabled = false;
      if (res && res.ok) toast(t('xs.coreDownloaded'), 'ok');
      else toast(t('xs.coreDownloadFailed') + (res && res.error ? ': ' + res.error : ''), 'err');
      refreshCore(false);
    };
    $('#btnXsPreview').onclick = async () => {
      let r;
      try { r = await window.api.xserverPreview(); }
      catch (e) { return toast((e && e.message) || String(e), 'err'); }
      if (!r || !r.config) return toast((r && r.error) || t('xs.genFailed'), 'err');
      $('#xsPreviewJson').textContent = JSON.stringify(r.config, null, 2);
      $('#xsPreviewModal').hidden = false;
    };
    $('#btnXsPreviewCopy').onclick = async () => {
      await copyText($('#xsPreviewJson').textContent);
      toast(t('xs.copied'), 'ok');
    };
    const closePreview = () => { $('#xsPreviewModal').hidden = true; };
    $('#btnXsPreviewClose').onclick = closePreview;
    $('#xsPreviewX').onclick = closePreview;

    /* log */
    $('#btnXsClearLog').onclick = () => { $('#xsLog').innerHTML = ''; };

    /* the inbound modal */
    $('#xiProtocol').onchange = syncInboundFields;
    $('#xiNetwork').onchange = syncInboundFields;
    $('#xiSecurity').onchange = syncInboundFields;
    $('#xiPort').oninput = syncInboundTag;
    $('#xiTag').oninput = () => { tagTouched = $('#xiTag').value.trim() !== ''; if (!tagTouched) syncInboundTag(); };
    $('#btnXiGenKeys').onclick = async () => {
      let r;
      try { r = await window.api.xserverGenKeys(); }
      catch (e) { return toast((e && e.message) || String(e), 'err'); }
      if (!r || r.error || !r.privateKey) return toast((r && r.error) || t('xs.genFailed'), 'err');
      $('#xiRealityPriv').value = r.privateKey;
      $('#xiRealityPub').value = r.publicKey;
    };
    $('#btnXiGenShort').onclick = async () => {
      const r = await window.api.xserverGenId('shortId');
      if (r && r.value) $('#xiRealityShort').value = r.value;
      else toast(t('xs.genFailed'), 'err');
    };
    $('#btnXiGenSsPass').onclick = async () => {
      const method = $('#xiSsMethod').value;
      const r = await window.api.xserverGenId(is2022(method) ? 'ss2022:' + method : 'password');
      if (r && r.value) $('#xiSsPassword').value = r.value;
      else toast(t('xs.genFailed'), 'err');
    };
    $('#btnXiSave').onclick = saveInbound;
    $('#btnXiCancel').onclick = closeInbound;
    $('#xiClose').onclick = closeInbound;
    $('#xsInboundModal').onclick = (e) => { if (e.target === $('#xsInboundModal')) closeInbound(); };

    /* the client modal */
    $('#btnXcGen').onclick = async () => {
      const inbound = editCl && xs.model.inbounds.find(i => i.id === editCl.inboundId);
      if (!inbound) return;
      const value = await genSecret(inbound);
      if (value) $('#xcSecret').value = value;
      else toast(t('xs.genFailed'), 'err');
    };
    $('#btnXcSave').onclick = saveClient;
    $('#btnXcCancel').onclick = closeClient;
    $('#xcClose').onclick = closeClient;
    $('#xsClientModal').onclick = (e) => { if (e.target === $('#xsClientModal')) closeClient(); };

    /* the outbound modal */
    $('#xoKind').onchange = syncOutboundFields;
    $('#xoLink').oninput = syncOutboundFields;
    $('#xoTag').oninput = () => { outTagTouched = $('#xoTag').value.trim() !== ''; if (!outTagTouched) syncOutboundFields(); };
    $('#btnXoSave').onclick = saveOutbound;
    $('#btnXoCancel').onclick = closeOutbound;
    $('#xoClose').onclick = closeOutbound;
    $('#xsOutboundModal').onclick = (e) => { if (e.target === $('#xsOutboundModal')) closeOutbound(); };

    /* the rule modal */
    $('#btnXrSave').onclick = saveRule;
    $('#btnXrCancel').onclick = closeRule;
    $('#xrClose').onclick = closeRule;
    $('#xsRuleModal').onclick = (e) => { if (e.target === $('#xsRuleModal')) closeRule(); };
  }

  /* ----------------------------- start ----------------------------- */

  async function boot() {
    wire();
    showTab(tab);
    await load();
    window.api.onXServerStatus(onStatus);
    window.api.onXServerLog((d) => { if (d) appendLog(d.line, d.level); });
    // applyI18n re-translates [data-i18n] nodes; everything this file built is
    // out of its reach, so redraw when the document's language changes
    new MutationObserver(() => { render(); paintStatus(); })
      .observe(document.documentElement, { attributes: true, attributeFilter: ['lang'] });
  }

  /**
   * Two things start this tab: app.js's plusInit loop, and the safety net at
   * the bottom of this file (over HTTP the loop can run before this script has
   * finished downloading). Whichever gets here first boots; the other only
   * redraws, because the loop is the one that knows state.servers has been
   * filled.
   */
  function initXServer() {
    if (!ready) ready = boot();
    else ready.then(render);
    return ready;
  }

  window.plusInit = window.plusInit || [];
  window.plusInit.push(initXServer);
  setTimeout(initXServer, 0);
})();
