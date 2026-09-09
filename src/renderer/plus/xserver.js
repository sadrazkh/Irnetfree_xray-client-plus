'use strict';
/**
 * plus: the Server tab — this machine as an Xray server. Shares app.js globals
 * ($, $$, t, state, toast, escapeHtml, fmtBytes, fmtDuration, makeSearchSelect,
 * copyText).
 *
 * One rule shapes the whole file: the model is main's, not ours. Every edit
 * copies `xs.model`, mutates the copy and hands it to `xserver:set`; on `ok`
 * the reply's normalised model replaces ours (ids and tags are filled there),
 * on a refusal NOTHING was written and the errors say which path was wrong. So
 * there is no local "unsaved" state to keep in step, and a validation message
 * can always be pinned to the card it belongs to.
 *
 * The live status is the one thing that does not go through a re-render: it
 * arrives every five seconds while the core runs, and rebuilding every client
 * row for two counters would throw away the scroll position and any open menu.
 * Rows carry `data-xs-client` and are patched in place.
 */
(function () {
  const GB = 1024 * 1024 * 1024;
  const MAX_LOG = 300;
  const ROLE_ICONS = { off: '⭘', bridge: '🌉', portal: '🛰' };
  const EXIT_ICONS = { direct: '➡', server: '🔗' };
  const SS_2022 = ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm'];

  const xs = { model: null, status: null, engines: [] };
  let ready = null;              // the boot promise — initXServer can be reached twice
  let errors = [];               // the last refusal's [{ path, msg }]
  let attempted = null;          // the model those paths index into
  let bridgeSel = null, exitSel = null;
  let ticker = 0;                // the one-second uptime clock, only while running
  /**
   * A portal is only valid once it has a role AND an interconn inbound AND a
   * user inbound, and each of those fields only appears after the one before
   * it — so no single step can be saved on its own. The half-made block is
   * held here while the model still says otherwise: the cards stay selected,
   * the fields stay on screen and every following edit re-attempts the whole
   * thing. Both are cleared the moment a set goes through.
   */
  let draftReverse = null, draftExit = null;
  let editIn = null;             // { id, draft } while the inbound modal is open
  let editCl = null;             // { inboundId, id, draft } while the client modal is open

  /* ----------------------------- small helpers ----------------------------- */

  const deep = (v) => JSON.parse(JSON.stringify(v));
  const reverseOf = () => draftReverse || xs.model.reverse;
  const exitOf = () => (draftExit !== null ? draftExit : xs.model.exit.type);

  /** The stored model plus whatever choice is still being assembled on screen. */
  function nextModel() {
    const m = deep(xs.model);
    m.reverse = deep(reverseOf());
    m.exit.type = exitOf();
    return m;
  }

  /** One change to the reverse block, kept as a draft until it validates. */
  function editReverse(fn) {
    const rv = deep(reverseOf());
    fn(rv);
    draftReverse = rv;
    return apply(nextModel());
  }
  const usesUuid = (i) => i.protocol === 'vless' || i.protocol === 'vmess';
  const secretOf = (i, c) => (usesUuid(i) ? c.uuid : c.password) || '';
  const is2022 = (method) => SS_2022.includes(method);
  const csv = (v) => String(v || '').split(',').map(s => s.trim()).filter(Boolean);
  const inboundLabel = (i) => (i.remark || i.tag) + ' — ' + i.listen + ':' + i.port;
  /** Enough of a secret to recognise it, never enough to read it over a shoulder. */
  const mask = (s) => (s.length > 6 ? '••••' + s.slice(-4) : s ? '••••' : '—');

  const statusInbound = (id) => ((xs.status && xs.status.inbounds) || []).find(i => i.id === id) || null;

  /** Vision only means something for vless over raw tcp with tls or reality. */
  const flowOk = (i) => i.protocol === 'vless' && i.network === 'tcp' && (i.security === 'tls' || i.security === 'reality');

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

  const expiryLabel = (c) => (c.expiresAt ? toDateInput(c.expiresAt) : t('xs.never'));

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
      draftReverse = null;
      draftExit = null;
      setErrors([], null);
      render();
      return true;
    }
    const list = (r && r.errors && r.errors.length) ? r.errors : [{ path: '', msg: (r && r.error) || t('xs.refused') }];
    setErrors(list, next);
    // Nothing was written, so the screen goes back to the stored model — except
    // for the drafts above, whose fields are what the user still has to fill in.
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
    render();
    paintStatus();
    try {
      const lines = await window.api.xserverLog();
      for (const line of (lines || [])) appendLog(line, levelOf(line));
    } catch { /* the backlog is a nicety, not a requirement */ }
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
    const box = $('#xsErrors');
    box.innerHTML = '';
    for (const e of errors) box.appendChild(errorItem(e));
    $('#xsErrorsCard').hidden = !errors.length;
    markInvalid();
  }

  /** The inbound an `inbounds[2]…` path names — those indices belong to the refused model. */
  function pathInbound(path) {
    const m = /^inbounds\[(\d+)\]/.exec(path || '');
    if (!m || !attempted) return null;
    return attempted.inbounds[Number(m[1])] || null;
  }

  /**
   * A red outline on the card a message is about, and the message under it.
   * `#xsErrors` lists everything; this is what makes it findable.
   */
  function markInvalid() {
    $$('.xs-invalid').forEach(el => el.classList.remove('xs-invalid'));
    $$('.xs-card-err').forEach(el => el.remove());
    const per = new Map();
    const add = (el, msg) => {
      if (!el) return;
      if (!per.has(el)) per.set(el, []);
      per.get(el).push(msg);
    };
    for (const e of errors) {
      const p = String(e.path || '');
      if (p.startsWith('inbounds[')) {
        const i = pathInbound(p);
        const card = i && i.id ? document.querySelector('[data-xs-inbound="' + i.id + '"]') : null;
        add(card || $('#xsInboundsCard'), e.msg);
      } else if (p.startsWith('reverse')) add($('#xsReverseCard'), e.msg);
      else if (p.startsWith('exit')) add($('#xsExitCard'), e.msg);
      else add($('#xsErrorsCard'), e.msg);
    }
    for (const [el, msgs] of per) {
      el.classList.add('xs-invalid');
      const p = document.createElement('p');
      p.className = 'hint xs-card-err';
      p.textContent = msgs.join(' · ');
      el.appendChild(p);
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

  /* ----------------------------- the head ----------------------------- */

  function paintStatus() {
    const st = xs.status || { state: 'stopped' };
    const pill = $('#xsState');
    pill.dataset.state = st.state || 'stopped';
    pill.textContent = t('xs.state.' + (st.state || 'stopped'));

    const line = $('#xsEngine');
    if (st.state === 'error' && st.error) {
      line.textContent = st.error;
      line.classList.add('err');
    } else {
      // the engine and the metrics port belong to a live core; after a stop
      // they are last time's numbers and only mislead
      const up = st.state === 'running' || st.state === 'starting';
      const bits = [];
      if (up && st.engine) bits.push(st.engine);
      if (up && st.pid) bits.push('pid ' + st.pid);
      if (up && st.apiPort) bits.push('api ' + st.apiPort);
      line.textContent = bits.length ? bits.join(' · ') : t('xs.notRunning');
      line.classList.remove('err');
    }

    $('#btnXsStart').disabled = st.state === 'running' || st.state === 'starting';
    $('#btnXsStop').disabled = st.state === 'stopped';
    $('#btnXsRestart').disabled = st.state === 'stopped';

    paintUptime();
    const run = st.state === 'running';
    if (run && !ticker) ticker = setInterval(paintUptime, 1000);
    if (!run && ticker) { clearInterval(ticker); ticker = 0; }
  }

  function paintUptime() {
    const st = xs.status || {};
    const on = st.state === 'running' && st.since;
    $('#xsUptime').textContent = on ? fmtDuration(Math.floor((Date.now() - st.since) / 1000)) : '';
  }

  function renderHead() {
    const m = xs.model;
    const sel = $('#xsEngineSelect');
    sel.innerHTML = xs.engines
      .map(e => '<option value="' + escapeHtml(e.id) + '"' + (e.installed ? '' : ' disabled') + '>' + escapeHtml(e.label || e.id) + '</option>')
      .join('');
    sel.value = m.engine;
    $('#xsLogLevel').value = m.logLevel;
    $('#xsPublicAddr').value = m.publicAddress;
    $('#xsAutoStart').checked = !!m.autoStart;
  }

  /* ----------------------------- inbounds ----------------------------- */

  function summary(i) {
    if (i.protocol === 'shadowsocks') return i.ss.method;
    const bits = [i.network];
    if (i.security !== 'none') bits.push(i.security);
    if (i.network === 'ws' || i.network === 'xhttp') bits.push(i.path);
    if (i.network === 'grpc' && i.serviceName) bits.push(i.serviceName);
    return bits.filter(Boolean).join(' · ');
  }

  /** Counters, the online dot and the enforcer's badge — what a status tick owns. */
  function paintClient(row, client, live) {
    const up = live ? live.up : client.used.up;
    const down = live ? live.down : client.used.down;
    const used = up + down;
    const bar = row.querySelector('.usage-bar');
    const fill = row.querySelector('.usage-fill');
    if (client.quotaBytes > 0) {
      const pct = Math.max(0, Math.min(100, (used / client.quotaBytes) * 100));
      bar.hidden = false;
      fill.style.inlineSize = pct.toFixed(1) + '%';
      fill.className = 'usage-fill' + (pct >= 100 ? ' bad' : pct >= 80 ? ' mid' : '');
      row.querySelector('.xs-cl-used').textContent = fmtBytes(used) + ' / ' + fmtBytes(client.quotaBytes);
    } else {
      // no quota, no bar: an empty track would read as "nothing of nothing"
      bar.hidden = true;
      row.querySelector('.xs-cl-used').textContent = fmtBytes(used);
    }
    row.querySelector('.xs-cl-dot').dataset.online = live && live.online ? '1' : '0';
    const by = live ? live.disabledBy : client.disabledBy;
    const flag = row.querySelector('.xs-cl-flag');
    flag.hidden = !by;
    flag.textContent = by === 'expired' ? t('xs.expired') : by === 'quota' ? t('xs.quotaOut') : '';
    const on = live ? live.enabled : client.enabled;
    row.querySelector('.xs-cl-sw input').checked = !!on;
    row.classList.toggle('disabled', !on);
  }

  function clientRow(inbound, client) {
    const row = document.createElement('div');
    row.className = 'xs-cl-row';
    row.dataset.xsClient = client.id;
    row.innerHTML =
      '<span class="xs-cl-dot" data-online="0" title="' + escapeHtml(t('xs.online')) + '"></span>' +
      '<span class="xs-cl-name">' + escapeHtml(client.email || '—') + '</span>' +
      '<span class="xs-cl-secret" title="' + escapeHtml(t('xs.copySecret')) + '">' + escapeHtml(mask(secretOf(inbound, client))) + '</span>' +
      '<span class="xs-cl-exp">' + escapeHtml(expiryLabel(client)) + '</span>' +
      '<span class="xs-cl-quota"><span class="usage-bar"><span class="usage-fill"></span></span>' +
        '<span class="xs-cl-used"></span></span>' +
      '<span class="xs-cl-flag" hidden></span>' +
      '<label class="switch xs-cl-sw" title="' + escapeHtml(t('xs.enableClient')) + '">' +
        '<input type="checkbox" data-act="enable" /><span class="slider"></span></label>' +
      '<span class="xs-cl-actions">' +
        '<button class="icon-btn" data-act="link" title="' + escapeHtml(t('xs.copyLink')) + '">⧉</button>' +
        '<button class="icon-btn" data-act="qr" title="' + escapeHtml(t('xs.qr')) + '">▦</button>' +
        '<button class="icon-btn" data-act="edit" title="' + escapeHtml(t('xs.editClient')) + '">✎</button>' +
        '<button class="icon-btn danger" data-act="del" title="' + escapeHtml(t('xs.delClient')) + '">🗑</button>' +
      '</span>';
    const live = statusInbound(inbound.id);
    paintClient(row, client, live ? (live.clients || []).find(c => c.id === client.id) : null);
    return row;
  }

  function inboundCard(inbound) {
    const live = statusInbound(inbound.id);
    let up = 0, down = 0;
    if (live) { up = live.up; down = live.down; }
    else for (const c of inbound.clients) { up += c.used.up; down += c.used.down; }

    const card = document.createElement('div');
    card.className = 'card xs-in-card' + (inbound.enabled ? '' : ' disabled');
    card.dataset.xsInbound = inbound.id;
    const win = state.platform === 'win32';
    card.innerHTML =
      '<div class="xs-in-head">' +
        '<span class="proto-badge proto-' + escapeHtml(inbound.protocol) + '">' + escapeHtml(inbound.protocol) + '</span>' +
        '<span class="xs-in-name">' + escapeHtml(inbound.remark || inbound.tag) + '</span>' +
        '<span class="xs-in-addr">' + escapeHtml(inbound.listen + ':' + inbound.port) + '</span>' +
        '<span class="xs-in-meta">' + escapeHtml(summary(inbound)) + '</span>' +
        '<span class="xs-in-meta">' + escapeHtml(t('xs.clientCount').replace('{n}', inbound.clients.length)) + '</span>' +
        '<span class="xs-in-traffic">' + escapeHtml(fmtBytes(up + down)) + '</span>' +
        '<label class="switch xs-in-sw" title="' + escapeHtml(t('xs.enableIn')) + '">' +
          '<input type="checkbox" data-act="enable"' + (inbound.enabled ? ' checked' : '') + ' /><span class="slider"></span></label>' +
        '<span class="xs-in-actions">' +
          '<button class="icon-btn" data-act="addClient" title="' + escapeHtml(t('xs.addClient')) + '">＋</button>' +
          (win ? '<button class="icon-btn" data-act="fw" title="' + escapeHtml(t('xs.firewall')) + '">🛡</button>' : '') +
          '<button class="icon-btn" data-act="edit" title="' + escapeHtml(t('xs.editIn')) + '">✎</button>' +
          '<button class="icon-btn danger" data-act="del" title="' + escapeHtml(t('xs.delIn')) + '">🗑</button>' +
        '</span>' +
      '</div>' +
      '<div class="xs-clients"></div>';

    const host = card.querySelector('.xs-clients');
    if (!inbound.clients.length) {
      const none = document.createElement('div');
      none.className = 'xs-no-clients';
      none.textContent = t('xs.noClients');
      host.appendChild(none);
    } else for (const c of inbound.clients) host.appendChild(clientRow(inbound, c));
    return card;
  }

  function renderInbounds() {
    const host = $('#xsInbounds');
    host.innerHTML = '';
    for (const i of xs.model.inbounds) host.appendChild(inboundCard(i));
    $('#xsInboundsEmpty').hidden = xs.model.inbounds.length > 0;
    $('#xsFirewallHint').hidden = state.platform !== 'win32' || !xs.model.inbounds.length;
  }

  /* ----------------------------- reverse ----------------------------- */

  /** The settings page's option cards, over a <select> that stays the value holder. */
  function optionCards(selectId, hostId, icons) {
    const sel = $(selectId);
    const host = $(hostId);
    host.innerHTML = '';
    for (const opt of [...sel.options]) {
      const raw = opt.textContent.trim();
      const cut = raw.indexOf('—');
      const card = document.createElement('button');
      card.type = 'button';
      card.className = 'opt-card' + (opt.value === sel.value ? ' active' : '');
      card.dataset.value = opt.value;
      card.innerHTML =
        '<span class="opt-card-ico"></span>' +
        '<span class="opt-card-text"><span class="opt-card-title"></span><span class="opt-card-desc"></span></span>' +
        '<span class="opt-card-check">✓</span>';
      card.querySelector('.opt-card-ico').textContent = icons[opt.value] || '•';
      card.querySelector('.opt-card-title').textContent = cut > 0 ? raw.slice(0, cut).trim() : raw;
      card.querySelector('.opt-card-desc').textContent = cut > 0 ? raw.slice(cut + 1).trim() : '';
      card.onclick = () => {
        if (sel.value === opt.value) return;
        sel.value = opt.value;
        sel.dispatchEvent(new Event('change', { bubbles: true }));   // exactly what the menu would have raised
      };
      host.appendChild(card);
    }
  }

  function renderDiagram(role) {
    $('#xsDiagram').hidden = role === 'off';
    if (role === 'off') return;
    $('#xsDiagHere').textContent = t(role === 'bridge' ? 'xs.node.bridge' : 'xs.node.portal');
    $('#xsDiagThere').textContent = t('xs.diag.there');
    $('#xsDiagThereRole').textContent = t(role === 'bridge' ? 'xs.node.portal' : 'xs.node.bridge');
  }

  function renderBridge(rv) {
    $$('#xsBridgeVia .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.via === rv.bridge.via));
    $('#xsBridgeServerWrap').hidden = rv.bridge.via !== 'server';
    $('#xsBridgeLinkWrap').hidden = rv.bridge.via !== 'link';
    $('#xsBridgeLink').value = rv.bridge.link;

    const mount = $('#xsBridgeServerMount');
    mount.innerHTML = '';
    bridgeSel = null;
    // the reverse proxy rides VLESS: nothing else can be the portal
    const opts = (state.servers || [])
      .filter(s => s.protocol === 'vless')
      .map(s => ({ value: s.id, label: s.name + ' — ' + s.address + ':' + s.port }));
    if (!opts.length) {
      const note = document.createElement('p');
      note.className = 'hint warn';
      note.textContent = t('xs.noVless');
      mount.appendChild(note);
      return;
    }
    const value = opts.some(o => o.value === rv.bridge.serverId) ? rv.bridge.serverId : '';
    bridgeSel = makeSearchSelect({
      options: opts,
      value,
      onChange: (v) => editReverse(rv => { rv.bridge.serverId = v; })
    });
    mount.appendChild(bridgeSel);
  }

  function renderPortal(m, rv) {
    const sel = $('#xsPortalInterconn');
    const vless = m.inbounds.filter(i => i.enabled && i.protocol === 'vless');
    sel.innerHTML = '<option value=""></option>' +
      vless.map(i => '<option value="' + escapeHtml(i.id) + '">' + escapeHtml(inboundLabel(i)) + '</option>').join('');
    sel.value = rv.portal.interconnInboundId;

    const host = $('#xsPortalUsers');
    host.innerHTML = '';
    const users = m.inbounds.filter(i => i.enabled && i.id !== rv.portal.interconnInboundId);
    for (const i of users) {
      const label = document.createElement('label');
      label.className = 'xs-check';
      const box = document.createElement('input');
      box.type = 'checkbox';
      box.value = i.id;
      box.checked = rv.portal.userInboundIds.includes(i.id);
      const text = document.createElement('span');
      text.className = 'xs-check-label';
      text.textContent = inboundLabel(i);
      label.appendChild(box);
      label.appendChild(text);
      host.appendChild(label);
    }
  }

  function renderReverse() {
    const m = xs.model;
    const rv = reverseOf();
    $('#xsReverseRole').value = rv.role;
    optionCards('#xsReverseRole', '#xsReverseCards', ROLE_ICONS);
    $('#xsBridgeBody').hidden = rv.role !== 'bridge';
    $('#xsPortalBody').hidden = rv.role !== 'portal';
    // the other side is built from what is stored, not from a half-made choice
    $('#xsRevActions').hidden = m.reverse.role === 'off';
    $('#xsOtherWrap').hidden = true;
    renderDiagram(rv.role);
    renderBridge(rv);
    renderPortal(m, rv);
  }

  /* ----------------------------- exit ----------------------------- */

  function renderExit() {
    const m = xs.model;
    const type = exitOf();
    $('#xsExitType').value = type;
    optionCards('#xsExitType', '#xsExitCards', EXIT_ICONS);
    $('#xsExitServerWrap').hidden = type !== 'server';
    $('#xsBlockPrivate').checked = !!m.blockPrivate;
    $('#xsBlockTorrent').checked = !!m.blockTorrent;

    const mount = $('#xsExitServerMount');
    mount.innerHTML = '';
    exitSel = null;
    const opts = (state.servers || []).map(s => ({ value: s.id, label: s.name + ' — ' + s.address + ':' + s.port }));
    if (!opts.length) {
      const note = document.createElement('p');
      note.className = 'hint warn';
      note.textContent = t('xs.noServers');
      mount.appendChild(note);
      return;
    }
    const value = opts.some(o => o.value === m.exit.serverId) ? m.exit.serverId : '';
    exitSel = makeSearchSelect({
      options: opts,
      value,
      onChange: (v) => {
        const next = nextModel();
        next.exit.serverId = v;
        apply(next);
      }
    });
    mount.appendChild(exitSel);
  }

  function render() {
    if (!xs.model) return;
    renderHead();
    renderInbounds();
    renderReverse();
    renderExit();
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
   * The enforcer can switch a client off between our fetches, so the status is
   * also what keeps our copy of the model honest — otherwise the next `set`
   * would quietly switch that client back on.
   */
  function absorb(st) {
    if (!xs.model || !st || !Array.isArray(st.inbounds)) return;
    for (const li of st.inbounds) {
      const mi = xs.model.inbounds.find(i => i.id === li.id);
      if (!mi) continue;
      for (const lc of (li.clients || [])) {
        const mc = mi.clients.find(c => c.id === lc.id);
        if (!mc) continue;
        mc.enabled = lc.enabled;
        mc.disabledBy = lc.disabledBy || '';
        mc.used = { up: lc.up, down: lc.down };
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
      const card = document.querySelector('[data-xs-inbound="' + li.id + '"]');
      if (!card) continue;
      const traffic = card.querySelector('.xs-in-traffic');
      if (traffic) traffic.textContent = fmtBytes(li.up + li.down);
      const mi = xs.model.inbounds.find(i => i.id === li.id);
      for (const lc of (li.clients || [])) {
        const row = card.querySelector('[data-xs-client="' + lc.id + '"]');
        const mc = mi && mi.clients.find(c => c.id === lc.id);
        if (row && mc) paintClient(row, mc, lc);
      }
    }
  }

  /* ----------------------------- inbound editor ----------------------------- */

  function blankInbound() {
    // Reality over raw tcp: the right default for a machine with no domain
    return {
      enabled: true, remark: 'VLESS Reality', protocol: 'vless',
      listen: '0.0.0.0', port: 443, network: 'tcp', path: '/', host: '', serviceName: '',
      security: 'reality',
      tls: { certFile: '', keyFile: '', serverName: '', alpn: ['h2', 'http/1.1'] },
      reality: { dest: 'www.cloudflare.com:443', serverNames: ['www.cloudflare.com'], privateKey: '', publicKey: '', shortIds: [] },
      ss: { method: '2022-blake3-aes-128-gcm', password: '' },
      sniffing: true, clients: []
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

  function openInbound(inbound) {
    editIn = { id: inbound ? inbound.id : '', draft: inbound ? deep(inbound) : blankInbound() };
    const d = editIn.draft;
    $('#xiRemark').value = d.remark;
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
    $('#xiErrors').hidden = true;
    $('#xiErrors').innerHTML = '';
    syncInboundFields();
    $('#xsInboundModal').hidden = false;
  }

  const closeInbound = () => { $('#xsInboundModal').hidden = true; editIn = null; };

  function readInbound() {
    const d = editIn.draft;
    d.remark = $('#xiRemark').value.trim();
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
    return d;
  }

  async function saveInbound() {
    const d = readInbound();
    const next = nextModel();
    let idx;
    if (editIn.id) {
      idx = next.inbounds.findIndex(i => i.id === editIn.id);
      if (idx === -1) return closeInbound();
      next.inbounds[idx] = d;
    } else {
      next.inbounds.push(d);
      idx = next.inbounds.length - 1;
    }
    if (await apply(next)) return closeInbound();
    modalErrors('#xiErrors', 'inbounds[' + idx + ']', closeInbound);
  }

  async function delInbound(inbound) {
    if (!window.confirm(t('xs.confirmDelIn'))) return;
    const next = nextModel();
    next.inbounds = next.inbounds.filter(i => i.id !== inbound.id);
    // An inbound the reverse proxy names cannot just vanish under it: the same
    // write fixes the reverse fields, and a toast says so — better than a
    // refusal the user has to undo by hand.
    const rv = next.reverse;
    let cleared = false;
    if (rv.portal.interconnInboundId === inbound.id) {
      rv.portal.interconnInboundId = '';
      cleared = true;
    }
    if (rv.portal.userInboundIds.includes(inbound.id)) {
      rv.portal.userInboundIds = rv.portal.userInboundIds.filter(id => id !== inbound.id);
      cleared = true;
    }
    if (cleared && rv.role === 'portal') rv.role = 'off';
    if (await apply(next) && cleared) toast(t('xs.reverseCleared'), 'warn');
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
      enabled: true, email: '', uuid: '', password: '', flow: '',
      expiresAt: 0, quotaBytes: 0, limitIp: 0, note: '', used: { up: 0, down: 0 }, disabledBy: ''
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
    $('#xcExpiry').value = draft.expiresAt ? toDateInput(draft.expiresAt) : '';
    $('#xcQuotaGb').value = draft.quotaBytes ? String(Math.round((draft.quotaBytes / GB) * 100) / 100) : '0';
    $('#xcNote').value = draft.note || '';
    $('#xcEnabled').checked = draft.enabled !== false;
    $('#xcErrors').hidden = true;
    $('#xcErrors').innerHTML = '';
    $('#xsClientModal').hidden = false;
  }

  const closeClient = () => { $('#xsClientModal').hidden = true; editCl = null; };

  async function saveClient() {
    const next = nextModel();
    const inIdx = next.inbounds.findIndex(i => i.id === editCl.inboundId);
    if (inIdx === -1) return closeClient();
    const inbound = next.inbounds[inIdx];
    const d = editCl.draft;
    d.email = $('#xcEmail').value.trim();
    if (usesUuid(inbound)) d.uuid = $('#xcSecret').value.trim();
    else d.password = $('#xcSecret').value.trim();
    d.flow = flowOk(inbound) ? $('#xcFlow').value : '';
    d.expiresAt = fromDateInput($('#xcExpiry').value);
    d.quotaBytes = Math.max(0, Math.round((parseFloat($('#xcQuotaGb').value) || 0) * GB));
    d.note = $('#xcNote').value;
    d.enabled = $('#xcEnabled').checked;
    if (d.enabled) d.disabledBy = '';

    let cIdx;
    if (editCl.id) {
      cIdx = inbound.clients.findIndex(c => c.id === editCl.id);
      if (cIdx === -1) return closeClient();
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
    const next = nextModel();
    const ni = next.inbounds.find(i => i.id === inbound.id);
    if (!ni) return;
    ni.clients = ni.clients.filter(c => c.id !== client.id);
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

  /* ----------------------------- wiring ----------------------------- */

  function ctxOf(target) {
    const card = target.closest('[data-xs-inbound]');
    const row = target.closest('[data-xs-client]');
    const inbound = card ? xs.model.inbounds.find(i => i.id === card.dataset.xsInbound) : null;
    const client = inbound && row ? inbound.clients.find(c => c.id === row.dataset.xsClient) : null;
    return { inbound, client };
  }

  async function onInboundsClick(e) {
    const { inbound, client } = ctxOf(e.target);
    if (!inbound) return;
    const btn = e.target.closest('button[data-act]');
    if (!btn) {
      if (client && e.target.closest('.xs-cl-secret')) {
        await copyText(secretOf(inbound, client));
        toast(t('xs.copied'), 'ok');
      }
      return;
    }
    const act = btn.dataset.act;
    if (client) {
      if (act === 'edit') return openClient(inbound, client);
      if (act === 'del') return delClient(inbound, client);
      if (act === 'link') {
        const link = await linkFor(inbound, client);
        if (!link) return;
        await copyText(link);
        toast(t('xs.copied'), 'ok');
        return;
      }
      if (act === 'qr') {
        const link = await linkFor(inbound, client);
        if (link) showQr(link);
      }
      return;
    }
    if (act === 'addClient') return openClient(inbound, null);
    if (act === 'edit') return openInbound(inbound);
    if (act === 'del') return delInbound(inbound);
    if (act === 'fw') return firewall(inbound);
  }

  async function onInboundsChange(e) {
    if (!e.target.matches('input[data-act="enable"]')) return;
    const { inbound, client } = ctxOf(e.target);
    if (!inbound) return;
    const on = e.target.checked;
    const next = nextModel();
    const ni = next.inbounds.find(i => i.id === inbound.id);
    if (client) {
      const nc = ni.clients.find(c => c.id === client.id);
      nc.enabled = on;
      if (on) nc.disabledBy = '';
    } else ni.enabled = on;
    // a refusal leaves the store untouched, and apply's re-render puts the
    // switch back where the model says it belongs
    await apply(next);
  }

  function wire() {
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

    $('#xsEngineSelect').onchange = () => {
      const next = nextModel();
      next.engine = $('#xsEngineSelect').value;
      apply(next);
    };
    $('#xsLogLevel').onchange = () => {
      const next = nextModel();
      next.logLevel = $('#xsLogLevel').value;
      apply(next);
    };
    $('#xsPublicAddr').onchange = () => {
      const next = nextModel();
      next.publicAddress = $('#xsPublicAddr').value.trim();
      apply(next);
    };
    $('#xsAutoStart').onchange = () => {
      const next = nextModel();
      next.autoStart = $('#xsAutoStart').checked;
      apply(next);
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

    $('#btnXsAddInbound').onclick = () => openInbound(null);
    $('#xsInbounds').addEventListener('click', onInboundsClick);
    $('#xsInbounds').addEventListener('change', onInboundsChange);

    $('#xsReverseRole').onchange = () => {
      const role = $('#xsReverseRole').value;
      editReverse(rv => { rv.role = role; });
    };
    $('#xsBridgeVia').onclick = (e) => {
      const btn = e.target.closest('.seg-btn');
      if (!btn || btn.dataset.via === reverseOf().bridge.via) return;
      editReverse(rv => { rv.bridge.via = btn.dataset.via; });
    };
    $('#xsBridgeLink').onchange = () => {
      const link = $('#xsBridgeLink').value.trim();
      editReverse(rv => { rv.bridge.link = link; });
    };
    $('#xsPortalInterconn').onchange = () => {
      const id = $('#xsPortalInterconn').value;
      editReverse(rv => {
        rv.portal.interconnInboundId = id;
        // the interconn cannot also carry users through itself
        rv.portal.userInboundIds = rv.portal.userInboundIds.filter(x => x !== id);
      });
    };
    $('#xsPortalUsers').onchange = (e) => {
      if (!e.target.matches('input[type="checkbox"]')) return;
      const { value, checked } = e.target;
      editReverse(rv => {
        const ids = new Set(rv.portal.userInboundIds);
        if (checked) ids.add(value); else ids.delete(value);
        rv.portal.userInboundIds = [...ids];
      });
    };
    $('#btnXsOtherSide').onclick = async () => {
      let r;
      try { r = await window.api.xserverOtherSide(); }
      catch (e) { return toast((e && e.message) || String(e), 'err'); }
      if (!r || r.error || !r.snippet) return toast((r && r.error) || t('xs.genFailed'), 'err');
      await copyText(JSON.stringify(r.snippet, null, 2));
      toast(t('xs.otherSideCopied'), 'ok');
      $('#xsOtherWrap').hidden = !r.link;
      $('#xsOtherLink').value = r.link || '';
    };
    $('#btnXsOtherCopy').onclick = async () => {
      await copyText($('#xsOtherLink').value);
      toast(t('xs.copied'), 'ok');
    };
    $('#btnXsOtherQr').onclick = () => {
      if ($('#xsOtherLink').value) showQr($('#xsOtherLink').value);
    };

    $('#xsExitType').onchange = () => {
      draftExit = $('#xsExitType').value;
      apply(nextModel());
    };
    $('#xsBlockPrivate').onchange = () => {
      const next = nextModel();
      next.blockPrivate = $('#xsBlockPrivate').checked;
      apply(next);
    };
    $('#xsBlockTorrent').onchange = () => {
      const next = nextModel();
      next.blockTorrent = $('#xsBlockTorrent').checked;
      apply(next);
    };

    $('#btnXsClearLog').onclick = () => { $('#xsLog').innerHTML = ''; };

    /* the inbound modal */
    $('#xiProtocol').onchange = syncInboundFields;
    $('#xiNetwork').onchange = syncInboundFields;
    $('#xiSecurity').onchange = syncInboundFields;
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
  }

  /* ----------------------------- start ----------------------------- */

  async function boot() {
    wire();
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
