'use strict';
/**
 * plus: the Scan page (spec 2026-10-15 §4). Shares app.js's globals ($, t,
 * state, toast, escapeHtml, copyText, fmtMs, pingClass, makeSearchSelect,
 * setServers).
 *
 * One config and what to test — addresses × ports × SNIs — and a table that
 * fills while the cores work. The run has two phases and the strip says which
 * is in flight: the filter walks every target wide and cheap, the speed test
 * re-visits only the best one transfer at a time. A row therefore arrives
 * twice and the second REPLACES the first, which is why the table is a Map
 * keyed by `target|engine`.
 *
 * Results come one at a time in `scan-progress`, so a run of thousands of rows
 * must not become thousands of layouts: they are queued and applied once per
 * animation frame, each inserted at its sorted place. Nothing here expands an
 * address list or draws a sample — main owns the targets; the page only
 * counts what is typed. What a config allows (UDP: no TCP test; ECH; whether
 * an SNI can change; the addresses that fit) is main's answer to scan:suggest.
 */
(function () {
  const TEST_IDS = ['tcp', 'delay', 'down', 'up'];
  const TEST_DEFAULTS = { tcp: true, delay: true, down: true, up: false };
  /** The table has no room for "Xray-PattN (patterniha)". */
  const ENGINE_SHORT = { xray: 'Xray', 'xray-pattn': 'PattN' };
  const PRESET_IDS = ['fast', 'balanced', 'accurate'];
  /** main's refusals, by their bare code; anything else is shown as it came. */
  const START_ERRORS = {
    busy: 'scan.err.busy',
    'no server': 'scan.err.noServer',
    'server not found': 'scan.err.notFound',
    'unsupported protocol': 'scan.err.proto',
    'json chain': 'scan.err.chain',
    'no targets': 'scan.err.noTargets',
    'no engine': 'scan.err.noEngine',
    'core too old': 'scan.err.coreOld',
    'no tests': 'scan.err.noTests',
    'no rows': 'scan.err.noRows',
    sni: 'scan.err.sni'
  };
  /**
   * The number fields, each exactly one key of the opts object main
   * sanitizes, so a preset fills them and a run reads them back with no other
   * mapping. `lo` is the floor of a sane value; only speedTop may be 0.
   */
  const NUM_FIELDS = [
    ['#scanConc', 'filterConcurrency', 16, 1],
    ['#scanCores', 'coresInParallel', 2, 1],
    ['#scanSamples', 'delaySamples', 2, 1],
    ['#scanTcpTimeout', 'tcpTimeout', 2000, 500],
    ['#scanDelayTimeout', 'delayTimeout', 4000, 500],
    ['#scanSpeedTop', 'speedTop', 10, 0],
    ['#scanSpeedConc', 'speedConcurrency', 1, 1],
    ['#scanSpeedRounds', 'speedRounds', 1, 1],
    ['#scanBatch', 'batch', 20, 1]
  ];
  const STAGE_KEYS = { idle: 'scan.stage.idle', filter: 'scan.stage.filter', speed: 'scan.stage.speed', done: 'scan.stage.done' };
  /** A path main built from downBytes itself; filling it in would freeze the MB field. */
  const AUTO_DOWN_PATH = /^\/__down\?bytes=\d+$/;
  /** main's cap on one run's targets — the estimate under the box stops there too. */
  const MAX_TARGETS = 5000;
  /** A queue this deep means the frames stopped coming (hidden window): drain it. */
  const QUEUE_BURST = 500;
  const PRESET_NAMES = { cf: 'scan.p.cf', 'warp-masque': 'scan.p.warpMasque', 'warp-wg': 'scan.p.warpWg' };

  let started = false;           // initScan can be reached from two directions (see the bottom)
  let presets = { ranges: {}, defaults: {}, presets: {}, engines: [], last: null, tested: 0 };
  let facts = null;              // scan:suggest's answer for the chosen config
  let factsSeq = 0;              // the answer to the newest question wins
  let sourceSel = null;          // the makeSearchSelect element, when there is one
  let pendingPick = '';          // a config chosen elsewhere (Configs → «اسکن این»), applied at the next rebuild
  let srcMode = 'server';        // 'server' | 'link'
  let pickMode = 'all';          // 'all' | 'random'
  let run = null;                // { runId, startedAt } while a scan is in flight
  let prog = null;               // the newest progress; it outlives the run so the strip keeps its numbers
  let lastReq = null;            // the request the rows came from — links, saving and re-tests reuse its source
  let count = { kind: 'typed' }; // what #scanCount says, so a language switch can say it again
  let notes = [];                // what the last start said about ECH and the cores left out
  let ticker = null;
  const rows = new Map();        // 'target|engine' -> { result, tr }
  const order = [];              // the same keys, in the order the tbody shows them
  let sort = { key: 'score', dir: -1 };
  let best = 0;                  // the highest score in the table — what the bars are scaled to
  let queue = [];
  let frame = 0;
  let late = 0;
  let rowTpl = null;

  /* ----------------------------- small helpers ----------------------------- */

  const fill = (s, map) => String(s).replace(/\{(\w+)\}/g, (m, k) => (Object.prototype.hasOwnProperty.call(map, k) ? map[k] : m));
  const tbody = () => $('#scanTbody');
  const numOf = (sel, def, lo = 1) => { const n = Number($(sel).value); return Number.isFinite(n) && n >= lo ? n : def; };
  const setNumField = (sel, v, lo = 1) => { const n = Number(v); if (Number.isFinite(n) && n >= lo) $(sel).value = String(n); };
  const mbps = (v) => (Math.round((Number(v) || 0) * 10) / 10).toFixed(1);
  const int0 = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
  const addrPort = (addr, port) => (port ? (String(addr).includes(':') ? `[${addr}]:${port}` : `${addr}:${port}`) : String(addr));
  const rowKey = (r) => `${r.key || r.addr || r.ip}|${r.engine}`;

  /** mm:ss — the elapsed clock at the end of the run row. */
  function clock(ms) {
    const s = Math.max(0, Math.floor(ms / 1000));
    return String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0');
  }

  /** The non-comment tokens of a box. */
  function tokensOf(text) {
    const out = [];
    for (const raw of String(text || '').split(/\r?\n/)) {
      const h = raw.indexOf('#');
      const line = (h === -1 ? raw : raw.slice(0, h)).trim();
      if (line) out.push(...line.split(/[\s,;]+/).filter(Boolean));
    }
    return out;
  }

  /** A known refusal reads as a sentence; anything else is the raw text. */
  const errText = (code) => (START_ERRORS[code] ? t(START_ERRORS[code]) : String(code || ''));

  function setError(code) {
    const el = $('#scanError');
    el.textContent = code ? errText(code) : '';
    el.hidden = !code;
  }

  /* ----------------------------- the config ----------------------------- */

  function setMode(mode) {
    srcMode = mode === 'link' ? 'link' : 'server';
    $$('#scanSourceSeg .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.src === srcMode));
    $('#scanSrcServer').hidden = srcMode !== 'server';
    $('#scanSrcLink').hidden = srcMode !== 'link';
    refreshFacts();
  }

  function formSource() {
    if (srcMode === 'link') {
      const link = $('#scanLink').value.trim();
      return link ? { link } : {};
    }
    const id = $('#scanSource').value || '';
    return id ? { serverId: id } : {};
  }

  /** The rows came from one config; links, saving and re-tests go through that same one. */
  function rowSource() {
    const src = lastReq && (lastReq.serverId ? { serverId: lastReq.serverId } : (lastReq.link ? { link: lastReq.link } : {}));
    return src && (src.serverId || src.link) ? src : formSource();
  }

  /** The stored-config picker: every config — main says which it can take. */
  function refreshSourcePicker() {
    const mount = $('#scanSourceMount');
    const sel = $('#scanSource');
    if (!mount || !sel) return;
    // what was chosen, read before the options are rebuilt (rebuilding resets the select's value)
    const wanted = pendingPick || (sourceSel && sourceSel.getValue()) || sel.value || (presets.last && presets.last.serverId) || '';
    pendingPick = '';
    const opts = (state.servers || [])
      .filter(s => s && s.outbound)
      .map(s => ({ value: s.id, label: `${s.name || '—'} — ${String(s.protocol || '').toUpperCase()} ${addrPort(s.address, s.port)}` }));
    sel.innerHTML = opts.map(o => `<option value="${escapeHtml(o.value)}">${escapeHtml(o.label)}</option>`).join('');
    mount.innerHTML = '';
    if (!opts.length) {
      sourceSel = null;
      sel.value = '';
      const note = document.createElement('p');
      note.className = 'hint warn';
      note.dataset.i18n = 'scan.noServers';
      note.textContent = t('scan.noServers');
      mount.appendChild(note);
      refreshFacts();
      return;
    }
    const keep = opts.some(o => o.value === wanted) ? wanted : opts[0].value;
    sourceSel = makeSearchSelect({ options: opts, value: keep, onChange: (v) => { sel.value = v; refreshFacts(); } });
    mount.appendChild(sourceSel);
    sel.value = keep;
    refreshFacts();
  }

  /** The Configs page's «اسکن این»: this config, chosen. */
  function useConfig(id) {
    pendingPick = id;
    setMode('server');
    refreshSourcePicker();
  }

  /** What main says this config allows, as a short list under the picker. */
  async function refreshFacts() {
    const seq = ++factsSeq;
    const src = formSource();
    if (!src.serverId && !src.link) { facts = null; return paintFacts(); }
    let r;
    try { r = await window.api.scanSuggest(src); } catch { r = null; }
    if (seq !== factsSeq) return undefined;
    facts = r && !r.error ? r : null;
    return paintFacts();
  }

  function paintFacts() {
    const list = $('#scanFacts');
    list.innerHTML = '';
    const sni = $('#scanSnis');
    if (!facts) { sni.disabled = false; list.hidden = true; return; }
    const lines = [];
    const proto = (facts.protocol || '').toUpperCase() + (facts.warp ? ' · WARP' : '');
    lines.push(fill(t('scan.fact.proto'), { p: proto, t: facts.transport === 'udp' ? 'UDP' : 'TCP' }));
    if (facts.unsupported) lines.push(fill(t('scan.fact.unsupported'), { r: errText(facts.unsupported) }));
    lines.push(t(facts.transport === 'udp' ? 'scan.fact.udp' : 'scan.fact.tcp'));
    if (facts.ech) lines.push(t('scan.fact.ech'));
    else if (facts.sni && facts.sni.ok) lines.push(t('scan.fact.sniOk'));
    else if (facts.sni && facts.sni.code) lines.push(t('scan.fact.sni.' + facts.sni.code));
    if (facts.warp) lines.push(t('scan.fact.warp'));
    else if (facts.masque) lines.push(t('scan.fact.masque'));
    if (facts.preset && PRESET_NAMES[facts.preset]) lines.push(fill(t('scan.fact.suggest'), { p: t(PRESET_NAMES[facts.preset]) }));
    for (const text of lines) {
      const li = document.createElement('li');
      li.textContent = text;
      list.appendChild(li);
    }
    list.hidden = false;
    // an SNI list this config cannot take would only be refused at start
    sni.disabled = !(facts.sni && facts.sni.ok);
  }

  /* ----------------------------- what to test ----------------------------- */

  function setPick(mode) {
    pickMode = mode === 'random' ? 'random' : 'all';
    $$('#scanPickSeg .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.pick === pickMode));
    $('#scanPickOpts').hidden = pickMode !== 'random';
    updateCount();
  }
  const perRange = () => Math.round(numOf('#scanPerRange', 20, 1));

  /** The addresses an IPv4 token stands for; anything else (IPv6 blocks, names) is drawn, so it counts as one draw. */
  function sizeOf(tok) {
    const bare = tok.replace(/^\[([^\]]+)\](?::\d+)?$/, '$1').replace(/:(\d+)$/, (m, p) => (tok.includes('[') || tok.split(':').length > 2 ? m : ''));
    const cidr = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(bare);
    if (cidr) return 2 ** (32 - Math.max(8, Math.min(32, Number(cidr[2]))));
    const dash = /^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$/.exec(bare);
    if (dash) {
      const n = (ip) => ip.split('.').reduce((a, o) => a * 256 + Number(o), 0);
      return Math.max(1, n(dash[2]) - n(dash[1]) + 1);
    }
    if (/\/\d{1,3}$/.test(bare) || /^[0-9a-f:]+-[0-9a-f:]+$/i.test(bare)) return Infinity;
    return 1;
  }

  /** The line under the box: what a run will get, as far as the page can tell. */
  function paintCount() {
    const el = $('#scanCount');
    if (count.kind === 'run') {
      const parts = [fill(t('scan.countTotal'), { n: count.targets, e: count.engines })];
      if (count.truncated) parts.push(fill(t('scan.truncated'), { n: count.targets }));
      if (count.bad) parts.push(fill(t('scan.badLines'), { n: count.bad }));
      if (count.exhausted) parts.push(fill(t('scan.exhausted'), { n: count.exhausted }));
      el.textContent = parts.join(' · ');
      return;
    }
    if (count.kind === 'retest') { el.textContent = fill(t('scan.retopCount'), { n: count.n }); return; }
    const toks = tokensOf($('#scanIps').value);
    const ports = Math.max(1, tokensOf($('#scanPorts').value).length);
    const snis = $('#scanSnis').disabled ? 1 : Math.max(1, tokensOf($('#scanSnis').value).length);
    const product = ports > 1 || snis > 1 ? ' ' + fill(t('scan.countProduct'), { p: ports, s: snis }) : '';
    if (!toks.length) { el.textContent = t('scan.p.none') + product; return; }
    if (pickMode === 'random') {
      const k = perRange();
      const n = Math.min(MAX_TARGETS, toks.reduce((s, tok) => s + Math.min(k, sizeOf(tok)), 0));
      el.textContent = fill(t('scan.countRandom'), { r: toks.length, k, n }) + product;
      return;
    }
    el.textContent = fill(t('scan.count'), { n: toks.length }) + product;
  }

  function updateCount() {
    count = { kind: 'typed' };
    paintCount();
  }

  /** The history count next to the pick row; nothing while it is empty. */
  function paintTested(n) {
    const el = $('#scanTested');
    const v = Math.max(0, Math.floor(Number(n) || 0));
    el.textContent = v ? fill(t('scan.tested'), { n: v }) : '';
    el.hidden = !v;
  }

  /** An address preset: its ranges into the box; WARP WireGuard brings its ports too. */
  function applyAddrPreset(name) {
    const which = name === 'suggest' ? (facts && facts.preset) : name;
    const p = which && (presets.ranges || {})[which];
    if (!p || !Array.isArray(p.ranges)) return toast(t('scan.p.none'), 'warn');
    $('#scanIps').value = p.ranges.join('\n');
    if (Array.isArray(p.ports) && p.ports.length) $('#scanPorts').value = p.ports.join(', ');
    // a big list is meant to be sampled, not walked
    if (p.ranges.length > 1 || /\/(?:[0-9]|1[0-9]|2[0-3])$/.test(p.ranges[0] || '')) setPick('random');
    updateCount();
    return undefined;
  }

  function applyPortsPreset(name) {
    const r = presets.ranges || {};
    const list = Array.isArray(r[name]) ? r[name] : (r[name] && Array.isArray(r[name].ports) ? r[name].ports : null);
    if (!list) return;
    $('#scanPorts').value = list.join(', ');
    updateCount();
  }

  /* ----------------------------- how ----------------------------- */

  function renderEngines(list) {
    const host = $('#scanEngines');
    const ticked = new Set($$('#scanEngines input').filter(b => b.checked).map(b => b.value));
    const fresh = !host.children.length;
    host.innerHTML = '';
    for (const e of list) {
      const label = document.createElement('label');
      label.className = 'scan-check';
      if (!e.installed) label.classList.add('disabled');
      const box = document.createElement('input');
      box.type = 'checkbox';
      box.value = e.id;
      box.checked = !!e.installed && (fresh || ticked.has(e.id) || !ticked.size);
      box.disabled = !e.installed;
      const text = document.createElement('span');
      text.className = 'scan-check-label';
      text.textContent = e.label || e.id;
      label.appendChild(box);
      label.appendChild(text);
      if (!e.installed) {
        const why = document.createElement('span');
        why.className = 'scan-check-hint';
        why.dataset.i18n = 'scan.notInstalled';
        why.textContent = t('scan.notInstalled');
        label.appendChild(why);
      }
      host.appendChild(label);
    }
  }

  function renderTests() {
    const host = $('#scanTests');
    host.innerHTML = '';
    for (const id of TEST_IDS) {
      const label = document.createElement('label');
      label.className = 'scan-check';
      const box = document.createElement('input');
      box.type = 'checkbox';
      box.value = id;
      box.checked = !!TEST_DEFAULTS[id];
      const text = document.createElement('span');
      text.className = 'scan-check-label';
      text.dataset.i18n = 'scan.test.' + id;
      text.textContent = t('scan.test.' + id);
      label.appendChild(box);
      label.appendChild(text);
      host.appendChild(label);
    }
  }

  const testBox = (id) => document.querySelector(`#scanTests input[value="${id}"]`);
  const testOn = (id) => { const b = testBox(id); return !!(b && b.checked); };

  function fillLimits(o) {
    if (!o || typeof o !== 'object') return;
    for (const [sel, key, , lo] of NUM_FIELDS) setNumField(sel, o[key], lo);
    if (Number(o.downBytes) > 0) setNumField('#scanDownMb', Math.round(Number(o.downBytes) / 1e6));
    if (typeof o.downHost === 'string' && o.downHost) $('#scanDownHost').value = o.downHost;
    if (typeof o.delayHost === 'string' && o.delayHost) $('#scanDelayHost').value = o.delayHost;
    if (Number(o.delayPort) > 0) $('#scanDelayPort').value = String(Number(o.delayPort));
    if (typeof o.delayPath === 'string' && o.delayPath) $('#scanDelayPath').value = o.delayPath;
    if (typeof o.downPath === 'string' && o.downPath && !AUTO_DOWN_PATH.test(o.downPath)) $('#scanDownPath').value = o.downPath;
    paintPreset();
  }

  /** The preset the fields currently hold, or '' when they hold something else. */
  function currentPreset() {
    const all = presets.presets || {};
    for (const id of PRESET_IDS) {
      const p = all[id];
      if (p && NUM_FIELDS.every(([sel, key, , lo]) => numOf(sel, NaN, lo) === Number(p[key]))) return id;
    }
    return '';
  }

  function paintPreset() {
    const now = currentPreset();
    $$('#scanPreset .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.preset === now));
  }

  function buildOpts() {
    const o = {};
    for (const [sel, key, def, lo] of NUM_FIELDS) o[key] = Math.round(numOf(sel, def, lo));
    o.downBytes = Math.round(numOf('#scanDownMb', 10) * 1e6);
    o.downHost = $('#scanDownHost').value.trim();
    o.downPath = $('#scanDownPath').value.trim();
    o.delayHost = $('#scanDelayHost').value.trim();
    o.delayPort = Math.round(numOf('#scanDelayPort', 80));
    o.delayPath = $('#scanDelayPath').value.trim() || '/';
    return o;
  }

  /** The inputs of the last run, as main remembered them. */
  function restore(last) {
    if (!last) return;
    if (last.ipsText) $('#scanIps').value = last.ipsText;
    if (last.portsText) $('#scanPorts').value = last.portsText;
    if (last.snisText) $('#scanSnis').value = last.snisText;
    if (last.pick && typeof last.pick === 'object') {
      if (last.pick.perRange) $('#scanPerRange').value = last.pick.perRange;
      $('#scanFresh').checked = last.pick.fresh !== false;
      setPick(last.pick.mode);
    }
    if (Array.isArray(last.engines) && last.engines.length) {
      $$('#scanEngines input').forEach(b => { if (!b.disabled) b.checked = last.engines.includes(b.value); });
    }
    if (last.tests) for (const id of TEST_IDS) { const b = testBox(id); if (b) b.checked = !!last.tests[id]; }
    fillLimits(last.opts);
    if (last.link) { setMode('link'); $('#scanLink').value = last.link; }
    else if (last.serverId) setMode('server');
  }

  /* ----------------------------- the table ----------------------------- */

  function metric(r, key) {
    const d = r.delay && r.delay.loss < 1 ? r.delay : null;
    switch (key) {
      case 'tcp': return r.tcp && r.tcp.ok ? r.tcp.ms : null;
      case 'median': return d ? d.median : null;
      case 'avg': return d ? d.avg : null;
      case 'min': return d ? d.min : null;
      case 'jitter': return d ? d.jitter : null;
      case 'loss': return r.delay ? r.delay.loss : null;
      case 'down': return r.down && r.down.ok ? r.down.mbps : null;
      case 'up': return r.up && r.up.ok ? r.up.mbps : null;
      default: return Number(r.score) || 0;
    }
  }

  const textCmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

  /** A row with nothing to show in the sorted column goes last, either way. */
  function cmp(a, b) {
    const dir = sort.dir;
    const tie = textCmp(String(a.key || a.addr || ''), String(b.key || b.addr || ''));
    if (sort.key === 'addr') return dir * tie;
    if (sort.key === 'sni') return dir * textCmp(String(a.sni || ''), String(b.sni || '')) || tie;
    if (sort.key === 'engine') return dir * textCmp(a.engine, b.engine) || tie;
    const av = metric(a, sort.key), bv = metric(b, sort.key);
    if (av === null && bv === null) return tie;
    if (av === null) return 1;
    if (bv === null) return -1;
    return dir * (av - bv) || tie;
  }

  function rowTemplate() {
    if (rowTpl) return rowTpl;
    const tr = document.createElement('tr');
    tr.className = 'scan-row';
    tr.innerHTML =
      '<td class="scan-c-ip" dir="ltr"></td>' +
      '<td class="scan-c-sni" dir="ltr"></td>' +
      '<td class="scan-c-eng"></td>' +
      '<td class="scan-n"></td><td class="scan-n"></td><td class="scan-n"></td>' +
      '<td class="scan-n"></td><td class="scan-n"></td><td class="scan-n"></td>' +
      '<td class="scan-n scan-c-sp"></td><td class="scan-n scan-c-sp"></td>' +
      '<td class="scan-c-score"><span class="scan-score-wrap">' +
        '<span class="scan-score-bar"><span class="scan-score-fill"></span></span>' +
        '<span class="scan-score-val"></span>' +
      '</span></td>' +
      '<td class="scan-c-acts">' +
        '<button type="button" class="icon-btn" data-act="link" data-i18n-title="scan.link">⧉</button>' +
        '<button type="button" class="icon-btn" data-act="use" data-i18n-title="scan.use">✔</button>' +
        '<button type="button" class="icon-btn" data-act="retest" data-i18n-title="scan.retest">↻</button>' +
      '</td>';
    rowTpl = tr;
    return tr;
  }

  function newRow(key) {
    const tr = rowTemplate().cloneNode(true);
    tr.dataset.key = key;
    tr.querySelectorAll('[data-i18n-title]').forEach(b => { b.title = t(b.dataset.i18nTitle); });
    tr.cells[0].title = t('scan.copy');
    return tr;
  }

  const setCell = (cell, text, cls) => { cell.textContent = text; cell.className = 'scan-n' + (cls ? ' ' + cls : ''); };

  function paintScore(tr, r) {
    const s = Number(r.score) || 0;
    tr.querySelector('.scan-score-fill').style.inlineSize = (best > 0 ? Math.max(0, Math.min(100, (s / best) * 100)) : 0) + '%';
    tr.querySelector('.scan-score-val').textContent = s ? String(Math.round(s)) : '—';
  }

  function fillRow(tr, r) {
    const c = tr.cells;
    const p1 = Number(r.phase) === 1;
    c[0].textContent = addrPort(r.addr || r.ip, r.port);
    c[1].textContent = r.sni || '';
    c[2].textContent = ENGINE_SHORT[r.engine] || r.engine;
    const d = r.delay && r.delay.loss < 1 ? r.delay : null;
    const tcp = r.tcp && !r.tcp.skipped ? r.tcp : null;
    setCell(c[3], tcp ? (tcp.ok ? fmtMs(tcp.ms) : '×') : '—', tcp ? pingClass(tcp.ok ? tcp.ms : -1) : '');
    setCell(c[4], r.delay ? (d ? fmtMs(d.median) : '×') : '—', r.delay ? pingClass(d ? d.median : -1) : '');
    setCell(c[5], r.delay ? (d ? fmtMs(d.avg) : '×') : '—', '');
    setCell(c[6], d ? fmtMs(d.min) : (r.delay ? '×' : '—'), '');
    setCell(c[7], d ? fmtMs(d.jitter) : (r.delay ? '×' : '—'), '');
    setCell(c[8], r.delay ? Math.round(r.delay.loss * 100) + '%' : '—', r.delay ? pingClass(r.delay.loss >= 1 ? -1 : r.delay.loss * 1000) : '');
    setCell(c[9], r.down ? (r.down.ok ? mbps(r.down.mbps) : '×') : '—', 'scan-c-sp');
    setCell(c[10], r.up ? (r.up.ok ? mbps(r.up.mbps) : '×') : '—', 'scan-c-sp');
    c[1].className = 'scan-c-sni';
    paintScore(tr, r);
    tr.classList.toggle('scan-row-dead', !(Number(r.score) > 0));
    tr.classList.toggle('scan-row-p1', p1);
    if (r.error) tr.title = r.error;
    else if (p1) tr.title = t('scan.phase1');
    else tr.removeAttribute('title');
  }

  /** The SNI column shows only when a row carries one. */
  function paintSniColumn() {
    const any = [...rows.values()].some(e => !!e.result.sni);
    $('#scanTable').classList.toggle('scan-no-sni', !any);
  }

  function detach(key) {
    const i = order.indexOf(key);
    if (i !== -1) order.splice(i, 1);
    const e = rows.get(key);
    if (e && e.tr.parentNode) e.tr.remove();
  }

  function insertSorted(key, entry) {
    let lo = 0, hi = order.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (cmp(rows.get(order[mid]).result, entry.result) <= 0) lo = mid + 1; else hi = mid;
    }
    const before = order[lo];
    order.splice(lo, 0, key);
    tbody().insertBefore(entry.tr, before ? rows.get(before).tr : null);
  }

  function flushNow() {
    if (frame) cancelAnimationFrame(frame);
    clearTimeout(late);
    frame = 0;
    late = 0;
    flush();
  }

  /** One flush per frame, and a timer for when frames stop coming (a hidden window). */
  function schedule() {
    if (queue.length >= QUEUE_BURST) return flushNow();
    if (frame) return undefined;
    frame = requestAnimationFrame(flushNow);
    late = setTimeout(flushNow, 250);
    return undefined;
  }

  function flush() {
    if (!queue.length) return;
    const batch = queue;
    queue = [];
    let rescale = false;
    for (const r of batch) {
      const key = rowKey(r);
      let entry = rows.get(key);
      if (!entry) { entry = { result: r, tr: newRow(key) }; rows.set(key, entry); }
      else { entry.result = r; detach(key); }
      if ((Number(r.score) || 0) > best) { best = Number(r.score) || 0; rescale = true; }
      fillRow(entry.tr, r);
      insertSorted(key, entry);
    }
    if (rescale) for (const e of rows.values()) paintScore(e.tr, e.result);
    $('#scanEmpty').hidden = rows.size > 0;
    paintSniColumn();
    paintStrip();
  }

  function paintSortMarks() {
    $$('#scanTable th[data-sort]').forEach(th => {
      const mark = th.querySelector('.scan-sort');
      th.classList.toggle('active', th.dataset.sort === sort.key);
      if (mark) mark.textContent = th.dataset.sort === sort.key ? (sort.dir < 0 ? '▾' : '▴') : '';
    });
  }

  function resortAll() {
    const keys = [...rows.keys()].sort((a, b) => cmp(rows.get(a).result, rows.get(b).result));
    order.length = 0;
    const frag = document.createDocumentFragment();
    for (const k of keys) { order.push(k); frag.appendChild(rows.get(k).tr); }
    tbody().appendChild(frag);
    paintSortMarks();
  }

  function clearTable() {
    rows.clear();
    order.length = 0;
    queue = [];
    best = 0;
    tbody().innerHTML = '';
    $('#scanEmpty').hidden = false;
    paintSniColumn();
  }

  /* ----------------------------- the strip ----------------------------- */

  function setBar(sel, done, total) {
    const bar = $(sel).firstElementChild;
    if (!bar) return;
    const pct = total > 0 ? Math.max(0, Math.min(100, (done / total) * 100)) : 0;
    bar.style.inlineSize = pct.toFixed(1) + '%';
  }

  function etaText(ms) {
    const n = Number(ms);
    if (!Number.isFinite(n) || n <= 0) return '';
    const s = Math.round(n / 1000);
    return s >= 90 ? fill(t('scan.etaMin'), { n: Math.round(s / 60) }) : fill(t('scan.etaSec'), { n: Math.max(1, s) });
  }

  function paintStrip() {
    const p = prog || { stage: 'idle', done: 0, total: 0, alive: 0, speedDone: 0, speedTotal: 0, etaMs: null };
    const stage = STAGE_KEYS[p.stage] ? p.stage : 'idle';
    const pill = $('#scanStage');
    pill.dataset.stage = stage;
    pill.dataset.i18n = STAGE_KEYS[stage];
    pill.textContent = t(STAGE_KEYS[stage]);
    $('#scanStageText').textContent = !prog ? ''
      : p.stage === 'speed'
        ? fill(t('scan.stageSpeed'), { done: p.speedDone, total: p.speedTotal })
        : fill(t('scan.stageFilter'), { done: p.done, total: p.total, alive: p.alive });
    setBar('#scanBarFilter', p.done, p.total);
    setBar('#scanBarSpeed', p.speedDone, p.speedTotal);
    $('#scanEta').textContent = run ? etaText(p.etaMs) : '';
    $('#scanElapsed').textContent = prog ? clock((prog.endedAt || Date.now()) - prog.startedAt) : '';
  }

  /** What the last start said about ECH and the cores left out. */
  function paintNotes() {
    const list = $('#scanNotes');
    list.innerHTML = '';
    for (const n of notes) {
      const li = document.createElement('li');
      if (n.kind === 'ech') li.textContent = fill(t('scan.note.ech'), { via: n.via || '—', name: n.publicName || '—' });
      else if (n.kind === 'echFail') li.textContent = fill(t('scan.note.echFail'), { error: n.error || '—' });
      else li.textContent = fill(t('scan.note.skipped'), { engine: ENGINE_SHORT[n.engine] || n.engine, reason: n.reason || '' });
      if (n.kind !== 'ech') li.className = 'warn';
      list.appendChild(li);
    }
    list.hidden = !notes.length;
  }

  function notesOf(res) {
    const out = [];
    if (res && res.ech) out.push(res.ech.ok ? Object.assign({ kind: 'ech' }, res.ech) : Object.assign({ kind: 'echFail' }, res.ech));
    for (const s of (res && res.skipped) || []) out.push(Object.assign({ kind: 'skipped' }, s));
    return out;
  }

  /* ----------------------------- running ----------------------------- */

  const selectedEngines = () => $$('#scanEngines input').filter(b => b.checked).map(b => b.value);

  function selectedTests() {
    const tests = {};
    for (const id of TEST_IDS) tests[id] = testOn(id);
    return tests;
  }

  function buildReq() {
    return Object.assign({
      ipsText: $('#scanIps').value,
      portsText: $('#scanPorts').value,
      snisText: $('#scanSnis').disabled ? '' : $('#scanSnis').value,
      pick: { mode: pickMode, perRange: perRange(), fresh: $('#scanFresh').checked },
      engines: selectedEngines(),
      tests: selectedTests(),
      opts: buildOpts()
    }, formSource());
  }

  function beginRun(runId, init) {
    const startedAt = Date.now();
    run = { runId, startedAt };
    prog = Object.assign({ stage: 'filter', done: 0, total: 0, alive: 0, speedDone: 0, speedTotal: 0, etaMs: null }, init, { startedAt, endedAt: 0 });
    $('#btnScanStart').disabled = true;
    $('#btnScanStop').disabled = false;
    clearInterval(ticker);
    ticker = setInterval(paintStrip, 1000);
    paintStrip();
  }

  async function start() {
    if (run) return;
    const req = buildReq();
    setError('');
    const btn = $('#btnScanStart');
    btn.disabled = true;   // main may ask DNS for an ECH config first
    let res;
    try { res = await window.api.scanStart(req); }
    catch (e) { btn.disabled = false; setError((e && e.message) || String(e)); return; }
    btn.disabled = false;
    notes = notesOf(res);
    paintNotes();
    if (!res || res.error) { setError((res && res.error) || 'no server'); return; }
    lastReq = req;
    clearTable();
    beginRun(res.runId, { stage: 'filter', total: res.total || 0 });
    const bad = ((res.errors || []).length) + ((res.portErrors || []).length) + ((res.sniErrors || []).length);
    count = { kind: 'run', targets: res.targets || 0, engines: (res.engines || []).length || 1, truncated: !!res.truncated, bad, exhausted: res.exhausted || 0 };
    paintCount();
  }

  /** Phase 2 on rows the table already has; their TCP and delay samples ride along so the score keeps its latency half. */
  async function retest(list) {
    if (run) return;
    const rowsOut = (list || []).filter(r => r && (r.addr || r.ip) && r.engine)
      .map(r => ({ key: r.key, addr: r.addr || r.ip, port: r.port, sni: r.sni, engine: r.engine, tcp: r.tcp, delay: r.delay }));
    if (!rowsOut.length) { setError('no rows'); return; }
    const src = rowSource();
    if (!src.serverId && !src.link) { setError('no server'); return; }
    setError('');
    let res;
    try { res = await window.api.scanRetest(Object.assign({ rows: rowsOut, tests: { down: true, up: testOn('up') }, opts: buildOpts() }, src)); }
    catch (e) { setError((e && e.message) || String(e)); return; }
    if (!res || res.error) { setError((res && res.error) || 'no rows'); return; }
    const n = res.total || rowsOut.length;
    beginRun(res.runId, { stage: 'speed', total: n, done: n, alive: n, speedTotal: n });
    count = { kind: 'retest', n };
    paintCount();
  }

  function finish(ev) {
    flush();
    if (prog) {
      prog.endedAt = Date.now();
      if (ev.stage && STAGE_KEYS[ev.stage]) prog.stage = ev.stage;
    }
    clearInterval(ticker);
    ticker = null;
    run = null;
    paintStrip();
    $('#btnScanStart').disabled = false;
    $('#btnScanStop').disabled = true;
    if (ev.error) toast(t('scan.failed') + ': ' + errText(ev.error), 'err');
    else toast(ev.cancelled ? t('scan.stoppedToast') : t('scan.doneToast'), 'ok');
    window.api.scanPresets().then(p => paintTested(p && p.tested)).catch(() => {});
  }

  function onProgress(ev) {
    if (!ev || !run || ev.runId !== run.runId) return;
    if (prog) {
      prog.stage = STAGE_KEYS[ev.stage] ? ev.stage : prog.stage;
      prog.done = int0(ev.done);
      prog.total = int0(ev.total);
      prog.alive = int0(ev.alive);
      prog.speedDone = int0(ev.speedDone);
      prog.speedTotal = int0(ev.speedTotal);
      prog.etaMs = ev.etaMs;
    }
    if (ev.result) { queue.push(ev.result); schedule(); }
    if (ev.finished) finish(ev); else paintStrip();
  }

  /* ----------------------------- row and toolbar actions ----------------------------- */

  const targetOf = (r) => ({ addr: r.addr || r.ip, port: r.port, sni: r.sni });

  async function copyLinks(list) {
    const src = rowSource();
    if (!src.serverId && !src.link) return toast(t('scan.err.noServer'), 'err');
    let res;
    try { res = await window.api.scanLinks(Object.assign({ rows: list.map(targetOf) }, src)); }
    catch (e) { return toast((e && e.message) || String(e), 'err'); }
    const links = (res && res.links) || [];
    if (!links.length) return toast(t('scan.noRows'), 'err');
    await copyText(links.join('\n'));
    return toast(links.length === 1 ? t('scan.linkCopied') : fill(t('scan.linksCopied'), { n: links.length }), 'ok');
  }

  async function saveRow(r) {
    const src = rowSource();
    if (!src.serverId && !src.link) return toast(t('scan.err.noServer'), 'err');
    let res;
    try { res = await window.api.scanApply(Object.assign(targetOf(r), { engine: r.engine }, src)); }
    catch (e) { return toast((e && e.message) || String(e), 'err'); }
    if (!res || res.error) return toast(errText(res && res.error), 'err');
    if (Array.isArray(res.servers) && typeof setServers === 'function') setServers(res.servers);
    return toast(t('scan.applied'), 'ok');
  }

  /**
   * The best N live rows in the table's current order. For links each target
   * counts once, by its best core's row (a target scanned on two cores is one
   * link); a speed re-test takes every row, each core its own.
   */
  function topRows(perTarget = true) {
    const n = Math.max(1, Math.round(numOf('#scanTopN', 10)));
    const seen = new Set(), out = [];
    for (const k of order) {
      const r = rows.get(k).result;
      if (!((Number(r.score) || 0) > 0) || (perTarget && seen.has(r.key))) continue;
      seen.add(r.key);
      out.push(r);
      if (out.length >= n) break;
    }
    return out;
  }

  async function exportAs(format) {
    const results = order.map(k => rows.get(k).result);
    if (!results.length) return toast(t('scan.noRows'), 'err');
    let text;
    try { text = await window.api.scanExport({ format, results }); }
    catch (e) { return toast((e && e.message) || String(e), 'err'); }
    if (typeof text !== 'string') return toast(t('scan.failed'), 'err');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type: format === 'csv' ? 'text/csv' : 'application/json' }));
    a.download = 'irnetfree-plus-scan-' + new Date().toISOString().slice(0, 10) + '.' + format;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    return toast(t('scan.exported'), 'ok');
  }

  /* ----------------------------- wiring ----------------------------- */

  function wire() {
    $('#scanSourceSeg').onclick = (e) => { const b = e.target.closest('.seg-btn'); if (b) setMode(b.dataset.src); };
    let linkTimer = 0;
    $('#scanLink').oninput = () => { clearTimeout(linkTimer); linkTimer = setTimeout(refreshFacts, 400); };
    $('#scanPreset').onclick = (e) => {
      const b = e.target.closest('.seg-btn');
      const p = b && (presets.presets || {})[b.dataset.preset];
      if (p) fillLimits(p);
    };
    $$('.scan-limits input, #scanConc').forEach(el => { el.oninput = paintPreset; });

    $('#scanIps').oninput = updateCount;
    $('#scanPorts').oninput = updateCount;
    $('#scanSnis').oninput = updateCount;
    $('#scanPerRange').oninput = updateCount;
    $('#scanAddrPresets').onclick = (e) => { const b = e.target.closest('button[data-preset]'); if (b) applyAddrPreset(b.dataset.preset); };
    $$('button[data-ports]').forEach(b => { b.onclick = () => applyPortsPreset(b.dataset.ports); });
    $('#scanPickSeg').onclick = (e) => { const b = e.target.closest('.seg-btn'); if (b) setPick(b.dataset.pick); };
    $('#btnScanForget').onclick = async () => {
      let r;
      try { r = await window.api.scanForget(); } catch (e) { return toast((e && e.message) || String(e), 'err'); }
      paintTested(r && r.tested);
      return toast(t('scan.forgotToast'), 'ok');
    };
    $('#btnScanFile').onclick = () => $('#scanFile').click();
    $('#scanFile').onchange = async () => {
      const f = $('#scanFile').files[0];
      $('#scanFile').value = '';
      if (!f) return;
      try { $('#scanIps').value = await f.text(); } catch { toast(t('scan.fileErr'), 'err'); return; }
      updateCount();
    };

    $('#btnScanStart').onclick = start;
    $('#btnScanStop').onclick = () => { $('#btnScanStop').disabled = true; window.api.scanStop(); };

    $('#scanTable').onclick = (e) => {
      const th = e.target.closest('th[data-sort]');
      if (!th) return;
      const key = th.dataset.sort;
      if (sort.key === key) sort.dir = -sort.dir;
      else sort = { key, dir: (key === 'addr' || key === 'sni' || key === 'engine') ? 1 : -1 };
      resortAll();
    };

    tbody().onclick = (e) => {
      const tr = e.target.closest('tr[data-key]');
      if (!tr) return;
      const entry = rows.get(tr.dataset.key);
      if (!entry) return;
      const r = entry.result;
      const btn = e.target.closest('button[data-act]');
      if (!btn) {
        if (e.target.closest('.scan-c-ip')) { copyText(addrPort(r.addr || r.ip, r.port)); toast(t('scan.copied'), 'ok'); }
        return;
      }
      if (btn.dataset.act === 'link') copyLinks([r]);
      else if (btn.dataset.act === 'use') saveRow(r);
      else if (btn.dataset.act === 'retest') retest([r]);
    };

    $('#btnScanCopyTop').onclick = () => { const list = topRows(); if (!list.length) toast(t('scan.noRows'), 'err'); else copyLinks(list); };
    $('#btnScanRetop').onclick = () => { const list = topRows(false); if (!list.length) toast(t('scan.err.noRows'), 'err'); else retest(list); };
    $('#btnScanExportCsv').onclick = () => exportAs('csv');
    $('#btnScanExportJson').onclick = () => exportAs('json');
    $('#btnScanClear').onclick = () => { clearTable(); updateCount(); setError(''); notes = []; paintNotes(); };
  }

  /** The strip, the count, the facts and the row titles are written here, so a language switch redraws them. */
  function redrawText() {
    renderEngines(presets.engines || []);
    paintCount();
    paintStrip();
    paintSortMarks();
    paintFacts();
    paintNotes();
    for (const e of rows.values()) {
      e.tr.cells[0].title = t('scan.copy');
      e.tr.querySelectorAll('[data-i18n-title]').forEach(b => { b.title = t(b.dataset.i18nTitle); });
      if (!e.result.error && Number(e.result.phase) === 1) e.tr.title = t('scan.phase1');
    }
  }

  /** A core was downloaded or changed in Settings: the core list follows. */
  async function enginesChanged() {
    try { presets = Object.assign(presets, await window.api.scanPresets()); } catch { return; }
    renderEngines(presets.engines || []);
  }

  /**
   * Two things start this page: app.js's plusInit loop and the safety net at
   * the bottom. Whichever comes first does the setup; the other only rebuilds
   * the picker, because the loop is the one that knows state.servers is filled.
   */
  async function initScan() {
    if (started) return refreshSourcePicker();
    started = true;
    try { presets = Object.assign(presets, await window.api.scanPresets()); } catch (e) { console.error(e); }
    renderEngines(presets.engines || []);
    renderTests();
    fillLimits(presets.defaults || {});
    restore(presets.last);
    paintTested(presets.tested);
    refreshSourcePicker();
    wire();
    paintSortMarks();
    paintStrip();
    paintSniColumn();
    updateCount();
    window.api.onScanProgress(onProgress);
    new MutationObserver(redrawText).observe(document.documentElement, { attributes: true, attributeFilter: ['lang'] });
    return undefined;
  }

  window.plusScanRefresh = refreshSourcePicker;
  window.plusScanUse = useConfig;
  window.plusEnginesChanged = enginesChanged;
  window.plusInit = window.plusInit || [];
  window.plusInit.push(initScan);
  setTimeout(initScan, 0);
})();
