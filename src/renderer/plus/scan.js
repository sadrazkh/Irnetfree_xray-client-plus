'use strict';
/**
 * plus: the IP-scan tab (spec section 1 of v2.1). Shares app.js globals ($, t, state, toast, …).
 *
 * One config, a list of addresses, and a table that fills while the cores work.
 * The run has two phases and the strip above the table says which one is in
 * flight: *غربال* walks every address wide and cheap, *سرعت* re-visits only the
 * best ones one transfer at a time. A row therefore arrives twice — phase 1
 * without speeds, phase 2 with them — and the second one REPLACES the first,
 * which is why the table is a Map keyed by `ip|engine` and never an array.
 *
 * Everything measured comes from `scan-progress` events, one result at a time,
 * so a run of five thousand rows must not turn into five thousand layouts:
 * results are queued and applied once per animation frame, and the table is
 * kept sorted by inserting each row at its place instead of rebuilding the
 * body. Nothing here expands a CIDR or draws a sample — main owns the target
 * list, and in the *random* pick it draws a fresh set from the ranges on every
 * start (v2.2); the tab only counts what is typed so the line under the box
 * can say what a run will get.
 */
(function () {
  const XRAY_PROTOCOLS = ['vless', 'vmess', 'trojan', 'shadowsocks'];
  const TEST_IDS = ['tcp', 'delay', 'down', 'up'];
  const TEST_DEFAULTS = { tcp: true, delay: true, down: true, up: false };
  /** The table has no room for "Xray-PattN (patterniha)". */
  const ENGINE_SHORT = { xray: 'Xray', 'xray-pattn': 'PattN' };
  const PRESET_IDS = ['fast', 'balanced', 'accurate'];
  /** scan:start and scan:retest refuse with a bare code; anything else is shown as it came. */
  const START_ERRORS = {
    busy: 'scan.err.busy',
    'no server': 'scan.err.noServer',
    'server not found': 'scan.err.notFound',
    'unsupported protocol': 'scan.err.proto',
    'no targets': 'scan.err.noTargets',
    'no engine': 'scan.err.noEngine',
    'no tests': 'scan.err.noTests',
    'no rows': 'scan.err.noRows'
  };
  /**
   * The limits card, field by field: every one is exactly one key of the opts
   * object main sanitizes, so a preset can fill them and a run can read them
   * back with no mapping table anywhere else. `lo` is what an empty or silly
   * value falls back to — only speedTop may legitimately be 0 (skip phase 2).
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
  /** The stage of the run → the word on the pill. */
  const STAGE_KEYS = { idle: 'scan.stage.idle', filter: 'scan.stage.filter', speed: 'scan.stage.speed', done: 'scan.stage.done' };
  /** A path main built from downBytes itself; filling it in would freeze the MB field. */
  const AUTO_DOWN_PATH = /^\/__down\?bytes=\d+$/;
  /** main's cap on one run's targets — the estimate under the box stops there too. */
  const MAX_TARGETS = 5000;
  const PICK_DEFAULTS = { mode: 'all', perRange: 20, fresh: true };
  /** A queue this deep means the frames stopped coming (hidden window): drain it. */
  const QUEUE_BURST = 500;

  let started = false;           // initScan can be reached from two directions (see below)
  let presets = { cfRanges: [], defaults: {}, presets: {}, engines: [], last: null };
  let sourceSel = null;          // the makeSearchSelect element, when there is one
  let srcMode = 'server';        // 'server' | 'link'
  let pickMode = 'all';          // 'all' | 'random' — how main reads the box
  let tested = 0;                // addresses in main's tested history, for the line under the pick row
  let run = null;                // { runId, startedAt } while a scan is in flight
  let prog = null;               // the newest progress; it outlives the run so the strip keeps its numbers
  let lastReq = null;            // the request the rows came from — apply and re-test reuse its source
  let count = { kind: 'typed' }; // what #scanCount says, so a language switch can say it again
  let ticker = null;             // the one-second elapsed clock
  const rows = new Map();        // 'ip|engine' -> { result, tr }
  const order = [];              // the same keys, in the order the tbody shows them
  let sort = { key: 'score', dir: -1 };
  let best = 0;                  // the highest score in the table — what the bars are scaled to
  let queue = [];                // results waiting for the next frame
  let frame = 0;
  let late = 0;                  // the timer that flushes when frames stop coming
  let rowTpl = null;

  /* ----------------------------- small helpers ----------------------------- */

  const tbody = () => $('#scanTbody');
  const numOf = (sel, def, lo = 1) => { const n = Number($(sel).value); return Number.isFinite(n) && n >= lo ? n : def; };
  const setNumField = (sel, v, lo = 1) => { const n = Number(v); if (Number.isFinite(n) && n >= lo) $(sel).value = String(n); };
  const mbps = (v) => (Math.round((Number(v) || 0) * 10) / 10).toFixed(1);
  const int0 = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

  /** mm:ss — the elapsed clock at the end of the run row. */
  function clock(ms) {
    const s = Math.max(0, Math.floor(ms / 1000));
    return String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0');
  }

  /** A line with its comment cut off. */
  const uncomment = (raw) => { const h = raw.indexOf('#'); return (h === -1 ? raw : raw.slice(0, h)).trim(); };

  function ipInt(ip) {
    const p = String(ip).split('.');
    return ((((+p[0] || 0) * 256 + (+p[1] || 0)) * 256 + (+p[2] || 0)) * 256) + (+p[3] || 0);
  }
  const intIp = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');

  /** A known refusal reads as a sentence; anything else is the raw text. */
  const errText = (code) => (START_ERRORS[code] ? t(START_ERRORS[code]) : String(code || ''));

  function setError(code) {
    const el = $('#scanError');
    el.textContent = code ? errText(code) : '';
    el.hidden = !code;
  }

  /* ----------------------------- the form ----------------------------- */

  function setMode(mode) {
    srcMode = mode === 'link' ? 'link' : 'server';
    $$('#scanSourceSeg .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.src === srcMode));
    $('#scanSrcServer').hidden = srcMode !== 'server';
    $('#scanSrcLink').hidden = srcMode !== 'link';
  }

  function renderEngines(list) {
    const host = $('#scanEngines');
    host.innerHTML = '';
    for (const e of list) {
      const label = document.createElement('label');
      label.className = 'scan-check';
      if (!e.installed) label.classList.add('disabled');
      const box = document.createElement('input');
      box.type = 'checkbox';
      box.value = e.id;
      box.checked = !!e.installed;
      box.disabled = !e.installed;
      const text = document.createElement('span');
      text.className = 'scan-check-label';
      text.textContent = e.label || e.id;
      label.appendChild(box);
      label.appendChild(text);
      if (!e.installed) {
        // a core that is not on disk cannot be ticked; say why rather than
        // leaving a dead checkbox
        const why = document.createElement('span');
        why.className = 'scan-check-hint';
        why.dataset.i18n = 'scan.notInstalled';
        why.textContent = t('scan.notInstalled');
        label.appendChild(why);
      }
      host.appendChild(label);
    }
  }

  /** The names come from main, so a language switch only rewrites them in place — the ticks are the user’s. */
  function paintEngineLabels() {
    const list = presets.engines || [];
    $$('#scanEngines .scan-check').forEach((label, i) => {
      const text = label.querySelector('.scan-check-label');
      if (text && list[i]) text.textContent = list[i].label || list[i].id;
    });
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

  /* ----------------------------- presets and limits ----------------------------- */

  function fillLimits(o) {
    if (!o || typeof o !== 'object') return;
    for (const [sel, key, , lo] of NUM_FIELDS) setNumField(sel, o[key], lo);
    if (Number(o.downBytes) > 0) setNumField('#scanDownMb', Math.round(Number(o.downBytes) / 1e6));
    if (typeof o.downHost === 'string' && o.downHost) $('#scanDownHost').value = o.downHost;
    // only a path the user wrote is worth restoring: the generated one carries
    // its own byte count and would silently outrank the MB field
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

  /** No preset is ever "on" by itself: the mark follows the numbers in the fields. */
  function paintPreset() {
    const now = currentPreset();
    $$('#scanPreset .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.preset === now));
  }

  function applyPreset(name) {
    const p = (presets.presets || {})[name];
    if (!p) return;
    fillLimits(p);
  }

  /** Every field of the limits card, as the opts object main expects. */
  function buildOpts() {
    const o = {};
    for (const [sel, key, def, lo] of NUM_FIELDS) o[key] = Math.round(numOf(sel, def, lo));
    o.downBytes = Math.round(numOf('#scanDownMb', 10) * 1e6);
    o.downHost = $('#scanDownHost').value.trim();
    o.downPath = $('#scanDownPath').value.trim();
    return o;
  }

  /** The inputs of the last run, as main remembered them. */
  function restore(last) {
    if (!last) return;
    if (last.ipsText) $('#scanIps').value = last.ipsText;
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

  /**
   * The stored-config picker. Only the xray-format protocols can be dialled
   * through a substituted address, so the rest never appear. Exposed as
   * window.plusScanRefresh so a later change to the server list can rebuild it.
   */
  function refreshSourcePicker() {
    const mount = $('#scanSourceMount');
    const sel = $('#scanSource');
    if (!mount || !sel) return;
    const opts = (state.servers || [])
      .filter(s => XRAY_PROTOCOLS.includes(s.protocol))
      .map(s => ({ value: s.id, label: `${s.name} — ${s.address}:${s.port}` }));
    sel.innerHTML = opts
      .map(o => `<option value="${escapeHtml(o.value)}">${escapeHtml(o.label)}</option>`)
      .join('');
    mount.innerHTML = '';
    if (!opts.length) {
      sourceSel = null;
      sel.value = '';
      const note = document.createElement('p');
      note.className = 'hint warn';
      note.dataset.i18n = 'scan.noServers';
      note.textContent = t('scan.noServers');
      mount.appendChild(note);
      return;
    }
    const wanted = (sourceSel && sourceSel.getValue()) || sel.value ||
      (presets.last && presets.last.serverId) || '';
    const keep = opts.some(o => o.value === wanted) ? wanted : opts[0].value;
    sourceSel = makeSearchSelect({ options: opts, value: keep, onChange: (v) => { sel.value = v; } });
    mount.appendChild(sourceSel);
    sel.value = keep;
  }

  /* ----------------------------- the target box ----------------------------- */

  /** What the user typed, counted the way main splits it — items, not addresses. */
  function countTokens(text) {
    let n = 0;
    for (const raw of String(text || '').split(/\r?\n/)) {
      const line = uncomment(raw);
      if (line) n += line.split(/[\s,;]+/).filter(Boolean).length;
    }
    return n;
  }

  /**
   * One line, three things it can say: what is typed, what the run really got,
   * or how many rows went back for a speed test. It is rebuilt rather than
   * remembered as text so a language switch can say the same thing again.
   */
  function paintCount() {
    const el = $('#scanCount');
    if (count.kind === 'run') {
      const engines = Math.max(1, (count.engines || 1));
      const targets = Math.max(0, Math.round((count.total || 0) / engines));
      const parts = [t('scan.countTotal').replace('{n}', targets).replace('{e}', engines)];
      if (count.truncated) parts.push(t('scan.truncated').replace('{n}', targets));
      if (count.bad) parts.push(t('scan.badLines').replace('{n}', count.bad));
      if (count.exhausted) parts.push(t('scan.exhausted').replace('{n}', count.exhausted));
      el.textContent = parts.join(' · ');
      return;
    }
    if (count.kind === 'retest') { el.textContent = t('scan.retopCount').replace('{n}', count.n); return; }
    if (pickMode === 'random') {
      const est = drawEstimate($('#scanIps').value, perRange());
      el.textContent = t('scan.countRandom').replace('{r}', est.ranges).replace('{k}', perRange()).replace('{n}', est.perRun);
      return;
    }
    el.textContent = t('scan.count').replace('{n}', countTokens($('#scanIps').value));
  }

  function updateCount() {
    count = { kind: 'typed' };
    paintCount();
  }

  /** One token → an inclusive integer interval, or null. */
  function tokenRange(tok) {
    const cidr = /^([\d.]+)\/(\d{1,2})$/.exec(tok);
    if (cidr) {
      const base = ipInt(cidr[1]);
      const prefix = Number(cidr[2]);
      if (prefix < 8 || prefix > 32) return null;
      const size = 2 ** (32 - prefix);
      const start = base - (base % size);
      return { start, end: start + size - 1 };
    }
    const dash = tok.indexOf('-');
    if (dash !== -1) {
      const a = ipInt(tok.slice(0, dash)), b = ipInt(tok.slice(dash + 1));
      return b >= a ? { start: a, end: b } : null;
    }
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(tok)) return null;
    const n = ipInt(tok);
    return { start: n, end: n };
  }

  /**
   * What a random pick will draw: the ranges the box parses (the grammar main
   * uses) and min(k, size) from each, capped the way main caps a run. An
   * estimate for the line under the box — the draw itself happens in main.
   */
  function drawEstimate(text, k) {
    let ranges = 0, perRun = 0;
    for (const raw of String(text || '').split(/\r?\n/)) {
      for (const tok of uncomment(raw).split(/[\s,;]+/).filter(Boolean)) {
        const r = tokenRange(tok);
        if (!r) continue;
        ranges++;
        perRun += Math.min(k, r.end - r.start + 1);
      }
    }
    return { ranges, perRun: Math.min(perRun, MAX_TARGETS) };
  }
  const perRange = () => Math.round(numOf('#scanPerRange', PICK_DEFAULTS.perRange, 1));

  function setPick(mode) {
    pickMode = mode === 'random' ? 'random' : 'all';
    $$('#scanPickSeg .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.pick === pickMode));
    $('#scanPickOpts').hidden = pickMode !== 'random';
    updateCount();
  }

  /** The history count next to the pick row; nothing while it is empty. */
  function paintTested(n) {
    const el = $('#scanTested');
    tested = Math.max(0, Math.floor(Number(n) || 0));
    el.textContent = tested ? t('scan.tested').replace('{n}', tested) : '';
    el.hidden = !tested;
  }

  /* ----------------------------- the table ----------------------------- */

  /** The number a column sorts on, or null when the row has none. */
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

  /** A row with nothing to show in the sorted column goes last, either way. */
  function cmp(a, b) {
    const dir = sort.dir;
    const tie = ipInt(a.ip) - ipInt(b.ip);
    if (sort.key === 'ip') return dir * tie;
    if (sort.key === 'engine') {
      const e = a.engine < b.engine ? -1 : a.engine > b.engine ? 1 : 0;
      return dir * e || tie;
    }
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
      '<td class="scan-c-ip"></td>' +
      '<td class="scan-c-eng"></td>' +
      '<td class="scan-n"></td><td class="scan-n"></td><td class="scan-n"></td>' +
      '<td class="scan-n"></td><td class="scan-n"></td><td class="scan-n"></td>' +
      '<td class="scan-n scan-c-sp"></td><td class="scan-n scan-c-sp"></td>' +
      '<td class="scan-c-score"><span class="scan-score-wrap">' +
        '<span class="scan-score-bar"><span class="scan-score-fill"></span></span>' +
        '<span class="scan-score-val"></span>' +
      '</span></td>' +
      '<td class="scan-c-acts">' +
        '<button class="icon-btn" data-act="use" data-i18n-title="scan.use">✔</button>' +
        '<button class="icon-btn" data-act="copy" data-i18n-title="scan.copy">⧉</button>' +
        '<button class="icon-btn" data-act="retest" data-i18n-title="scan.retest">↻</button>' +
      '</td>';
    rowTpl = tr;
    return tr;
  }

  function newRow(key) {
    const tr = rowTemplate().cloneNode(true);
    tr.dataset.key = key;
    // the titles are set once here; applyI18n keeps them right after a language switch
    tr.querySelectorAll('[data-i18n-title]').forEach(b => b.title = t(b.dataset.i18nTitle));
    tr.cells[0].title = t('scan.copy');
    return tr;
  }

  const setCell = (cell, text, cls) => { cell.textContent = text; cell.className = 'scan-n' + (cls ? ' ' + cls : ''); };

  function paintScore(tr, r) {
    const s = Number(r.score) || 0;
    tr.querySelector('.scan-score-fill').style.inlineSize =
      (best > 0 ? Math.max(0, Math.min(100, (s / best) * 100)) : 0) + '%';
    tr.querySelector('.scan-score-val').textContent = s ? String(Math.round(s)) : '—';
  }

  function fillRow(tr, r) {
    const c = tr.cells;
    const p1 = Number(r.phase) === 1;
    c[0].textContent = r.ip;
    c[1].textContent = ENGINE_SHORT[r.engine] || r.engine;
    const d = r.delay && r.delay.loss < 1 ? r.delay : null;
    setCell(c[2], r.tcp ? (r.tcp.ok ? fmtMs(r.tcp.ms) : '×') : '—', r.tcp ? pingClass(r.tcp.ok ? r.tcp.ms : -1) : '');
    // the median is the headline figure of the delay group; the mean sits next to it
    setCell(c[3], r.delay ? (d ? fmtMs(d.median) : '×') : '—', r.delay ? pingClass(d ? d.median : -1) : '');
    setCell(c[4], r.delay ? (d ? fmtMs(d.avg) : '×') : '—', '');
    setCell(c[5], d ? fmtMs(d.min) : (r.delay ? '×' : '—'), '');
    setCell(c[6], d ? fmtMs(d.jitter) : (r.delay ? '×' : '—'), '');
    setCell(c[7], r.delay ? Math.round(r.delay.loss * 100) + '%' : '—', r.delay ? pingClass(r.delay.loss >= 1 ? -1 : r.delay.loss * 1000) : '');
    setCell(c[8], r.down ? (r.down.ok ? mbps(r.down.mbps) : '×') : '—', 'scan-c-sp');
    setCell(c[9], r.up ? (r.up.ok ? mbps(r.up.mbps) : '×') : '—', 'scan-c-sp');
    paintScore(tr, r);
    tr.classList.toggle('scan-row-dead', !(Number(r.score) > 0));
    // phase 1 is a provisional row: its speed cells are empty on purpose
    tr.classList.toggle('scan-row-p1', p1);
    if (r.error) tr.title = r.error;
    else if (p1) tr.title = t('scan.phase1');
    else tr.removeAttribute('title');
  }

  function detach(key) {
    const i = order.indexOf(key);
    if (i !== -1) order.splice(i, 1);
    const e = rows.get(key);
    if (e && e.tr.parentNode) e.tr.remove();
  }

  /** Binary search into an already-sorted body: one insert, no rebuild. */
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

  /**
   * One flush per frame keeps a five-thousand-row run to one layout per frame
   * instead of one per result. The timer beside it is not belt-and-braces: a
   * window that is minimised, or a browser tab in the background, stops
   * serving frames altogether, and the table would sit still for the whole run.
   */
  function schedule() {
    if (queue.length >= QUEUE_BURST) return flushNow();
    if (frame) return;
    frame = requestAnimationFrame(flushNow);
    late = setTimeout(flushNow, 250);
  }

  function flush() {
    if (!queue.length) return;
    const batch = queue;
    queue = [];
    let rescale = false;
    for (const r of batch) {
      const key = r.ip + '|' + r.engine;
      let entry = rows.get(key);
      // a phase-2 row replaces the phase-1 row of the same ip|engine
      if (!entry) { entry = { result: r, tr: newRow(key) }; rows.set(key, entry); }
      else { entry.result = r; detach(key); }
      if ((Number(r.score) || 0) > best) { best = Number(r.score) || 0; rescale = true; }
      fillRow(entry.tr, r);
      insertSorted(key, entry);
    }
    // a new best re-scales every bar; it happens a handful of times per run
    if (rescale) for (const e of rows.values()) paintScore(e.tr, e.result);
    $('#scanEmpty').hidden = rows.size > 0;
    paintStrip();
  }

  function paintSortMarks() {
    $$('#scanTable th[data-sort]').forEach(th => {
      const mark = th.querySelector('.scan-sort');
      th.classList.toggle('active', th.dataset.sort === sort.key);
      if (mark) mark.textContent = th.dataset.sort === sort.key ? (sort.dir < 0 ? '▾' : '▴') : '';
    });
  }

  /** A new sort column: the only time the whole body is rewritten. */
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
  }

  /* ----------------------------- the stage strip ----------------------------- */

  /** The track is the element with the id; the fill inside it is what moves. */
  function setBar(sel, done, total) {
    const fill = $(sel).firstElementChild;
    if (!fill) return;
    const pct = total > 0 ? Math.max(0, Math.min(100, (done / total) * 100)) : 0;
    fill.style.inlineSize = pct.toFixed(1) + '%';
  }

  /** Seconds while they are worth counting, minutes once they are not. */
  function etaText(ms) {
    const n = Number(ms);
    if (!Number.isFinite(n) || n <= 0) return '';
    const s = Math.round(n / 1000);
    return s >= 90 ? t('scan.etaMin').replace('{n}', Math.round(s / 60)) : t('scan.etaSec').replace('{n}', Math.max(1, s));
  }

  function paintStrip() {
    const p = prog || { stage: 'idle', done: 0, total: 0, alive: 0, speedDone: 0, speedTotal: 0, etaMs: null };
    const stage = STAGE_KEYS[p.stage] ? p.stage : 'idle';
    const pill = $('#scanStage');
    pill.dataset.stage = stage;
    // the pill is a JS-written label; the key rides along so applyI18n keeps it
    pill.dataset.i18n = STAGE_KEYS[stage];
    pill.textContent = t(STAGE_KEYS[stage]);
    $('#scanStageText').textContent = !prog ? ''
      : p.stage === 'speed'
        ? t('scan.stageSpeed').replace('{done}', p.speedDone).replace('{total}', p.speedTotal)
        : t('scan.stageFilter').replace('{done}', p.done).replace('{total}', p.total).replace('{alive}', p.alive);
    setBar('#scanBarFilter', p.done, p.total);
    setBar('#scanBarSpeed', p.speedDone, p.speedTotal);
    $('#scanEta').textContent = run ? etaText(p.etaMs) : '';
    $('#scanElapsed').textContent = prog ? clock((prog.endedAt || Date.now()) - prog.startedAt) : '';
  }

  /* ----------------------------- running ----------------------------- */

  /** The source of a request — one of the two keys, never both. */
  function srcOf(req) {
    if (req && req.serverId) return { serverId: req.serverId };
    if (req && req.link) return { link: req.link };
    return {};
  }

  function formSource() {
    if (srcMode === 'link') {
      const link = $('#scanLink').value.trim();
      return link ? { link } : {};
    }
    const id = $('#scanSource').value || '';
    return id ? { serverId: id } : {};
  }

  /** The rows came from one config; a re-test has to go through that same one. */
  function rowSource() {
    const src = srcOf(lastReq);
    return (src.serverId || src.link) ? src : formSource();
  }

  const selectedEngines = () => $$('#scanEngines input').filter(b => b.checked).map(b => b.value);

  function selectedTests() {
    const tests = {};
    for (const id of TEST_IDS) tests[id] = testOn(id);
    return tests;
  }

  function buildReq(over) {
    return Object.assign({
      ipsText: $('#scanIps').value,
      pick: { mode: pickMode, perRange: perRange(), fresh: $('#scanFresh').checked },
      engines: selectedEngines(),
      tests: selectedTests(),
      opts: buildOpts()
    }, formSource(), over || {});
  }

  /** A run is in flight: the buttons, the clock and the strip all follow from this. */
  function beginRun(runId, init) {
    const startedAt = Date.now();
    run = { runId, startedAt };
    prog = Object.assign({
      stage: 'filter', done: 0, total: 0, alive: 0, speedDone: 0, speedTotal: 0, etaMs: null
    }, init, { startedAt, endedAt: 0 });
    $('#btnScanStart').disabled = true;
    $('#btnScanStop').disabled = false;
    clearInterval(ticker);
    ticker = setInterval(paintStrip, 1000);
    paintStrip();
  }

  async function start(over) {
    if (run) return;
    const req = buildReq(over);
    setError('');
    let res;
    try { res = await window.api.scanStart(req); }
    catch (e) { return setError((e && e.message) || String(e)); }
    if (!res || res.error) return setError((res && res.error) || 'no server');
    lastReq = req;
    clearTable();
    beginRun(res.runId, { stage: 'filter', total: res.total || 0 });
    count = {
      kind: 'run', total: res.total || 0, engines: Math.max(1, (req.engines || []).length),
      truncated: !!res.truncated, bad: (res.errors && res.errors.length) || 0,
      exhausted: res.exhausted || 0
    };
    paintCount();
  }

  /**
   * Phase 2 on rows the table already has. The row carries its TCP and its
   * delay samples back to main so the re-measured row keeps the latency half
   * of its score instead of being ranked on throughput alone.
   */
  async function retest(list) {
    if (run) return;
    const rowsOut = (list || [])
      .filter(r => r && r.ip && r.engine)
      .map(r => ({ ip: r.ip, engine: r.engine, tcp: r.tcp, delay: r.delay }));
    if (!rowsOut.length) return setError('no rows');
    const src = rowSource();
    if (!src.serverId && !src.link) return setError('no server');
    setError('');
    let res;
    try { res = await window.api.scanRetest(Object.assign({ rows: rowsOut, tests: { down: true, up: testOn('up') }, opts: buildOpts() }, src)); }
    catch (e) { return setError((e && e.message) || String(e)); }
    if (!res || res.error) return setError((res && res.error) || 'no rows');
    const n = res.total || rowsOut.length;
    // these rows passed the filter once already, so that bar starts full
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
    // the run added what it tested to main's history
    window.api.scanPresets().then(p => paintTested(p && p.tested)).catch(() => {});
  }

  /** Events of a run that is no longer the current one are somebody else’s. */
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

  async function useIp(r) {
    const req = Object.assign(rowSource(), { ip: r.ip, engine: r.engine });
    if (!req.serverId && !req.link) return toast(t('scan.err.noServer'), 'err');
    let res;
    try { res = await window.api.scanApply(req); }
    catch (e) { return toast((e && e.message) || String(e), 'err'); }
    if (!res || res.error) return toast(errText(res && res.error), 'err');
    state.servers.push(res);
    renderServers();
    renderPicker();
    refreshSourcePicker();
    toast(t('scan.applied'), 'ok');
  }

  function copyIp(ip) {
    copyText(ip);
    toast(t('scan.copied'), 'ok');
  }

  /** The best N rows the filter left alive, each back through phase 2 alone. */
  function retestTop() {
    const n = Math.max(1, Math.round(numOf('#scanRetopN', 10)));
    const list = [...rows.values()]
      .map(e => e.result)
      .filter(r => (Number(r.score) || 0) > 0)
      .sort((a, b) => (b.score - a.score))
      .slice(0, n);
    if (!list.length) return toast(t('scan.err.noRows'), 'err');
    retest(list);
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
    a.download = 'irnetfree-scan-' + new Date().toISOString().slice(0, 10) + '.' + format;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    toast(t('scan.exported'), 'ok');
  }

  /* ----------------------------- wiring ----------------------------- */

  function wire() {
    $('#scanSourceSeg').onclick = (e) => {
      const btn = e.target.closest('.seg-btn');
      if (btn) setMode(btn.dataset.src);
    };
    $('#scanPreset').onclick = (e) => {
      const btn = e.target.closest('.seg-btn');
      if (btn) applyPreset(btn.dataset.preset);
    };
    // the mark says which preset the numbers ARE, so it has to follow the typing
    $$('.scan-limits input').forEach(el => { el.oninput = paintPreset; });
    $('#scanBatch').oninput = paintPreset;

    $('#scanIps').oninput = updateCount;
    $('#btnScanCf').onclick = () => { $('#scanIps').value = (presets.cfRanges || []).join('\n'); updateCount(); };
    $('#scanPickSeg').onclick = (e) => {
      const btn = e.target.closest('.seg-btn');
      if (btn) setPick(btn.dataset.pick);
    };
    $('#scanPerRange').oninput = updateCount;
    $('#btnScanForget').onclick = async () => {
      let r;
      try { r = await window.api.scanForget(); }
      catch (e) { return toast((e && e.message) || String(e), 'err'); }
      paintTested(r && r.tested);
      toast(t('scan.forgotToast'), 'ok');
    };
    $('#btnScanFile').onclick = () => $('#scanFile').click();
    $('#scanFile').onchange = async () => {
      const f = $('#scanFile').files[0];
      $('#scanFile').value = '';
      if (!f) return;
      try { $('#scanIps').value = await f.text(); }
      catch { return toast(t('scan.fileErr'), 'err'); }
      updateCount();
    };

    $('#btnScanStart').onclick = () => start(null);
    $('#btnScanStop').onclick = () => { $('#btnScanStop').disabled = true; window.api.scanStop(); };

    $('#scanTable').onclick = (e) => {
      const th = e.target.closest('th[data-sort]');
      if (!th) return;
      const key = th.dataset.sort;
      // a new column starts the way that column reads best: names up, numbers down
      if (sort.key === key) sort.dir = -sort.dir;
      else sort = { key, dir: (key === 'ip' || key === 'engine') ? 1 : -1 };
      resortAll();
    };

    tbody().onclick = (e) => {
      const tr = e.target.closest('tr[data-key]');
      if (!tr) return;
      const entry = rows.get(tr.dataset.key);
      if (!entry) return;
      const btn = e.target.closest('button[data-act]');
      if (!btn) {
        if (e.target.closest('.scan-c-ip')) copyIp(entry.result.ip);
        return;
      }
      if (btn.dataset.act === 'copy') copyIp(entry.result.ip);
      else if (btn.dataset.act === 'use') useIp(entry.result);
      else if (btn.dataset.act === 'retest') retest([entry.result]);
    };

    $('#btnScanRetop').onclick = retestTop;
    $('#btnScanExportCsv').onclick = () => exportAs('csv');
    $('#btnScanExportJson').onclick = () => exportAs('json');
    $('#btnScanClear').onclick = () => { clearTable(); updateCount(); setError(''); };
  }

  /**
   * applyI18n re-translates [data-i18n] nodes; the strip, the count line, the
   * engine names and the row titles are written by this file and are out of its
   * reach, so redraw them when the document’s language changes.
   */
  function redrawText() {
    paintEngineLabels();
    paintCount();
    paintStrip();
    paintSortMarks();
    for (const e of rows.values()) {
      e.tr.cells[0].title = t('scan.copy');
      if (!e.result.error && Number(e.result.phase) === 1) e.tr.title = t('scan.phase1');
    }
  }

  /**
   * Two things start this tab: app.js's plusInit loop, and the safety net at
   * the bottom of this file. Whichever gets here first does the whole setup;
   * the other only rebuilds the picker, because the loop is the one that knows
   * state.servers has been filled.
   */
  async function initScan() {
    if (started) return refreshSourcePicker();
    started = true;
    try { presets = Object.assign(presets, await window.api.scanPresets()); }
    catch (e) { console.error(e); }
    renderEngines(presets.engines || []);
    renderTests();
    // the balanced preset is what the tab opens on; the last run overrides it
    fillLimits(presets.defaults || {});
    restore(presets.last);
    paintTested(presets.tested);
    refreshSourcePicker();
    wire();
    paintSortMarks();
    paintStrip();
    updateCount();
    window.api.onScanProgress(onProgress);
    new MutationObserver(redrawText)
      .observe(document.documentElement, { attributes: true, attributeFilter: ['lang'] });
  }

  // nothing calls this yet; it is here so a change to the server list can
  // rebuild the picker without this file exporting anything else
  window.plusScanRefresh = refreshSourcePicker;

  window.plusInit = window.plusInit || [];
  window.plusInit.push(initScan);

  /*
   * And a net under it. app.js runs the plusInit loop the moment `app:init`
   * answers, and in the browser panel that answer regularly arrives BEFORE
   * this file has finished downloading — the loop then walks an array nobody
   * has pushed to and the tab comes up dead. Starting it here as well costs
   * one timer; initScan is idempotent, so when the loop does win the race it
   * only refreshes the picker with the server list it knows about.
   */
  setTimeout(initScan, 0);
})();
