'use strict';
/**
 * plus: the IP-scan tab — filled in by task R2. Shares app.js globals ($, t, state, toast, …).
 *
 * One config, a list of addresses, and a table that fills while the cores
 * work. Everything measured comes from `scan-progress` events, one result at a
 * time, so a run of five thousand rows must not turn into five thousand
 * layouts: results are queued and applied once per animation frame, and the
 * table is kept sorted by inserting each row at its place instead of rebuilding
 * the body. Nothing here expands a CIDR — main owns the target list; the
 * *sample* button is the one convenience that has to pick addresses itself
 * (there is no channel to ask for a sample) and it only writes text into the
 * box that main will expand anyway.
 */
(function () {
  const XRAY_PROTOCOLS = ['vless', 'vmess', 'trojan', 'shadowsocks'];
  const TEST_IDS = ['tcp', 'delay', 'down', 'up'];
  const TEST_DEFAULTS = { tcp: true, delay: true, down: true, up: false };
  /** The table has no room for "Xray-PattN (patterniha)". */
  const ENGINE_SHORT = { xray: 'Xray', 'xray-pattn': 'PattN' };
  /** scan:start refuses with a bare code; anything else is shown as it came. */
  const START_ERRORS = {
    busy: 'scan.err.busy',
    'no server': 'scan.err.noServer',
    'server not found': 'scan.err.notFound',
    'unsupported protocol': 'scan.err.proto',
    'no targets': 'scan.err.noTargets',
    'no engine': 'scan.err.noEngine',
    'no tests': 'scan.err.noTests'
  };
  const MAX_SAMPLE = 5000;
  /** A queue this deep means the frames stopped coming (hidden window): drain it. */
  const QUEUE_BURST = 500;

  let started = false;           // initScan can be reached from two directions (see below)
  let presets = { cfRanges: [], defaults: {}, engines: [], last: null };
  let sourceSel = null;          // the makeSearchSelect element, when there is one
  let srcMode = 'server';        // 'server' | 'link'
  let run = null;                // { runId, total, done, startedAt } while a scan is in flight
  let lastReq = null;            // the request the rows came from — apply and re-test reuse its source
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
  const numOf = (sel, def) => { const n = Number($(sel).value); return Number.isFinite(n) && n > 0 ? n : def; };
  const setNumField = (sel, v) => { if (Number.isFinite(Number(v)) && Number(v) > 0) $(sel).value = String(v); };
  const mbps = (v) => (Math.round((Number(v) || 0) * 10) / 10).toFixed(1);

  /** mm:ss — the elapsed clock next to the bar. */
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

  function fillLimits(d) {
    setNumField('#scanConc', d.concurrency);
    setNumField('#scanBatch', d.batch);
    setNumField('#scanSamples', d.delaySamples);
    setNumField('#scanDownMb', Math.round((Number(d.downBytes) || 10e6) / 1e6));
    if (d.downHost) $('#scanDownHost').value = d.downHost;
  }

  /** The inputs of the last run, as main remembered them. */
  function restore(last) {
    if (!last) return;
    if (last.ipsText) $('#scanIps').value = last.ipsText;
    if (Array.isArray(last.engines) && last.engines.length) {
      $$('#scanEngines input').forEach(b => { if (!b.disabled) b.checked = last.engines.includes(b.value); });
    }
    if (last.tests) for (const id of TEST_IDS) { const b = testBox(id); if (b) b.checked = !!last.tests[id]; }
    const o = last.opts || {};
    setNumField('#scanConc', o.concurrency);
    setNumField('#scanBatch', o.batch);
    setNumField('#scanSamples', o.delaySamples);
    setNumField('#scanDownMb', Math.round((Number(o.downBytes) || 0) / 1e6));
    if (o.downHost) $('#scanDownHost').value = o.downHost;
    if (o.downPath) $('#scanDownPath').value = o.downPath;
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

  function updateCount() {
    $('#scanCount').textContent = t('scan.count').replace('{n}', countTokens($('#scanIps').value));
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
   * A spread across every range in the box, not the first n of the first one —
   * a scan of 104.16.0.0/13 alone would otherwise only ever see one corner of
   * Cloudflare. Round-robin over the ranges, one random address each pass.
   */
  function sampleFrom(text, n) {
    const ranges = [];
    for (const raw of String(text || '').split(/\r?\n/)) {
      for (const tok of uncomment(raw).split(/[\s,;]+/).filter(Boolean)) {
        const r = tokenRange(tok);
        if (r) ranges.push(r);
      }
    }
    const out = new Set();
    if (!ranges.length) return [];
    let guard = n * 20;
    let i = 0;
    while (out.size < n && guard-- > 0) {
      const r = ranges[i++ % ranges.length];
      out.add(intIp(r.start + Math.floor(Math.random() * (r.end - r.start + 1))));
    }
    return [...out];
  }

  /* ----------------------------- the table ----------------------------- */

  /** The number a column sorts on, or null when the row has none. */
  function metric(r, key) {
    const d = r.delay && r.delay.loss < 1 ? r.delay : null;
    switch (key) {
      case 'tcp': return r.tcp && r.tcp.ok ? r.tcp.ms : null;
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
      '<td class="scan-n"></td><td class="scan-n"></td><td class="scan-n"></td><td class="scan-n"></td>' +
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
    c[0].textContent = r.ip;
    c[1].textContent = ENGINE_SHORT[r.engine] || r.engine;
    const d = r.delay && r.delay.loss < 1 ? r.delay : null;
    setCell(c[2], r.tcp ? (r.tcp.ok ? fmtMs(r.tcp.ms) : '×') : '—', r.tcp ? pingClass(r.tcp.ok ? r.tcp.ms : -1) : '');
    setCell(c[3], r.delay ? (d ? fmtMs(d.avg) : '×') : '—', r.delay ? pingClass(d ? d.avg : -1) : '');
    setCell(c[4], d ? fmtMs(d.min) : (r.delay ? '×' : '—'), '');
    setCell(c[5], d ? fmtMs(d.jitter) : (r.delay ? '×' : '—'), '');
    setCell(c[6], r.delay ? Math.round(r.delay.loss * 100) + '%' : '—', r.delay ? pingClass(r.delay.loss >= 1 ? -1 : r.delay.loss * 1000) : '');
    setCell(c[7], r.down ? (r.down.ok ? mbps(r.down.mbps) : '×') : '—', '');
    setCell(c[8], r.up ? (r.up.ok ? mbps(r.up.mbps) : '×') : '—', '');
    paintScore(tr, r);
    tr.classList.toggle('scan-row-dead', !(Number(r.score) > 0));
    if (r.error) tr.title = r.error; else tr.removeAttribute('title');
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
      if (!entry) { entry = { result: r, tr: newRow(key) }; rows.set(key, entry); }
      else { entry.result = r; detach(key); }
      if ((Number(r.score) || 0) > best) { best = Number(r.score) || 0; rescale = true; }
      fillRow(entry.tr, r);
      insertSorted(key, entry);
    }
    // a new best re-scales every bar; it happens a handful of times per run
    if (rescale) for (const e of rows.values()) paintScore(e.tr, e.result);
    $('#scanEmpty').hidden = rows.size > 0;
    paintProgress();
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

  /* ----------------------------- running ----------------------------- */

  function paintProgress() {
    if (!run) return;
    const pct = run.total ? Math.min(100, (run.done / run.total) * 100) : 0;
    $('#scanProgress').style.inlineSize = pct.toFixed(1) + '%';
    $('#scanProgressText').textContent = `${run.done} / ${run.total} · ${clock(Date.now() - run.startedAt)}`;
  }

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

  const selectedEngines = () => $$('#scanEngines input').filter(b => b.checked).map(b => b.value);

  function selectedTests() {
    const tests = {};
    for (const id of TEST_IDS) { const b = testBox(id); tests[id] = !!(b && b.checked); }
    return tests;
  }

  function buildReq(over) {
    return Object.assign({
      ipsText: $('#scanIps').value,
      engines: selectedEngines(),
      tests: selectedTests(),
      opts: {
        concurrency: Math.round(numOf('#scanConc', 8)),
        batch: Math.round(numOf('#scanBatch', 20)),
        delaySamples: Math.round(numOf('#scanSamples', 3)),
        downBytes: Math.round(numOf('#scanDownMb', 10) * 1e6),
        downHost: $('#scanDownHost').value.trim(),
        downPath: $('#scanDownPath').value.trim()
      }
    }, formSource(), over || {});
  }

  /** The real numbers, once main has expanded the ranges. */
  function showCount(req, res) {
    const engines = Math.max(1, (req.engines || []).length);
    const targets = Math.max(0, Math.round((res.total || 0) / engines));
    const parts = [t('scan.countTotal').replace('{n}', targets).replace('{e}', engines)];
    if (res.truncated) parts.push(t('scan.truncated').replace('{n}', targets));
    if (res.errors && res.errors.length) parts.push(t('scan.badLines').replace('{n}', res.errors.length));
    $('#scanCount').textContent = parts.join(' · ');
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
    run = { runId: res.runId, total: res.total || 0, done: 0, startedAt: Date.now() };
    $('#btnScanStart').disabled = true;
    $('#btnScanStop').disabled = false;
    clearInterval(ticker);
    ticker = setInterval(paintProgress, 1000);
    showCount(req, res);
    paintProgress();
  }

  function finish(ev) {
    flush();
    paintProgress();
    clearInterval(ticker);
    ticker = null;
    run = null;
    $('#btnScanStart').disabled = false;
    $('#btnScanStop').disabled = true;
    if (ev.error) toast(t('scan.failed') + ': ' + ev.error, 'err');
    else toast(ev.cancelled ? t('scan.stoppedToast') : t('scan.doneToast'), 'ok');
  }

  /** Events of a run that is no longer the current one are somebody else's. */
  function onProgress(ev) {
    if (!ev || !run || ev.runId !== run.runId) return;
    if (typeof ev.done === 'number') run.done = ev.done;
    if (ev.result) { queue.push(ev.result); schedule(); }
    if (ev.finished) finish(ev); else paintProgress();
  }

  /* ----------------------------- row and toolbar actions ----------------------------- */

  async function useIp(r) {
    const req = Object.assign(srcOf(lastReq), { ip: r.ip, engine: r.engine });
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

  /** The best N addresses, each once, re-run on every ticked core. */
  function retestTop() {
    const n = Math.round(numOf('#scanRetopN', 10));
    const ips = [];
    for (const e of [...rows.values()].sort((a, b) => (b.result.score - a.result.score))) {
      if (!ips.includes(e.result.ip)) ips.push(e.result.ip);
      if (ips.length >= n) break;
    }
    if (!ips.length) return toast(t('scan.noRows'), 'err');
    start(Object.assign(srcOf(lastReq), { ipsText: ips.join('\n') }));
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
    $('#scanIps').oninput = updateCount;
    $('#btnScanCf').onclick = () => { $('#scanIps').value = (presets.cfRanges || []).join('\n'); updateCount(); };
    $('#btnScanSample').onclick = () => {
      const n = Math.min(MAX_SAMPLE, Math.round(numOf('#scanSampleN', 100)));
      const picked = sampleFrom($('#scanIps').value, n);
      if (!picked.length) return setError('no targets');
      $('#scanIps').value = picked.join('\n');
      setError('');
      updateCount();
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
      else if (btn.dataset.act === 'retest') {
        start(Object.assign(srcOf(lastReq), { ipsText: entry.result.ip, engines: [entry.result.engine] }));
      }
    };

    $('#btnScanRetop').onclick = retestTop;
    $('#btnScanExportCsv').onclick = () => exportAs('csv');
    $('#btnScanExportJson').onclick = () => exportAs('json');
    $('#btnScanClear').onclick = () => { clearTable(); updateCount(); setError(''); };
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
    fillLimits(presets.defaults || {});
    restore(presets.last);
    refreshSourcePicker();
    wire();
    paintSortMarks();
    updateCount();
    window.api.onScanProgress(onProgress);
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
