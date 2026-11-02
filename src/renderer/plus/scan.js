'use strict';
/**
 * plus: the Scan page (spec 2026-10-15 §4; 2026-11-01 for the input rows, the
 * parameter matrix, the live summary and what a pass means). Shares app.js's
 * globals ($, $$, t, state, toast, escapeHtml, copyText, fmtMs, pingClass,
 * makeSearchSelect, setServers).
 *
 * One config and what to test. Every input is a ROW with a switch: the
 * addresses, the ports, the SNIs and — under «Parameters», folded — each
 * dimension of the config itself (variants.js: fingerprint, ALPN, ciphers,
 * fragment, finalMask, dialMode, mux, XHTTP's mode). On, a row's values
 * multiply the run; off, the config's own value is used as it is. The line at
 * the top says what the run will be, live ("3 of 65,792 addresses × 2 ports ×
 * 4 fingerprints = 300 tests (limit 300 → 300 sampled evenly)") — main's
 * answer to scan:plan, asked a moment after the last change; nothing here
 * expands an address list or builds a variant.
 *
 * The run has a pre-check and two phases and the strip says which is in
 * flight. A row arrives twice (the filter, then the speed test) and the second
 * REPLACES the first, which is why the table is a Map keyed by
 * `target#variant|engine`. Results come one at a time in `scan-progress`, so
 * a run of thousands of rows must not become thousands of layouts: they are
 * queued and applied once per animation frame, each inserted at its sorted
 * place; past TABLE_MAX the weakest rows leave the table (a run too big to
 * list sends only the rows that passed anyway, and says the rest by reason).
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
    'proxy-addr': 'scan.path.proxy-addr',
    'proxy-down': 'scan.path.proxy-down',
    'proxy-bad': 'scan.path.proxy-bad',
    'proxy-auth': 'scan.path.proxy-auth',
    'proxy-udp': 'scan.path.proxy-udp',
    'no engine': 'scan.err.noEngine',
    'core too old': 'scan.err.coreOld',
    'no tests': 'scan.err.noTests',
    'no rows': 'scan.err.noRows',
    sni: 'scan.err.sni',
    'singbox only': 'scan.err.singbox',
    'too many variants': 'scan.err.tooMany',
    'no variant runs': 'scan.err.noVariant'
  };
  /**
   * The number fields, each exactly one key of the opts object main
   * sanitizes, so a preset fills them and a run reads them back with no other
   * mapping. `lo` is the floor of a sane value; only speedTop may be 0.
   */
  const NUM_FIELDS = [
    ['#scanConc', 'filterConcurrency', 16, 1],
    ['#scanCores', 'coresInParallel', 2, 1],
    ['#scanSamples', 'delaySamples', 3, 1],
    ['#scanTcpTimeout', 'tcpTimeout', 2000, 500],
    ['#scanDelayTimeout', 'delayTimeout', 4000, 500],
    ['#scanSpeedTop', 'speedTop', 10, 0],
    ['#scanSpeedConc', 'speedConcurrency', 1, 1],
    ['#scanSpeedRounds', 'speedRounds', 1, 1],
    ['#scanBatch', 'batch', 20, 1],
    ['#scanPreConc', 'prefilterConcurrency', 128, 1]
  ];
  const STAGE_KEYS = { idle: 'scan.stage.idle', filter: 'scan.stage.filter', speed: 'scan.stage.speed', done: 'scan.stage.done' };
  /** A path main built from downBytes itself; filling it in would freeze the MB field. */
  const AUTO_DOWN_PATH = /^\/__down\?bytes=\d+$/;
  /** A queue this deep means the frames stopped coming (hidden window): drain it. */
  const QUEUE_BURST = 500;
  /** The rows the table holds; past it (and a fifth more) the weakest leave. */
  const TABLE_MAX = 3000;
  /** How long after the last change the summary asks main again. */
  const PLAN_MS = 300;
  const PRESET_NAMES = { cf: 'scan.p.cf', fastly: 'scan.p.fastly', cloudfront: 'scan.p.cloudfront', 'cloudfront-regional': 'scan.p.cloudfrontRegional', gcore: 'scan.p.gcore', 'warp-masque': 'scan.p.warpMasque', 'warp-wg': 'scan.p.warpWg' };
  /** The presets the update button refreshes, in the order of their buttons. */
  const CDN_IDS = ['cf', 'fastly', 'cloudfront', 'cloudfront-regional', 'gcore'];
  /** Each dimension's name, hint and plural (for the summary), as dictionary keys. */
  const DIM_KEYS = {
    fingerprint: ['scan.dim.fingerprint', 'scan.dim.fingerprint.hint', 'scan.dim.fingerprint.many'],
    alpn: ['scan.dim.alpn', 'scan.dim.alpn.hint', 'scan.dim.alpn.many'],
    cipherSuites: ['scan.dim.cipherSuites', 'scan.dim.cipherSuites.hint', 'scan.dim.cipherSuites.many'],
    fragment: ['scan.dim.fragment', 'scan.dim.fragment.hint', 'scan.dim.fragment.many'],
    finalMask: ['scan.dim.finalMask', 'scan.dim.finalMask.hint', 'scan.dim.finalMask.many'],
    dialMode: ['scan.dim.dialMode', 'scan.dim.dialMode.hint', 'scan.dim.dialMode.many'],
    mux: ['scan.dim.mux', 'scan.dim.mux.hint', 'scan.dim.mux.many'],
    xhttpMode: ['scan.dim.xhttpMode', 'scan.dim.xhttpMode.hint', 'scan.dim.xhttpMode.many']
  };
  /** Why a row failed, as dictionary keys (main's probes.REASONS). */
  const REASON_KEYS = {
    'no-tcp': 'scan.reason.no-tcp', tls: 'scan.reason.tls', core: 'scan.reason.core',
    'proxy-refused': 'scan.reason.proxy-refused', 'proxy-closed': 'scan.reason.proxy-closed', timeout: 'scan.reason.timeout',
    'wrong-answer': 'scan.reason.wrong-answer', unstable: 'scan.reason.unstable', 'download-failed': 'scan.reason.download-failed'
  };

  let started = false;           // initScan can be reached from two directions (see the bottom)
  let presets = { ranges: {}, defaults: {}, presets: {}, engines: [], last: null, tested: 0, dimensions: [], limits: {}, sets: [] };
  let facts = null;              // scan:suggest's answer for the chosen config
  let factsSeq = 0;              // the answer to the newest question wins
  let sourceSel = null;          // the makeSearchSelect element, when there is one
  let pendingPick = '';          // a config chosen elsewhere (Configs → «اسکن این»), applied at the next rebuild
  let srcMode = 'server';        // 'server' | 'link'
  let pickMode = 'all';          // 'all' | 'sample' | 'random' | 'block'
  let cdnFailed = [];            // the last update's failures: [{ name, error }]
  let pathState = null;          // the last answer about the way out: { via, state }, or 'checking'
  let pathSeq = 0;               // an older check's answer must not overwrite a newer one's
  let pathTimer = null;
  let run = null;                // { runId, startedAt } while a scan is in flight
  let prog = null;               // the newest progress; it outlives the run so the strip keeps its numbers
  let lastReq = null;            // the request the rows came from — links, saving and re-tests reuse its source
  let count = { kind: 'typed' }; // what #scanCount says, so a language switch can say it again
  let notes = [];                // what the last start said about ECH, the cores and the variants left out
  let ticker = null;
  let plan = null;               // scan:plan's newest answer
  let planSeq = 0;
  let planTimer = 0;
  const dimState = {};           // dimension id → { on, values: [raw text] }
  const variantByKey = new Map(); // the last run's variants: key → { label, raw, engines }
  let variantSkipped = [];       // the last run's variants that had no core, with the reason
  let variantStats = null;       // a run too big to list: key → [tested, passed], from main
  let reasons = {};              // the newest progress's failures by reason
  let capped = false;            // rows left the table for TABLE_MAX
  const rows = new Map();        // 'target#variant|engine' -> { result, tr }
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
  const fmtN = (v) => Number(v || 0).toLocaleString('en-US');
  const addrPort = (addr, port) => (port ? (String(addr).includes(':') ? `[${addr}]:${port}` : `${addr}:${port}`) : String(addr));
  const rowKey = (r) => `${r.key || r.addr || r.ip}|${r.engine}`;
  const reasonText = (r) => (r && REASON_KEYS[r] ? t(REASON_KEYS[r]) : String(r || ''));

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

  /** What main says this config allows, as a short list under the picker — and the rows' own values. */
  async function refreshFacts() {
    const seq = ++factsSeq;
    const src = formSource();
    if (!src.serverId && !src.link) { facts = null; paintFacts(); renderDims(); return schedulePlan(); }
    let r;
    try { r = await window.api.scanSuggest(src); } catch { r = null; }
    if (seq !== factsSeq) return undefined;
    facts = r && !r.error ? r : null;
    paintFacts();
    renderDims();
    return schedulePlan();
  }

  function paintFacts() {
    const list = $('#scanFacts');
    list.innerHTML = '';
    const sni = $('#scanSnis');
    paintOwn();
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
    $('#scanUseSnis').disabled = sni.disabled;
  }

  /** "this config: …" beside each target row. */
  function paintOwn() {
    const own = (sel, v) => { const el = $(sel); el.textContent = v ? fill(t('scan.own'), { v }) : ''; };
    own('#scanOwnAddrs', facts && facts.address);
    own('#scanOwnPorts', facts && facts.port ? String(facts.port) : '');
    own('#scanOwnSnis', facts && facts.sniName);
  }

  /* ----------------------------- the target rows ----------------------------- */

  /** A row's switch shows or hides its values; off, the config's own value stands. */
  function paintRows() {
    $('#scanAddrsBody').hidden = !$('#scanUseAddrs').checked;
    $('#scanPortsBody').hidden = !$('#scanUsePorts').checked;
    $('#scanSnisBody').hidden = !$('#scanUseSnis').checked;
    $('#scanRowAddrs').classList.toggle('off', !$('#scanUseAddrs').checked);
    $('#scanRowPorts').classList.toggle('off', !$('#scanUsePorts').checked);
    $('#scanRowSnis').classList.toggle('off', !$('#scanUseSnis').checked);
  }

  function setPick(mode) {
    pickMode = mode === 'random' || mode === 'sample' || mode === 'block' ? mode : 'all';
    $$('#scanPickSeg .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.pick === pickMode));
    $('#scanPickOpts').hidden = pickMode === 'all';
    $('#scanPickN').hidden = pickMode !== 'sample';
    $('#scanPerRange').hidden = pickMode !== 'random';
    $('#scanPerBlock').hidden = pickMode !== 'block';
    $('#scanBlockWrap').hidden = pickMode !== 'block';
    const label = $('#scanPickNLabel');
    label.htmlFor = pickMode === 'random' ? 'scanPerRange' : (pickMode === 'block' ? 'scanPerBlock' : 'scanPickN');
    label.dataset.i18n = pickMode === 'random' ? 'scan.perRange' : (pickMode === 'block' ? 'scan.perBlock' : 'scan.pickN');
    label.textContent = t(label.dataset.i18n);
    updateCount();
  }
  const perRange = () => Math.round(numOf('#scanPerRange', 20, 1));
  const pickCount = () => Math.round(numOf('#scanPickN', 1000, 1));
  const perBlock = () => Math.round(numOf('#scanPerBlock', 5, 1));

  /** The line under the box: what a run took, or main's count of what the box names. */
  function paintCount() {
    const el = $('#scanCount');
    if (count.kind === 'run') {
      const parts = [fill(t('scan.countTotal'), { n: fmtN(count.targets), e: count.engines })];
      if (count.addresses && count.addresses.total) parts.unshift(fill(t('scan.countOf'), { x: fmtN(count.addresses.taken), y: fmtN(count.addresses.total) }));
      if (count.bad) parts.push(fill(t('scan.badLines'), { n: count.bad }));
      if (count.exhausted) parts.push(fill(t('scan.exhausted'), { n: count.exhausted }));
      el.textContent = parts.join(' · ');
      return;
    }
    if (count.kind === 'retest') { el.textContent = fill(t('scan.retopCount'), { n: count.n }); return; }
    const a = plan && plan.addresses;
    if (!$('#scanUseAddrs').checked || !tokensOf($('#scanIps').value).length) { el.textContent = t('scan.p.none'); return; }
    if (!a) { el.textContent = ''; return; }
    el.textContent = a.taken === a.total ? fill(t('scan.countAll'), { x: fmtN(a.total) }) : fill(t('scan.countOf'), { x: fmtN(a.taken), y: fmtN(a.total) });
  }

  function updateCount() {
    count = { kind: 'typed' };
    paintCount();
    schedulePlan();
  }

  /** The history count next to the pick row; nothing while it is empty. */
  function paintTested(n) {
    const el = $('#scanTested');
    const v = Math.max(0, Math.floor(Number(n) || 0));
    el.textContent = v ? fill(t('scan.tested'), { n: fmtN(v) }) : '';
    el.hidden = !v;
  }

  /** An address preset: its ranges into the box; WARP WireGuard brings its ports too. */
  function applyAddrPreset(name) {
    const which = name === 'suggest' ? (facts && facts.preset) : name;
    const p = which && (presets.ranges || {})[which];
    if (!p || !Array.isArray(p.ranges)) return toast(t('scan.p.none'), 'warn');
    $('#scanUseAddrs').checked = true;
    $('#scanIps').value = p.ranges.join('\n');
    if (Array.isArray(p.ports) && p.ports.length) { $('#scanPorts').value = p.ports.join(', '); $('#scanUsePorts').checked = true; }
    paintRows();
    // a big list is meant to be sampled, not walked; a sampling pick already chosen stays
    if (pickMode === 'all' && (p.ranges.length > 1 || /\/(?:[0-9]|1[0-9]|2[0-3])$/.test(p.ranges[0] || ''))) setPick('random');
    updateCount();
    return undefined;
  }

  const proxyReq = () => ({ on: $('#scanProxyOn').checked, addr: $('#scanProxyAddr').value.trim() });

  /** The line under the path row: what the last check found. */
  function paintPath() {
    const el = $('#scanPathLine');
    $('#scanProxyAddr').hidden = !$('#scanProxyOn').checked;
    if (pathState === 'checking') { el.textContent = t('scan.path.checking'); el.className = 'scan-path-line'; return; }
    if (!pathState) { el.textContent = ''; el.className = 'scan-path-line'; return; }
    const key = pathState.state === 'clean' || pathState.state === 'lying' ? `scan.path.${pathState.state}.${pathState.via}` : `scan.path.${pathState.state}`;
    el.textContent = t(key);
    el.className = 'scan-path-line ' + (pathState.state === 'clean' ? 'ok' : 'warn');
  }

  /** Asks main whether the way out is honest; the newest question's answer is the one shown. */
  async function checkPathNow() {
    clearTimeout(pathTimer);
    const seq = ++pathSeq;
    pathState = 'checking';
    paintPath();
    let r;
    try { r = await window.api.scanPathCheck({ upstream: proxyReq() }); } catch { r = null; }
    if (seq !== pathSeq) return;
    pathState = r && r.state ? r : null;
    paintPath();
  }

  /** The line beside the update button: each list's size and date, then what the last update could not reach. */
  function paintCdnStatus() {
    const el = $('#scanCdnStatus');
    const date = (ms) => (ms ? new Date(ms).toLocaleDateString(document.documentElement.lang === 'fa' ? 'fa-IR' : 'en-GB', { year: 'numeric', month: 'short', day: 'numeric' }) : '');
    const rows = CDN_IDS.map((id) => ({ name: t(PRESET_NAMES[id]), list: (presets.ranges || {})[id] })).filter((r) => r.list && Array.isArray(r.list.ranges));
    const parts = rows.map((r) => fill(t('scan.cdn.line'), { name: r.name, n: fmtN(r.list.ranges.length), d: date(r.list.updatedAt) }));
    for (const f of cdnFailed) parts.push(fill(t('scan.cdn.fail'), { name: f.name, e: f.error }));
    el.textContent = parts.join(' · ');
  }

  /** Asks every CDN for its list; what comes back replaces the presets, what fails stays and is said. */
  async function updateCdnLists() {
    const btn = $('#btnScanCdnUpdate');
    btn.disabled = true;
    $('#scanCdnStatus').textContent = t('scan.cdn.updating');
    try {
      const r = await window.api.scanCdnUpdate({ upstream: proxyReq() });
      if (r.error) { setError(r.error); return; }
      Object.assign(presets.ranges, r.ranges);
      cdnFailed = r.results.filter((x) => !x.ok).map((x) => ({ name: x.name, error: x.error }));
      if (!cdnFailed.length) toast(t('scan.cdn.doneAll'), 'ok');
      else toast(fill(t('scan.cdn.someFailed'), { n: cdnFailed.length }), 'warn');
    } catch (e) {
      toast((e && e.message) || String(e), 'err');
    } finally {
      btn.disabled = false;
      paintCdnStatus();
    }
  }

  function applyPortsPreset(name) {
    const r = presets.ranges || {};
    const list = Array.isArray(r[name]) ? r[name] : (r[name] && Array.isArray(r[name].ports) ? r[name].ports : null);
    if (!list) return;
    $('#scanPorts').value = list.join(', ');
    $('#scanUsePorts').checked = true;
    paintRows();
    updateCount();
  }

  /* ----------------------------- the parameter rows ----------------------------- */

  /** Each dimension of the catalog with its state: off, the values it starts with. */
  function initDims() {
    for (const d of presets.dimensions || []) {
      if (!dimState[d.id]) dimState[d.id] = { on: false, values: d.start.slice() };
    }
  }

  /** The chip text of a value: a custom JSON or cipher list is shown short, in full on hover. */
  function chipText(dim, v) {
    const s = String(v);
    if (dim === 'finalMask' && s.startsWith('{')) return 'custom';
    if (dim === 'cipherSuites' && s.includes(':')) return 'custom';
    return s.length > 28 ? s.slice(0, 26) + '…' : s;
  }

  /** A value main could not read (scan:plan's variants.errors), to mark its chip. */
  function badValue(dim, v) {
    const errs = (plan && plan.variants && plan.variants.errors) || [];
    return errs.some((e) => e.dim === dim && String(v).startsWith(String(e.value).slice(0, 60)));
  }

  function chip(dim, v, { removable, selected, preset }) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'scan-chip' + (selected ? ' on' : '') + (preset ? ' preset' : '') + (badValue(dim, v) ? ' bad' : '');
    b.dataset.value = v;
    b.dataset.act = removable ? 'remove' : (selected ? 'toggle' : 'add');
    b.title = removable ? `${v} — ${t('scan.dim.remove')}` : String(v);
    const label = document.createElement('span');
    label.textContent = (preset && !selected ? '+ ' : '') + chipText(dim, v);
    b.appendChild(label);
    if (removable) {
      const x = document.createElement('span');
      x.className = 'scan-chip-x';
      x.textContent = '×';
      b.appendChild(x);
    }
    return b;
  }

  /** One row per dimension: its switch, name and hint, the config's own value, and its values as chips. */
  function renderDims() {
    const host = $('#scanDims');
    if (!host) return;
    initDims();
    host.innerHTML = '';
    const app = (facts && facts.variants) || {};
    for (const d of presets.dimensions || []) {
      const st = dimState[d.id];
      const keys = DIM_KEYS[d.id] || [d.id, '', d.id];
      const a = app[d.id];
      const na = !!(a && !a.ok);
      const row = document.createElement('div');
      row.className = 'scan-inrow scan-dim' + (st.on ? '' : ' off') + (na ? ' na' : '');
      row.dataset.dim = d.id;
      row.innerHTML =
        '<div class="scan-inrow-head">' +
          '<label class="switch"><input type="checkbox" data-dim-on /><span class="slider"></span></label>' +
          '<div class="scan-inrow-title"><span class="scan-inrow-name"></span><span class="scan-inrow-hint"></span></div>' +
          '<span class="scan-inrow-own"></span>' +
        '</div>' +
        '<div class="scan-inrow-body">' +
          '<p class="scan-inrow-why"></p>' +
          '<div class="scan-chips"></div>' +
        '</div>';
      const box = row.querySelector('input');
      box.checked = st.on;
      // a dimension this config does not take says why in its hint, and is not turned on (one already on can be turned off)
      box.disabled = na && !st.on;
      box.setAttribute('aria-label', t(keys[0]));
      row.querySelector('.scan-inrow-name').textContent = t(keys[0]);
      row.querySelector('.scan-inrow-hint').textContent = na ? fill(t('scan.dim.na'), { r: a.reason }) : t(keys[1]);
      row.querySelector('.scan-inrow-own').textContent = a && a.current && a.current !== 'none' && a.current !== 'off' ? fill(t('scan.own'), { v: chipText(d.id, a.current) }) : '';
      const why = row.querySelector('.scan-inrow-why');
      why.textContent = na && st.on ? fill(t('scan.dim.na'), { r: a.reason }) : '';
      why.hidden = !(na && st.on);
      const body = row.querySelector('.scan-inrow-body');
      body.hidden = !st.on;
      const chips = row.querySelector('.scan-chips');
      if (d.options) {
        for (const o of d.options) chips.appendChild(chip(d.id, o, { selected: st.values.includes(o) }));
      } else {
        for (const v of st.values) chips.appendChild(chip(d.id, v, { removable: true, selected: true }));
        const shown = new Set(st.values);
        for (const p of [d.none].concat(d.presets || []).filter(Boolean)) if (!shown.has(p)) chips.appendChild(chip(d.id, p, { preset: true }));
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'input scan-chip-input';
        input.dir = 'ltr';
        input.spellcheck = false;
        input.placeholder = t('scan.dim.customPh');
        input.dataset.custom = '1';
        chips.appendChild(input);
      }
      if (st.on && !st.values.length) {
        const empty = document.createElement('span');
        empty.className = 'scan-chips-empty';
        empty.textContent = t('scan.dim.empty');
        chips.appendChild(empty);
      }
      host.appendChild(row);
    }
    paintParamsCount();
  }

  function paintParamsCount() {
    const n = Object.values(dimState).filter((s) => s.on && s.values.length).length;
    $('#scanParamsCount').textContent = n ? fill(t('scan.paramsCount'), { n }) : '';
  }

  /** The dimensions as the request carries them: the ones on, with their values. */
  function buildSpec() {
    const dims = {};
    for (const [id, st] of Object.entries(dimState)) if (st.on && st.values.length) dims[id] = st.values.slice();
    return { dims, limit: Math.round(numOf('#scanLimit', presets.limits && presets.limits.variants || 300, 1)) };
  }

  /** A set's (or a remembered request's) dimensions onto the rows: those it names on, the rest off. */
  function applySpec(spec) {
    initDims();
    const dims = (spec && spec.dims) || {};
    for (const [id, st] of Object.entries(dimState)) {
      const vals = Array.isArray(dims[id]) ? dims[id].map(String) : null;
      st.on = !!(vals && vals.length);
      if (vals && vals.length) st.values = vals;
    }
    if (spec && Number(spec.limit) > 0) $('#scanLimit').value = String(Math.round(Number(spec.limit)));
    if (Object.values(dimState).some((s) => s.on)) $('#scanParams').open = true;
    renderDims();
  }

  function wireDims() {
    const host = $('#scanDims');
    host.addEventListener('change', (e) => {
      const box = e.target.closest('input[data-dim-on]');
      if (!box) return;
      const id = box.closest('[data-dim]').dataset.dim;
      dimState[id].on = box.checked;
      renderDims();
      schedulePlan();
    });
    host.addEventListener('click', (e) => {
      const b = e.target.closest('button.scan-chip');
      if (!b) return;
      const id = b.closest('[data-dim]').dataset.dim;
      const st = dimState[id];
      const v = b.dataset.value;
      if (b.dataset.act === 'remove' || (b.dataset.act === 'toggle' && st.values.includes(v))) st.values = st.values.filter((x) => x !== v);
      else if (!st.values.includes(v)) st.values.push(v);
      renderDims();
      schedulePlan();
    });
    host.addEventListener('keydown', (e) => {
      const input = e.target.closest('input[data-custom]');
      if (!input || e.key !== 'Enter') return;
      e.preventDefault();
      const id = input.closest('[data-dim]').dataset.dim;
      const v = input.value.trim();
      if (v && !dimState[id].values.includes(v)) dimState[id].values.push(v);
      renderDims();
      schedulePlan();
      const again = $(`#scanDims [data-dim="${id}"] input[data-custom]`);
      if (again) again.focus();
    });
  }

  /* ----------------------------- saved sets ----------------------------- */

  function renderSets(list) {
    presets.sets = Array.isArray(list) ? list : [];
    const sel = $('#scanSetPick');
    const keep = sel.value;
    sel.innerHTML = '';
    if (!presets.sets.length) {
      const o = document.createElement('option');
      o.value = '';
      o.textContent = t('scan.setNone');
      o.disabled = true;
      o.selected = true;
      sel.appendChild(o);
    }
    for (const s of presets.sets) {
      const o = document.createElement('option');
      o.value = s.name;
      o.textContent = s.name;
      sel.appendChild(o);
    }
    if (presets.sets.some((s) => s.name === keep)) sel.value = keep;
    $('#btnScanSetLoad').disabled = !presets.sets.length;
    $('#btnScanSetDelete').disabled = !presets.sets.length;
  }

  async function saveSet() {
    const name = $('#scanSetName').value.trim();
    if (!name) return toast(t('scan.setNoName'), 'warn');
    const set = buildSpec();
    if (!Object.keys(set.dims).length) return toast(t('scan.setEmpty'), 'warn');
    let r;
    try { r = await window.api.scanSets({ action: 'save', name, set }); } catch (e) { return toast((e && e.message) || String(e), 'err'); }
    if (!r || r.error) return toast(String((r && r.error) || 'error'), 'err');
    renderSets(r.sets);
    $('#scanSetPick').value = name;
    $('#scanSetName').value = '';
    return toast(t('scan.setSaved'), 'ok');
  }

  function loadSet() {
    const name = $('#scanSetPick').value;
    const s = (presets.sets || []).find((x) => x.name === name);
    if (!s) return;
    applySpec(s);
    schedulePlan();
    toast(t('scan.setLoaded'), 'ok');
  }

  async function deleteSet() {
    const name = $('#scanSetPick').value;
    if (!name) return undefined;
    let r;
    try { r = await window.api.scanSets({ action: 'delete', name }); } catch (e) { return toast((e && e.message) || String(e), 'err'); }
    renderSets((r && r.sets) || []);
    return toast(t('scan.setDeleted'), 'ok');
  }

  /* ----------------------------- the live summary ----------------------------- */

  function schedulePlan() {
    clearTimeout(planTimer);
    planTimer = setTimeout(refreshPlan, PLAN_MS);
  }

  async function refreshPlan() {
    const seq = ++planSeq;
    const req = buildReq();
    if (!req.serverId && !req.link) { plan = null; paintSummary(); paintCount(); return; }
    let p;
    try { p = await window.api.scanPlan(req); } catch (e) { p = { error: (e && e.message) || String(e) }; }
    if (seq !== planSeq) return;
    plan = p || null;
    paintSummary();
    paintCount();
    // a value main could not read is marked on its chip
    if (plan && plan.variants && plan.variants.errors && plan.variants.errors.length) renderDims();
  }

  /**
   * "3 of 65,792 addresses × 2 ports × 4 fingerprints = 300 tests (limit 300 →
   * 300 sampled evenly) · on 2 cores", as its pieces and the joints between
   * them. Each piece is laid out on its own (a <bdi>): in Persian a factor that
   * ends in a Latin name ("2 dialMode") next to "= 300" would otherwise be one
   * left-to-right run, and the numbers would trade places.
   */
  function summaryParts(p) {
    const a = p.addresses;
    const out = [!a ? t('scan.sum.own') : (a.taken === a.total ? fill(t('scan.sum.addrs'), { n: fmtN(a.taken) }) : fill(t('scan.sum.addrsOf'), { x: fmtN(a.taken), y: fmtN(a.total) }))];
    const add = (joint, text) => { out.push(joint, text); };
    if (p.ports > 1) add(' × ', fill(t('scan.sum.ports'), { n: p.ports }));
    if (p.snis > 1) add(' × ', fill(t('scan.sum.snis'), { n: p.snis }));
    const v = p.variants;
    if (v && v.count) for (const d of v.dims) add(' × ', fill(t('scan.sum.dim'), { n: d.n, name: t((DIM_KEYS[d.id] || [])[2] || d.id) }));
    add(' ', fill(t('scan.sum.tests'), { n: fmtN(p.tests) }));
    if (v && v.sampled) add(' ', fill(t('scan.sum.sampled'), { l: fmtN(v.limit), n: fmtN(v.tests) }));
    if (p.engines && p.engines.length) add(' · ', fill(t('scan.sum.cores'), { n: p.engines.length }));
    return out;
  }

  /**
   * The pieces into the line, each isolated in the page's own direction (not
   * `auto`: a piece that starts with a number was measured laid out left to
   * right in the Persian page); the joints between them as plain text.
   */
  function setSummaryText(el, parts) {
    el.textContent = '';
    const dir = document.documentElement.dir === 'rtl' ? 'rtl' : 'ltr';
    el.dir = dir;
    parts.forEach((s, i) => {
      if (i % 2) { el.appendChild(document.createTextNode(s)); return; }
      const b = document.createElement('bdi');
      b.dir = dir;
      b.textContent = s;
      el.appendChild(b);
    });
  }

  function paintSummary() {
    const text = $('#scanSummaryText'), note = $('#scanSummaryNote');
    const bar = $('#scanSummary');
    if (!plan) { text.textContent = formSource().serverId || formSource().link ? '…' : t('scan.sum.noConfig'); note.textContent = ''; bar.classList.remove('warn'); return; }
    if (plan.error && !plan.addresses && !plan.variants) {
      text.textContent = errText(plan.error);
      note.textContent = '';
      bar.classList.add('warn');
      return;
    }
    const v = plan.variants;
    const notesOut = [];
    if (plan.error === 'too many variants') notesOut.push(fill(t('scan.sum.tooMany'), { max: fmtN(plan.max), n: fmtN(v && v.total) }));
    else if (plan.error === 'no variant runs') notesOut.push(t('scan.sum.noVariant'));
    else if (plan.error) notesOut.push(errText(plan.error));
    if (v) {
      if (v.skippedDims && v.skippedDims.length) notesOut.push(fill(t('scan.sum.skippedDims'), { n: v.skippedDims.length }));
      const dropped = v.dropped ? (v.dropped.cipher || 0) + (v.dropped.dialFragment || 0) + (v.dropped.same || 0) : 0;
      if (dropped) notesOut.push(fill(t('scan.sum.dropped'), { n: dropped }));
      if (v.skipped && v.skipped.length) notesOut.push(fill(t('scan.sum.gated'), { n: v.skipped.length }));
      if (v.errors && v.errors.length) notesOut.push(fill(t('scan.sum.badValues'), { n: v.errors.length }));
    }
    if (plan.addresses && plan.addresses.errors) notesOut.push(fill(t('scan.badLines'), { n: plan.addresses.errors }));
    setSummaryText(text, summaryParts(plan));
    note.textContent = notesOut.join(' · ');
    bar.classList.toggle('warn', !!plan.error);
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
    if (typeof o.delayExpect === 'string') $('#scanDelayExpect').value = o.delayExpect;
    if (Number(o.passRatio) > 0) $('#scanPassRatio').value = String(Math.round(Number(o.passRatio) * 100));
    if (typeof o.prefilterTls === 'boolean') $('#scanPreTls').checked = o.prefilterTls;
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
    o.delayExpect = $('#scanDelayExpect').value.trim();
    o.passRatio = Math.min(100, Math.max(30, numOf('#scanPassRatio', 66, 30))) / 100;
    o.prefilterTls = $('#scanPreTls').checked;
    return o;
  }

  /** The inputs of the last run, as main remembered them. */
  function restore(last) {
    if (!last) return;
    if (last.ipsText) $('#scanIps').value = last.ipsText;
    $('#scanUseAddrs').checked = true;
    if (last.portsText) { $('#scanPorts').value = last.portsText; $('#scanUsePorts').checked = true; }
    if (last.snisText) { $('#scanSnis').value = last.snisText; $('#scanUseSnis').checked = true; }
    if (last.pick && typeof last.pick === 'object') {
      if (last.pick.perRange) $('#scanPerRange').value = last.pick.perRange;
      if (last.pick.count) $('#scanPickN').value = last.pick.count;
      if (last.pick.perBlock) $('#scanPerBlock').value = last.pick.perBlock;
      if (last.pick.block) $('#scanBlock').value = String(last.pick.block);
      $('#scanFresh').checked = last.pick.fresh !== false;
      setPick(last.pick.mode);
    }
    if (last.upstream && typeof last.upstream === 'object') {
      $('#scanProxyOn').checked = !!last.upstream.on;
      $('#scanProxyAddr').value = String(last.upstream.addr || '');
    }
    if (Array.isArray(last.engines) && last.engines.length) {
      $$('#scanEngines input').forEach(b => { if (!b.disabled) b.checked = last.engines.includes(b.value); });
    }
    if (last.tests) for (const id of TEST_IDS) { const b = testBox(id); if (b) b.checked = !!last.tests[id]; }
    fillLimits(last.opts);
    if (last.variants) applySpec(last.variants);
    if (last.link) { setMode('link'); $('#scanLink').value = last.link; }
    else if (last.serverId) setMode('server');
    paintRows();
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

  /** A row with nothing to show in the sorted column goes last, either way. The score ties on the median, then the jitter. */
  function cmp(a, b) {
    const dir = sort.dir;
    const tie = textCmp(String(a.key || a.addr || ''), String(b.key || b.addr || ''));
    if (sort.key === 'addr') return dir * tie;
    if (sort.key === 'sni') return dir * textCmp(String(a.sni || ''), String(b.sni || '')) || tie;
    if (sort.key === 'variant') return dir * textCmp(String(a.variantLabel || ''), String(b.variantLabel || '')) || tie;
    if (sort.key === 'engine') return dir * textCmp(a.engine, b.engine) || tie;
    const av = metric(a, sort.key), bv = metric(b, sort.key);
    if (av === null && bv === null) return tie;
    if (av === null) return 1;
    if (bv === null) return -1;
    if (sort.key === 'score' && Math.floor(av / 100) === Math.floor(bv / 100)) {
      const ma = metric(a, 'median'), mb = metric(b, 'median');
      if (ma !== null && mb !== null && ma !== mb) return ma - mb;
      const ja = metric(a, 'jitter'), jb = metric(b, 'jitter');
      if (ja !== null && jb !== null && ja !== jb) return ja - jb;
    }
    return dir * (av - bv) || tie;
  }

  function rowTemplate() {
    if (rowTpl) return rowTpl;
    const tr = document.createElement('tr');
    tr.className = 'scan-row';
    tr.innerHTML =
      '<td class="scan-c-ip" dir="ltr"></td>' +
      '<td class="scan-c-sni" dir="ltr"></td>' +
      '<td class="scan-c-var" dir="ltr"></td>' +
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
        '<button type="button" class="icon-btn" data-act="json" data-i18n-title="scan.json">{}</button>' +
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

  /** The bar is the score against the best; the figure is score / 100 (success %, then the speed) — or why the row failed. */
  function paintScore(tr, r) {
    const s = Number(r.score) || 0;
    tr.querySelector('.scan-score-fill').style.inlineSize = (best > 0 ? Math.max(0, Math.min(100, (s / best) * 100)) : 0) + '%';
    const val = tr.querySelector('.scan-score-val');
    val.textContent = s ? (s / 100).toFixed(2) : (r.reason ? reasonText(r.reason) : '—');
    val.classList.toggle('reason', !s && !!r.reason);
  }

  function fillRow(tr, r) {
    const c = tr.cells;
    const p1 = Number(r.phase) === 1;
    c[0].textContent = addrPort(r.addr || r.ip, r.port);
    c[1].textContent = r.sni || '';
    c[2].textContent = r.variantLabel || '';
    c[3].textContent = ENGINE_SHORT[r.engine] || r.engine;
    const d = r.delay && r.delay.loss < 1 ? r.delay : null;
    const tcp = r.tcp && !r.tcp.skipped ? r.tcp : null;
    setCell(c[4], tcp ? (tcp.ok ? fmtMs(tcp.ms) : '×') : '—', tcp ? pingClass(tcp.ok ? tcp.ms : -1) : '');
    setCell(c[5], r.delay ? (d ? fmtMs(d.median) : '×') : '—', r.delay ? pingClass(d ? d.median : -1) : '');
    setCell(c[6], r.delay ? (d ? fmtMs(d.avg) : '×') : '—', '');
    setCell(c[7], d ? fmtMs(d.min) : (r.delay ? '×' : '—'), '');
    setCell(c[8], d ? fmtMs(d.jitter) : (r.delay ? '×' : '—'), '');
    setCell(c[9], r.delay ? Math.round(r.delay.loss * 100) + '%' : '—', r.delay ? pingClass(r.delay.loss >= 1 ? -1 : r.delay.loss * 1000) : '');
    setCell(c[10], r.down ? (r.down.ok ? mbps(r.down.mbps) : '×') : '—', 'scan-c-sp');
    setCell(c[11], r.up ? (r.up.ok ? mbps(r.up.mbps) : '×') : '—', 'scan-c-sp');
    c[1].className = 'scan-c-sni';
    c[2].className = 'scan-c-var';
    paintScore(tr, r);
    tr.classList.toggle('scan-row-dead', !(Number(r.score) > 0));
    tr.classList.toggle('scan-row-p1', p1);
    if (r.error) tr.title = r.error;
    else if (!(Number(r.score) > 0) && r.reason) tr.title = reasonText(r.reason) + (r.delay && r.delay.status ? ' (HTTP ' + r.delay.status + ')' : '');
    else if (p1) tr.title = t('scan.phase1');
    else tr.removeAttribute('title');
  }

  /** The SNI and the parameters columns show only when a row carries one. */
  function paintColumns() {
    const all = [...rows.values()];
    $('#scanTable').classList.toggle('scan-no-sni', !all.some(e => !!e.result.sni));
    $('#scanTable').classList.toggle('scan-no-var', !all.some(e => !!e.result.variant));
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

  /** Past TABLE_MAX (and a fifth more) the weakest rows leave the table, by score. */
  function capTable() {
    if (rows.size <= TABLE_MAX * 1.2) return;
    const weakest = [...rows.entries()].sort((a, b) => (Number(a[1].result.score) || 0) - (Number(b[1].result.score) || 0)).slice(0, rows.size - TABLE_MAX);
    for (const [key] of weakest) { detach(key); rows.delete(key); }
    capped = true;
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
    capTable();
    if (rescale) for (const e of rows.values()) paintScore(e.tr, e.result);
    $('#scanEmpty').hidden = rows.size > 0;
    paintColumns();
    paintStrip();
    paintVarSummary();
    paintFails();
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
    capped = false;
    reasons = {};
    variantStats = null;
    tbody().innerHTML = '';
    $('#scanEmpty').hidden = false;
    paintColumns();
    paintVarSummary();
    paintFails();
  }

  /* ----------------------------- per variant ----------------------------- */

  const median = (xs) => { if (!xs.length) return null; const s = xs.slice().sort((a, b) => a - b); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };

  /**
   * One line per variant across every address: how many of its rows passed,
   * the median of their median delays, its best row — best first (the rate,
   * then the delay); the variants that had no core last, with the reason.
   */
  function paintVarSummary() {
    const box = $('#scanVarSum');
    if (!variantByKey.size && !variantSkipped.length) { box.hidden = true; return; }
    const agg = new Map();
    for (const [key, v] of variantByKey) agg.set(key, { key, label: v.label, tested: 0, ok: 0, medians: [], best: null });
    for (const e of rows.values()) {
      const r = e.result;
      if (!r.variant) continue;
      if (!agg.has(r.variant)) agg.set(r.variant, { key: r.variant, label: r.variantLabel || r.variant, tested: 0, ok: 0, medians: [], best: null });
      const a = agg.get(r.variant);
      a.tested++;
      if (Number(r.score) > 0) {
        a.ok++;
        if (r.delay && r.delay.loss < 1) a.medians.push(Number(r.delay.median) || 0);
        if (!a.best || r.score > a.best.score) a.best = r;
      }
    }
    if (variantStats) for (const [key, s] of Object.entries(variantStats)) if (agg.has(key)) { agg.get(key).tested = s[0]; agg.get(key).ok = s[1]; }
    const list = [...agg.values()].map((a) => Object.assign(a, { rate: a.tested ? a.ok / a.tested : 0, med: median(a.medians) }))
      .sort((x, y) => (y.rate - x.rate) || ((x.med == null ? Infinity : x.med) - (y.med == null ? Infinity : y.med)));
    const host = $('#scanVarTbody');
    host.innerHTML = '';
    for (const a of list) {
      const tr = document.createElement('tr');
      tr.className = 'scan-row' + (a.ok ? '' : ' scan-row-dead');
      tr.dataset.variant = a.key;
      tr.innerHTML = '<td class="scan-c-var" dir="ltr"></td><td class="scan-n"></td><td class="scan-n"></td><td class="scan-n"></td><td class="scan-c-ip" dir="ltr"></td><td class="scan-c-acts"></td>';
      tr.cells[0].textContent = a.label;
      tr.cells[1].textContent = `${fmtN(a.ok)} / ${fmtN(a.tested)}`;
      tr.cells[2].textContent = a.tested ? Math.round(a.rate * 100) + '%' : '—';
      tr.cells[3].textContent = a.med == null ? '—' : fmtMs(a.med);
      tr.cells[4].textContent = a.best ? addrPort(a.best.addr, a.best.port) + (a.best.engine ? ' · ' + (ENGINE_SHORT[a.best.engine] || a.best.engine) : '') : '—';
      if (a.best) {
        tr.dataset.row = rowKey(a.best);
        for (const [act, label, key] of [['link', '⧉', 'scan.link'], ['json', '{}', 'scan.json']]) {
          const b = document.createElement('button');
          b.type = 'button';
          b.className = 'icon-btn';
          b.dataset.act = act;
          b.textContent = label;
          b.title = t(key);
          tr.cells[5].appendChild(b);
        }
      }
      host.appendChild(tr);
    }
    for (const s of variantSkipped) {
      const tr = document.createElement('tr');
      tr.className = 'scan-row scan-row-dead';
      tr.innerHTML = '<td class="scan-c-var" dir="ltr"></td><td class="scan-vskip" colspan="5"></td>';
      tr.cells[0].textContent = s.label;
      tr.cells[1].textContent = fill(t('scan.vskipped'), { r: s.reason });
      host.appendChild(tr);
    }
    box.hidden = false;
  }

  /** The failures by reason ("312 failed — no TCP 300 · timeout 12"), and the table's cap when it bit. */
  function paintFails() {
    const el = $('#scanFails');
    const entries = Object.entries(reasons || {}).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]);
    const total = entries.reduce((s, [, n]) => s + n, 0);
    const parts = [];
    if (total) parts.push(fill(t('scan.fails'), { n: fmtN(total), list: entries.map(([r, n]) => `${reasonText(r)} ${fmtN(n)}`).join(' · ') }));
    if (capped) parts.push(fill(t('scan.tableCap'), { n: fmtN(TABLE_MAX) }));
    el.textContent = parts.join(' — ');
    el.hidden = !parts.length;
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
        ? fill(t('scan.stageSpeed'), { done: fmtN(p.speedDone), total: fmtN(p.speedTotal) })
        : fill(t('scan.stageFilter'), { done: fmtN(p.done), total: fmtN(p.total), alive: fmtN(p.alive) });
    setBar('#scanBarFilter', p.done, p.total);
    setBar('#scanBarSpeed', p.speedDone, p.speedTotal);
    $('#scanEta').textContent = run ? etaText(p.etaMs) : '';
    $('#scanElapsed').textContent = prog ? clock((prog.endedAt || Date.now()) - prog.startedAt) : '';
  }

  /** What the last start said about ECH, the cores and the parameters left out. */
  function paintNotes() {
    const list = $('#scanNotes');
    list.innerHTML = '';
    for (const n of notes) {
      const li = document.createElement('li');
      if (n.kind === 'ech') li.textContent = fill(t('scan.note.ech'), { via: n.via || '—', name: n.publicName || '—' });
      else if (n.kind === 'echFail') li.textContent = fill(t('scan.note.echFail'), { error: n.error || '—' });
      else if (n.kind === 'variant') li.textContent = fill(t('scan.note.variant'), { label: n.label, reason: n.reason || '' });
      else if (n.kind === 'path') li.textContent = t(`scan.path.lying.${n.via}`);
      else if (n.kind === 'proxyTricks') li.textContent = t('scan.path.tricks');
      else if (n.kind === 'dim') li.textContent = fill(t('scan.note.dim'), { dim: t((DIM_KEYS[n.dim] || [n.dim])[0]), reason: n.reason || '' });
      else li.textContent = fill(t('scan.note.skipped'), { engine: ENGINE_SHORT[n.engine] || n.engine, reason: n.reason || '' });
      if (n.kind !== 'ech') li.className = 'warn';
      list.appendChild(li);
    }
    list.hidden = !notes.length;
  }

  function notesOf(res) {
    const out = [];
    if (res && res.path && res.path.state === 'lying') out.push({ kind: 'path', via: res.path.via });
    if (res && res.proxyTricks) out.push({ kind: 'proxyTricks' });
    if (res && res.ech) out.push(res.ech.ok ? Object.assign({ kind: 'ech' }, res.ech) : Object.assign({ kind: 'echFail' }, res.ech));
    for (const s of (res && res.skipped) || []) out.push(Object.assign({ kind: 'skipped' }, s));
    const v = res && res.variants;
    if (v) {
      for (const d of v.skippedDims || []) out.push({ kind: 'dim', dim: d.dim, reason: d.reason });
      for (const s of v.skipped || []) out.push({ kind: 'variant', label: s.label, reason: s.reason });
    }
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
      ipsText: $('#scanUseAddrs').checked ? $('#scanIps').value : '',
      portsText: $('#scanUsePorts').checked ? $('#scanPorts').value : '',
      snisText: $('#scanUseSnis').checked && !$('#scanSnis').disabled ? $('#scanSnis').value : '',
      pick: { mode: pickMode, perRange: perRange(), count: pickCount(), perBlock: perBlock(), block: Number($('#scanBlock').value), fresh: $('#scanFresh').checked },
      engines: selectedEngines(),
      tests: selectedTests(),
      opts: buildOpts(),
      variants: buildSpec(),
      upstream: proxyReq()
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
    if (res && res.path) { pathSeq++; pathState = res.path; paintPath(); }
    if (!res || res.error) { setError((res && res.error) || 'no server'); return; }
    lastReq = req;
    variantByKey.clear();
    for (const v of (res.variants && res.variants.list) || []) variantByKey.set(v.key, { label: v.label, raw: v.raw, engines: v.engines });
    variantSkipped = ((res.variants && res.variants.skipped) || []).slice();
    clearTable();
    beginRun(res.runId, { stage: 'filter', total: res.total || 0 });
    const bad = ((res.errors || []).length) + ((res.portErrors || []).length) + ((res.sniErrors || []).length);
    count = { kind: 'run', targets: res.tests || res.targets || 0, engines: (res.engines || []).length || 1, bad, exhausted: res.exhausted || 0, addresses: res.addresses };
    paintCount();
  }

  /** A row's variant as main reads it back: the values the run sent for it. */
  const variantRaw = (r) => (r && r.variant && variantByKey.has(r.variant) ? variantByKey.get(r.variant).raw : undefined);

  /** Phase 2 on rows the table already has; their TCP and delay samples ride along so the score keeps its latency half. */
  async function retest(list) {
    if (run) return;
    const rowsOut = (list || []).filter(r => r && (r.addr || r.ip) && r.engine)
      .map(r => ({ key: r.key, addr: r.addr || r.ip, port: r.port, sni: r.sni, engine: r.engine, tcp: r.tcp, delay: r.delay, variant: variantRaw(r) }));
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
    paintVarSummary();
    paintFails();
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
    if (ev.reasons && typeof ev.reasons === 'object') reasons = ev.reasons;
    if (ev.variantStats && typeof ev.variantStats === 'object') variantStats = ev.variantStats;
    if (ev.result) { queue.push(ev.result); schedule(); }
    if (ev.finished) finish(ev);
    else { paintStrip(); if (!ev.result) { paintFails(); paintVarSummary(); } }
  }

  /* ----------------------------- row and toolbar actions ----------------------------- */

  const targetOf = (r) => ({ addr: r.addr || r.ip, port: r.port, sni: r.sni, variant: variantRaw(r) });

  async function copyLinks(list) {
    const src = rowSource();
    if (!src.serverId && !src.link) return toast(t('scan.err.noServer'), 'err');
    let res;
    try { res = await window.api.scanLinks(Object.assign({ rows: list.map(targetOf) }, src)); }
    catch (e) { return toast((e && e.message) || String(e), 'err'); }
    const links = (res && res.links) || [];
    const lossy = (res && res.lossy) || 0;
    if (!links.length) return toast(lossy ? fill(t('scan.linksLossy'), { n: lossy }) : t('scan.noRows'), 'err');
    await copyText(links.join('\n'));
    const msg = links.length === 1 ? t('scan.linkCopied') : fill(t('scan.linksCopied'), { n: links.length });
    return toast(lossy ? msg + ' — ' + fill(t('scan.linksLossy'), { n: lossy }) : msg, lossy ? 'warn' : 'ok');
  }

  /** One row as a share link (or as JSON, when a link cannot carry its variant) or as JSON. */
  async function copyRow(r, kind) {
    const src = rowSource();
    if (!src.serverId && !src.link) return toast(t('scan.err.noServer'), 'err');
    let res;
    try { res = await window.api.scanCopy(Object.assign(targetOf(r), { engine: r.engine }, src)); }
    catch (e) { return toast((e && e.message) || String(e), 'err'); }
    if (!res || res.error) return toast(errText(res && res.error), 'err');
    if (kind === 'link' && res.link) { await copyText(res.link); return toast(t('scan.linkCopied'), 'ok'); }
    if (!res.json) return toast(t('scan.failed'), 'err');
    await copyText(res.json);
    return toast(kind === 'link' ? t('scan.linkLossy') : t('scan.jsonCopied'), kind === 'link' ? 'warn' : 'ok');
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
   * (and variant) counts once, by its best core's row; a speed re-test takes
   * every row, each core its own.
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

    for (const id of ['#scanUseAddrs', '#scanUsePorts', '#scanUseSnis']) $(id).onchange = () => { paintRows(); updateCount(); };
    $('#scanIps').oninput = updateCount;
    $('#scanPorts').oninput = updateCount;
    $('#scanSnis').oninput = updateCount;
    $('#scanPerRange').oninput = updateCount;
    $('#scanPickN').oninput = updateCount;
    $('#scanPerBlock').oninput = updateCount;
    $('#scanBlock').onchange = updateCount;
    $('#btnScanCdnUpdate').onclick = updateCdnLists;
    $('#btnScanPathCheck').onclick = checkPathNow;
    $('#scanProxyOn').onchange = () => { paintPath(); checkPathNow(); };
    $('#scanProxyAddr').oninput = () => { clearTimeout(pathTimer); pathTimer = setTimeout(checkPathNow, 700); };
    $('#scanLimit').oninput = schedulePlan;
    $('#scanEngines').addEventListener('change', schedulePlan);
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
      $('#scanUseAddrs').checked = true;
      paintRows();
      updateCount();
    };
    wireDims();
    $('#btnScanSetSave').onclick = saveSet;
    $('#btnScanSetLoad').onclick = loadSet;
    $('#btnScanSetDelete').onclick = deleteSet;
    $('#scanSetName').onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); saveSet(); } };

    $('#btnScanStart').onclick = start;
    $('#btnScanStop').onclick = () => { $('#btnScanStop').disabled = true; window.api.scanStop(); };

    $('#scanTable').onclick = (e) => {
      const th = e.target.closest('th[data-sort]');
      if (!th) return;
      const key = th.dataset.sort;
      if (sort.key === key) sort.dir = -sort.dir;
      else sort = { key, dir: (key === 'addr' || key === 'sni' || key === 'engine' || key === 'variant') ? 1 : -1 };
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
      if (btn.dataset.act === 'link') copyRow(r, 'link');
      else if (btn.dataset.act === 'json') copyRow(r, 'json');
      else if (btn.dataset.act === 'use') saveRow(r);
      else if (btn.dataset.act === 'retest') retest([r]);
    };
    $('#scanVarTbody').onclick = (e) => {
      const btn = e.target.closest('button[data-act]');
      const tr = e.target.closest('tr[data-row]');
      const entry = tr && rows.get(tr.dataset.row);
      if (btn && entry) copyRow(entry.result, btn.dataset.act);
    };

    $('#btnScanCopyTop').onclick = () => { const list = topRows(); if (!list.length) toast(t('scan.noRows'), 'err'); else copyLinks(list); };
    $('#btnScanRetop').onclick = () => { const list = topRows(false); if (!list.length) toast(t('scan.err.noRows'), 'err'); else retest(list); };
    $('#btnScanExportCsv').onclick = () => exportAs('csv');
    $('#btnScanExportJson').onclick = () => exportAs('json');
    $('#btnScanClear').onclick = () => { clearTable(); variantByKey.clear(); variantSkipped = []; paintVarSummary(); updateCount(); setError(''); notes = []; paintNotes(); };
  }

  /** The strip, the count, the facts, the rows and the row titles are written here, so a language switch redraws them. */
  function redrawText() {
    renderEngines(presets.engines || []);
    paintCount();
    paintCdnStatus();
    paintPath();
    paintStrip();
    paintSortMarks();
    paintFacts();
    paintNotes();
    renderDims();
    renderSets(presets.sets);
    paintSummary();
    paintVarSummary();
    paintFails();
    for (const e of rows.values()) {
      e.tr.cells[0].title = t('scan.copy');
      e.tr.querySelectorAll('[data-i18n-title]').forEach(b => { b.title = t(b.dataset.i18nTitle); });
      paintScore(e.tr, e.result);
      if (!e.result.error && Number(e.result.phase) === 1 && Number(e.result.score) > 0) e.tr.title = t('scan.phase1');
    }
  }

  /** A core was downloaded or changed in Settings: the core list follows. */
  async function enginesChanged() {
    try { presets = Object.assign(presets, await window.api.scanPresets()); } catch { return; }
    renderEngines(presets.engines || []);
    schedulePlan();
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
    if (presets.limits && presets.limits.variants) $('#scanLimit').value = String(presets.limits.variants);
    initDims();
    renderSets(presets.sets);
    restore(presets.last);
    paintRows();
    paintTested(presets.tested);
    paintCdnStatus();
    paintPath();
    checkPathNow();
    renderDims();
    refreshSourcePicker();
    wire();
    paintSortMarks();
    paintStrip();
    paintColumns();
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
