'use strict';
/**
 * plus: the Configs page — the list the Scan tab dials and the Server tab's
 * exits point at. Add pasted text or a file, import IRNetFree's configs from
 * this machine (read-only), copy a link, remove, or hand one to the scan.
 * Shares app.js's globals ($, t, state, toast, escapeHtml, copyText, setServers).
 */
(function () {
  const fill = (s, map) => String(s).replace(/\{(\w+)\}/g, (m, k) => (Object.prototype.hasOwnProperty.call(map, k) ? map[k] : m));
  let started = false;

  function matches(s, q) {
    if (!q) return true;
    const hay = [s.name, s.address, s.protocol, s.port, s.importedSub].join(' ').toLowerCase();
    return q.split(/\s+/).filter(Boolean).every(w => hay.includes(w));
  }

  function render() {
    const list = $('#cfgList');
    if (!list) return;
    const q = ($('#cfgSearch').value || '').trim().toLowerCase();
    const all = state.servers || [];
    const shown = all.filter(s => matches(s, q));
    $('#cfgCount').textContent = all.length ? fill(t('cfg.count'), { n: all.length }) : '';
    $('#cfgEmpty').hidden = all.length > 0;
    list.innerHTML = '';
    for (const s of shown) {
      const row = document.createElement('div');
      row.className = 'cfg-row';
      row.dataset.id = s.id;
      const proto = String(s.protocol || (s.outbound && s.outbound.protocol) || '?');
      const from = s.importedFrom === 'irnetfree' ? `<span class="cfg-src">${escapeHtml(t('cfg.fromIrnetfree'))}${s.importedSub ? ' · ' + escapeHtml(s.importedSub) : ''}</span>` : '';
      row.innerHTML = `
        <span class="cfg-proto">${escapeHtml(proto)}</span>
        <div class="cfg-main">
          <span class="cfg-name">${escapeHtml(s.name || '—')}</span>
          <span class="cfg-addr" dir="ltr">${escapeHtml(String(s.address || ''))}${s.port ? ':' + escapeHtml(String(s.port)) : ''}</span>
          ${from}
        </div>
        <div class="cfg-acts">
          <button class="btn ghost small" type="button" data-act="scan">${escapeHtml(t('cfg.scan'))}</button>
          <button class="btn ghost small" type="button" data-act="copy">${escapeHtml(t('cfg.copy'))}</button>
          <button class="btn ghost small danger" type="button" data-act="remove">${escapeHtml(t('cfg.remove'))}</button>
        </div>`;
      list.appendChild(row);
    }
  }

  function linkOf(s) {
    if (s.raw && /^[a-z0-9+.-]+:\/\//i.test(s.raw)) return s.raw;
    if (s.raw && /^\s*[{[]/.test(s.raw)) return s.raw;
    if (s.json) return JSON.stringify(s.json);
    return '';
  }

  async function onRow(e) {
    const btn = e.target.closest('button[data-act]');
    if (!btn) return;
    const id = btn.closest('.cfg-row').dataset.id;
    const s = (state.servers || []).find(x => x.id === id);
    if (!s) return;
    if (btn.dataset.act === 'copy') {
      const link = linkOf(s);
      if (!link) return toast(t('cfg.noLink'), 'warn');
      await copyText(link);
      return toast(t('cfg.copied'), 'ok');
    }
    if (btn.dataset.act === 'scan') {
      if (typeof window.plusScanUse === 'function') window.plusScanUse(id);
      if (typeof window.plusShowView === 'function') window.plusShowView('scan');
      return undefined;
    }
    if (btn.dataset.act === 'remove') {
      if (!window.confirm(fill(t('cfg.removeConfirm'), { name: s.name || s.address || id }))) return undefined;
      let r;
      try { r = await window.api.configsRemove([id]); } catch (err) { return toast((err && err.message) || String(err), 'err'); }
      setServers(r.servers);
      return toast(t('cfg.removed'), 'ok');
    }
    return undefined;
  }

  async function add(text) {
    const out = $('#cfgResult');
    let r;
    try { r = await window.api.configsAdd(text); } catch (e) { out.textContent = (e && e.message) || String(e); return; }
    setServers(r.servers);
    const parts = [];
    if (r.added && r.added.length) parts.push(fill(t('cfg.added'), { n: r.added.length }));
    if (r.errors && r.errors.length) parts.push(fill(t('cfg.addErrors'), { n: r.errors.length }));
    out.textContent = parts.length ? parts.join(' · ') : t('cfg.nothing');
    if (r.added && r.added.length) $('#cfgText').value = '';
  }

  function wire() {
    $('#cfgSearch').oninput = render;
    $('#cfgList').onclick = onRow;
    $('#btnCfgAdd').onclick = () => add($('#cfgText').value);
    $('#btnCfgFile').onclick = () => $('#cfgFile').click();
    $('#cfgFile').onchange = async () => {
      const f = $('#cfgFile').files[0];
      $('#cfgFile').value = '';
      if (!f) return;
      let text;
      try { text = await f.text(); } catch { return toast(t('cfg.fileErr'), 'err'); }
      add(text);
    };
    $('#btnCfgImport').onclick = async () => {
      const btn = $('#btnCfgImport');
      btn.disabled = true;
      let r;
      try { r = await window.api.configsImport({}); } catch (e) { r = { error: (e && e.message) || String(e) }; }
      btn.disabled = false;
      if (r && r.servers) setServers(r.servers);
      if (!r || r.error) return toast(r && r.error === 'not found' ? t('cfg.importMissing') : t('cfg.importFailed'), 'err');
      return toast(fill(t('cfg.imported'), { a: r.added, u: r.updated }), 'ok');
    };
  }

  function initConfigs() {
    if (started) return render();
    started = true;
    wire();
    render();
    new MutationObserver(render).observe(document.documentElement, { attributes: true, attributeFilter: ['lang'] });
    return undefined;
  }

  window.plusConfigsRefresh = render;
  window.plusInit = window.plusInit || [];
  window.plusInit.push(initConfigs);
})();
