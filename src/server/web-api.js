'use strict';
/**
 * plus: `window.api` in a browser, for the headless server — the same methods
 * the Electron preload exposes, from the same map (server.js prepends it as
 * window.__PLUS_API__), over POST /rpc and the /events stream. The token from
 * the address (?token=…) is kept for the session so a reload keeps working.
 */
(function () {
  const map = window.__PLUS_API__ || { INVOKE: {}, EVENTS: {}, WINDOW: {} };
  let token = '';
  try {
    token = new URLSearchParams(location.search).get('token') || sessionStorage.getItem('irnf-plus-token') || '';
    if (token) sessionStorage.setItem('irnf-plus-token', token);
  } catch { /* storage off: the address keeps it */ }

  const argOf = (kind, args) => {
    if (kind === 'none') return undefined;
    if (kind === 'versions') return Object.assign({}, args[1], { component: args[0] });
    if (kind === 'install') return { component: args[0], tag: args[1] };
    return args[0];
  };

  async function invoke(channel, arg) {
    const res = await fetch('rpc' + (token ? '?token=' + encodeURIComponent(token) : ''), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ channel, arg })
    });
    const body = await res.json().catch(() => ({ error: 'HTTP ' + res.status }));
    if (body.error) throw new Error(body.error);
    return body.result;
  }

  const listeners = {};
  function connect() {
    const es = new EventSource('events' + (token ? '?token=' + encodeURIComponent(token) : ''));
    es.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      for (const cb of listeners[msg.channel] || []) { try { cb(msg.payload); } catch (e) { console.error(e); } }
    };
  }

  const api = { headless: true };
  for (const [name, [channel, kind]] of Object.entries(map.INVOKE)) api[name] = (...args) => invoke(channel, argOf(kind, args));
  for (const [name, channel] of Object.entries(map.EVENTS)) api[name] = (cb) => { (listeners[channel] = listeners[channel] || []).push(cb); };
  for (const name of Object.keys(map.WINDOW)) api[name] = async () => {};
  api.openExternal = async (url) => { if (/^https?:\/\//i.test(String(url || ''))) window.open(String(url), '_blank', 'noopener'); };
  window.api = api;
  connect();
})();
