'use strict';
/**
 * plus: the way a scan leaves the machine, and whether that way tells the truth.
 * 2026-11-02 (the owner: "let it use a port I leave open outside the VPN,
 * optionally"; and warn when the VPN would make a scan meaningless).
 *
 * Why it matters. On the owner's laptop, with the VPN on, a TLS request to the
 * reserved address 192.0.2.1 answered 200 from CloudFront: a sniffing VPN redials
 * the name in the handshake, so every address "answers". A reserved address
 * answering is the proof, and needs no list of VPN adapters.
 *
 *  - Direct: a TCP connect to an address that cannot exist. Anything that accepts
 *    it stands between the scan and the network.
 *  - Through a port: a CONNECT reply says nothing, because Xray's SOCKS inbound says
 *    success before it dials. Only a finished TLS handshake with a reserved address
 *    proves a lie. A plain direct port dials the address and gets nowhere.
 *
 * Through a port, the same fact ends the plain TCP pre-check (a pass would mean
 * nothing), so the TLS handshake takes its place where the config has TLS. And
 * what a config does to its own packets (fragment, finalMask, dialMode) happens
 * between the core and the port, not on the real line: scan:start says so. A UDP
 * config does not pass through at all, and is refused.
 */
const net = require('net');
const tls = require('tls');

const TAG = 'scan-upstream';
/** RFC 5737's documentation addresses: no server is ever there. */
const CONTROL = [['192.0.2.1', 443], ['198.51.100.1', 443]];
const CONTROL_SNI = 'www.cloudflare.com';
const DIRECT_CHECK_MS = 1500;
/** Longer: a sniffing VPN's redial has to finish a handshake through its server. */
const PROXY_CHECK_MS = 3000;
const NOT_DIALS = new Set(['blackhole', 'dns', 'loopback']);

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

/** `host:port`, `[v6]:port`, `user:pass@host:port`, with or without socks5:// → { host, port, user?, pass? }, or null. */
function parseUpstream(text) {
  let s = String(text == null ? '' : text).trim().replace(/^socks5?h?:\/\//i, '').replace(/\/+$/, '');
  if (!s) return null;
  let user = '', pass = '';
  const at = s.lastIndexOf('@');
  if (at !== -1) {
    const cred = s.slice(0, at);
    s = s.slice(at + 1);
    const c = cred.indexOf(':');
    user = c === -1 ? cred : cred.slice(0, c);
    pass = c === -1 ? '' : cred.slice(c + 1);
    if (!user || Buffer.byteLength(user) > 255 || Buffer.byteLength(pass) > 255) return null;
  }
  const v6 = /^\[([0-9a-f:.]+)\]:(\d+)$/i.exec(s);
  const m = v6 || /^([^\s:/[\]]+):(\d+)$/.exec(s);
  if (!m || (v6 && !net.isIPv6(m[1]))) return null;
  const port = Number(m[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return Object.assign({ host: m[1], port }, user ? { user, pass } : {});
}

/** The option as a request carries it and the store keeps it. */
function sanitizeUpstream(raw) {
  const r = isObj(raw) ? raw : {};
  return { on: !!r.on, addr: String(r.addr == null ? '' : r.addr).trim().slice(0, 600) };
}

/** What a run uses: null when off, { error } when on and unreadable, else the parsed address. */
function upstreamOf(raw) {
  const r = sanitizeUpstream(raw);
  if (!r.on) return null;
  return parseUpstream(r.addr) || { error: 'proxy-addr' };
}

/** The 16 bytes of an IPv6 address. */
function ip6Bytes(addr) {
  const [head, tail] = addr.split('::');
  const group = (s) => (s ? s.split(':') : []);
  const h = group(head), t = group(tail);
  const words = tail === undefined ? h : h.concat(Array(8 - h.length - t.length).fill('0'), t);
  const out = Buffer.alloc(16);
  words.forEach((w, i) => out.writeUInt16BE(parseInt(w, 16) || 0, i * 2));
  return out;
}

/** A SOCKS5 CONNECT's request bytes. */
function connectRequest(host, port) {
  const p = Buffer.from([port >> 8, port & 255]);
  if (net.isIPv4(host)) return Buffer.concat([Buffer.from([5, 1, 0, 1, ...host.split('.').map(Number)]), p]);
  if (net.isIPv6(host) && !host.includes('.')) return Buffer.concat([Buffer.from([5, 1, 0, 4]), ip6Bytes(host), p]);
  const name = Buffer.from(host);
  return Buffer.concat([Buffer.from([5, 1, 0, 3, name.length]), name, p]);
}

/**
 * socksConnect(up, host, port, timeout) → a socket past the CONNECT, paused. It
 * rejects with a `code`: PROXY_DOWN (the port does not answer), PROXY_BAD (it does
 * not speak SOCKS5), PROXY_AUTH (refused), TARGET (the proxy could not reach it).
 */
function socksConnect(up, host, port, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: up.host, port: up.port });
    let stage = 'connect', buf = Buffer.alloc(0), done = false;
    const fail = (code, message) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      reject(Object.assign(new Error(message), { code }));
    };
    const failAtStage = (why) => {
      if (stage === 'connect') fail('PROXY_DOWN', `the port does not answer (${why})`);
      else if (stage === 'reply') fail('TARGET', `the proxy could not reach it (${why})`);
      else fail('PROXY_BAD', `no SOCKS5 answer (${why})`);
    };
    const timer = setTimeout(() => failAtStage('timeout'), timeout);
    const request = () => { stage = 'reply'; sock.write(connectRequest(host, port)); };
    const onError = (e) => failAtStage(e.code || e.message);
    const onClose = () => failAtStage('closed');
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 'hello') {
        if (buf.length < 2) return;
        if (buf[0] !== 5) { fail('PROXY_BAD', 'not a SOCKS5 port'); return; }
        const method = buf[1];
        buf = buf.subarray(2);
        if (method === 0) request();
        else if (method === 2 && up.user) {
          stage = 'auth';
          const u = Buffer.from(up.user), p = Buffer.from(up.pass || '');
          sock.write(Buffer.concat([Buffer.from([1, u.length]), u, Buffer.from([p.length]), p]));
        } else { fail('PROXY_AUTH', 'the port wants a username and password'); return; }
      }
      if (stage === 'auth') {
        if (buf.length < 2) return;
        if (buf[1] !== 0) { fail('PROXY_AUTH', 'the username or password was refused'); return; }
        buf = buf.subarray(2);
        request();
      }
      if (stage === 'reply') {
        if (buf.length < 5) return;
        if (buf[0] !== 5) { fail('PROXY_BAD', 'not a SOCKS5 port'); return; }
        if (buf[1] !== 0) { fail('TARGET', `the proxy refused it (SOCKS reply ${buf[1]})`); return; }
        const need = 4 + (buf[3] === 1 ? 4 : buf[3] === 4 ? 16 : 1 + buf[4]) + 2;
        if (buf.length < need) return;
        done = true;
        clearTimeout(timer);
        sock.pause();
        sock.removeListener('data', onData);
        sock.removeListener('error', onError);
        sock.removeListener('close', onClose);
        if (buf.length > need) sock.unshift(buf.subarray(need));
        resolve(sock);
      }
    };
    sock.on('error', onError);
    sock.on('close', onClose);
    sock.on('data', onData);
    sock.once('connect', () => {
      stage = 'hello';
      sock.write(Buffer.from(up.user ? [5, 2, 0, 2] : [5, 1, 0]));
    });
  });
}

/** A dial for the probes: `(host, port, timeout) → socket` through `up`. */
const dialVia = (up) => (host, port, timeout) => socksConnect(up, host, port, timeout);

/** The config with every direct dial through `up`, in place. Off: not touched. A chain's later hops and a helper's user already go through another outbound. */
function withUpstream(config, up) {
  if (!up) return config;
  const outs = Array.isArray(config.outbounds) ? config.outbounds : (config.outbounds = []);
  for (const o of outs) {
    if (!isObj(o) || NOT_DIALS.has(o.protocol)) continue;
    if (isObj(o.proxySettings) && o.proxySettings.tag) continue;
    const ss = isObj(o.streamSettings) ? o.streamSettings : (o.streamSettings = {});
    const so = isObj(ss.sockopt) ? ss.sockopt : (ss.sockopt = {});
    if (!so.dialerProxy) so.dialerProxy = TAG;
  }
  outs.push({
    tag: TAG, protocol: 'socks',
    settings: { servers: [Object.assign({ address: up.host, port: up.port }, up.user ? { users: [{ user: up.user, pass: up.pass || '' }] } : {})] }
  });
  return config;
}

/** Does this address accept a TCP connect within `timeout`? */
function tcpOpens(host, port, timeout) {
  return new Promise((resolve) => {
    let done = false;
    const s = net.connect({ host, port });
    const end = (v) => { if (done) return; done = true; clearTimeout(t); s.destroy(); resolve(v); };
    const t = setTimeout(() => end(false), timeout);
    s.once('connect', () => end(true));
    s.once('error', () => end(false));
  });
}

/** Does a TLS handshake finish on this socket within `timeout`? */
function handshakes(sock, servername, timeout) {
  return new Promise((resolve) => {
    let done = false, secure = null;
    const end = (v) => { if (done) return; done = true; clearTimeout(t); try { (secure || sock).destroy(); } catch { /* gone */ } resolve(v); };
    const t = setTimeout(() => end(false), timeout);
    secure = tls.connect({ socket: sock, servername, rejectUnauthorized: false }, () => end(true));
    secure.once('error', () => end(false));
    secure.once('close', () => end(false));
  });
}

/**
 * checkPath(up, { control, directMs, proxyMs }) → { via: 'direct' | 'proxy', state, error? }.
 * state: `clean`, `lying` (something answers for an address that cannot exist), or
 * for a port `proxy-down`, `proxy-bad`, `proxy-auth`. It never rejects.
 */
async function checkPath(up, opts = {}) {
  const control = opts.control || CONTROL;
  if (!up) {
    const ms = opts.directMs || DIRECT_CHECK_MS;
    const opened = await Promise.all(control.map(([h, p]) => tcpOpens(h, p, ms)));
    return { via: 'direct', state: opened.some(Boolean) ? 'lying' : 'clean' };
  }
  const ms = opts.proxyMs || PROXY_CHECK_MS;
  let sock;
  try {
    sock = await socksConnect(up, control[0][0], control[0][1], ms);
  } catch (e) {
    if (e.code === 'TARGET') return { via: 'proxy', state: 'clean' };
    const state = e.code === 'PROXY_AUTH' ? 'proxy-auth' : (e.code === 'PROXY_BAD' ? 'proxy-bad' : 'proxy-down');
    return { via: 'proxy', state, error: e.message };
  }
  return { via: 'proxy', state: (await handshakes(sock, opts.sni || CONTROL_SNI, ms)) ? 'lying' : 'clean' };
}

module.exports = { TAG, parseUpstream, sanitizeUpstream, upstreamOf, socksConnect, dialVia, withUpstream, checkPath, connectRequest };
