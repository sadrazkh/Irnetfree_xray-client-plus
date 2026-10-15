'use strict';
/**
 * plus: put a scan target — address, port, SNI — into a stored config (spec
 * v3 §4.2). Pure: the stored record is never touched, a deep copy comes back.
 *
 * The address goes where the protocol keeps it: `vnext[0]` (vless, vmess),
 * `servers[0]` (trojan, shadowsocks), the flat `settings.address/port`
 * (hysteria, MASQUE, and any flat shape a JSON config uses), a WireGuard
 * peer's `endpoint`. The names the server hides behind — TLS SNI, the
 * WebSocket / HTTPUpgrade / XHTTP / h2 Host, the gRPC authority — stay on the
 * original host name, and are filled from it when the link left them empty.
 * That is the Cloudflare-fronting trick: any edge IP works as long as the
 * handshake still names the site. REALITY's serverName is the camouflage
 * site, not ours, so it is never touched.
 *
 * An SNI goes into tlsSettings.serverName; a verifyPeerCertByName follows it
 * (MASQUE always gets one: a cover domain is checked by its own name). It is
 * refused for REALITY (the server's serverNames decide), for ECH (the SNI on
 * the wire is the ECH config's public name; the inner one must stay) and for
 * a config without TLS.
 */
const { isIP } = require('net');
const { addrPort } = require('./targets');
const { masqueHttpOf } = require('../../renderer/serverFields');
const { PROXY_PROTOCOLS } = require('../jsonImport');

const SUPPORTED = ['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'masque', 'wireguard'];

const REASONS = {
  unsupported: 'this protocol cannot be scanned (vless, vmess, trojan, shadowsocks, hysteria2, masque and wireguard can)',
  reality: 'REALITY: the server\'s serverNames decide the SNI, so it is not changed',
  ech: 'ECH: the SNI on the wire is the ECH config\'s public name, and the inner one must stay',
  notls: 'no TLS: the config sends no SNI to change'
};

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const clone = (v) => JSON.parse(JSON.stringify(v));
const present = (v) => v != null && String(v).trim() !== '';
const fail = (code, msg) => Object.assign(new Error(msg), { code });
const isName = (a) => !!a && isIP(a) === 0;

/** 1–65535, or null. */
function toPort(v) {
  const n = Number(v);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

/** The record's protocol in its own terms ('hysteria2' for a hysteria outbound); the outbound's protocol wins. */
function protocolOf(server) {
  const ob = server && server.outbound;
  const p = isObj(ob) && typeof ob.protocol === 'string' && ob.protocol ? ob.protocol : String((server && server.protocol) || '');
  return p === 'hysteria' ? 'hysteria2' : p;
}

const streamOf = (server) => (server && isObj(server.outbound) && isObj(server.outbound.streamSettings) ? server.outbound.streamSettings : {});

/** The node that carries the dial address, or null for a shape this cannot rewrite. WireGuard: wgPeer. */
function dialNode(ob, proto) {
  const st = isObj(ob && ob.settings) ? ob.settings : null;
  if (!st) return null;
  const first = (l) => (Array.isArray(l) && isObj(l[0]) ? l[0] : null);
  const flat = typeof st.address === 'string' && st.address.trim() ? st : null;
  if (proto === 'vless' || proto === 'vmess') return first(st.vnext) || flat;
  if (proto === 'trojan' || proto === 'shadowsocks') return first(st.servers) || flat;
  if (proto === 'hysteria2' || proto === 'masque') return flat;
  return null;
}

function wgPeer(ob) {
  const st = isObj(ob && ob.settings) ? ob.settings : null;
  return st && Array.isArray(st.peers) && isObj(st.peers[0]) ? st.peers[0] : null;
}

/** 'host:port' / '[v6]:port' → { host, port }. */
function splitEndpoint(ep) {
  const e = String(ep == null ? '' : ep).trim();
  const m6 = /^\[([^\]]+)\](?::(\d*))?$/.exec(e);
  if (m6) return { host: m6[1], port: m6[2] || '' };
  const i = e.lastIndexOf(':');
  if (i === -1 || e.indexOf(':') !== i) return { host: e, port: '' };
  return { host: e.slice(0, i), port: e.slice(i + 1) };
}

/** The SNI the config sends: its serverName, else — over TLS — the address it dials by name. '' when none. */
function sniOf(st, addr, proto) {
  if (proto === 'wireguard') return '';
  const sec = proto === 'hysteria2' || proto === 'masque' ? 'tls' : String(st.security || 'none').toLowerCase();
  if (sec === 'reality') return String((isObj(st.realitySettings) && st.realitySettings.serverName) || '');
  if (sec !== 'tls') return '';
  const sn = isObj(st.tlsSettings) ? String(st.tlsSettings.serverName || '') : '';
  return sn || (isName(addr) ? addr : '');
}

/** The Host / authority the transport announces (what a CDN routes by); '' when the config sets none. */
function hostOf(st, proto) {
  if (proto === 'masque') return String((isObj(st.masqueSettings) && st.masqueSettings.host) || '');
  const net = String(st.network || 'tcp').toLowerCase();
  const first = (v) => String([].concat(v == null ? [] : v)[0] || '');
  if (net === 'ws' && isObj(st.wsSettings)) {
    const ws = st.wsSettings, h = isObj(ws.headers) ? ws.headers : {};
    return String(ws.host || h.Host || h.host || '');
  }
  if (net === 'httpupgrade' && isObj(st.httpupgradeSettings)) return String(st.httpupgradeSettings.host || '');
  if ((net === 'xhttp' || net === 'splithttp') && isObj(st.xhttpSettings)) return String(st.xhttpSettings.host || '');
  if ((net === 'h2' || net === 'http') && isObj(st.httpSettings)) return first(st.httpSettings.host);
  if (net === 'grpc' && isObj(st.grpcSettings)) return String(st.grpcSettings.authority || '');
  if ((net === 'tcp' || net === 'raw') && isObj(st.tcpSettings) && isObj(st.tcpSettings.header)) {
    const rq = st.tcpSettings.header.request;
    return isObj(rq) && isObj(rq.headers) ? first(rq.headers.Host) : '';
  }
  return '';
}

/**
 * dialOf(server) → { addr, port, sni, host }: what the config dials today —
 * its server address and port, the SNI it sends ('' when none) and the
 * fronting Host ('' when it sets none). `port` is null when it has none.
 */
function dialOf(server) {
  const proto = protocolOf(server);
  const ob = server && isObj(server.outbound) ? server.outbound : {};
  let addr = '', port = null;
  if (proto === 'wireguard') {
    const ep = splitEndpoint(wgPeer(ob) && wgPeer(ob).endpoint);
    addr = ep.host;
    port = toPort(ep.port);
  } else {
    const node = dialNode(ob, proto);
    if (node) { addr = String(node.address || '').trim(); port = toPort(node.port); }
  }
  if (!addr) addr = String((server && server.address) || '').trim();
  if (port == null) port = toPort(server && server.port);
  const st = streamOf(server);
  return { addr, port, sni: sniOf(st, addr, proto), host: hostOf(st, proto) };
}

/**
 * transportOf(server) → 'tcp' | 'udp': what reaches the server. Hysteria2,
 * WireGuard, mKCP and MASQUE over HTTP/3 are UDP — a TCP connect says nothing
 * about them.
 */
function transportOf(server) {
  const proto = protocolOf(server);
  if (proto === 'hysteria2' || proto === 'wireguard') return 'udp';
  const st = streamOf(server);
  if (proto === 'masque') return masqueHttpOf(st.tlsSettings) === 'h2' ? 'tcp' : 'udp';
  const net = String(st.network || '').toLowerCase();
  return net === 'kcp' || net === 'mkcp' ? 'udp' : 'tcp';
}

/**
 * sniSupport(server) → { ok: true } | { ok: false, code, reason }: whether an
 * SNI of the scan's can go into this config. Codes: 'unsupported', 'notls'
 * (no TLS, WireGuard), 'reality', 'ech'.
 */
function sniSupport(server) {
  const proto = protocolOf(server);
  const no = (code) => ({ ok: false, code, reason: REASONS[code] });
  if (!server || !isObj(server.outbound) || !SUPPORTED.includes(proto)) return no('unsupported');
  if (proto === 'wireguard') return no('notls');
  const st = streamOf(server);
  const sec = proto === 'hysteria2' || proto === 'masque' ? 'tls' : String(st.security || 'none').toLowerCase();
  if (sec === 'reality') return no('reality');
  if (sec !== 'tls') return no('notls');
  const ech = isObj(st.tlsSettings) ? st.tlsSettings.echConfigList : null;
  if (Array.isArray(ech) ? ech.length > 0 : present(ech)) return no('ech');
  return { ok: true };
}

/** Fill the fronting names a link may have left empty. Only existing blocks are touched; REALITY never. */
function fillHostNames(stream, name) {
  const tls = stream.tlsSettings;
  if (isObj(tls) && !tls.serverName) tls.serverName = name;
  const ws = stream.wsSettings;
  if (isObj(ws) && !ws.host) {
    if (!isObj(ws.headers)) ws.headers = {};
    if (!ws.headers.Host && !ws.headers.host) ws.headers.Host = name;
  }
  const hu = stream.httpupgradeSettings;
  if (isObj(hu) && !hu.host) hu.host = name;
  const xh = stream.xhttpSettings;
  if (isObj(xh) && !xh.host) xh.host = name;
  const h2 = stream.httpSettings;
  if (isObj(h2)) {
    if (!Array.isArray(h2.host)) h2.host = h2.host ? [String(h2.host)] : [];
    if (!h2.host.length) h2.host.push(name);
  }
  const grpc = stream.grpcSettings;
  if (isObj(grpc) && !grpc.authority) grpc.authority = name;
}

/** The SNI into tlsSettings; a verifyPeerCertByName follows it — MASQUE's always. */
function setSni(stream, sni, proto) {
  const tls = isObj(stream.tlsSettings) ? stream.tlsSettings : (stream.tlsSettings = {});
  tls.serverName = sni;
  if (proto === 'masque' || present(tls.verifyPeerCertByName)) tls.verifyPeerCertByName = sni;
}

/** The tags an outbound dials through: its dialerProxy and its proxySettings.tag. */
function refsOf(o) {
  const so = isObj(o.streamSettings) && isObj(o.streamSettings.sockopt) ? o.streamSettings.sockopt : {};
  return [so.dialerProxy, isObj(o.proxySettings) ? o.proxySettings.tag : null].filter((t) => typeof t === 'string' && t);
}

/**
 * Does a JSON server's main outbound reach its server through another proxy
 * (a chain)? Through a freedom helper (a fragment or noise dialer) it still
 * dials the address itself, so the walk goes on through those; a tag that
 * names no helper is a direct dial, as configBuilder reads it.
 */
function dialsThroughProxy(server) {
  const extras = Array.isArray(server.extraOutbounds) ? server.extraOutbounds.filter(isObj) : [];
  const byTag = new Map(extras.filter((o) => typeof o.tag === 'string' && o.tag).map((o) => [o.tag, o]));
  const visited = new Set();
  const queue = [server.outbound];
  while (queue.length) {
    const o = queue.shift();
    if (visited.has(o)) continue;
    visited.add(o);
    for (const t of refsOf(o)) {
      const h = byTag.get(t);
      if (!h) continue;
      if (PROXY_PROTOCOLS.has(h.protocol)) return true;
      queue.push(h);
    }
  }
  return false;
}

/** Key order aside, the same JSON. */
function canon(v) {
  const sort = (x) => (Array.isArray(x) ? x.map(sort)
    : (isObj(x) ? Object.keys(x).sort().reduce((o, k) => { o[k] = sort(x[k]); return o; }, {}) : x));
  return JSON.stringify(sort(v));
}

/**
 * A JSON server's config (`json`) gets the same outbound, so the record stays
 * one config: its main outbound in `json.outbounds` — the one that is the
 * stored outbound, its tag aside — becomes the new one, tag kept.
 */
function mirrorIntoJson(out, original) {
  const json = out.json;
  if (!isObj(json) || !Array.isArray(json.outbounds)) return;
  const want = canon(original);
  const i = json.outbounds.findIndex((o) => {
    if (!isObj(o)) return false;
    const c = Object.assign({}, o);
    delete c.tag;
    return canon(c) === want;
  });
  if (i === -1) return;
  const tag = json.outbounds[i].tag;
  json.outbounds[i] = tag === undefined ? clone(out.outbound) : Object.assign({ tag }, clone(out.outbound));
}

/**
 * applyTarget(server, { addr, port, sni }) → a deep copy of `server` that
 * dials addr:port with sni. An absent (null, undefined or empty) field keeps
 * the config's own. Throws an Error with `.code`:
 *  - 'unsupported' — a protocol or a record shape this cannot rewrite;
 *  - 'json-chain' — a JSON server whose main outbound dials through another proxy;
 *  - 'reality' | 'ech' | 'notls' — an `sni` this config cannot take (sniSupport);
 *  - 'invalid' — a port outside 1–65535.
 * `raw` (the share link) is left as it was — the caller rebuilds it.
 */
function applyTarget(server, target = {}) {
  const { addr, port, sni } = target || {};
  const proto = protocolOf(server);
  if (!server || !isObj(server.outbound) || !SUPPORTED.includes(proto)) {
    throw fail('unsupported', 'unsupported protocol' + (proto ? ': ' + proto : ''));
  }
  if (proto === 'wireguard' ? !wgPeer(server.outbound) : !dialNode(server.outbound, proto)) {
    throw fail('unsupported', `unsupported protocol: this ${proto} config names no server to dial`);
  }
  if (server.source === 'json' && dialsThroughProxy(server)) {
    throw fail('json-chain', 'this JSON config dials its server through another proxy (a chain): the scan cannot reach that server directly');
  }
  const newAddr = present(addr) ? String(addr).trim().replace(/^\[(.*)\]$/, '$1') : null;
  let newPort = null;
  if (port != null && port !== '') {
    newPort = toPort(port);
    if (newPort == null) throw fail('invalid', 'invalid port: ' + port);
  }
  const newSni = present(sni) ? String(sni).trim() : null;
  if (newSni) {
    const s = sniSupport(server);
    if (!s.ok) throw fail(s.code, s.reason);
  }

  const origin = dialOf(server).addr;
  const out = clone(server);
  const ob = out.outbound;
  if (proto === 'wireguard') {
    const peer = wgPeer(ob);
    const ep = splitEndpoint(peer.endpoint);
    const host = newAddr != null ? newAddr : ep.host;
    const p = newPort != null ? newPort : (toPort(ep.port) || toPort(server.port));
    peer.endpoint = addrPort(host, p);
  } else {
    const node = dialNode(ob, proto);
    if (newAddr != null) node.address = newAddr;
    if (newPort != null) node.port = newPort;
  }
  if (newAddr != null) out.address = newAddr;
  if (newPort != null) out.port = newPort;

  const st = ob.streamSettings;
  if (isObj(st)) {
    // the names first, from the original host: an SNI below must not become the Host too
    if (isName(origin)) fillHostNames(st, origin);
    if (newSni) setSni(st, newSni, proto);
  }
  if (out.source === 'json') mirrorIntoJson(out, server.outbound);
  return out;
}

/** withAddress(server, ip) → applyTarget(server, { addr: ip }) — for older callers. */
function withAddress(server, ip) {
  return applyTarget(server, { addr: ip });
}

module.exports = { SUPPORTED_PROTOCOLS: SUPPORTED.slice(), dialOf, transportOf, sniSupport, applyTarget, withAddress };
