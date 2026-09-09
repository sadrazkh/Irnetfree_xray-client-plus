'use strict';
/**
 * plus: dial a stored config through another IP. Pure.
 *
 * Only the address the core connects to changes. The names the server hides
 * behind — TLS SNI, the WebSocket/xhttp/h2 Host, the gRPC authority — stay on
 * the original hostname, and are filled from it when the share link left
 * them empty. That is the Cloudflare-fronting trick: any edge IP works as
 * long as the handshake still names the site. Reality's serverName is the
 * camouflage site, not ours, so it is never touched.
 */
const { isIP } = require('net');

const SUPPORTED = new Set(['vless', 'vmess', 'trojan', 'shadowsocks']);

/** The node that carries the dial address, or null for a shape we cannot rewrite. */
function dialNode(protocol, settings) {
  if (!settings) return null;
  if (protocol === 'vless' || protocol === 'vmess') return Array.isArray(settings.vnext) && settings.vnext[0] ? settings.vnext[0] : null;
  if (protocol === 'trojan' || protocol === 'shadowsocks') return Array.isArray(settings.servers) && settings.servers[0] ? settings.servers[0] : null;
  return null;
}

/** Fill the fronting names a link may have left empty. Only existing blocks are touched. */
function fillHostNames(stream, name) {
  if (!stream) return;
  const tls = stream.tlsSettings;
  if (tls && !tls.serverName) tls.serverName = name;
  const ws = stream.wsSettings;
  if (ws) {
    if (!ws.headers || typeof ws.headers !== 'object') ws.headers = {};
    if (!ws.headers.Host && !ws.headers.host) ws.headers.Host = name;
  }
  const xh = stream.xhttpSettings;
  if (xh && !xh.host) xh.host = name;
  const h2 = stream.httpSettings;
  if (h2) {
    if (!Array.isArray(h2.host)) h2.host = [];
    if (!h2.host.length) h2.host.push(name);
  }
  const grpc = stream.grpcSettings;
  if (grpc && !grpc.authority) grpc.authority = name;
}

/**
 * withAddress(server, ip) → a deep copy of `server` that dials `ip`.
 * Throws Error('unsupported protocol') for WireGuard, socks, http, or a
 * record without the vnext/servers shape.
 */
function withAddress(server, ip) {
  const protocol = server && (server.protocol || (server.outbound && server.outbound.protocol));
  if (!server || !server.outbound || !SUPPORTED.has(protocol)) throw new Error('unsupported protocol');
  const original = String(server.address || '').trim();
  const out = JSON.parse(JSON.stringify(server));
  const node = dialNode(protocol, out.outbound.settings);
  if (!node) throw new Error('unsupported protocol');
  const fromName = original || String(node.address || '');
  out.address = ip;
  node.address = ip;
  if (fromName && isIP(fromName) === 0) fillHostNames(out.outbound.streamSettings, fromName);
  return out;
}

module.exports = { withAddress, SUPPORTED_PROTOCOLS: [...SUPPORTED] };
