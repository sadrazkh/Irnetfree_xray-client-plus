'use strict';
/**
 * IP-scan address substitution: the same config dialled through another IP.
 *
 * What matters: only the dial address changes; the names the server is
 * fronted by (SNI, Host, xhttp/h2 host, gRPC authority) stay on the original
 * hostname and are filled from it when the link left them empty, since that
 * is the whole trick behind scanning Cloudflare's ranges. The input record is
 * never touched, anti-DPI markers survive, and anything that is not an
 * xray-format proxy is refused.
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const { withAddress } = require('../src/main/scan/substitute');
const F = require('./fixtures');

const clone = (o) => JSON.parse(JSON.stringify(o));

test('vless ws tls: address and vnext address become the IP; SNI and Host stay on the name', () => {
  const src = clone(F.VLESS_WS_TLS);
  src.outbound.streamSettings.wsSettings.headers = {};      // a link without &host=
  src.outbound._fragment = '1,40-60,10-20';
  src.certPin = 'ab11bf7ac877baa539294f5a3c864b8ed43e6fe3a9a8230fc2db7fff85c27fde';
  src.engine = 'xray-pattn';
  const before = clone(src);

  const out = withAddress(src, '104.16.1.2');
  assert.equal(out.address, '104.16.1.2');
  assert.equal(out.port, 443);
  assert.equal(out.outbound.settings.vnext[0].address, '104.16.1.2');
  assert.equal(out.outbound.settings.vnext[0].port, 443);
  assert.equal(out.outbound.streamSettings.tlsSettings.serverName, 'a.example.com');
  assert.equal(out.outbound.streamSettings.wsSettings.headers.Host, 'a.example.com', 'filled from the original address');
  assert.equal(out.outbound._fragment, '1,40-60,10-20');
  assert.equal(out.certPin, src.certPin);
  assert.equal(out.engine, 'xray-pattn');
  assert.equal(out.name, src.name, 'the name is the caller\'s business');
  assert.equal(out.id, src.id);
  assert.deepEqual(src, before, 'deep copy: the stored record is untouched');
  assert.notEqual(out.outbound, src.outbound);
});

test('an SNI or Host that is already set is left alone', () => {
  const src = clone(F.VLESS_WS_TLS);
  src.outbound.streamSettings.tlsSettings.serverName = 'cdn.other.net';
  src.outbound.streamSettings.wsSettings.headers.Host = 'front.other.net';
  const out = withAddress(src, '1.1.1.1');
  assert.equal(out.outbound.streamSettings.tlsSettings.serverName, 'cdn.other.net');
  assert.equal(out.outbound.streamSettings.wsSettings.headers.Host, 'front.other.net');
});

test('an empty SNI is filled from the hostname, but not from an IP address', () => {
  const named = clone(F.VLESS_WS_TLS);
  named.outbound.streamSettings.tlsSettings.serverName = '';
  assert.equal(withAddress(named, '1.1.1.1').outbound.streamSettings.tlsSettings.serverName, 'a.example.com');

  const byIp = clone(F.VLESS_WS_TLS);
  byIp.address = '5.6.7.8';
  byIp.outbound.settings.vnext[0].address = '5.6.7.8';
  byIp.outbound.streamSettings.tlsSettings.serverName = '';
  byIp.outbound.streamSettings.wsSettings.headers = {};
  const out = withAddress(byIp, '1.1.1.1');
  assert.equal(out.outbound.streamSettings.tlsSettings.serverName, '', 'an IP is not a name to front with');
  assert.equal(out.outbound.streamSettings.wsSettings.headers.Host, undefined);
});

test('trojan and shadowsocks use servers[0].address', () => {
  const t = withAddress(F.TROJAN_TCP_TLS, '9.9.9.9');
  assert.equal(t.address, '9.9.9.9');
  assert.equal(t.outbound.settings.servers[0].address, '9.9.9.9');
  assert.equal(t.outbound.settings.servers[0].password, 'pw');
  assert.equal(t.outbound.streamSettings.tlsSettings.serverName, 'b.example.com');

  const s = withAddress(F.SS_TCP, '8.8.8.8');
  assert.equal(s.outbound.settings.servers[0].address, '8.8.8.8');
  assert.equal(s.outbound.settings.servers[0].method, 'aes-256-gcm');
  assert.equal(F.SS_TCP.outbound.settings.servers[0].address, 'c.example.com');
});

test('vmess uses vnext[0].address', () => {
  const src = F.server('sv-vm', 'VMess', 'vmess', 'v.example.com', 80, {
    protocol: 'vmess',
    settings: { vnext: [{ address: 'v.example.com', port: 80, users: [{ id: 'u', alterId: 0, security: 'auto' }] }] },
    streamSettings: { network: 'ws', security: 'none', wsSettings: { path: '/', headers: {} } }
  });
  const out = withAddress(src, '7.7.7.7');
  assert.equal(out.outbound.settings.vnext[0].address, '7.7.7.7');
  assert.equal(out.outbound.streamSettings.wsSettings.headers.Host, 'v.example.com');
  assert.equal(out.outbound.streamSettings.tlsSettings, undefined, 'no TLS block is invented');
});

test('reality: serverName is the camouflage name and is never rewritten', () => {
  const src = F.server('sv-rl', 'Reality', 'vless', 'r.example.com', 443, {
    protocol: 'vless',
    settings: { vnext: [{ address: 'r.example.com', port: 443, users: [{ id: 'u', encryption: 'none', flow: 'xtls-rprx-vision' }] }] },
    streamSettings: { network: 'tcp', security: 'reality', realitySettings: { serverName: '', fingerprint: 'chrome', publicKey: 'pk', shortId: '', spiderX: '' } }
  });
  const out = withAddress(src, '3.3.3.3');
  assert.equal(out.outbound.settings.vnext[0].address, '3.3.3.3');
  assert.equal(out.outbound.streamSettings.realitySettings.serverName, '');
  const named = clone(src);
  named.outbound.streamSettings.realitySettings.serverName = 'www.microsoft.com';
  assert.equal(withAddress(named, '3.3.3.3').outbound.streamSettings.realitySettings.serverName, 'www.microsoft.com');
});

test('xhttp host, h2 host[0] and gRPC authority are filled from the name when empty', () => {
  const mk = (stream) => F.server('sv-x', 'X', 'vless', 'x.example.com', 443, {
    protocol: 'vless',
    settings: { vnext: [{ address: 'x.example.com', port: 443, users: [{ id: 'u', encryption: 'none', flow: '' }] }] },
    streamSettings: stream
  });
  const xh = withAddress(mk({ network: 'xhttp', security: 'tls', xhttpSettings: { path: '/p', host: '', mode: 'auto' }, tlsSettings: { serverName: 'x.example.com' } }), '1.2.3.4');
  assert.equal(xh.outbound.streamSettings.xhttpSettings.host, 'x.example.com');

  const h2 = withAddress(mk({ network: 'h2', security: 'tls', httpSettings: { path: '/', host: [] }, tlsSettings: { serverName: '' } }), '1.2.3.4');
  assert.deepEqual(h2.outbound.streamSettings.httpSettings.host, ['x.example.com']);
  assert.equal(h2.outbound.streamSettings.tlsSettings.serverName, 'x.example.com');

  const g = withAddress(mk({ network: 'grpc', security: 'tls', grpcSettings: { serviceName: 'svc', multiMode: false }, tlsSettings: { serverName: 'x.example.com' } }), '1.2.3.4');
  assert.equal(g.outbound.streamSettings.grpcSettings.authority, 'x.example.com');

  const gset = withAddress(mk({ network: 'grpc', security: 'tls', grpcSettings: { serviceName: 'svc', authority: 'keep.me' }, tlsSettings: { serverName: 'x.example.com' } }), '1.2.3.4');
  assert.equal(gset.outbound.streamSettings.grpcSettings.authority, 'keep.me');
});

test('wireguard, socks, http and malformed records are refused', () => {
  assert.throws(() => withAddress(F.WG_BAD_MASK, '1.1.1.1'), /unsupported protocol/);
  const socks = F.server('sv-s', 'S', 'socks', 's.example.com', 1080, { protocol: 'socks', settings: { servers: [{ address: 's.example.com', port: 1080 }] } });
  assert.throws(() => withAddress(socks, '1.1.1.1'), /unsupported protocol/);
  const http = F.server('sv-h', 'H', 'http', 'h.example.com', 8080, { protocol: 'http', settings: { servers: [{ address: 'h.example.com', port: 8080 }] } });
  assert.throws(() => withAddress(http, '1.1.1.1'), /unsupported protocol/);
  const broken = F.server('sv-b', 'B', 'vless', 'b.example.com', 443, { protocol: 'vless', settings: {} });
  assert.throws(() => withAddress(broken, '1.1.1.1'), /unsupported protocol/);
  assert.throws(() => withAddress(null, '1.1.1.1'), /unsupported protocol/);
  assert.throws(() => withAddress({ protocol: 'vless' }, '1.1.1.1'), /unsupported protocol/);
});
