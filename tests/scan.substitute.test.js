'use strict';
/**
 * Scan substitution (spec v3 §4.2): the same config dialled at another
 * address, port and SNI.
 *
 * What matters: the target lands where each protocol keeps its server (vnext,
 * servers, the flat settings, a WireGuard endpoint — `[v6]:port`); the names
 * the server is fronted by (SNI, Host, httpupgrade/xhttp/h2 host, gRPC
 * authority) stay on the original host name and are filled from it when the
 * link left them empty, since that is the whole trick behind scanning
 * Cloudflare's ranges; an SNI goes into TLS (a verifyPeerCertByName follows
 * it, MASQUE's always) and is refused where it cannot work (REALITY, ECH, no
 * TLS); a JSON server takes it in its main outbound unless that dials through
 * another proxy; the input record is never touched; and what the config dials
 * today (dialOf) and over what (transportOf) read right for every protocol.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { withAddress, applyTarget, dialOf, transportOf, sniSupport, SUPPORTED_PROTOCOLS } = require('../src/main/scan/substitute');
const { createServer, parseLink } = require('../src/main/parser');
const { importJson } = require('../src/main/jsonImport');
const F = require('./fixtures');

const clone = (o) => JSON.parse(JSON.stringify(o));
const WARP_PUB = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==';
const warpPem = () => crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'pkcs8', format: 'pem' });

/** Throws an Error carrying `code`. */
const throwsCode = (fn, code, re) => assert.throws(fn, (e) => e instanceof Error && e.code === code && (!re || re.test(e.message)));

/* ------------------------------- the records ------------------------------- */

const VMESS_WS = () => createServer({ protocol: 'vmess', name: 'vm', address: 'v.example.com', port: 8080, uuid: 'u-vm', network: 'ws', path: '/vm' });
const HY2 = () => parseLink('hy2://pass@h.example:443?sni=h.example#x');
const MASQUE_H2 = () => createServer({ protocol: 'masque', name: 'mq', address: 'm.example.com', port: 443, masqueHttp: 'h2', sni: 'cover.example', vcn: 'm.example.com' });
const MASQUE_H3 = () => createServer({ protocol: 'masque', name: 'mq3', address: 'm.example.com', port: 8443 });
const WARP = () => createServer({
  protocol: 'masque', name: 'warp', address: '162.159.198.1', port: 443,
  warpPrivateKey: warpPem(), warpPublicKey: WARP_PUB, warpAddress: '172.16.0.2/32'
});
const WG_V6 = () => createServer({ protocol: 'wireguard', name: 'wg6', address: '2606:4700::1', port: 2408, privateKey: 'k', publicKey: 'p' });
const REALITY = () => createServer({ protocol: 'vless', name: 'r', address: 'r.example.com', port: 443, uuid: 'u', security: 'reality', pbk: 'abc', sni: 'www.microsoft.com' });
const ECH = () => createServer({ protocol: 'vless', name: 'e', address: 'e.example.com', port: 443, uuid: 'u', network: 'ws', security: 'tls', ech: 'cloudflare-ech.com+udp://1.1.1.1' });
const PLAIN_WS = () => createServer({ protocol: 'vless', name: 'p', address: 'p.example.com', port: 80, uuid: 'u', network: 'ws', security: 'none' });
const SOCKS = () => F.server('sv-s', 'S', 'socks', 's.example.com', 1080, { protocol: 'socks', settings: { servers: [{ address: 's.example.com', port: 1080 }] } });

/** Where each protocol keeps its server: read back from the copy. */
const AT = {
  vless: (s) => s.outbound.settings.vnext[0],
  vmess: (s) => s.outbound.settings.vnext[0],
  trojan: (s) => s.outbound.settings.servers[0],
  shadowsocks: (s) => s.outbound.settings.servers[0],
  hysteria2: (s) => s.outbound.settings,
  masque: (s) => s.outbound.settings
};

const RECORDS = {
  vless: () => clone(F.VLESS_WS_TLS),
  vmess: VMESS_WS,
  trojan: () => clone(F.TROJAN_TCP_TLS),
  shadowsocks: () => clone(F.SS_TCP),
  hysteria2: HY2,
  masque: MASQUE_H2,
  wireguard: () => clone(F.WG_BAD_MASK)
};

/* ------------------------------ every protocol ------------------------------ */

test('SUPPORTED_PROTOCOLS: the seven a scan can dial elsewhere', () => {
  assert.deepEqual(SUPPORTED_PROTOCOLS, ['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'masque', 'wireguard']);
});

test('every protocol × IPv4 / IPv6 / host name, with and without a port: the copy dials it, the input is untouched', () => {
  const addrs = ['104.16.1.2', '2606:4700::1111', 'edge.example.net'];
  for (const [proto, make] of Object.entries(RECORDS)) {
    for (const addr of addrs) {
      for (const port of [undefined, 2053]) {
        const src = make();
        const before = clone(src);
        const own = dialOf(src);
        const out = applyTarget(src, { addr, port });
        const label = `${proto} ${addr} ${port}`;
        const want = { addr, port: port || own.port };
        assert.deepEqual({ addr: dialOf(out).addr, port: dialOf(out).port }, want, label);
        assert.equal(out.address, addr, label);
        assert.equal(out.port, port || src.port, label);
        if (proto === 'wireguard') {
          const ep = out.outbound.settings.peers[0].endpoint;
          assert.equal(ep, addr.includes(':') ? `[${addr}]:${want.port}` : `${addr}:${want.port}`, label);
        } else {
          assert.equal(AT[proto](out).address, addr, label);
          assert.equal(AT[proto](out).port, want.port, label);
        }
        assert.equal(out.raw, src.raw, 'raw is the caller\'s to rebuild: ' + label);
        assert.equal(out.id, src.id);
        assert.deepEqual(src, before, 'deep copy, the stored record untouched: ' + label);
        assert.notEqual(out.outbound, src.outbound);
      }
    }
  }
});

test('WireGuard: an IPv6 endpoint is bracketed — given, kept when only the port changes, and dropped for an IPv4', () => {
  const src = WG_V6();
  assert.equal(src.outbound.settings.peers[0].endpoint, '[2606:4700::1]:2408');
  assert.equal(applyTarget(src, { port: 500 }).outbound.settings.peers[0].endpoint, '[2606:4700::1]:500');
  assert.equal(applyTarget(src, { addr: '162.159.192.7' }).outbound.settings.peers[0].endpoint, '162.159.192.7:2408');
  assert.equal(applyTarget(src, { addr: '2606:4700:d0::a29f:c001', port: 4500 }).outbound.settings.peers[0].endpoint, '[2606:4700:d0::a29f:c001]:4500');
  assert.equal(applyTarget(src, { addr: '[2606:4700:d0::1]' }).outbound.settings.peers[0].endpoint, '[2606:4700:d0::1]:2408', 'brackets given are not doubled');
  assert.equal(applyTarget(F.WG_BAD_MASK, { addr: '2606:4700::5' }).outbound.settings.peers[0].endpoint, '[2606:4700::5]:51820');
  assert.equal(applyTarget(F.WG_BAD_MASK, { addr: '2606:4700::5' }).address, '2606:4700::5', 'the record keeps the bare address');
  assert.equal(withAddress(F.WG_CORP, '10.1.1.1').outbound.settings.peers[0].endpoint, '10.1.1.1:51821');
});

test('absent fields keep the config\'s own; a port outside 1–65535 is refused', () => {
  const src = clone(F.VLESS_WS_TLS);
  assert.deepEqual(applyTarget(src, {}).outbound.settings, src.outbound.settings);
  assert.deepEqual(applyTarget(src).outbound.settings, src.outbound.settings);
  assert.deepEqual(applyTarget(src, { addr: null, port: null, sni: null }).outbound, src.outbound);
  assert.deepEqual(applyTarget(src, { addr: '', port: '', sni: '' }).outbound, src.outbound);
  const p = applyTarget(src, { port: '8443' });
  assert.equal(p.outbound.settings.vnext[0].port, 8443);
  assert.equal(p.outbound.settings.vnext[0].address, 'a.example.com');
  for (const bad of [0, 65536, 'x', -1, 1.5]) throwsCode(() => applyTarget(src, { addr: '1.1.1.1', port: bad }), 'invalid', /port/);
});

/* ---------------------------------- names ---------------------------------- */

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
  // the core's newer ws `host` field counts as a Host too
  const newer = clone(F.VLESS_WS_TLS);
  newer.outbound.streamSettings.wsSettings = { path: '/ws', host: 'front.other.net' };
  assert.deepEqual(withAddress(newer, '1.1.1.1').outbound.streamSettings.wsSettings, { path: '/ws', host: 'front.other.net' });
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
  // nor from an IPv6 one
  const byV6 = clone(byIp);
  byV6.address = byV6.outbound.settings.vnext[0].address = '2606:4700::10';
  assert.equal(withAddress(byV6, '1.1.1.1').outbound.streamSettings.tlsSettings.serverName, '');
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

test('xhttp host, h2 host[0], gRPC authority and the httpupgrade host are filled from the name when empty', () => {
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

  // httpupgrade (new in v3), as a link writes it: an empty host
  const huSrc = createServer({ protocol: 'vless', name: 'hu', address: 'hu.example.com', port: 443, uuid: 'u', network: 'httpupgrade', security: 'tls', path: '/up' });
  assert.equal(huSrc.outbound.streamSettings.httpupgradeSettings.host, '');
  const hu = applyTarget(huSrc, { addr: '104.16.1.2' });
  assert.deepEqual(hu.outbound.streamSettings.httpupgradeSettings, { path: '/up', host: 'hu.example.com' });
  assert.equal(hu.outbound.streamSettings.tlsSettings.serverName, 'hu.example.com');
  const huSet = clone(huSrc);
  huSet.outbound.streamSettings.httpupgradeSettings.host = 'front.example.org';
  assert.equal(applyTarget(huSet, { addr: '104.16.1.2' }).outbound.streamSettings.httpupgradeSettings.host, 'front.example.org');
  // only blocks that exist: a tcp stream gains none of them
  const tcp = applyTarget(F.TROJAN_TCP_TLS, { addr: '1.2.3.4' }).outbound.streamSettings;
  assert.deepEqual(Object.keys(tcp).sort(), ['network', 'security', 'tlsSettings']);
});

/* ----------------------------------- SNI ----------------------------------- */

test('SNI over TLS: serverName becomes it, the Host stays the original name (fronting); a verifyPeerCertByName follows it', () => {
  const src = clone(F.VLESS_WS_TLS);
  src.outbound.streamSettings.wsSettings.headers = {};
  src.outbound.streamSettings.tlsSettings.serverName = '';
  const before = clone(src);
  const out = applyTarget(src, { addr: '104.16.1.2', port: 2053, sni: 'cover.example.org' });
  const st = out.outbound.streamSettings;
  assert.equal(st.tlsSettings.serverName, 'cover.example.org');
  assert.equal(st.wsSettings.headers.Host, 'a.example.com', 'the Host is the original name, not the SNI');
  assert.equal('verifyPeerCertByName' in st.tlsSettings, false, 'none is added where there was none');
  assert.deepEqual(dialOf(out), { addr: '104.16.1.2', port: 2053, sni: 'cover.example.org', host: 'a.example.com' });
  assert.deepEqual(src, before);

  const vcn = clone(F.VLESS_WS_TLS);
  vcn.outbound.streamSettings.tlsSettings.verifyPeerCertByName = 'a.example.com';
  assert.equal(applyTarget(vcn, { sni: 'cover.example.org' }).outbound.streamSettings.tlsSettings.verifyPeerCertByName, 'cover.example.org');

  // an SNI alone: the address stays, the Host is filled from it first
  const only = applyTarget(src, { sni: 'cover.example.org' });
  assert.equal(only.outbound.settings.vnext[0].address, 'a.example.com');
  assert.equal(only.outbound.streamSettings.wsSettings.headers.Host, 'a.example.com');
  assert.equal(only.outbound.streamSettings.tlsSettings.serverName, 'cover.example.org');

  // trojan over TLS takes one too
  assert.equal(applyTarget(F.TROJAN_TCP_TLS, { addr: '1.1.1.1', sni: 'x.example.org' }).outbound.streamSettings.tlsSettings.serverName, 'x.example.org');
});

test('SNI on MASQUE: verifyPeerCertByName is the SNI always — a cover domain is checked by its own name', () => {
  const h2 = MASQUE_H2();
  assert.equal(h2.outbound.streamSettings.tlsSettings.verifyPeerCertByName, 'm.example.com');
  const out = applyTarget(h2, { addr: '104.16.1.2', sni: 'other-cover.example' });
  assert.equal(out.outbound.settings.address, '104.16.1.2');
  assert.equal(out.outbound.streamSettings.tlsSettings.serverName, 'other-cover.example');
  assert.equal(out.outbound.streamSettings.tlsSettings.verifyPeerCertByName, 'other-cover.example');
  assert.deepEqual(out.outbound.streamSettings.tlsSettings.alpn, ['h2'], 'still HTTP/2');

  const warp = WARP();
  const before = clone(warp);
  const w = applyTarget(warp, { addr: '162.159.198.2', port: 4443, sni: 'cover.example.org' });
  assert.deepEqual(w.outbound.settings, { address: '162.159.198.2', port: 4443 });
  assert.deepEqual(w.outbound.streamSettings.tlsSettings, { serverName: 'cover.example.org', verifyPeerCertByName: 'cover.example.org' });
  assert.deepEqual(w.outbound.streamSettings.masqueSettings, warp.outbound.streamSettings.masqueSettings, 'the WARP account is kept');
  assert.deepEqual(warp, before);
  // no SNI: nothing is added to an IP-dialled WARP config
  assert.deepEqual(applyTarget(warp, { addr: '162.159.198.9' }).outbound.streamSettings.tlsSettings, {});
});

test('SNI on Hysteria2: serverName becomes it', () => {
  const out = applyTarget(HY2(), { addr: '2606:4700::1111', port: 8443, sni: 'cover.example.org' });
  assert.deepEqual(out.outbound.settings, { version: 2, address: '2606:4700::1111', port: 8443 });
  assert.equal(out.outbound.streamSettings.tlsSettings.serverName, 'cover.example.org');
  assert.equal('verifyPeerCertByName' in out.outbound.streamSettings.tlsSettings, false);
  assert.equal(out.outbound.protocol, 'hysteria');
  assert.equal(out.protocol, 'hysteria2');
});

test('refusals: an SNI for REALITY, ECH, no TLS or WireGuard says why; socks, http and malformed records are unsupported', () => {
  throwsCode(() => applyTarget(REALITY(), { addr: '1.1.1.1', sni: 'x.example.org' }), 'reality');
  throwsCode(() => applyTarget(ECH(), { addr: '1.1.1.1', sni: 'x.example.org' }), 'ech');
  throwsCode(() => applyTarget(PLAIN_WS(), { addr: '1.1.1.1', sni: 'x.example.org' }), 'notls');
  throwsCode(() => applyTarget(F.SS_TCP, { sni: 'x.example.org' }), 'notls');
  throwsCode(() => applyTarget(F.WG_BAD_MASK, { addr: '1.1.1.1', sni: 'x.example.org' }), 'notls');
  const echHy2 = parseLink('hy2://pass@h.example:443?sni=h.example&ech=AEX%2Bexample#x');
  throwsCode(() => applyTarget(echHy2, { sni: 'x.example.org' }), 'ech');
  // without an SNI the address still goes in
  assert.equal(applyTarget(REALITY(), { addr: '1.1.1.1' }).outbound.settings.vnext[0].address, '1.1.1.1');
  assert.equal(applyTarget(ECH(), { addr: '1.1.1.1' }).outbound.streamSettings.tlsSettings.echConfigList, 'cloudflare-ech.com+udp://1.1.1.1');
  assert.equal(applyTarget(PLAIN_WS(), { addr: '1.1.1.1' }).outbound.streamSettings.wsSettings.headers.Host, 'p.example.com');

  throwsCode(() => withAddress(SOCKS(), '1.1.1.1'), 'unsupported', /unsupported protocol/);
  const http = F.server('sv-h', 'H', 'http', 'h.example.com', 8080, { protocol: 'http', settings: { servers: [{ address: 'h.example.com', port: 8080 }] } });
  throwsCode(() => withAddress(http, '1.1.1.1'), 'unsupported', /unsupported protocol/);
  const broken = F.server('sv-b', 'B', 'vless', 'b.example.com', 443, { protocol: 'vless', settings: {} });
  throwsCode(() => withAddress(broken, '1.1.1.1'), 'unsupported', /unsupported protocol/);
  const noPeer = F.server('sv-w', 'W', 'wireguard', 'w.example.com', 51820, { protocol: 'wireguard', settings: { secretKey: 'k', peers: [] } });
  throwsCode(() => withAddress(noPeer, '1.1.1.1'), 'unsupported', /unsupported protocol/);
  throwsCode(() => withAddress(null, '1.1.1.1'), 'unsupported', /unsupported protocol/);
  throwsCode(() => withAddress({ protocol: 'vless' }, '1.1.1.1'), 'unsupported', /unsupported protocol/);
  throwsCode(() => applyTarget(SOCKS(), { sni: 'x.example.org' }), 'unsupported');
});

test('sniSupport: ok for TLS (vless, trojan, hysteria2, MASQUE, a WARP one), a code and a reason otherwise', () => {
  for (const s of [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS, HY2(), MASQUE_H2(), MASQUE_H3(), WARP()]) assert.deepEqual(sniSupport(s), { ok: true }, s.name);
  const cases = [[REALITY(), 'reality'], [ECH(), 'ech'], [PLAIN_WS(), 'notls'], [F.SS_TCP, 'notls'], [F.WG_BAD_MASK, 'notls'], [SOCKS(), 'unsupported'], [null, 'unsupported'], [{}, 'unsupported']];
  for (const [s, code] of cases) {
    const r = sniSupport(s);
    assert.equal(r.ok, false, code);
    assert.equal(r.code, code);
    assert.equal(typeof r.reason, 'string');
    assert.ok(r.reason.length > 10);
  }
  // an ECH config list as an array counts too, an empty one does not
  const arr = clone(F.VLESS_WS_TLS);
  arr.outbound.streamSettings.tlsSettings.echConfigList = ['AEX+'];
  assert.equal(sniSupport(arr).code, 'ech');
  arr.outbound.streamSettings.tlsSettings.echConfigList = '';
  assert.deepEqual(sniSupport(arr), { ok: true });
});

/* -------------------------------- JSON servers -------------------------------- */

const jsonServer = (config) => {
  const r = importJson(JSON.stringify(config));
  assert.equal(r.errors.length, 0, JSON.stringify(r.errors));
  assert.equal(r.servers.length, 1);
  return r.servers[0];
};
const MAIN = (stream) => ({
  tag: 'proxy', protocol: 'vless',
  settings: { vnext: [{ address: 'j.example.com', port: 443, users: [{ id: 'u', encryption: 'none' }] }] },
  streamSettings: Object.assign({ network: 'ws', security: 'tls', tlsSettings: { serverName: '' }, wsSettings: { path: '/j' } }, stream || {})
});
const FRAG = { tag: 'frag', protocol: 'freedom', settings: { fragment: { packets: 'tlshello', length: '100-200', interval: '10-20' } } };
const HOP = { tag: 'hop', protocol: 'trojan', settings: { servers: [{ address: 'hop.example.com', port: 443, password: 'pw' }] }, streamSettings: { network: 'tcp', security: 'tls' } };

test('a JSON server through a fragment helper: the target goes into its main outbound — and into its config', () => {
  const src = jsonServer({ remarks: 'J', outbounds: [MAIN({ sockopt: { dialerProxy: 'frag' } }), FRAG, { tag: 'direct', protocol: 'freedom' }] });
  assert.equal(src.source, 'json');
  assert.deepEqual(src.extraOutbounds.map((o) => o.tag), ['frag']);
  const before = clone(src);
  assert.deepEqual(dialOf(src), { addr: 'j.example.com', port: 443, sni: 'j.example.com', host: '' });
  assert.equal(transportOf(src), 'tcp');
  assert.deepEqual(sniSupport(src), { ok: true });

  const out = applyTarget(src, { addr: '104.16.1.2', port: 2053, sni: 'cover.example.org' });
  assert.deepEqual(out.outbound.settings.vnext[0].address, '104.16.1.2');
  assert.deepEqual(out.outbound.settings.vnext[0].port, 2053);
  assert.equal(out.outbound.streamSettings.sockopt.dialerProxy, 'frag', 'still through the fragment dialer');
  assert.equal(out.outbound.streamSettings.tlsSettings.serverName, 'cover.example.org');
  assert.equal(out.outbound.streamSettings.wsSettings.headers.Host, 'j.example.com');
  assert.equal(out.outbound.tag, undefined);
  assert.deepEqual([out.address, out.port], ['104.16.1.2', 2053]);
  assert.deepEqual(out.extraOutbounds, src.extraOutbounds);
  assert.equal(out.raw, src.raw, 'raw stays the provider\'s text');
  // the config the record carries says the same: its main outbound, tag kept, the rest as it was
  assert.deepEqual(out.json.outbounds[0], Object.assign({ tag: 'proxy' }, out.outbound));
  assert.deepEqual(out.json.outbounds.slice(1), src.json.outbounds.slice(1));
  assert.deepEqual(src, before, 'the input is untouched');
});

test('a JSON server with a flat settings shape takes the target there', () => {
  const flat = {
    tag: 'proxy', protocol: 'vless',
    settings: { address: 'f.example.com', port: 443, id: 'u', encryption: 'none' },
    streamSettings: { network: 'xhttp', security: 'tls', tlsSettings: { serverName: 'f.example.com' }, xhttpSettings: { path: '/x' } }
  };
  const src = jsonServer({ outbounds: [flat] });
  const out = applyTarget(src, { addr: '2606:4700::1111', port: 8443 });
  assert.deepEqual(out.outbound.settings, { address: '2606:4700::1111', port: 8443, id: 'u', encryption: 'none' });
  assert.equal(out.outbound.streamSettings.xhttpSettings.host, 'f.example.com');
  assert.deepEqual(dialOf(out), { addr: '2606:4700::1111', port: 8443, sni: 'f.example.com', host: 'f.example.com' });
});

test('a JSON chain is refused: the main outbound dials through another proxy (dialerProxy, proxySettings, or a freedom that does)', () => {
  const viaDialer = jsonServer({ outbounds: [MAIN({ sockopt: { dialerProxy: 'hop' } }), HOP] });
  throwsCode(() => applyTarget(viaDialer, { addr: '1.1.1.1' }), 'json-chain');
  throwsCode(() => withAddress(viaDialer, '1.1.1.1'), 'json-chain');
  const viaProxySettings = jsonServer({ outbounds: [Object.assign(MAIN(), { proxySettings: { tag: 'hop' } }), HOP] });
  throwsCode(() => applyTarget(viaProxySettings, { addr: '1.1.1.1' }), 'json-chain');
  const fragThenHop = Object.assign(clone(FRAG), { streamSettings: { sockopt: { dialerProxy: 'hop' } } });
  const viaFreedom = jsonServer({ outbounds: [MAIN({ sockopt: { dialerProxy: 'frag' } }), fragThenHop, HOP] });
  throwsCode(() => applyTarget(viaFreedom, { addr: '1.1.1.1' }), 'json-chain');
  // a tag that names no outbound is a direct dial
  const dangling = jsonServer({ outbounds: [MAIN({ sockopt: { dialerProxy: 'gone' } })] });
  assert.equal(applyTarget(dangling, { addr: '1.1.1.1' }).outbound.settings.vnext[0].address, '1.1.1.1');
});

/* ---------------------------- dialOf, transportOf ---------------------------- */

test('dialOf: what each config dials today — address, port, the SNI it sends, the fronting Host', () => {
  assert.deepEqual(dialOf(F.VLESS_WS_TLS), { addr: 'a.example.com', port: 443, sni: 'a.example.com', host: 'a.example.com' });
  assert.deepEqual(dialOf(VMESS_WS()), { addr: 'v.example.com', port: 8080, sni: '', host: '' });
  assert.deepEqual(dialOf(F.TROJAN_TCP_TLS), { addr: 'b.example.com', port: 443, sni: 'b.example.com', host: '' });
  assert.deepEqual(dialOf(F.SS_TCP), { addr: 'c.example.com', port: 8388, sni: '', host: '' });
  assert.deepEqual(dialOf(HY2()), { addr: 'h.example', port: 443, sni: 'h.example', host: '' });
  assert.deepEqual(dialOf(MASQUE_H2()), { addr: 'm.example.com', port: 443, sni: 'cover.example', host: '' });
  assert.deepEqual(dialOf(MASQUE_H3()), { addr: 'm.example.com', port: 8443, sni: 'm.example.com', host: '' }, 'no serverName: the name it dials');
  assert.deepEqual(dialOf(WARP()), { addr: '162.159.198.1', port: 443, sni: '', host: '' });
  assert.deepEqual(dialOf(F.WG_BAD_MASK), { addr: 'd.example.com', port: 51820, sni: '', host: '' });
  assert.deepEqual(dialOf(WG_V6()), { addr: '2606:4700::1', port: 2408, sni: '', host: '' });
  assert.deepEqual(dialOf(REALITY()), { addr: 'r.example.com', port: 443, sni: 'www.microsoft.com', host: '' });
  assert.deepEqual(dialOf(ECH()), { addr: 'e.example.com', port: 443, sni: 'e.example.com', host: '' });
  assert.deepEqual(dialOf(PLAIN_WS()), { addr: 'p.example.com', port: 80, sni: '', host: '' });
  assert.deepEqual(dialOf(SOCKS()), { addr: 's.example.com', port: 1080, sni: '', host: '' }, 'unsupported: the record\'s own fields');
  const hu = createServer({ protocol: 'vless', name: 'hu', address: '1.2.3.4', port: 443, uuid: 'u', network: 'httpupgrade', security: 'tls', host: 'hu.example.com', sni: 'hu.example.com' });
  assert.deepEqual(dialOf(hu), { addr: '1.2.3.4', port: 443, sni: 'hu.example.com', host: 'hu.example.com' });
  const ipTls = clone(F.TROJAN_TCP_TLS);
  ipTls.outbound.settings.servers[0].address = '9.9.9.9';
  ipTls.outbound.streamSettings.tlsSettings.serverName = '';
  assert.equal(dialOf(ipTls).sni, '', 'an IP sends no SNI');
  const grpc = createServer({ protocol: 'vless', name: 'g', address: 'g.example.com', port: 443, uuid: 'u', network: 'grpc', security: 'tls', path: 'svc', host: 'auth.example.com' });
  assert.equal(dialOf(grpc).host, 'auth.example.com');
  const xh = createServer({ protocol: 'vless', name: 'x', address: 'x.example.com', port: 443, uuid: 'u', network: 'xhttp', security: 'tls', host: 'xh.example.com' });
  assert.equal(dialOf(xh).host, 'xh.example.com');
  const h2 = F.server('h2', 'h2', 'vless', 'h.example.com', 443, { protocol: 'vless', settings: { vnext: [{ address: 'h.example.com', port: 443, users: [] }] }, streamSettings: { network: 'h2', security: 'tls', httpSettings: { host: ['h2a.example.com', 'h2b.example.com'] }, tlsSettings: {} } });
  assert.equal(dialOf(h2).host, 'h2a.example.com');
  const masqueHost = MASQUE_H3();
  masqueHost.outbound.streamSettings.masqueSettings.host = 'mh.example.com';
  assert.equal(dialOf(masqueHost).host, 'mh.example.com');
});

test('transportOf: UDP for Hysteria2, WireGuard, mKCP and MASQUE over HTTP/3; TCP for the rest and MASQUE over HTTP/2', () => {
  assert.equal(transportOf(F.VLESS_WS_TLS), 'tcp');
  assert.equal(transportOf(VMESS_WS()), 'tcp');
  assert.equal(transportOf(F.TROJAN_TCP_TLS), 'tcp');
  assert.equal(transportOf(F.SS_TCP), 'tcp');
  assert.equal(transportOf(REALITY()), 'tcp');
  assert.equal(transportOf(HY2()), 'udp');
  assert.equal(transportOf(F.WG_BAD_MASK), 'udp');
  assert.equal(transportOf(WG_V6()), 'udp');
  assert.equal(transportOf(createServer({ protocol: 'vmess', name: 'k', address: 'k.example.com', port: 443, uuid: 'u', network: 'kcp' })), 'udp');
  assert.equal(transportOf(MASQUE_H2()), 'tcp');
  assert.equal(transportOf(MASQUE_H3()), 'udp');
  assert.equal(transportOf(WARP()), 'udp');
  const both = MASQUE_H2();
  both.outbound.streamSettings.tlsSettings.alpn = ['h3', 'h2'];
  assert.equal(transportOf(both), 'udp', 'h3 beside h2 is HTTP/3');
  assert.equal(transportOf(jsonServer({ outbounds: [MAIN()] })), 'tcp');
});
