'use strict';
/**
 * Client links for the Server tab (plus). The property that matters: every
 * link the server hands out parses back (parser.parseLink) into an outbound
 * that dials THIS inbound — same address and port, the same secret, the same
 * transport and security details the server-side config was built from. A
 * link that fails this round trip is a client that cannot connect.
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const X = require('../src/main/xserver/config');
const { parseLink } = require('../src/main/parser');

const UUID_A = '5d1a7e3c-4b0f-4a6e-9c1d-1f2e3d4c5b6a';
const PRIV = 'kOp0Yl1o8m6ZgFh3EiXJ5gMt3dY8hbz2j6wMv3aEp2A';
const PUB = 'D5UJIsDIIYFaaZxWaOsbUmB-uLE2OgOV1r-qyBHIsyI';
const SHORT = '0123456789abcdef';
const SERVER_KEY = Buffer.alloc(16, 1).toString('base64');
const USER_KEY = Buffer.alloc(16, 2).toString('base64');

function client(over) {
  return Object.assign({ id: 'c1c1c1c1c1c1c1c1', enabled: true, email: 'alice', uuid: UUID_A, password: 'pw-alice', flow: '' }, over || {});
}
function inbound(over) {
  return Object.assign({
    id: 'a1b2c3d4e5f60001', enabled: true, remark: 'Golden', protocol: 'vless', listen: '0.0.0.0', port: 443,
    network: 'tcp', security: 'none', sniffing: true, clients: [client()]
  }, over || {});
}
const TLS = { certFile: 'C:/certs/a.crt', keyFile: 'C:/certs/a.key', serverName: 'a.example.com', alpn: ['h2', 'http/1.1'] };
const REALITY = { dest: 'www.microsoft.com:443', serverNames: ['www.microsoft.com'], privateKey: PRIV, publicKey: PUB, shortIds: [SHORT] };

const GOLDEN = {
  'vless-tcp-reality': inbound({ remark: 'VLESS Reality', security: 'reality', reality: REALITY, clients: [client({ flow: 'xtls-rprx-vision' })] }),
  'vless-ws-tls': inbound({ remark: 'VLESS WS', port: 8443, network: 'ws', path: '/ws', host: 'cdn.example.com', security: 'tls', tls: TLS }),
  'vless-grpc-tls': inbound({ remark: 'VLESS gRPC', network: 'grpc', serviceName: 'svc', security: 'tls', tls: TLS }),
  'vless-xhttp-none': inbound({ remark: 'VLESS XHTTP', port: 80, network: 'xhttp', path: '/x', host: 'x.example.com' }),
  'vmess-ws-none': inbound({ remark: 'VMess WS', protocol: 'vmess', port: 8080, network: 'ws', path: '/v', host: '' }),
  'trojan-tcp-tls': inbound({ remark: 'Trojan', protocol: 'trojan', security: 'tls', tls: TLS }),
  'ss-2022': inbound({ remark: 'SS 2022', protocol: 'shadowsocks', port: 8388, ss: { method: '2022-blake3-aes-128-gcm', password: SERVER_KEY }, clients: [client({ password: USER_KEY })] }),
  'ss-aead': inbound({ remark: 'SS AEAD', protocol: 'shadowsocks', port: 8389, ss: { method: 'aes-256-gcm', password: '' } })
};

const ADDR = 'vpn.example.com';
const m = X.normalizeModel({ publicAddress: ADDR, inbounds: Object.values(GOLDEN) });
const at = (name) => m.inbounds[Object.keys(GOLDEN).indexOf(name)];
const linkOf = (name) => X.clientLink(at(name), at(name).clients[0], m);
const back = (name) => parseLink(linkOf(name));

test('every golden link parses back to the public address and the inbound port, with the protocol and a readable name', () => {
  for (const name of Object.keys(GOLDEN)) {
    const s = back(name);
    const inb = at(name);
    assert.equal(s.protocol, inb.protocol, name);
    assert.equal(s.address, ADDR, name);
    assert.equal(s.port, inb.port, name);
    assert.equal(s.name, `${inb.remark} - alice`, name);
    const st = s.outbound.settings;
    const dial = st.vnext ? st.vnext[0] : st.servers[0];
    assert.equal(dial.address, ADDR, name);
    assert.equal(dial.port, inb.port, name);
  }
});

test('vless + tcp + reality: uuid, vision flow, public key, short id and server name', () => {
  const s = back('vless-tcp-reality');
  assert.match(linkOf('vless-tcp-reality'), /^vless:\/\//);
  const u = s.outbound.settings.vnext[0].users[0];
  assert.equal(u.id, UUID_A);
  assert.equal(u.flow, 'xtls-rprx-vision');
  assert.equal(u.encryption, 'none');
  const st = s.outbound.streamSettings;
  assert.equal(st.network, 'tcp');
  assert.equal(st.security, 'reality');
  assert.deepEqual(st.realitySettings, { serverName: 'www.microsoft.com', fingerprint: 'chrome', publicKey: PUB, shortId: SHORT, spiderX: '' });
});

test('vless + ws + tls: path, Host, server name and alpn', () => {
  const s = back('vless-ws-tls');
  const st = s.outbound.streamSettings;
  assert.equal(st.network, 'ws');
  assert.equal(st.security, 'tls');
  assert.deepEqual(st.wsSettings, { path: '/ws', headers: { Host: 'cdn.example.com' } });
  assert.equal(st.tlsSettings.serverName, 'a.example.com');
  assert.deepEqual(st.tlsSettings.alpn, ['h2', 'http/1.1']);
  assert.equal(st.tlsSettings.fingerprint, 'chrome');
  assert.equal(s.outbound.settings.vnext[0].users[0].flow, '', 'no vision over ws');
});

test('vless + grpc + tls: service name', () => {
  const st = back('vless-grpc-tls').outbound.streamSettings;
  assert.equal(st.network, 'grpc');
  assert.equal(st.grpcSettings.serviceName, 'svc');
  assert.equal(st.tlsSettings.serverName, 'a.example.com');
});

test('vless + xhttp + none: path and host', () => {
  const st = back('vless-xhttp-none').outbound.streamSettings;
  assert.equal(st.network, 'xhttp');
  assert.equal(st.security, 'none');
  assert.equal(st.xhttpSettings.path, '/x');
  assert.equal(st.xhttpSettings.host, 'x.example.com');
});

test('vmess + ws + none: id, path, no tls', () => {
  const s = back('vmess-ws-none');
  assert.match(linkOf('vmess-ws-none'), /^vmess:\/\//);
  assert.equal(s.outbound.settings.vnext[0].users[0].id, UUID_A);
  const st = s.outbound.streamSettings;
  assert.equal(st.network, 'ws');
  assert.equal(st.security, 'none');
  assert.equal(st.wsSettings.path, '/v');
});

test('trojan + tcp + tls: password and server name', () => {
  const s = back('trojan-tcp-tls');
  assert.match(linkOf('trojan-tcp-tls'), /^trojan:\/\//);
  assert.equal(s.outbound.settings.servers[0].password, 'pw-alice');
  assert.equal(s.outbound.streamSettings.security, 'tls');
  assert.equal(s.outbound.streamSettings.tlsSettings.serverName, 'a.example.com');
});

test('shadowsocks 2022: the password is serverKey:userKey; AEAD: the plain password', () => {
  const s = back('ss-2022');
  assert.match(linkOf('ss-2022'), /^ss:\/\//);
  assert.equal(s.outbound.settings.servers[0].method, '2022-blake3-aes-128-gcm');
  assert.equal(s.outbound.settings.servers[0].password, `${SERVER_KEY}:${USER_KEY}`);
  const a = back('ss-aead');
  assert.equal(a.outbound.settings.servers[0].method, 'aes-256-gcm');
  assert.equal(a.outbound.settings.servers[0].password, 'pw-alice');
});

test('the tls server name falls back to the Host, then stays empty so the client uses the address', () => {
  const noSni = X.normalizeModel({ publicAddress: ADDR, inbounds: [inbound({ network: 'ws', path: '/w', host: 'h.example.com', security: 'tls', tls: Object.assign({}, TLS, { serverName: '' }) })] });
  assert.equal(parseLink(X.clientLink(noSni.inbounds[0], noSni.inbounds[0].clients[0], noSni)).outbound.streamSettings.tlsSettings.serverName, 'h.example.com');
  const bare = X.normalizeModel({ publicAddress: ADDR, inbounds: [inbound({ security: 'tls', tls: Object.assign({}, TLS, { serverName: '', alpn: [] }) })] });
  const st = parseLink(X.clientLink(bare.inbounds[0], bare.inbounds[0].clients[0], bare)).outbound.streamSettings;
  assert.equal(st.tlsSettings.serverName, '');
  assert.equal('alpn' in st.tlsSettings, false);
});

test('clientServerRecord is a stored-server-shaped record whose outbound is what the link carries', () => {
  const inb = at('vless-ws-tls');
  const r = X.clientServerRecord(inb, inb.clients[0], m);
  assert.deepEqual(Object.keys(r).sort(), ['address', 'id', 'name', 'outbound', 'port', 'protocol']);
  assert.equal(r.id, inb.clients[0].id);
  assert.equal(r.address, ADDR);
  assert.equal(r.port, 8443);
  assert.equal(r.protocol, 'vless');
  assert.deepEqual(parseLink(linkOf('vless-ws-tls')).outbound, r.outbound, 'the link carries the whole outbound');
});

test('the address defaults to the model, an explicit one wins, and an empty one throws', () => {
  const inb = at('vless-ws-tls');
  assert.equal(parseLink(X.clientLink(inb, inb.clients[0], m, { address: '198.51.100.7' })).address, '198.51.100.7');
  assert.equal(X.clientServerRecord(inb, inb.clients[0], m, { address: '198.51.100.7' }).address, '198.51.100.7');
  const blank = X.normalizeModel({ publicAddress: '', inbounds: [GOLDEN['vless-ws-tls']] });
  assert.throws(() => X.clientLink(blank.inbounds[0], blank.inbounds[0].clients[0], blank), /^Error: no public address$/);
  assert.throws(() => X.clientServerRecord(blank.inbounds[0], blank.inbounds[0].clients[0], blank), /no public address/);
  assert.throws(() => X.clientLink(inb, inb.clients[0], m, { address: '   ' }), /no public address/);
  assert.equal(parseLink(X.clientLink(blank.inbounds[0], blank.inbounds[0].clients[0], blank, { address: 'x.example.com' })).address, 'x.example.com');
});
