'use strict';
/**
 * Server config builder (plus, Server tab). The properties that matter: the
 * inbound objects are exactly what both cores accept (pinned against
 * `xray run -test` on the official 26.3.27 and the patterniha 26.9.1 cores),
 * the routing rule order is load-bearing, a disabled thing is simply absent,
 * the reverse pair is the VLESS reverse proxy (the legacy bridges/portals
 * block is gone from the 26.9 fork), and validation names the field it
 * complains about.
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const X = require('../src/main/xserver/config');
const { parseLink } = require('../src/main/parser');
const F = require('./fixtures');

const UUID_A = '5d1a7e3c-4b0f-4a6e-9c1d-1f2e3d4c5b6a';
const UUID_B = '6d1a7e3c-4b0f-4a6e-9c1d-1f2e3d4c5b6a';
const PRIV = 'kOp0Yl1o8m6ZgFh3EiXJ5gMt3dY8hbz2j6wMv3aEp2A';
const PUB = 'D5UJIsDIIYFaaZxWaOsbUmB-uLE2OgOV1r-qyBHIsyI';
const SHORT = '0123456789abcdef';
const SERVER_KEY = Buffer.alloc(16, 1).toString('base64');
const USER_KEY = Buffer.alloc(16, 2).toString('base64');
const SNIFF = { enabled: true, destOverride: ['http', 'tls', 'quic'] };
const PORTAL_LINK = `vless://${UUID_B}@203.0.113.9:47450?encryption=none&type=tcp&security=none#portal`;

/* ----------------------------- fixtures ----------------------------- */

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

/** The golden inbound models, by name. Each is one enabled inbound with one enabled client. */
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

function model(over) {
  return X.normalizeModel(Object.assign({ publicAddress: 'vpn.example.com' }, over || {}));
}

const build = (m, opts) => X.buildServerConfig(m, Object.assign({ apiPort: 10095, servers: [], geoAvailable: true }, opts || {}));
const tagsOf = (c) => c.outbounds.map(o => o.tag);
const errorsAt = (r, path) => r.errors.filter(e => e.path === path);
const hasError = (r, path) => errorsAt(r, path).length > 0;

/* ----------------------------- normalize ----------------------------- */

test('normalizeModel({}) is the default model, and it never throws on garbage', () => {
  assert.deepEqual(X.normalizeModel({}), X.DEFAULT_MODEL);
  assert.deepEqual(X.normalizeModel(null), X.DEFAULT_MODEL);
  assert.deepEqual(X.normalizeModel('nonsense'), X.DEFAULT_MODEL);
  assert.deepEqual(X.normalizeModel({ inbounds: 'x', reverse: 7, exit: null }), X.DEFAULT_MODEL);
  assert.deepEqual(X.DEFAULT_MODEL.inbounds, []);
  assert.equal(X.DEFAULT_MODEL.reverse.role, 'off');
  assert.equal(X.DEFAULT_MODEL.exit.type, 'direct');
  assert.equal(X.DEFAULT_MODEL.blockPrivate, true);
  assert.equal(X.DEFAULT_MODEL.blockTorrent, false);
});

test('normalizeModel fills every missing inbound and client field and is idempotent', () => {
  const m = X.normalizeModel({ inbounds: [{ id: 'a1b2c3d4e5f60001', remark: 'Half', protocol: 'trojan', clients: [{ id: 'c1', email: 'bob', password: 'x' }] }] });
  const i = m.inbounds[0];
  assert.equal(i.tag, 'half-a1b2', 'a missing tag is derived from remark + id');
  assert.equal(i.enabled, true);
  assert.equal(i.listen, '0.0.0.0');
  assert.equal(i.port, 443);
  assert.equal(i.network, 'tcp');
  assert.equal(i.security, 'none');
  assert.deepEqual(i.tls, { certFile: '', keyFile: '', serverName: '', alpn: ['h2', 'http/1.1'] });
  assert.deepEqual(i.reality, { dest: 'www.microsoft.com:443', serverNames: ['www.microsoft.com'], privateKey: '', publicKey: '', shortIds: [] });
  assert.deepEqual(i.ss, { method: '2022-blake3-aes-128-gcm', password: '' });
  assert.equal(i.sniffing, true);
  const c = i.clients[0];
  assert.deepEqual(c, { id: 'c1', enabled: true, email: 'bob', uuid: '', password: 'x', flow: '', expiresAt: 0, quotaBytes: 0, limitIp: 0, note: '', used: { up: 0, down: 0 }, disabledBy: '' });
  assert.deepEqual(X.normalizeModel(m), m, 'a second pass changes nothing');
  const full = model({ inbounds: Object.values(GOLDEN), reverse: { role: 'bridge', bridge: { via: 'link', link: PORTAL_LINK } } });
  assert.deepEqual(X.normalizeModel(full), full);
});

test('normalizeModel copies: the input is never mutated and the output is not shared', () => {
  const raw = { inbounds: [{ id: 'a1b2c3d4e5f60001', remark: 'R', clients: [] }] };
  const m = X.normalizeModel(raw);
  assert.equal('tag' in raw.inbounds[0], false);
  m.inbounds[0].clients.push({});
  assert.equal(raw.inbounds[0].clients.length, 0);
});

test('normalizeModel gives an inbound without an id a fresh one, and a client too', () => {
  const m = X.normalizeModel({ inbounds: [{ remark: 'R', clients: [{ email: 'a' }] }] });
  assert.match(m.inbounds[0].id, /^[0-9a-f]{16}$/);
  assert.match(m.inbounds[0].clients[0].id, /^[0-9a-f]{16}$/);
  assert.match(m.inbounds[0].tag, /^r-[0-9a-f]{4}$/);
});

/* ----------------------------- golden inbounds ----------------------------- */

test('golden: vless + tcp + reality carries the vision flow and the server-side reality block', () => {
  const c = build(model({ inbounds: [GOLDEN['vless-tcp-reality']] }));
  assert.deepEqual(c.inbounds, [{
    tag: 'vless-reality-a1b2', listen: '0.0.0.0', port: 443, protocol: 'vless',
    settings: { clients: [{ id: UUID_A, email: 'alice', flow: 'xtls-rprx-vision' }], decryption: 'none' },
    streamSettings: {
      network: 'tcp', security: 'reality',
      realitySettings: { show: false, target: 'www.microsoft.com:443', xver: 0, serverNames: ['www.microsoft.com'], privateKey: PRIV, shortIds: [SHORT] }
    },
    sniffing: SNIFF
  }]);
});

test('golden: vless + ws + tls', () => {
  const c = build(model({ inbounds: [GOLDEN['vless-ws-tls']] }));
  assert.deepEqual(c.inbounds, [{
    tag: 'vless-ws-a1b2', listen: '0.0.0.0', port: 8443, protocol: 'vless',
    settings: { clients: [{ id: UUID_A, email: 'alice' }], decryption: 'none' },
    streamSettings: {
      network: 'ws', security: 'tls',
      wsSettings: { path: '/ws', host: 'cdn.example.com' },
      tlsSettings: { certificates: [{ certificateFile: 'C:/certs/a.crt', keyFile: 'C:/certs/a.key' }], serverName: 'a.example.com', alpn: ['h2', 'http/1.1'] }
    },
    sniffing: SNIFF
  }]);
});

test('golden: vless + grpc + tls', () => {
  const c = build(model({ inbounds: [GOLDEN['vless-grpc-tls']] }));
  assert.deepEqual(c.inbounds[0].streamSettings, {
    network: 'grpc', security: 'tls',
    grpcSettings: { serviceName: 'svc' },
    tlsSettings: { certificates: [{ certificateFile: 'C:/certs/a.crt', keyFile: 'C:/certs/a.key' }], serverName: 'a.example.com', alpn: ['h2', 'http/1.1'] }
  });
  assert.equal(c.inbounds[0].tag, 'vless-grpc-a1b2');
});

test('golden: vless + xhttp + none', () => {
  const c = build(model({ inbounds: [GOLDEN['vless-xhttp-none']] }));
  assert.deepEqual(c.inbounds[0].streamSettings, { network: 'xhttp', security: 'none', xhttpSettings: { path: '/x', host: 'x.example.com' } });
  assert.deepEqual(c.inbounds[0].settings, { clients: [{ id: UUID_A, email: 'alice' }], decryption: 'none' });
  assert.equal(c.inbounds[0].port, 80);
});

test('golden: vmess + ws + none has no decryption key and no flow', () => {
  const c = build(model({ inbounds: [GOLDEN['vmess-ws-none']] }));
  assert.deepEqual(c.inbounds, [{
    tag: 'vmess-ws-a1b2', listen: '0.0.0.0', port: 8080, protocol: 'vmess',
    settings: { clients: [{ id: UUID_A, email: 'alice' }] },
    streamSettings: { network: 'ws', security: 'none', wsSettings: { path: '/v', host: '' } },
    sniffing: SNIFF
  }]);
});

test('golden: trojan + tcp + tls uses the password', () => {
  const c = build(model({ inbounds: [GOLDEN['trojan-tcp-tls']] }));
  assert.deepEqual(c.inbounds, [{
    tag: 'trojan-a1b2', listen: '0.0.0.0', port: 443, protocol: 'trojan',
    settings: { clients: [{ password: 'pw-alice', email: 'alice' }] },
    streamSettings: {
      network: 'tcp', security: 'tls',
      tlsSettings: { certificates: [{ certificateFile: 'C:/certs/a.crt', keyFile: 'C:/certs/a.key' }], serverName: 'a.example.com', alpn: ['h2', 'http/1.1'] }
    },
    sniffing: SNIFF
  }]);
});

test('golden: shadowsocks 2022 is method + server key at the top, per-user keys without a method', () => {
  const c = build(model({ inbounds: [GOLDEN['ss-2022']] }));
  assert.deepEqual(c.inbounds, [{
    tag: 'ss-2022-a1b2', listen: '0.0.0.0', port: 8388, protocol: 'shadowsocks',
    settings: { method: '2022-blake3-aes-128-gcm', password: SERVER_KEY, clients: [{ email: 'alice', password: USER_KEY }], network: 'tcp,udp' },
    streamSettings: { network: 'tcp', security: 'none' },
    sniffing: SNIFF
  }]);
});

test('golden: shadowsocks AEAD is a per-client method, nothing at the top', () => {
  const c = build(model({ inbounds: [GOLDEN['ss-aead']] }));
  assert.deepEqual(c.inbounds[0].settings, { clients: [{ email: 'alice', password: 'pw-alice', method: 'aes-256-gcm' }], network: 'tcp,udp' });
  assert.equal(c.inbounds[0].tag, 'ss-aead-a1b2');
});

test('the vision flow is only emitted where the core honours it (vless, raw tcp, tls or reality)', () => {
  const ws = build(model({ inbounds: [inbound({ network: 'ws', path: '/w', clients: [client({ flow: 'xtls-rprx-vision' })] })] }));
  assert.deepEqual(ws.inbounds[0].settings.clients, [{ id: UUID_A, email: 'alice' }]);
  const none = build(model({ inbounds: [inbound({ clients: [client({ flow: 'xtls-rprx-vision' })] })] }));
  assert.deepEqual(none.inbounds[0].settings.clients, [{ id: UUID_A, email: 'alice' }]);
  const tls = build(model({ inbounds: [inbound({ security: 'tls', tls: TLS, clients: [client({ flow: 'xtls-rprx-vision' })] })] }));
  assert.deepEqual(tls.inbounds[0].settings.clients, [{ id: UUID_A, email: 'alice', flow: 'xtls-rprx-vision' }]);
});

test('sniffing off is still an explicit object', () => {
  const c = build(model({ inbounds: [inbound({ sniffing: false })] }));
  assert.deepEqual(c.inbounds[0].sniffing, { enabled: false, destOverride: ['http', 'tls', 'quic'] });
});

/* ----------------------------- top level ----------------------------- */

test('metrics, stats and policy are the shapes the stats poller already reads', () => {
  const c = build(model({ inbounds: [GOLDEN['vless-ws-tls']], logLevel: 'debug' }), { apiPort: 10095 });
  assert.deepEqual(c.log, { loglevel: 'debug' });
  assert.deepEqual(c.metrics, { tag: 'metrics', listen: '127.0.0.1:10095' });
  assert.deepEqual(c.stats, {});
  assert.deepEqual(c.policy, {
    levels: { '0': { statsUserUplink: true, statsUserDownlink: true } },
    system: { statsInboundUplink: true, statsInboundDownlink: true, statsOutboundUplink: true, statsOutboundDownlink: true }
  });
  assert.equal(c.api, undefined);
  assert.equal(c.dns, undefined, 'a server has no managed resolver');
  assert.equal(c.routing.domainStrategy, 'IPIfNonMatch');
});

test('outbounds are exit then block; a direct exit is freedom', () => {
  const c = build(model({ inbounds: [GOLDEN['vless-ws-tls']] }));
  assert.deepEqual(tagsOf(c), ['exit', 'block']);
  assert.deepEqual(c.outbounds[0], { tag: 'exit', protocol: 'freedom', settings: {} });
  assert.deepEqual(c.outbounds[1], { tag: 'block', protocol: 'blackhole', settings: { response: { type: 'http' } } });
});

test('rule order: private block first (geoip when available, the literal list when not), torrent second', () => {
  const geo = build(model({ inbounds: [GOLDEN['vless-ws-tls']], blockPrivate: true, blockTorrent: true }), { geoAvailable: true });
  assert.deepEqual(geo.routing.rules, [
    { type: 'field', ip: ['geoip:private'], outboundTag: 'block' },
    { type: 'field', protocol: ['bittorrent'], outboundTag: 'block' }
  ]);
  const noGeo = build(model({ inbounds: [GOLDEN['vless-ws-tls']], blockPrivate: true, blockTorrent: false }), { geoAvailable: false });
  assert.deepEqual(noGeo.routing.rules, [{ type: 'field', ip: require('../src/main/configBuilder').PRIVATE_IPS, outboundTag: 'block' }]);
  assert.equal(noGeo.routing.rules[0].ip.includes('127.0.0.0/8'), true);
  const off = build(model({ inbounds: [GOLDEN['vless-ws-tls']], blockPrivate: false, blockTorrent: false }));
  assert.deepEqual(off.routing.rules, [], 'no catch-all: the first outbound is the exit');
});

test('a disabled inbound and a disabled client are absent from the config', () => {
  const m = model({ inbounds: [
    inbound({ id: 'a1b2c3d4e5f60001', remark: 'On', clients: [client(), client({ id: 'c2c2c2c2c2c2c2c2', email: 'bob', uuid: UUID_B, enabled: false })] }),
    inbound({ id: 'b1b2c3d4e5f60002', remark: 'Off', port: 444, enabled: false, clients: [client({ id: 'c3c3c3c3c3c3c3c3', email: 'carol' })] })
  ] });
  const c = build(m);
  assert.deepEqual(c.inbounds.map(i => i.tag), ['on-a1b2']);
  assert.deepEqual(c.inbounds[0].settings.clients, [{ id: UUID_A, email: 'alice' }]);
});

test('an inbound with no enabled client is emitted with an empty client list', () => {
  const c = build(model({ inbounds: [inbound({ clients: [] })] }));
  assert.deepEqual(c.inbounds[0].settings.clients, []);
});

test('exit through a stored server clones its outbound with cloneOut semantics', () => {
  const PIN = 'ab11bf7ac877baa539294f5a3c864b8ed43e6fe3a9a8230fc2db7fff85c27fde';
  const stored = Object.assign({}, F.VLESS_WS_TLS, { certPin: PIN.toUpperCase().match(/../g).join(':') });
  const before = JSON.stringify(stored);
  const c = build(model({ inbounds: [GOLDEN['vless-xhttp-none']], exit: { type: 'server', serverId: 'sv-vless' } }), { servers: [stored] });
  assert.deepEqual(tagsOf(c), ['exit', 'block']);
  const exit = c.outbounds[0];
  assert.equal(exit.protocol, 'vless');
  assert.equal(exit.settings.vnext[0].address, 'a.example.com');
  assert.equal(exit.streamSettings.tlsSettings.pinnedPeerCertSha256, PIN);
  assert.equal('allowInsecure' in exit.streamSettings.tlsSettings, false);
  assert.equal(JSON.stringify(stored), before, 'the stored record is not touched');
});

test('exit through a stored server carrying a fragment marker gets the anti-DPI dialer', () => {
  const frag = F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' });
  const c = build(model({ inbounds: [GOLDEN['vless-xhttp-none']], exit: { type: 'server', serverId: 'sv-frag' } }), { servers: [frag] });
  assert.deepEqual(tagsOf(c), ['exit', 'block', 'dpi-1']);
  assert.equal(c.outbounds[0].streamSettings.sockopt.dialerProxy, 'dpi-1');
  assert.equal('_fragment' in c.outbounds[0], false);
  assert.equal(c.outbounds[2].settings.fragment.packets, 'tlshello');
});

test('exit through an unknown server falls back to freedom (validation is what reports it)', () => {
  const c = build(model({ inbounds: [GOLDEN['vless-xhttp-none']], exit: { type: 'server', serverId: 'nope' } }), { servers: [] });
  assert.deepEqual(c.outbounds[0], { tag: 'exit', protocol: 'freedom', settings: {} });
});

/* ----------------------------- reverse ----------------------------- */

test('bridge via link: the interconn outbound is the flat VLESS form with reverse.tag, and the bridge rule is last', () => {
  const c = build(model({ inbounds: [GOLDEN['vless-ws-tls']], blockTorrent: true, reverse: { role: 'bridge', bridge: { via: 'link', link: PORTAL_LINK } } }));
  assert.deepEqual(tagsOf(c), ['exit', 'block', 'interconn']);
  assert.deepEqual(c.outbounds[2], {
    tag: 'interconn', protocol: 'vless',
    settings: { address: '203.0.113.9', port: 47450, id: UUID_B, flow: '', encryption: 'none', reverse: { tag: 'bridge' } },
    streamSettings: { network: 'tcp', security: 'none' }
  });
  assert.equal('vnext' in c.outbounds[2].settings, false, 'the core refuses reverse inside vnext users');
  assert.deepEqual(c.routing.rules, [
    { type: 'field', ip: ['geoip:private'], outboundTag: 'block' },
    { type: 'field', protocol: ['bittorrent'], outboundTag: 'block' },
    { type: 'field', inboundTag: ['bridge'], outboundTag: 'exit' }
  ]);
  assert.equal(c.reverse, undefined, 'no legacy reverse block: the 26.9 fork refuses it');
  // the 26.9 core blocks reversed traffic in freedom unless a final rule allows it (probe-reverse.js)
  assert.deepEqual(c.outbounds[0].settings, { finalRules: [{ action: 'allow' }] }, 'a bridge exit opts in to carrying the portal traffic');
});

test('only a bridge exit carries the freedom allow rule; a plain server or a portal does not', () => {
  assert.deepEqual(build(model({ inbounds: [GOLDEN['vless-ws-tls']] })).outbounds[0].settings, {});
});

test('bridge via a stored server clones its stream settings (pin applied, allowInsecure gone) into the flat form', () => {
  const stored = Object.assign({}, F.VLESS_WS_TLS, { certPin: 'a'.repeat(64) });
  const c = build(model({ inbounds: [], reverse: { role: 'bridge', bridge: { via: 'server', serverId: 'sv-vless' } } }), { servers: [stored] });
  const ic = c.outbounds[2];
  assert.equal(ic.tag, 'interconn');
  assert.deepEqual(ic.settings, { address: 'a.example.com', port: 443, id: 'uuid-a', flow: '', encryption: 'none', reverse: { tag: 'bridge' } });
  assert.equal(ic.streamSettings.network, 'ws');
  assert.deepEqual(ic.streamSettings.wsSettings, { path: '/ws', headers: { Host: 'a.example.com' } });
  assert.equal(ic.streamSettings.tlsSettings.pinnedPeerCertSha256, 'a'.repeat(64));
  assert.equal('allowInsecure' in ic.streamSettings.tlsSettings, false);
  assert.deepEqual(c.routing.rules.at(-1), { type: 'field', inboundTag: ['bridge'], outboundTag: 'exit' });
});

test('bridge with a reality + vision portal link keeps the flow and the reality client block', () => {
  const link = `vless://${UUID_B}@203.0.113.9:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=${PUB}&sid=${SHORT}#p`;
  const c = build(model({ reverse: { role: 'bridge', bridge: { via: 'link', link } } }));
  const ic = c.outbounds[2];
  assert.equal(ic.settings.flow, 'xtls-rprx-vision');
  assert.equal(ic.streamSettings.realitySettings.publicKey, PUB);
  assert.equal(ic.streamSettings.realitySettings.shortId, SHORT);
});

test('bridge with a fragment-marked link gets the anti-DPI dialer after the interconn', () => {
  const link = `${PORTAL_LINK.split('#')[0]}&fragment=tlshello,100-200,10-20#p`;
  const c = build(model({ reverse: { role: 'bridge', bridge: { via: 'link', link } } }));
  assert.deepEqual(tagsOf(c), ['exit', 'block', 'interconn', 'dpi-1']);
  assert.equal(c.outbounds[2].streamSettings.sockopt.dialerProxy, 'dpi-1');
});

test('bridge whose target is unusable emits no interconn and no bridge rule', () => {
  const c = build(model({ inbounds: [GOLDEN['vless-ws-tls']], reverse: { role: 'bridge', bridge: { via: 'link', link: 'trojan://pw@h:443' } } }));
  assert.deepEqual(tagsOf(c), ['exit', 'block']);
  assert.equal(c.routing.rules.some(r => r.outboundTag === 'interconn' || (r.inboundTag || []).includes('bridge')), false);
});

function portalModel(over) {
  return model(Object.assign({
    inbounds: [
      inbound({ id: 'a1b2c3d4e5f60001', remark: 'Interconn', port: 47450, clients: [client({ id: 'c1c1c1c1c1c1c1c1', email: 'bridge1', uuid: UUID_B })] }),
      inbound({ id: 'b1b2c3d4e5f60002', remark: 'Users', port: 47451, network: 'ws', path: '/u', clients: [client({ id: 'c2c2c2c2c2c2c2c2', email: 'alice' })] }),
      inbound({ id: 'c1b2c3d4e5f60003', remark: 'Local', protocol: 'trojan', port: 47452, security: 'tls', tls: TLS, clients: [client({ id: 'c3c3c3c3c3c3c3c3', email: 'carol' })] })
    ],
    reverse: { role: 'portal', portal: { interconnInboundId: 'a1b2c3d4e5f60001', userInboundIds: ['b1b2c3d4e5f60002'] } }
  }, over || {}));
}

test('portal: every enabled interconn client carries reverse.tag portal; the user inbounds route to it; the rest exit locally', () => {
  const m = portalModel();
  m.inbounds[0].clients.push(client({ id: 'c4c4c4c4c4c4c4c4', email: 'bridge2', uuid: UUID_A }));
  m.inbounds[0].clients.push(client({ id: 'c5c5c5c5c5c5c5c5', email: 'bridge3', uuid: UUID_A, enabled: false }));
  const c = build(m);
  assert.deepEqual(c.inbounds.map(i => i.tag), ['interconn-a1b2', 'users-b1b2', 'local-c1b2']);
  assert.deepEqual(c.inbounds[0].settings.clients, [
    { id: UUID_B, email: 'bridge1', reverse: { tag: 'portal' } },
    { id: UUID_A, email: 'bridge2', reverse: { tag: 'portal' } }
  ]);
  assert.deepEqual(c.inbounds[1].settings.clients, [{ id: UUID_A, email: 'alice' }], 'a user inbound client has no reverse');
  assert.deepEqual(tagsOf(c), ['exit', 'block']);
  assert.deepEqual(c.routing.rules, [
    { type: 'field', ip: ['geoip:private'], outboundTag: 'block' },
    { type: 'field', inboundTag: ['users-b1b2'], outboundTag: 'portal' }
  ]);
  assert.equal(c.reverse, undefined);
});

test('portal: several user inbounds share one rule, in model order', () => {
  const m = portalModel({ reverse: { role: 'portal', portal: { interconnInboundId: 'a1b2c3d4e5f60001', userInboundIds: ['c1b2c3d4e5f60003', 'b1b2c3d4e5f60002'] } } });
  const c = build(m);
  assert.deepEqual(c.routing.rules.at(-1), { type: 'field', inboundTag: ['users-b1b2', 'local-c1b2'], outboundTag: 'portal' });
});

test('role off: nothing reverse-related is emitted even when the bridge and portal fields are filled in', () => {
  const m = portalModel({ reverse: { role: 'off', bridge: { via: 'link', link: PORTAL_LINK }, portal: { interconnInboundId: 'a1b2c3d4e5f60001', userInboundIds: ['b1b2c3d4e5f60002'] } } });
  const c = build(m);
  assert.deepEqual(tagsOf(c), ['exit', 'block']);
  assert.deepEqual(c.inbounds[0].settings.clients, [{ id: UUID_B, email: 'bridge1' }]);
  assert.equal(c.routing.rules.some(r => r.outboundTag === 'portal'), false);
});

/* ----------------------------- validation ----------------------------- */

test('the golden model validates clean', () => {
  const r = X.validateModel(model({ inbounds: Object.values(GOLDEN).map((i, n) => Object.assign({}, i, { id: `${n}1b2c3d4e5f6000${n}`, port: 20000 + n, clients: i.clients.map(c => Object.assign({}, c, { id: `c${n}c${n}c${n}c${n}c${n}c${n}c${n}c${n}`, email: `user${n}` })) })) }), { servers: [] });
  assert.deepEqual(r, { ok: true, errors: [], warnings: [] });
});

test('validation: tags must be unique, well-formed and not reserved', () => {
  const dup = X.validateModel(model({ inbounds: [inbound({ tag: 'same' }), inbound({ id: 'b1b2c3d4e5f60002', port: 444, tag: 'same', clients: [client({ id: 'c2c2c2c2c2c2c2c2', email: 'bob' })] })] }));
  assert.equal(dup.ok, false);
  assert.equal(hasError(dup, 'inbounds[1].tag'), true);
  for (const tag of ['bridge', 'portal', 'interconn', 'exit', 'block', 'metrics']) {
    assert.equal(hasError(X.validateModel(model({ inbounds: [inbound({ tag })] })), 'inbounds[0].tag'), true, tag);
  }
  assert.equal(hasError(X.validateModel(model({ inbounds: [inbound({ tag: 'Has Space' })] })), 'inbounds[0].tag'), true);
});

test('validation: emails are unique across the whole server and never empty', () => {
  const r = X.validateModel(model({ inbounds: [
    inbound({ clients: [client(), client({ id: 'c2c2c2c2c2c2c2c2', email: '' })] }),
    inbound({ id: 'b1b2c3d4e5f60002', port: 444, clients: [client({ id: 'c3c3c3c3c3c3c3c3', email: 'alice' })] })
  ] }));
  assert.equal(hasError(r, 'inbounds[0].clients[1].email'), true);
  assert.equal(hasError(r, 'inbounds[1].clients[0].email'), true);
  assert.equal(hasError(r, 'inbounds[0].clients[0].email'), false, 'the first holder of a name is fine');
});

test('validation: ports are in range and unique per listen address; a wildcard listen collides with everything', () => {
  const bad = X.validateModel(model({ inbounds: [inbound({ port: 0 }), inbound({ id: 'b1b2c3d4e5f60002', port: 70000, clients: [client({ id: 'c2c2c2c2c2c2c2c2', email: 'bob' })] })] }));
  assert.equal(hasError(bad, 'inbounds[0].port'), true);
  assert.equal(hasError(bad, 'inbounds[1].port'), true);
  const same = X.validateModel(model({ inbounds: [inbound({ listen: '127.0.0.1' }), inbound({ id: 'b1b2c3d4e5f60002', listen: '127.0.0.1', clients: [client({ id: 'c2c2c2c2c2c2c2c2', email: 'bob' })] })] }));
  assert.equal(hasError(same, 'inbounds[1].port'), true);
  const wild = X.validateModel(model({ inbounds: [inbound({ listen: '0.0.0.0' }), inbound({ id: 'b1b2c3d4e5f60002', listen: '10.0.0.1', clients: [client({ id: 'c2c2c2c2c2c2c2c2', email: 'bob' })] })] }));
  assert.equal(hasError(wild, 'inbounds[1].port'), true);
  const apart = X.validateModel(model({ inbounds: [inbound({ listen: '127.0.0.1' }), inbound({ id: 'b1b2c3d4e5f60002', listen: '10.0.0.1', clients: [client({ id: 'c2c2c2c2c2c2c2c2', email: 'bob' })] })] }));
  assert.equal(hasError(apart, 'inbounds[1].port'), false);
  const off = X.validateModel(model({ inbounds: [inbound(), inbound({ id: 'b1b2c3d4e5f60002', enabled: false, clients: [client({ id: 'c2c2c2c2c2c2c2c2', email: 'bob' })] })] }));
  assert.equal(hasError(off, 'inbounds[1].port'), false, 'a disabled inbound binds nothing');
});

test('validation: tls needs both files, reality needs key, server name and short id, and never ws', () => {
  const tls = X.validateModel(model({ inbounds: [inbound({ security: 'tls', tls: { certFile: '', keyFile: '' } })] }));
  assert.equal(hasError(tls, 'inbounds[0].tls.certFile'), true);
  assert.equal(hasError(tls, 'inbounds[0].tls.keyFile'), true);
  const re = X.validateModel(model({ inbounds: [inbound({ security: 'reality', reality: { privateKey: '', serverNames: [], shortIds: [] } })] }));
  assert.equal(hasError(re, 'inbounds[0].reality.privateKey'), true);
  assert.equal(hasError(re, 'inbounds[0].reality.serverNames'), true);
  assert.equal(hasError(re, 'inbounds[0].reality.shortIds'), true);
  const sid = X.validateModel(model({ inbounds: [inbound({ security: 'reality', reality: Object.assign({}, REALITY, { shortIds: ['xyz'] }) })] }));
  assert.equal(hasError(sid, 'inbounds[0].reality.shortIds'), true, 'a short id is even-length hex up to 16 chars');
  const ws = X.validateModel(model({ inbounds: [inbound({ security: 'reality', reality: REALITY, network: 'ws', path: '/w' })] }));
  assert.equal(hasError(ws, 'inbounds[0].network'), true);
  assert.equal(X.validateModel(model({ inbounds: [GOLDEN['vless-tcp-reality']] })).ok, true);
});

test('validation: ws and xhttp need a path starting with a slash', () => {
  for (const network of ['ws', 'xhttp']) {
    assert.equal(hasError(X.validateModel(model({ inbounds: [inbound({ network, path: '' })] })), 'inbounds[0].path'), true, network);
    assert.equal(hasError(X.validateModel(model({ inbounds: [inbound({ network, path: 'nope' })] })), 'inbounds[0].path'), true, network);
    assert.equal(hasError(X.validateModel(model({ inbounds: [inbound({ network, path: '/ok' })] })), 'inbounds[0].path'), false, network);
  }
});

test('validation: an inbound without an enabled client is a warning, not an error', () => {
  const r = X.validateModel(model({ inbounds: [inbound({ clients: [client({ enabled: false })] })] }));
  assert.equal(r.ok, true);
  assert.deepEqual(r.errors, []);
  assert.equal(r.warnings.length, 1);
  assert.equal(r.warnings[0].path, 'inbounds[0].clients');
});

test('validation: a client needs the secret its protocol uses; ss2022 keys must be exact-length base64', () => {
  const v = X.validateModel(model({ inbounds: [inbound({ clients: [client({ uuid: '' })] })] }));
  assert.equal(hasError(v, 'inbounds[0].clients[0].uuid'), true);
  const t = X.validateModel(model({ inbounds: [inbound({ protocol: 'trojan', clients: [client({ password: '' })] })] }));
  assert.equal(hasError(t, 'inbounds[0].clients[0].password'), true);
  const s = X.validateModel(model({ inbounds: [inbound({ protocol: 'shadowsocks', ss: { method: '2022-blake3-aes-128-gcm', password: 'short' }, clients: [client({ password: Buffer.alloc(32, 1).toString('base64') })] })] }));
  assert.equal(hasError(s, 'inbounds[0].ss.password'), true);
  assert.equal(hasError(s, 'inbounds[0].clients[0].password'), true, 'a 32-byte key on a 128-bit method');
  const ok = X.validateModel(model({ inbounds: [inbound({ protocol: 'shadowsocks', ss: { method: '2022-blake3-aes-256-gcm', password: Buffer.alloc(32, 1).toString('base64') }, clients: [client({ password: Buffer.alloc(32, 2).toString('base64') })] })] }));
  assert.equal(ok.ok, true);
});

test('validation: a share link cannot carry reality for vmess or any transport for shadowsocks', () => {
  const vm = X.validateModel(model({ inbounds: [inbound({ protocol: 'vmess', security: 'reality', reality: REALITY })] }));
  assert.equal(hasError(vm, 'inbounds[0].security'), true);
  const ss = X.validateModel(model({ inbounds: [inbound({ protocol: 'shadowsocks', network: 'ws', path: '/w', ss: { method: 'aes-256-gcm', password: '' } })] }));
  assert.equal(hasError(ss, 'inbounds[0].network'), true);
  const ssTls = X.validateModel(model({ inbounds: [inbound({ protocol: 'shadowsocks', security: 'tls', tls: TLS, ss: { method: 'aes-256-gcm', password: '' } })] }));
  assert.equal(hasError(ssTls, 'inbounds[0].security'), true);
});

test('validation: a vision flow outside vless raw tls/reality is a warning (the builder drops it)', () => {
  const r = X.validateModel(model({ inbounds: [inbound({ network: 'ws', path: '/w', clients: [client({ flow: 'xtls-rprx-vision' })] })] }));
  assert.equal(r.ok, true);
  assert.equal(r.warnings.some(w => w.path === 'inbounds[0].clients[0].flow'), true);
});

test('validation: unknown protocol, network, security or method', () => {
  const r = X.validateModel(model({ inbounds: [inbound({ protocol: 'wireguard', network: 'kcp', security: 'xtls' })] }));
  assert.equal(hasError(r, 'inbounds[0].protocol'), true);
  assert.equal(hasError(r, 'inbounds[0].network'), true);
  assert.equal(hasError(r, 'inbounds[0].security'), true);
  const m = X.validateModel(model({ inbounds: [inbound({ protocol: 'shadowsocks', ss: { method: 'rc4-md5', password: '' } })] }));
  assert.equal(hasError(m, 'inbounds[0].ss.method'), true);
});

test('validation: the exit server must exist', () => {
  const r = X.validateModel(model({ inbounds: [GOLDEN['vless-ws-tls']], exit: { type: 'server', serverId: 'nope' } }), { servers: [F.TROJAN_TCP_TLS] });
  assert.equal(hasError(r, 'exit.serverId'), true);
  const ok = X.validateModel(model({ inbounds: [GOLDEN['vless-ws-tls']], exit: { type: 'server', serverId: 'sv-trojan' } }), { servers: [F.TROJAN_TCP_TLS] });
  assert.equal(ok.ok, true);
});

test('validation: a bridge needs a reachable VLESS target', () => {
  const none = X.validateModel(model({ reverse: { role: 'bridge', bridge: { via: 'link', link: '' } } }));
  assert.equal(hasError(none, 'reverse.bridge.link'), true);
  const bad = X.validateModel(model({ reverse: { role: 'bridge', bridge: { via: 'link', link: 'garbage' } } }));
  assert.equal(hasError(bad, 'reverse.bridge.link'), true);
  const trojan = X.validateModel(model({ reverse: { role: 'bridge', bridge: { via: 'link', link: 'trojan://pw@h:443' } } }));
  assert.equal(hasError(trojan, 'reverse.bridge.link'), true, 'the VLESS reverse proxy rides VLESS only');
  const missing = X.validateModel(model({ reverse: { role: 'bridge', bridge: { via: 'server', serverId: 'nope' } } }), { servers: [F.VLESS_WS_TLS] });
  assert.equal(hasError(missing, 'reverse.bridge.serverId'), true);
  const notVless = X.validateModel(model({ reverse: { role: 'bridge', bridge: { via: 'server', serverId: 'sv-trojan' } } }), { servers: [F.TROJAN_TCP_TLS] });
  assert.equal(hasError(notVless, 'reverse.bridge.serverId'), true);
  assert.equal(X.validateModel(model({ reverse: { role: 'bridge', bridge: { via: 'server', serverId: 'sv-vless' } } }), { servers: [F.VLESS_WS_TLS] }).ok, true);
  assert.equal(X.validateModel(model({ reverse: { role: 'bridge', bridge: { via: 'link', link: PORTAL_LINK } } })).ok, true);
});

test('validation: a portal needs a VLESS interconn inbound with a client, user inbounds, and no overlap', () => {
  assert.equal(X.validateModel(portalModel()).ok, true);
  const overlap = X.validateModel(portalModel({ reverse: { role: 'portal', portal: { interconnInboundId: 'a1b2c3d4e5f60001', userInboundIds: ['a1b2c3d4e5f60001', 'b1b2c3d4e5f60002'] } } }));
  assert.equal(hasError(overlap, 'reverse.portal.userInboundIds'), true);
  const noUsers = X.validateModel(portalModel({ reverse: { role: 'portal', portal: { interconnInboundId: 'a1b2c3d4e5f60001', userInboundIds: [] } } }));
  assert.equal(hasError(noUsers, 'reverse.portal.userInboundIds'), true);
  const noInterconn = X.validateModel(portalModel({ reverse: { role: 'portal', portal: { interconnInboundId: '', userInboundIds: ['b1b2c3d4e5f60002'] } } }));
  assert.equal(hasError(noInterconn, 'reverse.portal.interconnInboundId'), true);
  const unknown = X.validateModel(portalModel({ reverse: { role: 'portal', portal: { interconnInboundId: 'zzz', userInboundIds: ['b1b2c3d4e5f60002', 'yyy'] } } }));
  assert.equal(hasError(unknown, 'reverse.portal.interconnInboundId'), true);
  assert.equal(hasError(unknown, 'reverse.portal.userInboundIds'), true);
  const trojanInterconn = X.validateModel(portalModel({ reverse: { role: 'portal', portal: { interconnInboundId: 'c1b2c3d4e5f60003', userInboundIds: ['b1b2c3d4e5f60002'] } } }));
  assert.equal(hasError(trojanInterconn, 'reverse.portal.interconnInboundId'), true);
  const m = portalModel();
  m.inbounds[0].enabled = false;
  m.inbounds[1].enabled = false;
  const disabled = X.validateModel(m);
  assert.equal(hasError(disabled, 'reverse.portal.interconnInboundId'), true);
  assert.equal(hasError(disabled, 'reverse.portal.userInboundIds'), true);
  const m2 = portalModel();
  m2.inbounds[0].clients[0].enabled = false;
  assert.equal(hasError(X.validateModel(m2), 'reverse.portal.interconnInboundId'), true, 'no enabled bridge client');
});

test('validation: role, exit type and via are enumerations', () => {
  const r = X.validateModel(model({ reverse: { role: 'both' }, exit: { type: 'chain' } }));
  assert.equal(hasError(r, 'reverse.role'), true);
  assert.equal(hasError(r, 'exit.type'), true);
});

/* ----------------------------- helpers ----------------------------- */

test('slugTag: lower-case a-z 0-9 and dashes, a four-char id suffix, a fallback for a remark with nothing usable', () => {
  assert.equal(X.slugTag('VLESS Reality', 'a1b2c3d4e5f60001'), 'vless-reality-a1b2');
  assert.equal(X.slugTag('  Café -- Ünïcode!!  ', 'ffee0011'), 'caf-n-code-ffee');
  assert.equal(X.slugTag('سرور من', 'deadbeef'), 'in-dead');
  assert.equal(X.slugTag('', 'deadbeef'), 'in-dead');
  assert.match(X.slugTag('x'.repeat(200), 'deadbeef'), /^x{1,32}-dead$/);
  assert.match(X.slugTag('VLESS Reality', 'A1-B2'), /^vless-reality-a1b2$/, 'the suffix is cleaned too');
});

test('randomShortId is 8 bytes of hex; randomPassword is base64 of n bytes; randomKeyFor sizes the ss2022 key', () => {
  assert.match(X.randomShortId(), /^[0-9a-f]{16}$/);
  assert.notEqual(X.randomShortId(), X.randomShortId());
  assert.equal(Buffer.from(X.randomPassword(), 'base64').length, 16);
  assert.equal(Buffer.from(X.randomPassword(24), 'base64').length, 24);
  assert.equal(Buffer.from(X.randomKeyFor('2022-blake3-aes-128-gcm'), 'base64').length, 16);
  assert.equal(Buffer.from(X.randomKeyFor('2022-blake3-aes-256-gcm'), 'base64').length, 32);
  assert.equal(Buffer.from(X.randomKeyFor('aes-256-gcm'), 'base64').length, 16);
});

test('parseX25519 reads the 26.x form and the older form, and returns null for anything else', () => {
  assert.deepEqual(X.parseX25519(`PrivateKey: ${PRIV}\r\nPassword (PublicKey): ${PUB}\r\nHash32: uFzSQf6DWMJGA2uY0O4qlPM0jNnjvLYvo4puevoKquM\r\n`), { privateKey: PRIV, publicKey: PUB });
  assert.deepEqual(X.parseX25519(`Private key: ${PRIV}\nPublic key: ${PUB}\n`), { privateKey: PRIV, publicKey: PUB });
  assert.equal(X.parseX25519('Usage: xray x25519'), null);
  assert.equal(X.parseX25519(''), null);
  assert.equal(X.parseX25519(null), null);
  assert.equal(X.parseX25519(`PrivateKey: ${PRIV}`), null, 'half a pair is no pair');
});

test('newInbound: fresh id and tag, protocol-shaped defaults, overrides win and re-slug the tag', () => {
  const v = X.newInbound('vless');
  assert.match(v.id, /^[0-9a-f]{16}$/);
  assert.equal(v.protocol, 'vless');
  assert.equal(v.security, 'reality');
  assert.equal(v.port, 443);
  assert.equal(v.remark, 'VLESS Reality');
  assert.equal(v.tag, X.slugTag(v.remark, v.id));
  assert.equal(v.reality.shortIds.length, 1);
  assert.match(v.reality.shortIds[0], /^[0-9a-f]{16}$/);
  assert.deepEqual(v.clients, []);
  assert.notEqual(X.newInbound('vless').id, v.id);
  const s = X.newInbound('shadowsocks');
  assert.equal(s.protocol, 'shadowsocks');
  assert.equal(s.security, 'none');
  assert.equal(s.network, 'tcp');
  assert.equal(s.port, 8388);
  assert.equal(s.ss.method, '2022-blake3-aes-128-gcm');
  assert.equal(Buffer.from(s.ss.password, 'base64').length, 16);
  const t = X.newInbound('trojan');
  assert.equal(t.security, 'tls');
  const m = X.newInbound('vmess');
  assert.equal(m.network, 'ws');
  assert.equal(m.security, 'none');
  const o = X.newInbound('vless', { remark: 'Mine', port: 2053 });
  assert.equal(o.port, 2053);
  assert.equal(o.tag, X.slugTag('Mine', o.id));
  assert.deepEqual(X.normalizeModel({ inbounds: [v, s, t, m, o] }).inbounds, [v, s, t, m, o], 'a fresh inbound is already normal');
});

test('newClient: fresh id, a uuid for vless/vmess, a password for trojan, a sized key for shadowsocks', () => {
  const v = X.newClient('vless');
  assert.match(v.id, /^[0-9a-f]{16}$/);
  assert.match(v.uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(v.password, '');
  assert.equal(v.enabled, true);
  assert.equal(v.email, '');
  assert.notEqual(X.newClient('vless').uuid, v.uuid);
  assert.match(X.newClient('vmess').uuid, /-/);
  const t = X.newClient('trojan');
  assert.equal(t.uuid, '');
  assert.ok(t.password.length >= 16);
  const s = X.newClient('shadowsocks', { method: '2022-blake3-aes-256-gcm' });
  assert.equal(Buffer.from(s.password, 'base64').length, 32);
  assert.equal('method' in s, false, 'the method only sizes the key');
  assert.equal(Buffer.from(X.newClient('shadowsocks').password, 'base64').length, 16);
  const o = X.newClient('vless', { email: 'bob', quotaBytes: 5 });
  assert.equal(o.email, 'bob');
  assert.equal(o.quotaBytes, 5);
  assert.deepEqual(X.normalizeModel({ inbounds: [inbound({ clients: [v, t, s, o] })] }).inbounds[0].clients, [v, t, s, o]);
});

/* ----------------------------- other side ----------------------------- */

test('otherSideSnippet for a bridge here: what the portal pastes, with placeholders for what only it knows', () => {
  const r = X.otherSideSnippet(model({ reverse: { role: 'bridge', bridge: { via: 'link', link: PORTAL_LINK } } }));
  assert.equal(r.role, 'portal');
  assert.equal(r.link, null);
  assert.deepEqual(r.snippet.inbounds, [{
    tag: '<interconn-inbound-tag>', listen: '0.0.0.0', port: 47450, protocol: 'vless',
    settings: { clients: [{ id: UUID_B, email: 'bridge', reverse: { tag: 'portal' } }], decryption: 'none' },
    streamSettings: { network: 'tcp', security: 'none' }
  }]);
  assert.deepEqual(r.snippet.routing, { rules: [{ type: 'field', inboundTag: ['<user-inbound-tag>'], outboundTag: 'portal' }] });
  assert.equal('reverse' in r.snippet, false);
  assert.equal('outbounds' in r.snippet, false);
});

test('otherSideSnippet for a bridge here: a tls or reality link becomes a server-side stream with placeholders for the secrets', () => {
  const link = `vless://${UUID_B}@203.0.113.9:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=${PUB}&sid=${SHORT}#p`;
  const r = X.otherSideSnippet(model({ reverse: { role: 'bridge', bridge: { via: 'link', link } } }));
  const st = r.snippet.inbounds[0].streamSettings;
  assert.equal(st.security, 'reality');
  assert.deepEqual(st.realitySettings.serverNames, ['www.microsoft.com']);
  assert.deepEqual(st.realitySettings.shortIds, [SHORT]);
  assert.equal(st.realitySettings.target, 'www.microsoft.com:443');
  assert.match(st.realitySettings.privateKey, /^<.*>$/);
  assert.deepEqual(r.snippet.inbounds[0].settings.clients[0], { id: UUID_B, email: 'bridge', flow: 'xtls-rprx-vision', reverse: { tag: 'portal' } });
  const stored = Object.assign({}, F.VLESS_WS_TLS);
  const r2 = X.otherSideSnippet(model({ reverse: { role: 'bridge', bridge: { via: 'server', serverId: 'sv-vless' } } }), { servers: [stored] });
  const st2 = r2.snippet.inbounds[0].streamSettings;
  assert.deepEqual(st2.wsSettings, { path: '/ws', host: 'a.example.com' });
  assert.equal(st2.tlsSettings.serverName, 'a.example.com');
  assert.match(st2.tlsSettings.certificates[0].certificateFile, /^<.*>$/);
  assert.match(st2.tlsSettings.certificates[0].keyFile, /^<.*>$/);
});

test('otherSideSnippet for a portal here: the bridge outbound, its rule, and the interconn client link', () => {
  const m = portalModel();
  const r = X.otherSideSnippet(m);
  assert.equal(r.role, 'bridge');
  assert.equal(r.link, X.clientLink(m.inbounds[0], m.inbounds[0].clients[0], m));
  assert.deepEqual(r.snippet.outbounds, [
    { tag: 'interconn', protocol: 'vless', settings: { address: 'vpn.example.com', port: 47450, id: UUID_B, flow: '', encryption: 'none', reverse: { tag: 'bridge' } }, streamSettings: { network: 'tcp', security: 'none' } },
    { tag: 'direct', protocol: 'freedom', settings: {} }
  ]);
  assert.deepEqual(r.snippet.routing, { rules: [{ type: 'field', inboundTag: ['bridge'], outboundTag: 'direct' }] });
  assert.equal('inbounds' in r.snippet, false);
  const parsed = parseLink(r.link);
  assert.equal(parsed.address, 'vpn.example.com');
  assert.equal(parsed.port, 47450);
  const other = X.otherSideSnippet(m, { address: '198.51.100.7' });
  assert.equal(other.snippet.outbounds[0].settings.address, '198.51.100.7');
  assert.equal(parseLink(other.link).address, '198.51.100.7');
});

test('otherSideSnippet for a portal here uses the first enabled interconn client and needs a public address', () => {
  const m = portalModel();
  m.inbounds[0].clients[0].enabled = false;
  m.inbounds[0].clients.push(client({ id: 'c9c9c9c9c9c9c9c9', email: 'bridge9', uuid: UUID_A }));
  assert.equal(X.otherSideSnippet(m).snippet.outbounds[0].settings.id, UUID_A);
  assert.throws(() => X.otherSideSnippet(model({ publicAddress: '' , inbounds: m.inbounds, reverse: m.reverse })), /no public address/);
  assert.throws(() => X.otherSideSnippet(portalModel({ reverse: { role: 'portal', portal: { interconnInboundId: 'zzz', userInboundIds: ['b1b2c3d4e5f60002'] } } })), /interconn/);
  assert.throws(() => X.otherSideSnippet(model({ reverse: { role: 'bridge', bridge: { via: 'link', link: '' } } })), /portal/);
});

test('otherSideSnippet with the role off has nothing to say', () => {
  assert.deepEqual(X.otherSideSnippet(model()), { role: null, snippet: null, link: null });
});

test('the exported names are exactly the S1 interface', () => {
  assert.deepEqual(Object.keys(X).sort(), [
    'DEFAULT_MODEL', 'NETWORKS', 'PROTOCOLS', 'SECURITIES', 'SS_METHODS',
    'buildServerConfig', 'clientLink', 'clientServerRecord', 'newClient', 'newInbound', 'normalizeModel',
    'otherSideSnippet', 'parseX25519', 'randomKeyFor', 'randomPassword', 'randomShortId', 'slugTag', 'validateModel'
  ]);
  assert.deepEqual(X.PROTOCOLS, ['vless', 'vmess', 'trojan', 'shadowsocks']);
  assert.deepEqual(X.NETWORKS, ['tcp', 'ws', 'grpc', 'xhttp']);
  assert.deepEqual(X.SECURITIES, ['none', 'tls', 'reality']);
  assert.deepEqual(X.SS_METHODS, ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', 'aes-256-gcm', 'aes-128-gcm', 'chacha20-ietf-poly1305']);
  assert.equal(Object.isFrozen(X.DEFAULT_MODEL), true);
});
