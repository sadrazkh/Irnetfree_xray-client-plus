'use strict';
/**
 * Server config builder (plus, Server tab), model v2. The properties that
 * matter: the inbound objects are exactly what both cores accept (pinned
 * against `xray run -test` on the official 26.3.27 and the patterniha 26.9
 * cores), outbounds come out in the model’s order (the first is the default
 * exit), routing rules are emitted 1:1 in the model’s order, a disabled thing
 * is simply absent, the reverse pair is two tags on ordinary objects (a VLESS
 * client’s `reverseTag`, a VLESS outbound’s `reverseTag`), validation names
 * the field it complains about, and the wizards write nothing a user could
 * not have written by hand in the tables.
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

/** An inbound in the v2 shape; the tag defaults to the v1 slug so the golden tags read the same as in v2.0. */
function inbound(over) {
  const i = Object.assign({
    id: 'a1b2c3d4e5f60001', enabled: true, remark: 'Golden', protocol: 'vless', listen: '0.0.0.0', port: 443,
    network: 'tcp', security: 'none', sniffing: true, clients: [client()]
  }, over || {});
  if (!i.tag) i.tag = X.slugTag(i.remark, i.id);
  return i;
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

const out = (tag, kind, over) => Object.assign({ id: tag, tag, kind }, over || {});
const rule = (over) => Object.assign({ id: 'r-' + Math.random().toString(16).slice(2, 8) }, over || {});
const DIRECT_BLOCK = [out('direct', 'freedom'), out('block', 'blackhole')];
const PRIVATE_RULE = { id: 'rule-private', preset: 'private', ip: ['geoip:private'], outboundTag: 'block' };
const TORRENT_RULE = { id: 'rule-torrent', preset: 'torrent', protocol: ['bittorrent'], outboundTag: 'block' };

/** A v2 model: schema 2, the two plain outbounds and no rules unless given. */
function model(over) {
  return X.normalizeModel(Object.assign({ schema: 2, publicAddress: 'vpn.example.com', outbounds: DIRECT_BLOCK, routing: { rules: [] } }, over || {}));
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
  assert.deepEqual(X.normalizeModel({ inbounds: 'x', outbounds: 7, routing: null }), X.DEFAULT_MODEL);
  assert.equal(X.DEFAULT_MODEL.schema, 2);
  assert.deepEqual(X.DEFAULT_MODEL.inbounds, []);
  assert.deepEqual(X.DEFAULT_MODEL.outbounds.map(o => [o.tag, o.kind]), [['direct', 'freedom'], ['block', 'blackhole']]);
  assert.deepEqual(X.DEFAULT_MODEL.routing.rules.map(r => r.preset), ['private']);
  assert.equal(X.DEFAULT_MODEL.routing.domainStrategy, 'IPIfNonMatch');
  assert.equal(Object.isFrozen(X.DEFAULT_MODEL), true);
  assert.equal(Object.isFrozen(X.DEFAULT_MODEL.outbounds[0]), true);
});

test('normalizeModel fills every missing inbound, client, outbound and rule field and is idempotent', () => {
  const m = X.normalizeModel({ schema: 2, inbounds: [{ id: 'a1b2c3d4e5f60001', remark: 'Half', protocol: 'trojan', clients: [{ id: 'c1', email: 'bob', password: 'x' }] }], outbounds: [{ kind: 'freedom' }, { kind: 'blackhole' }, { kind: 'link', link: PORTAL_LINK, reverseTag: ' bridge ' }], routing: { rules: [{ outboundTag: 'direct', domain: 'a.com, b.com', ip: ['1.2.3.4'], port: 443, protocol: ['TLS'] }] } });
  const i = m.inbounds[0];
  assert.equal(i.tag, 'inbound-443', 'a v2 inbound without a tag is named after its port');
  assert.equal(i.enabled, true);
  assert.equal(i.listen, '0.0.0.0');
  assert.equal(i.port, 443);
  assert.equal(i.network, 'tcp');
  assert.equal(i.security, 'none');
  assert.deepEqual(i.tls, { certFile: '', keyFile: '', serverName: '', alpn: ['h2', 'http/1.1'] });
  assert.deepEqual(i.reality, { dest: 'www.cloudflare.com:443', serverNames: ['www.cloudflare.com'], privateKey: '', publicKey: '', shortIds: [] });
  assert.deepEqual(i.ss, { method: '2022-blake3-aes-128-gcm', password: '' });
  assert.equal(i.sniffing, true);
  assert.equal(i.totalBytes, 0);
  assert.equal(i.expiresAt, 0);
  assert.deepEqual(i.used, { up: 0, down: 0 });
  assert.deepEqual(i.clients[0], { id: 'c1', enabled: true, email: 'bob', uuid: '', password: 'x', flow: '', limitIp: 0, quotaBytes: 0, expiresAt: 0, resetDays: 0, resetAt: 0, comment: '', reverseTag: '', used: { up: 0, down: 0 }, disabledBy: '', lastSeenAt: 0 });
  assert.deepEqual(m.outbounds.map(o => o.tag), ['direct', 'block', 'proxy'], 'kind-shaped default tags');
  assert.match(m.outbounds[0].id, /^[0-9a-f]{16}$/);
  assert.deepEqual(m.outbounds[2], Object.assign({}, m.outbounds[2], { kind: 'link', link: PORTAL_LINK, serverId: '', reverseTag: 'bridge', enabled: true }));
  const r = m.routing.rules[0];
  assert.match(r.id, /^[0-9a-f]{16}$/);
  assert.deepEqual(r, { id: r.id, enabled: true, comment: '', inboundTags: [], outboundTag: 'direct', domain: ['a.com', 'b.com'], ip: ['1.2.3.4'], port: '443', protocol: ['tls'], network: '', preset: '' });
  assert.deepEqual(X.normalizeModel(m), m, 'a second pass changes nothing');
  const full = model({ inbounds: Object.values(GOLDEN), outbounds: DIRECT_BLOCK.concat([out('interconn', 'link', { link: PORTAL_LINK, reverseTag: 'bridge' })]), routing: { rules: [PRIVATE_RULE, TORRENT_RULE, rule({ inboundTags: ['bridge'], outboundTag: 'direct' })] } });
  assert.deepEqual(X.normalizeModel(full), full);
});

test('normalizeModel copies: the input is never mutated and the output is not shared', () => {
  const raw = { schema: 2, inbounds: [{ id: 'a1b2c3d4e5f60001', remark: 'R', clients: [] }], outbounds: [{ tag: 'direct', kind: 'freedom' }], routing: { rules: [{ inboundTags: ['x'], outboundTag: 'direct' }] } };
  const m = X.normalizeModel(raw);
  assert.equal('tag' in raw.inbounds[0], false);
  m.inbounds[0].clients.push({});
  m.routing.rules[0].inboundTags.push('y');
  assert.equal(raw.inbounds[0].clients.length, 0);
  assert.deepEqual(raw.routing.rules[0].inboundTags, ['x']);
});

test('normalizeModel gives an inbound, a client, an outbound and a rule without an id a fresh one', () => {
  const m = X.normalizeModel({ schema: 2, inbounds: [{ remark: 'R', clients: [{ email: 'a' }] }], outbounds: [{ kind: 'freedom' }], routing: { rules: [{ outboundTag: 'direct', port: '80' }] } });
  assert.match(m.inbounds[0].id, /^[0-9a-f]{16}$/);
  assert.match(m.inbounds[0].clients[0].id, /^[0-9a-f]{16}$/);
  assert.match(m.outbounds[0].id, /^[0-9a-f]{16}$/);
  assert.match(m.routing.rules[0].id, /^[0-9a-f]{16}$/);
  assert.equal(m.inbounds[0].tag, 'inbound-443');
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
  assert.equal(build(model({ routing: { domainStrategy: 'IPOnDemand', rules: [] } })).routing.domainStrategy, 'IPOnDemand');
});

test('outbounds come out in the model’s order: the first enabled one is the default exit', () => {
  const c = build(model({ inbounds: [GOLDEN['vless-ws-tls']] }));
  assert.deepEqual(tagsOf(c), ['direct', 'block']);
  assert.deepEqual(c.outbounds[0], { tag: 'direct', protocol: 'freedom', settings: {} });
  assert.deepEqual(c.outbounds[1], { tag: 'block', protocol: 'blackhole', settings: { response: { type: 'http' } } });
  const swapped = build(model({ outbounds: [out('block', 'blackhole'), out('direct', 'freedom')] }));
  assert.deepEqual(tagsOf(swapped), ['block', 'direct']);
  const off = build(model({ outbounds: [out('direct', 'freedom', { enabled: false }), out('block', 'blackhole')] }));
  assert.deepEqual(tagsOf(off), ['block'], 'a disabled outbound is absent');
});

test('a server outbound clones the stored record with cloneOut semantics; a link outbound parses the link', () => {
  const PIN = 'ab11bf7ac877baa539294f5a3c864b8ed43e6fe3a9a8230fc2db7fff85c27fde';
  const stored = Object.assign({}, F.VLESS_WS_TLS, { certPin: PIN.toUpperCase().match(/../g).join(':') });
  const before = JSON.stringify(stored);
  const c = build(model({ inbounds: [GOLDEN['vless-xhttp-none']], outbounds: [out('exit', 'server', { serverId: 'sv-vless' }), out('block', 'blackhole')] }), { servers: [stored] });
  assert.deepEqual(tagsOf(c), ['exit', 'block']);
  const exit = c.outbounds[0];
  assert.equal(exit.protocol, 'vless');
  assert.equal(exit.settings.vnext[0].address, 'a.example.com');
  assert.equal(exit.streamSettings.tlsSettings.pinnedPeerCertSha256, PIN);
  assert.equal('allowInsecure' in exit.streamSettings.tlsSettings, false);
  assert.equal(JSON.stringify(stored), before, 'the stored record is not touched');
  const viaLink = build(model({ outbounds: [out('direct', 'freedom'), out('p', 'link', { link: `trojan://pw@h.example.com:443?security=tls&sni=h.example.com#t` })] }));
  assert.deepEqual(tagsOf(viaLink), ['direct', 'p']);
  assert.equal(viaLink.outbounds[1].protocol, 'trojan');
  assert.equal(viaLink.outbounds[1].settings.servers[0].address, 'h.example.com');
  assert.equal('allowInsecure' in viaLink.outbounds[1].streamSettings.tlsSettings, false);
});

test('an outbound carrying a fragment marker gets the anti-DPI dialer appended after every model outbound', () => {
  const frag = F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' });
  const c = build(model({ inbounds: [GOLDEN['vless-xhttp-none']], outbounds: [out('exit', 'server', { serverId: 'sv-frag' }), out('block', 'blackhole')] }), { servers: [frag] });
  assert.deepEqual(tagsOf(c), ['exit', 'block', 'dpi-1']);
  assert.equal(c.outbounds[0].streamSettings.sockopt.dialerProxy, 'dpi-1');
  assert.equal('_fragment' in c.outbounds[0], false);
  assert.equal(c.outbounds[2].settings.fragment.packets, 'tlshello');
});

test('an outbound whose target is unusable is simply absent (validation is what reports it)', () => {
  const c = build(model({ inbounds: [GOLDEN['vless-xhttp-none']], outbounds: [out('exit', 'server', { serverId: 'nope' }), out('direct', 'freedom'), out('bad', 'link', { link: 'garbage' })] }), { servers: [] });
  assert.deepEqual(tagsOf(c), ['direct']);
});

test('rules come out 1:1 in the model’s order with the empty fields left out; a disabled rule is absent', () => {
  const c = build(model({ inbounds: [GOLDEN['vless-ws-tls']], routing: { rules: [
    PRIVATE_RULE,
    rule({ enabled: false, domain: ['geosite:google'], outboundTag: 'block' }),
    rule({ inboundTags: ['vless-ws-a1b2'], domain: ['a.com', 'geosite:cn'], ip: ['1.2.3.0/24'], port: '443,8000-8100', protocol: ['tls'], network: 'tcp', outboundTag: 'direct', comment: 'everything set' }),
    TORRENT_RULE
  ] } }));
  assert.deepEqual(c.routing.rules, [
    { type: 'field', ip: ['geoip:private'], outboundTag: 'block' },
    { type: 'field', inboundTag: ['vless-ws-a1b2'], domain: ['a.com', 'geosite:cn'], ip: ['1.2.3.0/24'], port: '443,8000-8100', protocol: ['tls'], network: 'tcp', outboundTag: 'direct' },
    { type: 'field', protocol: ['bittorrent'], outboundTag: 'block' }
  ]);
  assert.equal(c.routing.rules.some(r => 'comment' in r || 'id' in r || 'preset' in r), false, 'nothing of the model leaks into the config');
  assert.deepEqual(build(model({ inbounds: [GOLDEN['vless-ws-tls']] })).routing.rules, [], 'no rules, no catch-all: the first outbound is the exit');
});

test('without geoip.dat the private block is the literal list, other geo entries are dropped, and a rule left with nothing goes', () => {
  const m = model({ inbounds: [GOLDEN['vless-ws-tls']], routing: { rules: [
    PRIVATE_RULE,
    rule({ preset: 'ads', domain: ['geosite:category-ads-all'], outboundTag: 'block' }),
    rule({ domain: ['geosite:cn', 'a.com'], ip: ['geoip:cn', '1.2.3.4'], outboundTag: 'direct' }),
    TORRENT_RULE
  ] } });
  const noGeo = build(m, { geoAvailable: false });
  assert.deepEqual(noGeo.routing.rules, [
    { type: 'field', ip: require('../src/main/configBuilder').PRIVATE_IPS, outboundTag: 'block' },
    { type: 'field', domain: ['a.com'], ip: ['1.2.3.4'], outboundTag: 'direct' },
    { type: 'field', protocol: ['bittorrent'], outboundTag: 'block' }
  ]);
  assert.equal(noGeo.routing.rules[0].ip.includes('127.0.0.0/8'), true);
  const geo = build(m, { geoAvailable: true });
  assert.deepEqual(geo.routing.rules[1], { type: 'field', domain: ['geosite:category-ads-all'], outboundTag: 'block' });
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

/* ----------------------------- reverse ----------------------------- */

const BRIDGE_OUT = out('interconn', 'link', { link: PORTAL_LINK, reverseTag: 'bridge' });
const BRIDGE_RULE = { id: 'rule-bridge', inboundTags: ['bridge'], outboundTag: 'direct' };

test('bridge: a link outbound with a reverseTag is the flat VLESS form with reverse.tag; its rule stays where the model put it', () => {
  const c = build(model({ inbounds: [GOLDEN['vless-ws-tls']], outbounds: DIRECT_BLOCK.concat([BRIDGE_OUT]), routing: { rules: [PRIVATE_RULE, TORRENT_RULE, BRIDGE_RULE] } }));
  assert.deepEqual(tagsOf(c), ['direct', 'block', 'interconn']);
  assert.deepEqual(c.outbounds[2], {
    tag: 'interconn', protocol: 'vless',
    settings: { address: '203.0.113.9', port: 47450, id: UUID_B, flow: '', encryption: 'none', reverse: { tag: 'bridge' } },
    streamSettings: { network: 'tcp', security: 'none' }
  });
  assert.equal('vnext' in c.outbounds[2].settings, false, 'the core refuses reverse inside vnext users');
  assert.deepEqual(c.routing.rules, [
    { type: 'field', ip: ['geoip:private'], outboundTag: 'block' },
    { type: 'field', protocol: ['bittorrent'], outboundTag: 'block' },
    { type: 'field', inboundTag: ['bridge'], outboundTag: 'direct' }
  ]);
  assert.equal(c.reverse, undefined, 'no legacy reverse block: the 26.9 fork refuses it');
});

test('every freedom outbound carries the allow rule exactly when an enabled outbound has a reverseTag (the 26.9 core blackholes reversed destinations otherwise)', () => {
  const bridge = build(model({ outbounds: [out('direct', 'freedom'), out('block', 'blackhole'), out('direct2', 'freedom'), BRIDGE_OUT] }));
  assert.deepEqual(bridge.outbounds[0].settings, { finalRules: [{ action: 'allow' }] });
  assert.deepEqual(bridge.outbounds[2].settings, { finalRules: [{ action: 'allow' }] });
  assert.deepEqual(build(model({ inbounds: [GOLDEN['vless-ws-tls']] })).outbounds[0].settings, {}, 'a plain server');
  const portal = build(model({ inbounds: [inbound({ clients: [client({ reverseTag: 'bridge-1' })] })] }));
  assert.deepEqual(portal.outbounds[0].settings, {}, 'a portal is no bridge');
  const off = build(model({ outbounds: DIRECT_BLOCK.concat([Object.assign({}, BRIDGE_OUT, { enabled: false })]) }));
  assert.deepEqual(off.outbounds[0].settings, {}, 'a disabled bridge outbound is absent, and so is its allow');
});

test('bridge via a stored server clones its stream settings (pin applied, allowInsecure gone) into the flat form', () => {
  const stored = Object.assign({}, F.VLESS_WS_TLS, { certPin: 'a'.repeat(64) });
  const c = build(model({ outbounds: DIRECT_BLOCK.concat([out('interconn', 'server', { serverId: 'sv-vless', reverseTag: 'bridge' })]), routing: { rules: [BRIDGE_RULE] } }), { servers: [stored] });
  const ic = c.outbounds[2];
  assert.equal(ic.tag, 'interconn');
  assert.deepEqual(ic.settings, { address: 'a.example.com', port: 443, id: 'uuid-a', flow: '', encryption: 'none', reverse: { tag: 'bridge' } });
  assert.equal(ic.streamSettings.network, 'ws');
  assert.deepEqual(ic.streamSettings.wsSettings, { path: '/ws', headers: { Host: 'a.example.com' } });
  assert.equal(ic.streamSettings.tlsSettings.pinnedPeerCertSha256, 'a'.repeat(64));
  assert.equal('allowInsecure' in ic.streamSettings.tlsSettings, false);
  assert.deepEqual(c.routing.rules.at(-1), { type: 'field', inboundTag: ['bridge'], outboundTag: 'direct' });
});

test('bridge with a reality + vision portal link keeps the flow and the reality client block', () => {
  const link = `vless://${UUID_B}@203.0.113.9:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=${PUB}&sid=${SHORT}#p`;
  const c = build(model({ outbounds: DIRECT_BLOCK.concat([out('interconn', 'link', { link, reverseTag: 'bridge' })]) }));
  const ic = c.outbounds[2];
  assert.equal(ic.settings.flow, 'xtls-rprx-vision');
  assert.equal(ic.streamSettings.realitySettings.publicKey, PUB);
  assert.equal(ic.streamSettings.realitySettings.shortId, SHORT);
});

test('bridge with a fragment-marked link gets the anti-DPI dialer after the interconn', () => {
  const link = `${PORTAL_LINK.split('#')[0]}&fragment=tlshello,100-200,10-20#p`;
  const c = build(model({ outbounds: DIRECT_BLOCK.concat([out('interconn', 'link', { link, reverseTag: 'bridge' })]) }));
  assert.deepEqual(tagsOf(c), ['direct', 'block', 'interconn', 'dpi-1']);
  assert.equal(c.outbounds[2].streamSettings.sockopt.dialerProxy, 'dpi-1');
});

test('a reverseTag on an outbound whose target is not VLESS emits nothing for it', () => {
  const c = build(model({ inbounds: [GOLDEN['vless-ws-tls']], outbounds: DIRECT_BLOCK.concat([out('interconn', 'link', { link: 'trojan://pw@h:443', reverseTag: 'bridge' })]) }));
  assert.deepEqual(tagsOf(c), ['direct', 'block']);
});

/** A portal: an interconn inbound with two bridge credentials, a user inbound routed to one of them, one inbound left local. */
function portalModel(over) {
  return model(Object.assign({
    inbounds: [
      inbound({ id: 'a1b2c3d4e5f60001', remark: 'Interconn', port: 47450, clients: [
        client({ id: 'c1c1c1c1c1c1c1c1', email: 'bridge1', uuid: UUID_B, reverseTag: 'bridge-1' }),
        client({ id: 'c4c4c4c4c4c4c4c4', email: 'bridge2', uuid: UUID_A, reverseTag: 'bridge-2' }),
        client({ id: 'c5c5c5c5c5c5c5c5', email: 'bridge3', uuid: UUID_A, reverseTag: 'bridge-3', enabled: false })
      ] }),
      inbound({ id: 'b1b2c3d4e5f60002', remark: 'Users', port: 47451, network: 'ws', path: '/u', clients: [client({ id: 'c2c2c2c2c2c2c2c2', email: 'alice' })] }),
      inbound({ id: 'c1b2c3d4e5f60003', remark: 'Local', protocol: 'trojan', port: 47452, security: 'tls', tls: TLS, clients: [client({ id: 'c3c3c3c3c3c3c3c3', email: 'carol' })] })
    ],
    routing: { rules: [PRIVATE_RULE, { id: 'rule-portal', inboundTags: ['users-b1b2'], outboundTag: 'bridge-1' }, { id: 'rule-portal-2', inboundTags: ['local-c1b2'], outboundTag: 'bridge-2', enabled: false }] }
  }, over || {}));
}

test('portal: every enabled VLESS client with a reverseTag carries reverse.tag; the rules route to those tags; nothing else changes', () => {
  const c = build(portalModel());
  assert.deepEqual(c.inbounds.map(i => i.tag), ['interconn-a1b2', 'users-b1b2', 'local-c1b2']);
  assert.deepEqual(c.inbounds[0].settings.clients, [
    { id: UUID_B, email: 'bridge1', reverse: { tag: 'bridge-1' } },
    { id: UUID_A, email: 'bridge2', reverse: { tag: 'bridge-2' } }
  ]);
  assert.deepEqual(c.inbounds[1].settings.clients, [{ id: UUID_A, email: 'alice' }], 'a user inbound client has no reverse');
  assert.deepEqual(tagsOf(c), ['direct', 'block']);
  assert.deepEqual(c.routing.rules, [
    { type: 'field', ip: ['geoip:private'], outboundTag: 'block' },
    { type: 'field', inboundTag: ['users-b1b2'], outboundTag: 'bridge-1' }
  ]);
  assert.equal(c.reverse, undefined);
});

test('a reverseTag on a vmess client is never emitted (validation refuses it)', () => {
  const c = build(model({ inbounds: [inbound({ protocol: 'vmess', clients: [client({ reverseTag: 'x' })] })] }));
  assert.deepEqual(c.inbounds[0].settings.clients, [{ id: UUID_A, email: 'alice' }]);
});

/* ----------------------------- validation ----------------------------- */

test('the golden model validates clean, and so does the portal', () => {
  const r = X.validateModel(model({ inbounds: Object.values(GOLDEN).map((i, n) => Object.assign({}, i, { id: `${n}1b2c3d4e5f6000${n}`, tag: `g-${n}`, port: 20000 + n, clients: i.clients.map(c => Object.assign({}, c, { id: `c${n}c${n}c${n}c${n}c${n}c${n}c${n}c${n}`, email: `user${n}` })) })) }), { servers: [] });
  assert.deepEqual(r, { ok: true, errors: [], warnings: [] });
  assert.deepEqual(X.validateModel(portalModel()), { ok: true, errors: [], warnings: [{ path: 'routing.rules', msg: 'no rule sends anyone to "bridge-2": the bridge behind it carries nothing' }] });
});

test('validation: tags are one namespace across inbounds, outbounds and both kinds of reverse tag; well-formed and not the core’s own', () => {
  const dup = X.validateModel(model({ inbounds: [inbound({ tag: 'same' }), inbound({ id: 'b1b2c3d4e5f60002', port: 444, tag: 'same', clients: [client({ id: 'c2c2c2c2c2c2c2c2', email: 'bob' })] })] }));
  assert.equal(dup.ok, false);
  assert.equal(hasError(dup, 'inbounds[1].tag'), true);
  assert.equal(hasError(dup, 'inbounds[0].tag'), false, 'the first holder is fine');
  const inOut = X.validateModel(model({ inbounds: [inbound({ tag: 'direct' })] }));
  assert.equal(hasError(inOut, 'outbounds[0].tag'), true, 'an outbound named like an inbound');
  const outOut = X.validateModel(model({ outbounds: [out('direct', 'freedom'), out('direct', 'blackhole')] }));
  assert.equal(hasError(outOut, 'outbounds[1].tag'), true);
  const clientVsOut = X.validateModel(model({ inbounds: [inbound({ clients: [client({ reverseTag: 'block' })] })] }));
  assert.equal(hasError(clientVsOut, 'outbounds[1].tag'), true, 'a client reverse tag named like an outbound');
  const revVsIn = X.validateModel(model({ inbounds: [inbound({ tag: 'bridge' })], outbounds: DIRECT_BLOCK.concat([BRIDGE_OUT]) }));
  assert.equal(hasError(revVsIn, 'outbounds[2].reverseTag'), true, 'an outbound reverse tag named like an inbound');
  const revVsRev = X.validateModel(model({ inbounds: [inbound({ clients: [client({ reverseTag: 'bridge' })] })], outbounds: DIRECT_BLOCK.concat([BRIDGE_OUT]) }));
  assert.equal(hasError(revVsRev, 'outbounds[2].reverseTag'), true, 'the two reverse tags collide');
  const shared = X.validateModel(model({ inbounds: [inbound({ clients: [client({ reverseTag: 'portal' }), client({ id: 'c2c2c2c2c2c2c2c2', email: 'bob', reverseTag: 'portal' })] })], routing: { rules: [rule({ port: '80', outboundTag: 'portal' })] } }));
  assert.deepEqual(shared, { ok: true, errors: [], warnings: [] }, 'two bridge credentials may answer to one portal tag, as the v1 portal did');
  const outVsShared = X.validateModel(model({ inbounds: [inbound({ clients: [client({ reverseTag: 'portal' }), client({ id: 'c2c2c2c2c2c2c2c2', email: 'bob', reverseTag: 'portal' })] })], outbounds: DIRECT_BLOCK.concat([out('portal', 'freedom')]) }));
  assert.equal(hasError(outVsShared, 'outbounds[2].tag'), true, 'but nothing else may take that name');
  for (const tag of ['metrics', 'api']) {
    assert.equal(hasError(X.validateModel(model({ inbounds: [inbound({ tag })] })), 'inbounds[0].tag'), true, tag);
    assert.equal(hasError(X.validateModel(model({ outbounds: [out(tag, 'freedom')] })), 'outbounds[0].tag'), true, tag);
    assert.equal(hasError(X.validateModel(model({ inbounds: [inbound({ clients: [client({ reverseTag: tag })] })] })), 'inbounds[0].clients[0].reverseTag'), true, tag);
  }
  for (const tag of ['Has Space', 'UPPER', 'a_b', '']) {
    assert.equal(hasError(X.validateModel(model({ inbounds: [inbound({ tag: tag || undefined })] })), 'inbounds[0].tag'), tag !== '', JSON.stringify(tag));
  }
  assert.equal(hasError(X.validateModel(model({ outbounds: [out('Bad Tag', 'freedom')] })), 'outbounds[0].tag'), true);
  assert.equal(hasError(X.validateModel(model({ outbounds: DIRECT_BLOCK.concat([out('interconn', 'link', { link: PORTAL_LINK, reverseTag: 'Bad' })]) })), 'outbounds[2].reverseTag'), true);
  // the v1 names are ordinary now: an inbound may be called exit, bridge or portal
  assert.equal(X.validateModel(model({ inbounds: [inbound({ tag: 'exit' })] })).ok, true);
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

test('validation: a reverseTag lives only on a VLESS client', () => {
  for (const protocol of ['vmess', 'trojan', 'shadowsocks']) {
    const r = X.validateModel(model({ inbounds: [inbound({ protocol, ss: { method: 'aes-256-gcm', password: '' }, clients: [client({ reverseTag: 'b' })] })] }));
    assert.equal(hasError(r, 'inbounds[0].clients[0].reverseTag'), true, protocol);
  }
  assert.equal(X.validateModel(model({ inbounds: [inbound({ clients: [client({ reverseTag: 'b' })] })], routing: { rules: [rule({ inboundTags: ['golden-a1b2'], outboundTag: 'b' })] } })).ok, true);
});

test('validation: outbounds need a known kind, a reachable target, and a VLESS target for a reverse tag; at least one must be enabled', () => {
  const kind = X.validateModel(model({ outbounds: [out('x', 'socks')] }));
  assert.equal(hasError(kind, 'outbounds[0].kind'), true);
  const missing = X.validateModel(model({ outbounds: [out('exit', 'server', { serverId: 'nope' })] }), { servers: [F.TROJAN_TCP_TLS] });
  assert.equal(hasError(missing, 'outbounds[0].serverId'), true);
  assert.equal(X.validateModel(model({ outbounds: [out('exit', 'server', { serverId: 'sv-trojan' })] }), { servers: [F.TROJAN_TCP_TLS] }).ok, true, 'any stored config can be a plain exit');
  const noLink = X.validateModel(model({ outbounds: [out('p', 'link', { link: '' })] }));
  assert.equal(hasError(noLink, 'outbounds[0].link'), true);
  const badLink = X.validateModel(model({ outbounds: [out('p', 'link', { link: 'garbage' })] }));
  assert.equal(hasError(badLink, 'outbounds[0].link'), true);
  assert.equal(X.validateModel(model({ outbounds: [out('p', 'link', { link: 'trojan://pw@h:443' })] })).ok, true);
  const trojanRev = X.validateModel(model({ outbounds: DIRECT_BLOCK.concat([out('interconn', 'link', { link: 'trojan://pw@h:443', reverseTag: 'bridge' })]) }));
  assert.equal(hasError(trojanRev, 'outbounds[2].reverseTag'), true, 'the VLESS reverse proxy rides VLESS only');
  const notVless = X.validateModel(model({ outbounds: DIRECT_BLOCK.concat([out('interconn', 'server', { serverId: 'sv-trojan', reverseTag: 'bridge' })]) }), { servers: [F.TROJAN_TCP_TLS] });
  assert.equal(hasError(notVless, 'outbounds[2].reverseTag'), true);
  assert.equal(X.validateModel(model({ outbounds: DIRECT_BLOCK.concat([out('interconn', 'server', { serverId: 'sv-vless', reverseTag: 'bridge' })]), routing: { rules: [BRIDGE_RULE] } }), { servers: [F.VLESS_WS_TLS] }).ok, true);
  const plain = X.validateModel(model({ outbounds: [out('direct', 'freedom', { reverseTag: 'x' }), out('block', 'blackhole', { reverseTag: 'y' })] }));
  assert.equal(hasError(plain, 'outbounds[0].reverseTag'), true);
  assert.equal(hasError(plain, 'outbounds[1].reverseTag'), true);
  const none = X.validateModel(model({ outbounds: [] }));
  assert.equal(hasError(none, 'outbounds'), true);
  const allOff = X.validateModel(model({ outbounds: [out('direct', 'freedom', { enabled: false })] }));
  assert.equal(hasError(allOff, 'outbounds'), true);
});

test('validation: a rule must match something and point at an enabled outbound or an enabled VLESS client’s reverse tag', () => {
  const m = (rules) => model({ inbounds: [inbound({ clients: [client({ reverseTag: 'b1' }), client({ id: 'c2c2c2c2c2c2c2c2', email: 'bob', reverseTag: 'b2', enabled: false })] })], outbounds: DIRECT_BLOCK.concat([out('off', 'freedom', { enabled: false }), BRIDGE_OUT]), routing: { rules } });
  const empty = X.validateModel(m([rule({ outboundTag: 'direct' })]));
  assert.equal(hasError(empty, 'routing.rules[0]'), true, 'nothing to match');
  const noTarget = X.validateModel(m([rule({ port: '443' })]));
  assert.equal(hasError(noTarget, 'routing.rules[0].outboundTag'), true);
  const unknown = X.validateModel(m([rule({ port: '443', outboundTag: 'nope' })]));
  assert.equal(hasError(unknown, 'routing.rules[0].outboundTag'), true);
  const disabledOut = X.validateModel(m([rule({ port: '443', outboundTag: 'off' })]));
  assert.equal(hasError(disabledOut, 'routing.rules[0].outboundTag'), true, 'a disabled outbound is no target');
  const portal = X.validateModel(m([rule({ inboundTags: ['golden-a1b2'], outboundTag: 'b1' })]));
  assert.equal(portal.ok, true, 'an enabled VLESS client reverse tag is a target');
  const offPortal = X.validateModel(m([rule({ inboundTags: ['golden-a1b2'], outboundTag: 'b2' })]));
  assert.equal(hasError(offPortal, 'routing.rules[0].outboundTag'), true, 'a disabled client reverse tag is not');
  const srcUnknown = X.validateModel(m([rule({ inboundTags: ['golden-a1b2', 'ghost'], outboundTag: 'direct' })]));
  assert.equal(hasError(srcUnknown, 'routing.rules[0].inboundTags'), true);
  const srcReverse = X.validateModel(m([rule({ inboundTags: ['bridge'], outboundTag: 'direct' })]));
  assert.equal(srcReverse.ok, true, 'an outbound reverse tag is an inbound tag for rules');
  const disabledRule = X.validateModel(m([rule({ enabled: false, inboundTags: ['ghost'], outboundTag: 'nope' })]));
  assert.equal(disabledRule.errors.length, 0, 'a disabled rule is inert, whatever it says');
  for (const port of ['443', '443,8443', '1000-2000', '80,1000-2000,8443']) assert.equal(X.validateModel(m([rule({ port, outboundTag: 'direct' })])).ok, true, port);
  for (const port of ['abc', '70000', '443-', '2000-1000', '1,,2']) assert.equal(hasError(X.validateModel(m([rule({ port, outboundTag: 'direct' })])), 'routing.rules[0].port'), true, port);
  assert.equal(hasError(X.validateModel(m([rule({ network: 'sctp', outboundTag: 'direct' })])), 'routing.rules[0].network'), true);
  assert.equal(hasError(X.validateModel(m([rule({ protocol: ['ftp'], outboundTag: 'direct' })])), 'routing.rules[0].protocol'), true);
  assert.equal(X.validateModel(m([rule({ protocol: ['http', 'tls', 'bittorrent', 'quic'], network: 'tcp,udp', outboundTag: 'direct' })])).ok, true);
  assert.equal(hasError(X.validateModel(m([rule({ preset: 'nope', ip: ['1.1.1.1'], outboundTag: 'direct' })])), 'routing.rules[0].preset'), true);
  assert.equal(hasError(X.validateModel(model({ routing: { domainStrategy: 'Sideways', rules: [] } })), 'routing.domainStrategy'), true);
});

test('validation: a reverse tag nobody routes to or from is a warning', () => {
  const portal = X.validateModel(model({ inbounds: [inbound({ clients: [client({ reverseTag: 'b1' })] })] }));
  assert.equal(portal.ok, true);
  assert.equal(portal.warnings.some(w => w.path === 'routing.rules' && /"b1"/.test(w.msg)), true);
  const bridge = X.validateModel(model({ outbounds: DIRECT_BLOCK.concat([BRIDGE_OUT]) }));
  assert.equal(bridge.ok, true);
  assert.equal(bridge.warnings.some(w => w.path === 'routing.rules' && /"bridge"/.test(w.msg)), true);
  assert.deepEqual(X.validateModel(model({ outbounds: DIRECT_BLOCK.concat([BRIDGE_OUT]), routing: { rules: [BRIDGE_RULE] } })).warnings, []);
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

test('defaultTag is inbound-<port>', () => {
  assert.equal(X.defaultTag({ port: 2053 }), 'inbound-2053');
  assert.equal(X.defaultTag({ port: '8443' }), 'inbound-8443');
  assert.equal(X.defaultTag({}), 'inbound-443');
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

test('newInbound: fresh id, the tag inbound-<port>, protocol-shaped defaults, overrides win', () => {
  const v = X.newInbound('vless');
  assert.match(v.id, /^[0-9a-f]{16}$/);
  assert.equal(v.protocol, 'vless');
  assert.equal(v.security, 'reality');
  assert.equal(v.port, 443);
  assert.equal(v.remark, 'VLESS Reality');
  assert.equal(v.tag, 'inbound-443');
  assert.equal(v.reality.shortIds.length, 1);
  assert.match(v.reality.shortIds[0], /^[0-9a-f]{16}$/);
  assert.deepEqual(v.clients, []);
  assert.equal(v.totalBytes, 0);
  assert.deepEqual(v.used, { up: 0, down: 0 });
  assert.notEqual(X.newInbound('vless').id, v.id);
  const s = X.newInbound('shadowsocks');
  assert.equal(s.protocol, 'shadowsocks');
  assert.equal(s.security, 'none');
  assert.equal(s.network, 'tcp');
  assert.equal(s.port, 8388);
  assert.equal(s.tag, 'inbound-8388');
  assert.equal(s.ss.method, '2022-blake3-aes-128-gcm');
  assert.equal(Buffer.from(s.ss.password, 'base64').length, 16);
  const t = X.newInbound('trojan');
  assert.equal(t.security, 'tls');
  const m = X.newInbound('vmess');
  assert.equal(m.network, 'ws');
  assert.equal(m.security, 'none');
  const o = X.newInbound('vless', { remark: 'Mine', port: 2053 });
  assert.equal(o.port, 2053);
  assert.equal(o.tag, 'inbound-2053', 'the tag follows the overridden port');
  assert.equal(X.newInbound('vless', { tag: 'mine' }).tag, 'mine');
  assert.deepEqual(X.normalizeModel({ schema: 2, inbounds: [v, s, t, m, o] }).inbounds, [v, s, t, m, o], 'a fresh inbound is already normal');
});

test('newClient: fresh id, a uuid for vless/vmess, a password for trojan, a sized key for shadowsocks, the v2 fields', () => {
  const v = X.newClient('vless');
  assert.match(v.id, /^[0-9a-f]{16}$/);
  assert.match(v.uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(v.password, '');
  assert.equal(v.enabled, true);
  assert.equal(v.email, '');
  assert.equal(v.comment, '');
  assert.equal(v.reverseTag, '');
  assert.equal(v.resetDays, 0);
  assert.equal(v.lastSeenAt, 0);
  assert.notEqual(X.newClient('vless').uuid, v.uuid);
  assert.match(X.newClient('vmess').uuid, /-/);
  const t = X.newClient('trojan');
  assert.equal(t.uuid, '');
  assert.ok(t.password.length >= 16);
  const s = X.newClient('shadowsocks', { method: '2022-blake3-aes-256-gcm' });
  assert.equal(Buffer.from(s.password, 'base64').length, 32);
  assert.equal('method' in s, false, 'the method only sizes the key');
  assert.equal(Buffer.from(X.newClient('shadowsocks').password, 'base64').length, 16);
  const o = X.newClient('vless', { email: 'bob', quotaBytes: 5, reverseTag: 'b1', comment: 'hi', resetDays: 30 });
  assert.equal(o.email, 'bob');
  assert.equal(o.quotaBytes, 5);
  assert.equal(o.reverseTag, 'b1');
  assert.equal(o.comment, 'hi');
  assert.equal(o.resetDays, 30);
  assert.deepEqual(X.normalizeModel({ schema: 2, inbounds: [inbound({ clients: [v, t, s, o] })] }).inbounds[0].clients, [v, t, s, o]);
});

test('newOutbound: fresh id, a kind-shaped tag, overrides win; newRule and presetRule are normal rules', () => {
  const d = X.newOutbound('freedom');
  assert.match(d.id, /^[0-9a-f]{16}$/);
  assert.deepEqual(d, { id: d.id, tag: 'direct', kind: 'freedom', serverId: '', link: '', reverseTag: '', enabled: true });
  assert.equal(X.newOutbound('blackhole').tag, 'block');
  assert.equal(X.newOutbound('server', { serverId: 'sv-vless' }).tag, 'proxy');
  assert.equal(X.newOutbound('link', { link: PORTAL_LINK, tag: 'interconn', reverseTag: 'bridge' }).reverseTag, 'bridge');
  assert.equal(X.newOutbound('nope').kind, 'freedom', 'an unknown kind is the plain exit');
  assert.notEqual(X.newOutbound('freedom').id, d.id);
  const r = X.newRule({ domain: ['a.com'], outboundTag: 'direct', comment: 'c' });
  assert.deepEqual(r, { id: r.id, enabled: true, comment: 'c', inboundTags: [], outboundTag: 'direct', domain: ['a.com'], ip: [], port: '', protocol: [], network: '', preset: '' });
  const p = X.presetRule('private', 'block');
  assert.deepEqual(p, { id: p.id, enabled: true, comment: 'block private ranges', inboundTags: [], outboundTag: 'block', domain: [], ip: ['geoip:private'], port: '', protocol: [], network: '', preset: 'private' });
  assert.deepEqual(X.presetRule('torrent', 'b2').protocol, ['bittorrent']);
  assert.equal(X.presetRule('torrent', 'b2').outboundTag, 'b2');
  assert.deepEqual(X.presetRule('ads').domain, ['geosite:category-ads-all']);
  assert.equal(X.presetRule('ads').outboundTag, 'block');
  assert.throws(() => X.presetRule('nope'), /unknown preset/);
  assert.deepEqual(Object.keys(X.RULE_PRESETS).sort(), ['ads', 'private', 'torrent']);
  assert.equal(Object.isFrozen(X.RULE_PRESETS.private.ip), true);
  p.ip.push('x');
  assert.deepEqual(X.RULE_PRESETS.private.ip, ['geoip:private'], 'a preset rule is a copy');
});

test('allTags: the four sets, from every inbound, client and outbound, enabled or not', () => {
  const t = X.allTags(model({ inbounds: [inbound({ tag: 'in-a', clients: [client({ reverseTag: 'b1' }), client({ id: 'c2c2c2c2c2c2c2c2', email: 'bob', reverseTag: 'b2', enabled: false })] }), inbound({ id: 'b1b2c3d4e5f60002', tag: 'in-b', port: 444, enabled: false, clients: [] })], outbounds: DIRECT_BLOCK.concat([BRIDGE_OUT, Object.assign({}, BRIDGE_OUT, { id: 'x', tag: 'ic2', reverseTag: 'br2', enabled: false })]) }));
  assert.deepEqual([...t.inbounds], ['in-a', 'in-b']);
  assert.deepEqual([...t.outbounds], ['direct', 'block', 'interconn', 'ic2']);
  assert.deepEqual([...t.clientReverse], ['b1', 'b2']);
  assert.deepEqual([...t.outboundReverse], ['bridge', 'br2']);
});

/* ----------------------------- other side ----------------------------- */

test('otherSideSnippet: nothing reverse-related, nothing to say', () => {
  assert.deepEqual(X.otherSideSnippet(model({ inbounds: [GOLDEN['vless-ws-tls']] })), { items: [] });
});

test('otherSideSnippet for a client with a reverseTag (this is the portal): what the bridge pastes, and the client link', () => {
  const m = portalModel();
  const r = X.otherSideSnippet(m);
  assert.deepEqual(r.items.map(i => [i.kind, i.tag, i.email]), [['bridge-side', 'bridge-1', 'bridge1'], ['bridge-side', 'bridge-2', 'bridge2']], 'one per enabled client with a tag');
  const it = r.items[0];
  assert.equal(it.inboundId, 'a1b2c3d4e5f60001');
  assert.equal(it.clientId, 'c1c1c1c1c1c1c1c1');
  assert.equal(it.link, X.clientLink(m.inbounds[0], m.inbounds[0].clients[0], m));
  assert.deepEqual(it.snippet, {
    outbounds: [
      { tag: 'interconn', protocol: 'vless', settings: { address: 'vpn.example.com', port: 47450, id: UUID_B, flow: '', encryption: 'none', reverse: { tag: 'bridge-1' } }, streamSettings: { network: 'tcp', security: 'none' } },
      { tag: 'direct', protocol: 'freedom', settings: { finalRules: [{ action: 'allow' }] } }
    ],
    routing: { rules: [{ type: 'field', inboundTag: ['bridge-1'], outboundTag: 'direct' }] }
  });
  assert.equal('inbounds' in it.snippet, false);
  const parsed = parseLink(it.link);
  assert.equal(parsed.address, 'vpn.example.com');
  assert.equal(parsed.port, 47450);
  const other = X.otherSideSnippet(m, { address: '198.51.100.7' });
  assert.equal(other.items[0].snippet.outbounds[0].settings.address, '198.51.100.7');
  assert.equal(parseLink(other.items[0].link).address, '198.51.100.7');
  const blank = X.otherSideSnippet(Object.assign({}, m, { publicAddress: '' }));
  assert.equal(blank.items[0].link, null, 'no address, no link');
  assert.equal(blank.items[0].snippet.outbounds[0].settings.address, '<public-address>');
  const off = portalModel();
  off.inbounds[0].enabled = false;
  assert.deepEqual(X.otherSideSnippet(off).items, [], 'a disabled inbound offers nothing');
});

test('otherSideSnippet for an outbound with a reverseTag (this is the bridge): the portal-side inbound skeleton with placeholders', () => {
  const r = X.otherSideSnippet(model({ outbounds: DIRECT_BLOCK.concat([BRIDGE_OUT]), routing: { rules: [BRIDGE_RULE] } }));
  assert.equal(r.items.length, 1);
  const it = r.items[0];
  assert.equal(it.kind, 'portal-side');
  assert.equal(it.tag, 'bridge');
  assert.equal(it.outboundId, 'interconn');
  assert.equal(it.outboundTag, 'interconn');
  assert.equal(it.link, null);
  assert.deepEqual(it.snippet.inbounds, [{
    tag: '<interconn-inbound-tag>', listen: '0.0.0.0', port: 47450, protocol: 'vless',
    settings: { clients: [{ id: UUID_B, email: 'bridge', reverse: { tag: 'bridge' } }], decryption: 'none' },
    streamSettings: { network: 'tcp', security: 'none' }
  }]);
  assert.deepEqual(it.snippet.routing, { rules: [{ type: 'field', inboundTag: ['<user-inbound-tag>'], outboundTag: 'bridge' }] });
  assert.equal('outbounds' in it.snippet, false);
  const link = `vless://${UUID_B}@203.0.113.9:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=${PUB}&sid=${SHORT}#p`;
  const re = X.otherSideSnippet(model({ outbounds: DIRECT_BLOCK.concat([out('interconn', 'link', { link, reverseTag: 'bridge' })]) })).items[0];
  const st = re.snippet.inbounds[0].streamSettings;
  assert.equal(st.security, 'reality');
  assert.deepEqual(st.realitySettings.serverNames, ['www.microsoft.com']);
  assert.deepEqual(st.realitySettings.shortIds, [SHORT]);
  assert.equal(st.realitySettings.target, 'www.microsoft.com:443');
  assert.match(st.realitySettings.privateKey, /^<.*>$/);
  assert.deepEqual(re.snippet.inbounds[0].settings.clients[0], { id: UUID_B, email: 'bridge', flow: 'xtls-rprx-vision', reverse: { tag: 'bridge' } });
  const stored = X.otherSideSnippet(model({ outbounds: DIRECT_BLOCK.concat([out('interconn', 'server', { serverId: 'sv-vless', reverseTag: 'bridge' })]) }), { servers: [F.VLESS_WS_TLS] }).items[0];
  const st2 = stored.snippet.inbounds[0].streamSettings;
  assert.deepEqual(st2.wsSettings, { path: '/ws', host: 'a.example.com' });
  assert.equal(st2.tlsSettings.serverName, 'a.example.com');
  assert.match(st2.tlsSettings.certificates[0].certificateFile, /^<.*>$/);
  assert.match(st2.tlsSettings.certificates[0].keyFile, /^<.*>$/);
  assert.deepEqual(X.otherSideSnippet(model({ outbounds: DIRECT_BLOCK.concat([out('interconn', 'link', { link: 'trojan://pw@h:443', reverseTag: 'bridge' })]) })).items, [], 'an unusable target offers nothing');
});

test('otherSideSnippet on a machine that is both: one item per tag, portal items first', () => {
  const m = portalModel({ outbounds: DIRECT_BLOCK.concat([BRIDGE_OUT]) });
  assert.deepEqual(X.otherSideSnippet(m).items.map(i => [i.kind, i.tag]), [['bridge-side', 'bridge-1'], ['bridge-side', 'bridge-2'], ['portal-side', 'bridge']]);
});

/* ----------------------------- wizards ----------------------------- */

/** A portal-to-be: an interconn inbound, two user inbounds, a catch-all rule that already names one of them. */
function portalBefore(over) {
  return model(Object.assign({
    inbounds: [
      inbound({ id: 'a1b2c3d4e5f60001', remark: 'Interconn', port: 47450, clients: [client({ id: 'c1c1c1c1c1c1c1c1', email: 'bridge1', uuid: UUID_B })] }),
      inbound({ id: 'b1b2c3d4e5f60002', remark: 'Users', port: 47451, network: 'ws', path: '/u', clients: [client({ id: 'c2c2c2c2c2c2c2c2', email: 'alice' })] }),
      inbound({ id: 'c1b2c3d4e5f60003', remark: 'Local', protocol: 'trojan', port: 47452, security: 'tls', tls: TLS, clients: [client({ id: 'c3c3c3c3c3c3c3c3', email: 'carol' })] })
    ],
    routing: { rules: [PRIVATE_RULE, { id: 'rule-catch', inboundTags: ['users-b1b2', 'local-c1b2'], outboundTag: 'direct', comment: 'catch-all' }] }
  }, over || {}));
}

test('wizardPortal: tags the client, inserts its rule before the first rule that would catch those inbounds, returns the link; the input is untouched', () => {
  const before = portalBefore();
  const snapshot = JSON.stringify(before);
  const { model: after, link } = X.wizardPortal(before, { inboundId: 'a1b2c3d4e5f60001', clientId: 'c1c1c1c1c1c1c1c1', userInboundIds: ['b1b2c3d4e5f60002'] });
  assert.equal(JSON.stringify(before), snapshot);
  assert.equal(after.inbounds[0].clients[0].reverseTag, 'bridge-1', 'the default tag');
  assert.deepEqual(after.routing.rules.map(r => [r.outboundTag, r.inboundTags]), [
    ['block', []],
    ['bridge-1', ['users-b1b2']],
    ['direct', ['users-b1b2', 'local-c1b2']]
  ]);
  const r = after.routing.rules[1];
  assert.equal(r.comment, 'reverse → bridge-1');
  assert.equal(r.enabled, true);
  assert.match(r.id, /^[0-9a-f]{16}$/);
  assert.equal(link, X.clientLink(after.inbounds[0], after.inbounds[0].clients[0], after));
  assert.deepEqual(X.validateModel(after), { ok: true, errors: [], warnings: [] });
  const c = build(after);
  assert.deepEqual(c.inbounds[0].settings.clients, [{ id: UUID_B, email: 'bridge1', reverse: { tag: 'bridge-1' } }]);
  assert.deepEqual(c.routing.rules[1], { type: 'field', inboundTag: ['users-b1b2'], outboundTag: 'bridge-1' });
});

test('wizardPortal: with no rule in the way the rule is appended; a chosen tag and several user inbounds are honoured, in model order', () => {
  const m = portalBefore({ routing: { rules: [PRIVATE_RULE] } });
  const { model: after } = X.wizardPortal(m, { inboundId: 'a1b2c3d4e5f60001', clientId: 'c1c1c1c1c1c1c1c1', userInboundIds: ['c1b2c3d4e5f60003', 'b1b2c3d4e5f60002'], tag: 'home' });
  assert.deepEqual(after.routing.rules.map(r => r.outboundTag), ['block', 'home']);
  assert.deepEqual(after.routing.rules[1].inboundTags, ['users-b1b2', 'local-c1b2']);
  assert.equal(after.inbounds[0].clients[0].reverseTag, 'home');
  assert.equal(X.validateModel(after).ok, true);
});

test('wizardPortal: running it twice adds nothing twice; a second client gets the next free tag and its own rule', () => {
  const once = X.wizardPortal(portalBefore(), { inboundId: 'a1b2c3d4e5f60001', clientId: 'c1c1c1c1c1c1c1c1', userInboundIds: ['b1b2c3d4e5f60002'] }).model;
  const twice = X.wizardPortal(once, { inboundId: 'a1b2c3d4e5f60001', clientId: 'c1c1c1c1c1c1c1c1', userInboundIds: ['b1b2c3d4e5f60002'] }).model;
  assert.deepEqual(twice, once);
  once.inbounds[0].clients.push(client({ id: 'c4c4c4c4c4c4c4c4', email: 'bridge2', uuid: UUID_A }));
  const second = X.wizardPortal(once, { inboundId: 'a1b2c3d4e5f60001', clientId: 'c4c4c4c4c4c4c4c4', userInboundIds: ['c1b2c3d4e5f60003'] }).model;
  assert.deepEqual(second.inbounds[0].clients.map(c => c.reverseTag), ['bridge-1', 'bridge-2'], 'the default tag steps past the one in use');
  const joined = X.wizardPortal(once, { inboundId: 'a1b2c3d4e5f60001', clientId: 'c4c4c4c4c4c4c4c4', userInboundIds: ['b1b2c3d4e5f60002'], tag: 'bridge-1' }).model;
  assert.deepEqual(joined.inbounds[0].clients.map(c => c.reverseTag), ['bridge-1', 'bridge-1'], 'a tag named on purpose joins the other bridge behind one outbound');
  assert.equal(joined.routing.rules.length, once.routing.rules.length, 'and the rule for it is already there');
  assert.equal(X.validateModel(joined).ok, true);
  assert.deepEqual(second.routing.rules.map(r => [r.outboundTag, r.inboundTags]), [
    ['block', []],
    ['bridge-1', ['users-b1b2']],
    ['bridge-2', ['local-c1b2']],
    ['direct', ['users-b1b2', 'local-c1b2']]
  ], 'inserted before the catch-all, the first rule that names local');
  assert.equal(X.validateModel(second).ok, true);
});

test('wizardPortal refuses what would not validate: unknown or disabled inbound/client, a non-VLESS interconn, overlap, a taken or bad tag, no users', () => {
  const args = { inboundId: 'a1b2c3d4e5f60001', clientId: 'c1c1c1c1c1c1c1c1', userInboundIds: ['b1b2c3d4e5f60002'] };
  assert.throws(() => X.wizardPortal(portalBefore(), Object.assign({}, args, { inboundId: 'zzz' })), /inbound/);
  assert.throws(() => X.wizardPortal(portalBefore(), Object.assign({}, args, { clientId: 'zzz' })), /client/);
  assert.throws(() => X.wizardPortal(portalBefore(), Object.assign({}, args, { inboundId: 'c1b2c3d4e5f60003', clientId: 'c3c3c3c3c3c3c3c3' })), /vless/i);
  assert.throws(() => X.wizardPortal(portalBefore(), Object.assign({}, args, { userInboundIds: ['a1b2c3d4e5f60001', 'b1b2c3d4e5f60002'] })), /cannot also be/);
  assert.throws(() => X.wizardPortal(portalBefore(), Object.assign({}, args, { userInboundIds: [] })), /choose/);
  assert.throws(() => X.wizardPortal(portalBefore(), Object.assign({}, args, { userInboundIds: ['b1b2c3d4e5f60002', 'zzz'] })), /no longer exists/);
  assert.throws(() => X.wizardPortal(portalBefore(), Object.assign({}, args, { tag: 'direct' })), /already used/);
  assert.throws(() => X.wizardPortal(portalBefore(), Object.assign({}, args, { tag: 'users-b1b2' })), /already used/);
  assert.throws(() => X.wizardPortal(portalBefore(), Object.assign({}, args, { tag: 'Bad Tag' })), /lower-case/);
  assert.throws(() => X.wizardPortal(portalBefore(), Object.assign({}, args, { tag: 'metrics' })), /core/);
  const off = portalBefore();
  off.inbounds[0].enabled = false;
  assert.throws(() => X.wizardPortal(off, args), /disabled/);
  const offClient = portalBefore();
  offClient.inbounds[0].clients[0].enabled = false;
  assert.throws(() => X.wizardPortal(offClient, args), /disabled/);
});

test('wizardBridge: appends the interconn outbound and the rule to the first enabled freedom outbound; the input is untouched', () => {
  const before = model({ inbounds: [GOLDEN['vless-ws-tls']], routing: { rules: [PRIVATE_RULE] } });
  const snapshot = JSON.stringify(before);
  const { model: after } = X.wizardBridge(before, { link: PORTAL_LINK });
  assert.equal(JSON.stringify(before), snapshot);
  assert.deepEqual(after.outbounds.slice(0, 2), before.outbounds);
  assert.deepEqual(after.outbounds[2], Object.assign({}, after.outbounds[2], { tag: 'interconn', kind: 'link', link: PORTAL_LINK, serverId: '', reverseTag: 'bridge', enabled: true }));
  assert.match(after.outbounds[2].id, /^[0-9a-f]{16}$/);
  assert.deepEqual(after.routing.rules.map(r => [r.outboundTag, r.inboundTags]), [['block', []], ['direct', ['bridge']]]);
  assert.equal(after.routing.rules[1].comment, 'reverse ← bridge');
  assert.deepEqual(X.validateModel(after), { ok: true, errors: [], warnings: [] });
  const c = build(after);
  assert.deepEqual(tagsOf(c), ['direct', 'block', 'interconn']);
  assert.deepEqual(c.outbounds[0].settings, { finalRules: [{ action: 'allow' }] });
  assert.deepEqual(c.outbounds[2].settings.reverse, { tag: 'bridge' });
  assert.deepEqual(c.routing.rules.at(-1), { type: 'field', inboundTag: ['bridge'], outboundTag: 'direct' });
});

test('wizardBridge: a stored config, chosen tags and a chosen exit; running it twice with the same tags is refused', () => {
  const m = model({ outbounds: [out('exit', 'server', { serverId: 'sv-trojan' }), out('block', 'blackhole'), out('direct', 'freedom')] });
  const { model: after } = X.wizardBridge(m, { serverId: 'sv-vless', tag: 'ic', reverseTag: 'rev', exitOutboundTag: 'exit', servers: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS] });
  assert.deepEqual(after.outbounds.map(o => o.tag), ['exit', 'block', 'direct', 'ic']);
  assert.equal(after.outbounds[3].kind, 'server');
  assert.equal(after.outbounds[3].serverId, 'sv-vless');
  assert.equal(after.outbounds[3].reverseTag, 'rev');
  assert.deepEqual(after.routing.rules.map(r => [r.outboundTag, r.inboundTags]), [['exit', ['rev']]]);
  assert.equal(X.validateModel(after, { servers: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS] }).ok, true);
  assert.throws(() => X.wizardBridge(after, { serverId: 'sv-vless', tag: 'ic', reverseTag: 'rev2', servers: [F.VLESS_WS_TLS] }), /already used/);
  assert.throws(() => X.wizardBridge(after, { serverId: 'sv-vless', tag: 'ic2', reverseTag: 'rev', servers: [F.VLESS_WS_TLS] }), /already used/);
  const byDefault = X.wizardBridge(m, { link: PORTAL_LINK }).model;
  assert.deepEqual(byDefault.routing.rules.map(r => [r.outboundTag, r.inboundTags]), [['direct', ['bridge']]], 'the default exit is the first enabled freedom, wherever it sits');
});

test('wizardBridge: without a freedom outbound one is created for the reversed traffic, under a free name', () => {
  const m = model({ outbounds: [out('exit', 'server', { serverId: 'sv-trojan' }), out('block', 'blackhole')] });
  const { model: after } = X.wizardBridge(m, { link: PORTAL_LINK, servers: [F.TROJAN_TCP_TLS] });
  assert.deepEqual(after.outbounds.map(o => [o.tag, o.kind]), [['exit', 'server'], ['block', 'blackhole'], ['direct', 'freedom'], ['interconn', 'link']]);
  assert.deepEqual(after.routing.rules.map(r => [r.outboundTag, r.inboundTags]), [['direct', ['bridge']]]);
  assert.equal(X.validateModel(after, { servers: [F.TROJAN_TCP_TLS] }).ok, true);
  const taken = model({ inbounds: [inbound({ tag: 'direct' })], outbounds: [out('block', 'blackhole')] });
  const t = X.wizardBridge(taken, { link: PORTAL_LINK }).model;
  assert.deepEqual(t.outbounds.map(o => o.tag), ['block', 'direct-2', 'interconn']);
  assert.equal(X.validateModel(t).ok, true);
});

test('wizardBridge refuses a missing or non-VLESS target, an unknown exit, and bad tags', () => {
  const m = model();
  assert.throws(() => X.wizardBridge(m, {}), /link|config/);
  assert.throws(() => X.wizardBridge(m, { link: 'garbage' }), /link/i);
  assert.throws(() => X.wizardBridge(m, { link: 'trojan://pw@h:443' }), /vless/i);
  assert.throws(() => X.wizardBridge(m, { serverId: 'nope', servers: [F.VLESS_WS_TLS] }), /config/);
  assert.throws(() => X.wizardBridge(m, { serverId: 'sv-trojan', servers: [F.TROJAN_TCP_TLS] }), /vless/i);
  assert.throws(() => X.wizardBridge(m, { link: PORTAL_LINK, exitOutboundTag: 'nope' }), /exit/);
  assert.throws(() => X.wizardBridge(m, { link: PORTAL_LINK, exitOutboundTag: 'block' }), /exit/, 'a blackhole is no exit');
  assert.throws(() => X.wizardBridge(m, { link: PORTAL_LINK, tag: 'Bad' }), /lower-case/);
  assert.throws(() => X.wizardBridge(m, { link: PORTAL_LINK, reverseTag: 'api' }), /core/);
  assert.equal(X.wizardBridge(m, { serverId: 'sv-vless' }).model.outbounds[2].serverId, 'sv-vless', 'without the servers list the record is taken on trust; validation checks it');
});

test('the exported names are exactly the Z1 interface', () => {
  assert.deepEqual(Object.keys(X).sort(), [
    'DEFAULT_MODEL', 'NETWORKS', 'OUTBOUND_KINDS', 'PROTOCOLS', 'RULE_PRESETS', 'SCHEMA', 'SECURITIES', 'SS_METHODS',
    'allTags', 'buildServerConfig', 'clientLink', 'clientServerRecord', 'defaultTag', 'migrateModel',
    'newClient', 'newInbound', 'newOutbound', 'newRule', 'normalizeModel', 'otherSideSnippet',
    'parseX25519', 'presetRule', 'randomKeyFor', 'randomPassword', 'randomShortId', 'slugTag',
    'validateModel', 'wizardBridge', 'wizardPortal'
  ]);
  assert.deepEqual(X.PROTOCOLS, ['vless', 'vmess', 'trojan', 'shadowsocks']);
  assert.deepEqual(X.NETWORKS, ['tcp', 'ws', 'grpc', 'xhttp']);
  assert.deepEqual(X.SECURITIES, ['none', 'tls', 'reality']);
  assert.deepEqual(X.SS_METHODS, ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', 'aes-256-gcm', 'aes-128-gcm', 'chacha20-ietf-poly1305']);
  assert.deepEqual(X.OUTBOUND_KINDS, ['freedom', 'blackhole', 'server', 'link']);
  assert.equal(Object.isFrozen(X.DEFAULT_MODEL), true);
});
