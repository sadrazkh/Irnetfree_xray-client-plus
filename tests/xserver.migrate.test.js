'use strict';
/**
 * The v1 → v2 migration of the Server tab’s model (plus). The properties
 * that matter: it is pure and total (any v1, even `{}`, gives a well-formed
 * v2 and the input is never touched), it is exact (the fixtures below pin
 * every field), the v1 exit / blocks / reverse role become ordinary tagged
 * outbounds and rules, v1 tags and meters survive, and a migrated model
 * builds the same core config the v1 builder emitted.
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const X = require('../src/main/xserver/config');
const F = require('./fixtures');

const UUID_A = '5d1a7e3c-4b0f-4a6e-9c1d-1f2e3d4c5b6a';
const UUID_B = '6d1a7e3c-4b0f-4a6e-9c1d-1f2e3d4c5b6a';
const PORTAL_LINK = `vless://${UUID_B}@203.0.113.9:47450?encryption=none&type=tcp&security=none#portal`;
const TLS = { certFile: 'C:/certs/a.crt', keyFile: 'C:/certs/a.key', serverName: 'a.example.com', alpn: ['h2', 'http/1.1'] };

/* ----------------------------- v1 fixtures ----------------------------- */

function v1Client(over) {
  return Object.assign({ id: 'c1c1c1c1c1c1c1c1', enabled: true, email: 'alice', uuid: UUID_A, password: '', flow: '', expiresAt: 0, quotaBytes: 0, limitIp: 0, note: '', used: { up: 0, down: 0 }, disabledBy: '' }, over || {});
}

function v1Inbound(over) {
  return Object.assign({
    id: 'a1b2c3d4e5f60001', tag: 'golden-a1b2', enabled: true, remark: 'Golden', protocol: 'vless', listen: '0.0.0.0', port: 443,
    network: 'tcp', path: '/', host: '', serviceName: '', security: 'none',
    tls: { certFile: '', keyFile: '', serverName: '', alpn: ['h2', 'http/1.1'] },
    reality: { dest: 'www.cloudflare.com:443', serverNames: ['www.cloudflare.com'], privateKey: '', publicKey: '', shortIds: [] },
    ss: { method: '2022-blake3-aes-128-gcm', password: '' },
    sniffing: true, clients: [v1Client()]
  }, over || {});
}

/** A whole v1 model as the v2.0 store kept it. */
function v1Model(over) {
  return Object.assign({
    autoStart: false, engine: 'xray', logLevel: 'warning', publicAddress: 'vpn.example.com',
    inbounds: [v1Inbound()],
    exit: { type: 'direct', serverId: '' },
    blockPrivate: true, blockTorrent: false,
    reverse: { role: 'off', bridge: { via: 'server', serverId: '', link: '' }, portal: { interconnInboundId: '', userInboundIds: [] } }
  }, over || {});
}

/* ----------------------------- expected v2 pieces ----------------------------- */

const v2Client = (over) => Object.assign({
  id: 'c1c1c1c1c1c1c1c1', enabled: true, email: 'alice', uuid: UUID_A, password: '', flow: '',
  limitIp: 0, quotaBytes: 0, expiresAt: 0, resetDays: 0, resetAt: 0, comment: '', reverseTag: '',
  used: { up: 0, down: 0 }, disabledBy: '', lastSeenAt: 0
}, over || {});

const v2Inbound = (over) => Object.assign({
  id: 'a1b2c3d4e5f60001', tag: 'golden-a1b2', enabled: true, remark: 'Golden', protocol: 'vless', listen: '0.0.0.0', port: 443,
  network: 'tcp', path: '/', host: '', serviceName: '', security: 'none',
  tls: { certFile: '', keyFile: '', serverName: '', alpn: ['h2', 'http/1.1'] },
  reality: { dest: 'www.cloudflare.com:443', serverNames: ['www.cloudflare.com'], privateKey: '', publicKey: '', shortIds: [] },
  ss: { method: '2022-blake3-aes-128-gcm', password: '' },
  sniffing: true, totalBytes: 0, expiresAt: 0, used: { up: 0, down: 0 }, disabledBy: '', clients: [v2Client()]
}, over || {});

const out = (tag, kind, over) => Object.assign({ id: tag, tag, kind, serverId: '', link: '', reverseTag: '', enabled: true }, over || {});
const rule = (id, over) => Object.assign({ id, enabled: true, comment: '', inboundTags: [], outboundTag: '', domain: [], ip: [], port: '', protocol: [], network: '', preset: '' }, over || {});
const PRIVATE = rule('rule-private', { preset: 'private', comment: 'block private ranges', ip: ['geoip:private'], outboundTag: 'block' });
const TORRENT = rule('rule-torrent', { preset: 'torrent', comment: 'block BitTorrent', protocol: ['bittorrent'], outboundTag: 'block' });

const build = (m, opts) => X.buildServerConfig(m, Object.assign({ apiPort: 10095, servers: [], geoAvailable: true }, opts || {}));

/* ----------------------------- the empty model ----------------------------- */

test('migrateModel({}) is the default v2 model: direct + block outbounds and the private block rule', () => {
  const m = X.migrateModel({});
  assert.deepEqual(m, {
    schema: 2, autoStart: false, engine: 'xray', logLevel: 'warning', publicAddress: '',
    inbounds: [],
    outbounds: [out('direct', 'freedom'), out('block', 'blackhole')],
    routing: { domainStrategy: 'IPIfNonMatch', rules: [PRIVATE] }
  });
  assert.deepEqual(m, X.DEFAULT_MODEL);
  assert.deepEqual(X.normalizeModel({}), X.DEFAULT_MODEL);
  assert.deepEqual(X.normalizeModel(undefined), X.DEFAULT_MODEL);
  assert.deepEqual(X.migrateModel(null), X.DEFAULT_MODEL);
  assert.deepEqual(X.migrateModel('nonsense'), X.DEFAULT_MODEL);
  assert.deepEqual(X.migrateModel({ inbounds: 'x', reverse: 7, exit: null }), X.DEFAULT_MODEL);
  assert.equal(X.SCHEMA, 2);
  assert.equal(X.validateModel(m).ok, true, 'the default model is a runnable server with no inbounds');
});

/* ----------------------------- exact outputs ----------------------------- */

test('v1 direct exit with both blocks: the note becomes the comment, the meters survive, the v1 tag is kept', () => {
  const v1 = v1Model({
    blockTorrent: true, logLevel: 'debug', autoStart: true, engine: 'xray-pattn',
    inbounds: [v1Inbound({ clients: [v1Client({ note: 'my phone', used: { up: 5, down: 7 }, quotaBytes: 9, expiresAt: 11, limitIp: 2, enabled: false, disabledBy: 'quota' })] })]
  });
  const before = JSON.stringify(v1);
  const m = X.migrateModel(v1);
  assert.deepEqual(m, {
    schema: 2, autoStart: true, engine: 'xray-pattn', logLevel: 'debug', publicAddress: 'vpn.example.com',
    inbounds: [v2Inbound({ clients: [v2Client({ comment: 'my phone', used: { up: 5, down: 7 }, quotaBytes: 9, expiresAt: 11, limitIp: 2, enabled: false, disabledBy: 'quota' })] })],
    outbounds: [out('direct', 'freedom'), out('block', 'blackhole')],
    routing: { domainStrategy: 'IPIfNonMatch', rules: [PRIVATE, TORRENT] }
  });
  assert.equal(JSON.stringify(v1), before, 'the v1 model is not touched');
  assert.equal('note' in m.inbounds[0].clients[0], false);
  assert.equal('exit' in m, false);
  assert.equal('blockPrivate' in m, false);
  assert.equal('reverse' in m, false);
});

test('v1 server exit: the first outbound is the stored config under the tag exit; no freedom outbound at all', () => {
  const m = X.migrateModel(v1Model({ exit: { type: 'server', serverId: 'sv-vless' }, blockPrivate: false, blockTorrent: true }));
  assert.deepEqual(m.outbounds, [out('exit', 'server', { serverId: 'sv-vless' }), out('block', 'blackhole')]);
  assert.deepEqual(m.routing.rules, [TORRENT]);
  const c = build(m, { servers: [F.VLESS_WS_TLS] });
  assert.deepEqual(c.outbounds.map(o => o.tag), ['exit', 'block']);
  assert.equal(c.outbounds[0].protocol, 'vless');
});

test('v1 bridge via link: an interconn outbound with the reverse tag bridge, and the bridge rule to the exit', () => {
  const m = X.migrateModel(v1Model({ blockTorrent: true, reverse: { role: 'bridge', bridge: { via: 'link', serverId: '', link: PORTAL_LINK }, portal: { interconnInboundId: '', userInboundIds: [] } } }));
  assert.deepEqual(m.outbounds, [
    out('direct', 'freedom'), out('block', 'blackhole'),
    out('interconn', 'link', { link: PORTAL_LINK, reverseTag: 'bridge' })
  ]);
  assert.deepEqual(m.routing.rules, [PRIVATE, TORRENT, rule('rule-bridge', { inboundTags: ['bridge'], outboundTag: 'direct', comment: 'reverse ← bridge' })]);
  assert.equal(X.validateModel(m).ok, true);
  // the same config the v1 builder emitted
  const c = build(m);
  assert.deepEqual(c.outbounds.map(o => o.tag), ['direct', 'block', 'interconn']);
  assert.deepEqual(c.outbounds[0], { tag: 'direct', protocol: 'freedom', settings: { finalRules: [{ action: 'allow' }] } });
  assert.deepEqual(c.outbounds[2], {
    tag: 'interconn', protocol: 'vless',
    settings: { address: '203.0.113.9', port: 47450, id: UUID_B, flow: '', encryption: 'none', reverse: { tag: 'bridge' } },
    streamSettings: { network: 'tcp', security: 'none' }
  });
  assert.deepEqual(c.routing.rules, [
    { type: 'field', ip: ['geoip:private'], outboundTag: 'block' },
    { type: 'field', protocol: ['bittorrent'], outboundTag: 'block' },
    { type: 'field', inboundTag: ['bridge'], outboundTag: 'direct' }
  ]);
});

test('v1 bridge via a stored config, with a server exit: the bridge rule goes to the exit tag that exists', () => {
  const m = X.migrateModel(v1Model({ exit: { type: 'server', serverId: 'sv-trojan' }, reverse: { role: 'bridge', bridge: { via: 'server', serverId: 'sv-vless', link: '' } } }));
  assert.deepEqual(m.outbounds, [
    out('exit', 'server', { serverId: 'sv-trojan' }), out('block', 'blackhole'),
    out('interconn', 'server', { serverId: 'sv-vless', reverseTag: 'bridge' })
  ]);
  assert.deepEqual(m.routing.rules.at(-1), rule('rule-bridge', { inboundTags: ['bridge'], outboundTag: 'exit', comment: 'reverse ← bridge' }));
  assert.equal(X.validateModel(m, { servers: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS] }).ok, true);
});

test('v1 bridge with nothing filled in still migrates; validation is what reports the missing link', () => {
  const m = X.migrateModel(v1Model({ reverse: { role: 'bridge', bridge: { via: 'link', serverId: '', link: '' } } }));
  assert.deepEqual(m.outbounds[2], out('interconn', 'link', { reverseTag: 'bridge' }));
  const v = X.validateModel(m);
  assert.equal(v.ok, false);
  assert.equal(v.errors.some(e => e.path === 'outbounds[2].link'), true);
});

function v1Portal(over) {
  return v1Model(Object.assign({
    inbounds: [
      v1Inbound({ id: 'a1b2c3d4e5f60001', tag: 'interconn-a1b2', remark: 'Interconn', port: 47450, clients: [
        v1Client({ id: 'c1c1c1c1c1c1c1c1', email: 'bridge1', uuid: UUID_B }),
        v1Client({ id: 'c4c4c4c4c4c4c4c4', email: 'bridge2', uuid: UUID_A }),
        v1Client({ id: 'c5c5c5c5c5c5c5c5', email: 'bridge3', uuid: UUID_A, enabled: false })
      ] }),
      v1Inbound({ id: 'b1b2c3d4e5f60002', tag: 'users-b1b2', remark: 'Users', port: 47451, network: 'ws', path: '/u', clients: [v1Client({ id: 'c2c2c2c2c2c2c2c2', email: 'alice' })] }),
      v1Inbound({ id: 'c1b2c3d4e5f60003', tag: 'local-c1b2', remark: 'Local', protocol: 'trojan', port: 47452, security: 'tls', tls: TLS, clients: [v1Client({ id: 'c3c3c3c3c3c3c3c3', email: 'carol', password: 'pw' })] })
    ],
    reverse: { role: 'portal', bridge: { via: 'server', serverId: '', link: '' }, portal: { interconnInboundId: 'a1b2c3d4e5f60001', userInboundIds: ['b1b2c3d4e5f60002'] } }
  }, over || {}));
}

test('v1 portal: the enabled interconn clients get the reverse tag portal; the user inbounds route to it after the blocks', () => {
  const m = X.migrateModel(v1Portal());
  assert.deepEqual(m.inbounds[0].clients.map(c => [c.email, c.reverseTag]), [['bridge1', 'portal'], ['bridge2', 'portal'], ['bridge3', '']]);
  assert.deepEqual(m.inbounds[1].clients.map(c => c.reverseTag), ['']);
  assert.deepEqual(m.outbounds, [out('direct', 'freedom'), out('block', 'blackhole')]);
  assert.deepEqual(m.routing.rules, [PRIVATE, rule('rule-portal', { inboundTags: ['users-b1b2'], outboundTag: 'portal', comment: 'reverse → portal' })]);
  assert.equal(X.validateModel(m).ok, true);
  const c = build(m);
  assert.deepEqual(c.inbounds[0].settings.clients, [
    { id: UUID_B, email: 'bridge1', reverse: { tag: 'portal' } },
    { id: UUID_A, email: 'bridge2', reverse: { tag: 'portal' } }
  ]);
  assert.deepEqual(c.inbounds[1].settings.clients, [{ id: UUID_A, email: 'alice' }]);
  assert.deepEqual(c.outbounds[0].settings, {}, 'a portal is no bridge: the freedom exit carries no allow rule');
  assert.deepEqual(c.routing.rules, [
    { type: 'field', ip: ['geoip:private'], outboundTag: 'block' },
    { type: 'field', inboundTag: ['users-b1b2'], outboundTag: 'portal' }
  ]);
});

test('v1 portal: several user inbounds share one rule in model order; the interconn itself and unknown ids are left out', () => {
  const m = X.migrateModel(v1Portal({ reverse: { role: 'portal', bridge: {}, portal: { interconnInboundId: 'a1b2c3d4e5f60001', userInboundIds: ['c1b2c3d4e5f60003', 'zzz', 'a1b2c3d4e5f60001', 'b1b2c3d4e5f60002'] } } }));
  assert.deepEqual(m.routing.rules.at(-1).inboundTags, ['users-b1b2', 'local-c1b2']);
});

test('v1 portal whose interconn inbound is gone, or without user inbounds, migrates without a dangling rule', () => {
  const gone = X.migrateModel(v1Portal({ reverse: { role: 'portal', bridge: {}, portal: { interconnInboundId: 'zzz', userInboundIds: ['b1b2c3d4e5f60002'] } } }));
  assert.deepEqual(gone.routing.rules, [PRIVATE]);
  assert.equal(gone.inbounds[0].clients.some(c => c.reverseTag), false);
  const none = X.migrateModel(v1Portal({ reverse: { role: 'portal', bridge: {}, portal: { interconnInboundId: 'a1b2c3d4e5f60001', userInboundIds: [] } } }));
  assert.deepEqual(none.routing.rules, [PRIVATE]);
  assert.equal(none.inbounds[0].clients[0].reverseTag, 'portal', 'the credential is kept: a rule can be added later');
});

test('role off: the bridge and portal fields are ignored even when filled in', () => {
  const m = X.migrateModel(v1Portal({ reverse: { role: 'off', bridge: { via: 'link', link: PORTAL_LINK }, portal: { interconnInboundId: 'a1b2c3d4e5f60001', userInboundIds: ['b1b2c3d4e5f60002'] } } }));
  assert.deepEqual(m.outbounds.map(o => o.tag), ['direct', 'block']);
  assert.deepEqual(m.routing.rules, [PRIVATE]);
  assert.equal(m.inbounds[0].clients.some(c => c.reverseTag), false);
});

/* ----------------------------- tags ----------------------------- */

test('an untagged v1 inbound gets the slug v1 would have given it; a v2 inbound without a tag gets inbound-<port>', () => {
  const v1 = X.migrateModel({ inbounds: [{ id: 'a1b2c3d4e5f60001', remark: 'Half', protocol: 'trojan', clients: [{ id: 'c1', email: 'bob', password: 'x' }] }] });
  assert.equal(v1.inbounds[0].tag, 'half-a1b2');
  const v2 = X.normalizeModel({ schema: 2, inbounds: [{ id: 'a1b2c3d4e5f60001', remark: 'Half', protocol: 'trojan', port: 2053 }] });
  assert.equal(v2.inbounds[0].tag, 'inbound-2053');
});

test('a v1 inbound already tagged direct or block pushes the new outbound to the next free name, so the migrated model still validates', () => {
  const m = X.migrateModel(v1Model({ blockTorrent: true, inbounds: [v1Inbound({ tag: 'direct' }), v1Inbound({ id: 'b1b2c3d4e5f60002', tag: 'block', port: 444, clients: [v1Client({ id: 'c2', email: 'bob' })] })] }));
  assert.deepEqual(m.outbounds.map(o => o.tag), ['direct-2', 'block-2']);
  assert.deepEqual(m.routing.rules.map(r => r.outboundTag), ['block-2', 'block-2']);
  assert.equal(X.validateModel(m).ok, true);
});

/* ----------------------------- idempotence ----------------------------- */

test('normalizeModel migrates whatever is not schema 2 and leaves a v2 model alone; migrateModel on a v2 model only normalises', () => {
  const v1 = v1Portal();
  const m = X.normalizeModel(v1);
  assert.deepEqual(m, X.migrateModel(v1));
  assert.deepEqual(X.normalizeModel(m), m, 'a second pass changes nothing');
  assert.deepEqual(X.migrateModel(m), m, 'no double migration');
  const asString = X.normalizeModel(Object.assign({}, m, { schema: '2' }));
  assert.deepEqual(asString, m, 'a schema stored as a string is the same schema');
  const stale = X.normalizeModel(Object.assign({}, m, { blockTorrent: true, exit: { type: 'server', serverId: 'x' }, reverse: { role: 'bridge' } }));
  assert.deepEqual(stale, m, 'v1 fields on a v2 model are ignored, not migrated on top');
});

test('a whole v1 golden set migrates to a model that validates and builds every inbound unchanged', () => {
  const PRIV = 'kOp0Yl1o8m6ZgFh3EiXJ5gMt3dY8hbz2j6wMv3aEp2A';
  const inbounds = [
    v1Inbound({ id: '01b2c3d4e5f60000', tag: 'vless-reality-01b2', port: 20000, security: 'reality', reality: { dest: 'www.microsoft.com:443', serverNames: ['www.microsoft.com'], privateKey: PRIV, publicKey: 'x', shortIds: ['0123456789abcdef'] }, clients: [v1Client({ id: 'c0', email: 'user0', flow: 'xtls-rprx-vision' })] }),
    v1Inbound({ id: '11b2c3d4e5f60001', tag: 'vless-ws-11b2', port: 20001, network: 'ws', path: '/ws', host: 'cdn.example.com', security: 'tls', tls: TLS, clients: [v1Client({ id: 'c1', email: 'user1' })] }),
    v1Inbound({ id: '21b2c3d4e5f60002', tag: 'trojan-21b2', port: 20002, protocol: 'trojan', security: 'tls', tls: TLS, clients: [v1Client({ id: 'c2', email: 'user2', password: 'pw' })] }),
    v1Inbound({ id: '31b2c3d4e5f60003', tag: 'ss-31b2', port: 20003, protocol: 'shadowsocks', ss: { method: 'aes-256-gcm', password: '' }, clients: [v1Client({ id: 'c3', email: 'user3', password: 'pw' })] })
  ];
  const m = X.migrateModel(v1Model({ inbounds, blockTorrent: true }));
  assert.deepEqual(X.validateModel(m), { ok: true, errors: [], warnings: [] });
  const c = build(m);
  assert.deepEqual(c.inbounds.map(i => i.tag), ['vless-reality-01b2', 'vless-ws-11b2', 'trojan-21b2', 'ss-31b2']);
  assert.deepEqual(c.inbounds[0].settings.clients, [{ id: UUID_A, email: 'user0', flow: 'xtls-rprx-vision' }]);
  assert.equal(c.inbounds[0].streamSettings.realitySettings.target, 'www.microsoft.com:443');
  assert.deepEqual(c.outbounds.map(o => o.tag), ['direct', 'block']);
  assert.deepEqual(c.routing.rules.map(r => r.outboundTag), ['block', 'block']);
});
