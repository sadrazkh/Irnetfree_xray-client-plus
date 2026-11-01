'use strict';
/**
 * plus: every config Plus writes, through `xray run -test` — the only check
 * that proves the CORE accepts it (the unit tests pin our own output).
 *
 *  - The Server tab's shapes: every golden inbound, its client link, exits
 *    through a stored config (pins, the anti-DPI dialer), the VLESS reverse
 *    proxy's portal and bridge, the wizards' output.
 *  - The scanner's shapes: for every protocol the scan takes — VLESS / VMess /
 *    Trojan / Shadowsocks over each transport, REALITY, Hysteria2 with its
 *    mask and port hopping, WireGuard, MASQUE over HTTP/3 and HTTP/2 with and
 *    without a WARP account and behind a cover domain, ECH, a JSON config with
 *    its fragment dialer — the very config a scan core gets: the targets put
 *    in by applyTarget (an IPv4, an IPv6, another port, another SNI where an
 *    SNI may change), many of them in one buildMultiTestConfig.
 *
 * Every config is first written for the core that runs it
 * (coreCompat.adaptForCore with the core's own version), as the app does.
 * MASQUE needs Xray 26.9.30 (a WARP account 26.10.10): on an older core those
 * shapes are SKIPPED and said so — CI runs them on the suggested cores (the
 * `cores` job of .github/workflows/test.yml). Xray-PattN's own masks (the
 * merge mask, PattNG's ClientHello splits — upstream v1.41) are refused by the
 * official core, so those scan shapes run only when the core is the fork:
 * IRNF_XRAY_FORK=pattn, or a core file named xray-pattn as the app installs it.
 *
 * Needs bin/xray(.exe) (`npm run get-xray`), or IRNF_XRAY_EXE.
 * IRNF_VALIDATE_DRY=1 runs no core: every config is built, adapted (for
 * IRNF_CORE_VERSION, else the suggested Xray) and written — into
 * IRNF_VALIDATE_OUT when set.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { buildMultiTestConfig } = require('../src/main/configBuilder');
const { adaptForCore } = require('../src/main/coreCompat');
const { parseLink, parseMany, createServer } = require('../src/main/parser');
const { SUGGESTED } = require('../src/main/coreVersions');
const { usesMasque, usesMasqueWarp, versionBelow, MASQUE_SINCE, MASQUE_WARP_SINCE, PATTN_OOB_SINCE, PLAINTEXT_REJECT } = require('../src/main/xrayManager');
const { applyTarget, sniSupport } = require('../src/main/scan/substitute');
const F = require('../tests/fixtures');

const DRY = process.env.IRNF_VALIDATE_DRY === '1';
const exe = process.env.IRNF_XRAY_EXE || path.join(__dirname, '..', 'bin', process.platform === 'win32' ? 'xray.exe' : 'xray');
if (!DRY && !fs.existsSync(exe)) { console.error('no core at ' + exe + ' — run: npm run get-xray'); process.exit(2); }
// Is this core the PattN fork? Its own shapes (scan-pattn-*) run then — and in a dry run.
const FORK = process.env.IRNF_XRAY_FORK === 'pattn' || /pattn/i.test(path.basename(exe));

/** The core's own version — the first x.y.z `<core> version` prints — which every config is written for. */
function coreVersion() {
  if (DRY) return process.env.IRNF_CORE_VERSION || SUGGESTED.xray;
  const r = spawnSync(exe, ['version'], { encoding: 'utf8', timeout: 15000, windowsHide: true });
  const said = `${r.stdout || ''}${r.stderr || ''}`;
  const m = /(\d+\.\d+\.\d+)/.exec(said);
  if (!m) {
    console.error(`${exe} did not say its version: ${JSON.stringify(said.trim().split(/\r?\n/)[0] || (r.error && r.error.message) || '')}`);
    process.exit(2);
  }
  return m[1];
}
const version = coreVersion();
console.log(`${path.basename(exe)} ${version}${DRY ? ' — dry run: every config is built and written, no core is run' : ''}`);

const work = process.env.IRNF_VALIDATE_OUT || fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-validate-'));
fs.mkdirSync(work, { recursive: true });
const assetDir = path.dirname(exe);
let failed = 0, total = 0, skipped = 0, forkSkipped = 0, plainToFork = 0;

/** One config: written for this core's version, then `run -test` — dry, only written. */
function check(name, cfg) {
  const need = usesMasqueWarp(cfg) ? MASQUE_WARP_SINCE : (usesMasque(cfg) ? MASQUE_SINCE : '');
  if (!DRY && need && versionBelow(version, need)) {
    skipped++;
    console.log(`skip ${name}.json — MASQUE${need === MASQUE_WARP_SINCE ? ' with a WARP account' : ''} needs ${need}, this core is ${version}`);
    return;
  }
  total++;
  const file = path.join(work, `${name}.json`);
  fs.writeFileSync(file, JSON.stringify(adaptForCore(cfg, version), null, 2));
  if (DRY) { console.log('built ' + path.basename(file)); return; }
  const r = spawnSync(exe, ['run', '-test', '-c', file], {
    env: Object.assign({}, process.env, { XRAY_LOCATION_ASSET: assetDir, V2RAY_LOCATION_ASSET: assetDir }),
    encoding: 'utf8', timeout: 15000, windowsHide: true
  });
  if (r.status === 0) { console.log('ok   ' + path.basename(file)); return; }
  const said = ((r.stdout || '') + (r.stderr || '')).trim();
  // The official core refuses VLESS/Trojan without TLS to a public address (26.10.31 measured it on the
  // server tab's plaintext bridge links). The server tab runs such a config on Xray-PattN, as the client
  // does (xserver/core.js, xrayManager's validateWithFallback) — so here it is that core's to prove: the
  // PattN step (IRNF_XRAY_FORK=pattn) takes the same shape with no such allowance.
  if (!FORK && PLAINTEXT_REJECT.test(said)) {
    plainToFork++;
    console.log(`fork ${path.basename(file)} — the official core refuses plaintext to a public address; it runs on Xray-PattN, whose step proves it`);
    return;
  }
  failed++;
  console.log('FAIL ' + path.basename(file));
  console.log('     ' + said.split(/\r?\n/).slice(-3).join('\n     '));
}

// Server-tab shapes (plus): every golden inbound, the exit through a stored
// config, a bridge and a portal of the VLESS reverse proxy — and, for each
// golden inbound, the CLIENT config its share link parses into, so the link a
// user copies is proven to dial in a form the core takes. The TLS inbounds
// need real files (the core reads them at load), so the self-signed pair from
// tests/fixtures is written to the work dir. Nothing listens: `-test` only.
let srvTotal = 0, srvFailed = 0;
{
  const X = require('../src/main/xserver/config');
  const { buildTestConfig } = require('../src/main/configBuilder');
  const { parseLink } = require('../src/main/parser');
  const pem = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'tests', 'fixtures', 'selfsigned.json'), 'utf8'));
  const pemDir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-plus-pem-'));
  const certFile = path.join(pemDir, 'server.crt'), keyFile = path.join(pemDir, 'server.key');
  fs.writeFileSync(certFile, pem.certificate.join('\n') + '\n');
  fs.writeFileSync(keyFile, pem.key.join('\n') + '\n');
  for (const [name, cfg] of serverShapes({ certFile, keyFile })) {
    const before = failed;
    srvTotal++;
    check(`server-${name}`, cfg);
    if (failed > before) srvFailed++;
  }

  function serverShapes({ certFile, keyFile }) {
    const PRIV = 'kOp0Yl1o8m6ZgFh3EiXJ5gMt3dY8hbz2j6wMv3aEp2A';
    const PUB = 'D5UJIsDIIYFaaZxWaOsbUmB-uLE2OgOV1r-qyBHIsyI';
    const tls = { certFile, keyFile, serverName: 'a.example.com', alpn: ['h2', 'http/1.1'] };
    const reality = { dest: 'www.microsoft.com:443', serverNames: ['www.microsoft.com'], privateKey: PRIV, publicKey: PUB, shortIds: [X.randomShortId()] };
    const alice = (protocol, over) => X.newClient(protocol, Object.assign({ email: 'alice' }, over || {}));
    // Every inbound listens on loopback at a high port; -test binds nothing anyway.
    const inb = (protocol, over, clients) => X.newInbound(protocol, Object.assign({ listen: '127.0.0.1' }, over, { clients: clients || [alice(protocol, over && over.ss ? { method: over.ss.method } : null)] }));
    const golden = {
      'vless-tcp-reality': inb('vless', { port: 47443, security: 'reality', reality }, [alice('vless', { flow: 'xtls-rprx-vision' })]),
      'vless-ws-tls': inb('vless', { port: 47444, network: 'ws', path: '/ws', host: 'cdn.example.com', security: 'tls', tls }),
      'vless-grpc-tls': inb('vless', { port: 47445, network: 'grpc', serviceName: 'svc', security: 'tls', tls }),
      'vless-grpc-reality': inb('vless', { port: 47455, network: 'grpc', serviceName: 'svc', security: 'reality', reality }),
      'vless-xhttp-none': inb('vless', { port: 47446, network: 'xhttp', path: '/x', host: 'x.example.com', security: 'none' }),
      'vless-xhttp-reality': inb('vless', { port: 47456, network: 'xhttp', path: '/x', host: '', security: 'reality', reality }),
      'vmess-ws-none': inb('vmess', { port: 47447, network: 'ws', path: '/v', host: '' }),
      'vmess-tcp-tls': inb('vmess', { port: 47457, network: 'tcp', security: 'tls', tls }),
      'trojan-tcp-tls': inb('trojan', { port: 47448, security: 'tls', tls }),
      'trojan-ws-tls': inb('trojan', { port: 47458, network: 'ws', path: '/t', security: 'tls', tls }),
      'ss-2022-128': inb('shadowsocks', { port: 47388, ss: { method: '2022-blake3-aes-128-gcm', password: X.randomKeyFor('2022-blake3-aes-128-gcm') } }),
      'ss-2022-256': inb('shadowsocks', { port: 47389, ss: { method: '2022-blake3-aes-256-gcm', password: X.randomKeyFor('2022-blake3-aes-256-gcm') } }),
      'ss-aes-256-gcm': inb('shadowsocks', { port: 47390, ss: { method: 'aes-256-gcm', password: '' } }),
      'ss-chacha20': inb('shadowsocks', { port: 47391, ss: { method: 'chacha20-ietf-poly1305', password: '' } })
    };
    // Client names are unique across a server, so the combined models below can hold every golden inbound at once.
    for (const [name, i] of Object.entries(golden)) i.clients[0].email = name;
    const model = (over) => X.normalizeModel(Object.assign({ publicAddress: '203.0.113.9', blockPrivate: true, blockTorrent: true }, over));
    const build = (m, over) => X.buildServerConfig(m, Object.assign({ apiPort: 47095, servers: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS], geoAvailable: true }, over || {}));
    const out = [];
    for (const [name, i] of Object.entries(golden)) {
      const m = model({ inbounds: [i] });
      const v = X.validateModel(m, { servers: [] });
      if (!v.ok) throw new Error(`server shape ${name} does not validate: ${JSON.stringify(v.errors)}`);
      out.push([name, build(m)]);
      // the client that this inbound's link produces, dialling it
      out.push(['client-' + name, buildTestConfig(parseLink(X.clientLink(i, i.clients[0], m)), 47001)]);
    }
    const all = Object.values(golden);
    out.push(['all-nogeo', build(model({ inbounds: all }), { geoAvailable: false })]);
    out.push(['exit-server-pinned', build(model({ inbounds: [golden['vless-xhttp-none']], exit: { type: 'server', serverId: 'sv-vless' } }),
      { servers: [Object.assign({}, F.VLESS_WS_TLS, { certPin: 'ab11bf7ac877baa539294f5a3c864b8ed43e6fe3a9a8230fc2db7fff85c27fde' })] })]);
    out.push(['exit-server-fragment', build(model({ inbounds: [golden['vless-xhttp-none']], exit: { type: 'server', serverId: 'sv-frag' } }),
      { servers: [F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' })] })]);
    // bridges: a plain portal link, a reality+vision one, one with the anti-DPI dialer, a stored ws+tls config
    const uuid = X.newClient('vless').uuid;
    const sid = X.randomShortId();
    out.push(['bridge-link', build(model({ inbounds: [golden['vless-ws-tls']], reverse: { role: 'bridge', bridge: { via: 'link', link: `vless://${uuid}@203.0.113.9:47450?encryption=none&type=tcp&security=none#portal` } } }))]);
    out.push(['bridge-link-reality-vision', build(model({ reverse: { role: 'bridge', bridge: { via: 'link', link: `vless://${uuid}@203.0.113.9:47443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=${PUB}&sid=${sid}#portal` } } }))]);
    out.push(['bridge-link-fragment', build(model({ reverse: { role: 'bridge', bridge: { via: 'link', link: `vless://${uuid}@203.0.113.9:47450?encryption=none&type=tcp&security=none&fragment=tlshello,100-200,10-20#portal` } } }))]);
    out.push(['bridge-server', build(model({ reverse: { role: 'bridge', bridge: { via: 'server', serverId: 'sv-vless' } } }))]);
    // portal: a reality+vision interconn with two bridge clients, three user inbounds, one inbound left local
    const interconn = inb('vless', { port: 47450, security: 'reality', reality }, [alice('vless', { email: 'bridge1', flow: 'xtls-rprx-vision' }), alice('vless', { email: 'bridge2' })]);
    const users = [golden['vless-ws-tls'], golden['vless-grpc-tls'], golden['trojan-tcp-tls']];
    const local = golden['ss-2022-128'];
    const portal = model({ inbounds: [interconn, ...users, local], reverse: { role: 'portal', portal: { interconnInboundId: interconn.id, userInboundIds: users.map(u => u.id) } } });
    const pv = X.validateModel(portal, { servers: [] });
    if (!pv.ok) throw new Error('portal shape does not validate: ' + JSON.stringify(pv.errors));
    out.push(['portal', build(portal)]);
    out.push(['portal-nogeo-exit-server', build(Object.assign({}, portal, { exit: { type: 'server', serverId: 'sv-trojan' } }), { geoAvailable: false })]);
    // the other side's snippets, wrapped into runnable configs
    const bridgeHere = model({ reverse: { role: 'bridge', bridge: { via: 'link', link: `vless://${uuid}@203.0.113.9:47443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=${PUB}&sid=${sid}#portal` } } });
    const forPortal = X.otherSideSnippet(bridgeHere).items.find(it => it.kind === 'portal-side').snippet;
    forPortal.inbounds[0].tag = 'interconn-in'; forPortal.inbounds[0].listen = '127.0.0.1';
    forPortal.inbounds[0].streamSettings.realitySettings.privateKey = PRIV;
    forPortal.routing.rules[0].inboundTag = ['users-in'];
    forPortal.inbounds.push({ tag: 'users-in', listen: '127.0.0.1', port: 47461, protocol: 'vless', settings: { clients: [{ id: uuid, email: 'u' }], decryption: 'none' }, streamSettings: { network: 'tcp', security: 'none' } });
    out.push(['other-side-for-portal', Object.assign({ log: { loglevel: 'warning' }, outbounds: [{ tag: 'direct', protocol: 'freedom' }] }, forPortal)]);
    const forBridge = X.otherSideSnippet(portal).items.find(it => it.kind === 'bridge-side').snippet;
    out.push(['other-side-for-bridge', Object.assign({ log: { loglevel: 'warning' } }, forBridge)]);
    // v2 shapes: what the two wizards write, and a model with three tagged outbounds and the preset rules
    const model2 = (over) => X.normalizeModel(Object.assign({
      schema: 2, publicAddress: '203.0.113.9',
      outbounds: [X.newOutbound('freedom', { tag: 'direct' }), X.newOutbound('blackhole', { tag: 'block' })],
      routing: { rules: [X.presetRule('private'), X.presetRule('torrent')] }
    }, over));
    const wIc = inb('vless', { port: 47470, security: 'reality', reality }, [alice('vless', { email: 'wbridge', flow: 'xtls-rprx-vision' })]);
    const wUsers = golden['vmess-ws-none'];
    const wp = X.wizardPortal(model2({ inbounds: [wIc, wUsers] }), { inboundId: wIc.id, clientId: wIc.clients[0].id, userInboundIds: [wUsers.id] });
    out.push(['wizard-portal', build(wp.model)]);
    const wb = X.wizardBridge(model2({ inbounds: [golden['trojan-tcp-tls']] }), { link: wp.link });
    out.push(['wizard-bridge', build(wb.model)]);
    const wbServer = X.wizardBridge(model2({ inbounds: [golden['vless-grpc-tls']] }), { serverId: 'sv-vless', servers: [F.VLESS_WS_TLS], exitOutboundTag: 'direct' });
    out.push(['wizard-bridge-stored', build(wbServer.model)]);
    const three = model2({
      inbounds: [golden['vless-tcp-reality']],
      outbounds: [X.newOutbound('freedom', { tag: 'direct' }), X.newOutbound('server', { tag: 'via-proxy', serverId: 'sv-trojan' }), X.newOutbound('blackhole', { tag: 'block' })],
      routing: { rules: [X.presetRule('private'), X.presetRule('torrent'), X.presetRule('ads'), X.newRule({ inboundTags: [golden['vless-tcp-reality'].tag], domain: ['geosite:google'], outboundTag: 'via-proxy', comment: 'google through the proxy' })] }
    });
    out.push(['three-outbounds-presets', build(three)]);
    for (const [name, m] of [['wizard-portal', wp.model], ['wizard-bridge', wb.model], ['wizard-bridge-stored', wbServer.model], ['three-outbounds-presets', three]]) {
      const v = X.validateModel(m, { servers: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS] });
      if (!v.ok) throw new Error(`server shape ${name} does not validate: ${JSON.stringify(v.errors)}`);
    }
    return out;
  }
}


// Scanner shapes: what a scan core is handed — one config per stored server,
// every target of the variant matrix in it (one inbound and one outbound each).
let scanTotal = 0, scanFailed = 0;
{
  const DEVICE_KEY = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ format: 'pem', type: 'pkcs8' });
  const WARP_PUB = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==';
  const UUID = '2c0f0d9a-6b3a-4f0e-9a1f-8c2b4d6e7a10';
  const PBK = 'Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw';
  // an ECHConfigList as a fetch hands it over: one 0xfe0d config, X25519, HKDF-SHA256 + AES-128-GCM, public name cloudflare-ech.com
  const ECH_LIST = (() => {
    const name = Buffer.from('cloudflare-ech.com');
    const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
    const pub = crypto.randomBytes(32);
    const contents = Buffer.concat([Buffer.from([1]), u16(0x0020), u16(32), pub, u16(4), u16(1), u16(1), Buffer.from([0]), Buffer.from([name.length]), name, u16(0)]);
    const config = Buffer.concat([u16(0xfe0d), u16(contents.length), contents]);
    return Buffer.concat([u16(config.length), config]).toString('base64');
  })();
  const link = (l) => parseLink(l);
  const masque = (over) => createServer(Object.assign({ protocol: 'masque', name: 'mq', port: '443' }, over));
  const warp = { address: '162.159.198.1', sni: 'consumer-masque.cloudflareclient.com', warpPrivateKey: DEVICE_KEY, warpPublicKey: WARP_PUB, warpAddress: '172.16.0.2, 2606:4700:110:8a36::2' };
  const jsonServer = parseMany(JSON.stringify({
    remarks: 'json-frag',
    outbounds: [
      { tag: 'proxy', protocol: 'vless', settings: { vnext: [{ address: 'j.example.com', port: 443, users: [{ id: UUID, encryption: 'none' }] }] },
        streamSettings: { network: 'ws', security: 'tls', tlsSettings: { serverName: 'j.example.com' }, wsSettings: { path: '/j' }, sockopt: { dialerProxy: 'frag' } } },
      { tag: 'frag', protocol: 'freedom', settings: { fragment: { packets: 'tlshello', length: '100-200', interval: '10-20' } } }
    ]
  })).servers[0];

  const servers = {
    'vless-ws-tls': F.VLESS_WS_TLS,
    'trojan-tcp-tls': F.TROJAN_TCP_TLS,
    'ss-tcp': F.SS_TCP,
    'vless-xhttp-tls': link(`vless://${UUID}@x.example.com:443?encryption=none&type=xhttp&security=tls&sni=x.example.com&host=x.example.com&path=%2Fx&mode=packet-up#x`),
    'vless-grpc-tls': link(`vless://${UUID}@g.example.com:443?encryption=none&type=grpc&security=tls&sni=g.example.com&serviceName=svc#g`),
    'vless-httpupgrade-tls': link(`vless://${UUID}@u.example.com:443?encryption=none&type=httpupgrade&security=tls&sni=u.example.com&path=%2Fu#u`),
    'vmess-ws-none': link('vmess://' + Buffer.from(JSON.stringify({ v: '2', ps: 'vm', add: 'v.example.com', port: '80', id: UUID, aid: '0', net: 'ws', type: 'none', host: 'v.example.com', path: '/v', tls: '' })).toString('base64')),
    'vless-reality-vision': link(`vless://${UUID}@r.example.com:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=${PBK}&sid=6ba85179#r`),
    'vless-ws-tls-ech': link(`vless://${UUID}@e.example.com:443?encryption=none&type=ws&security=tls&sni=e.example.com&host=e.example.com&path=%2Fws&ech=${encodeURIComponent(ECH_LIST)}#ech`),
    'vless-ws-tls-fragment': F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' }),
    'hy2-salamander-hop': link('hy2://secret@h.example.com:443?sni=h.example.com&obfs=salamander&obfs-password=mask&mport=20000-30000#hy2'),
    'wireguard': link('wireguard://2K2GILDj0FUWeLh2MhyzOfVm3cpC7evzkWZGRNL7yUA%3D@engage.cloudflareclient.com:2408?publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&address=172.16.0.2%2F32&mtu=1280#wg'),
    'json-fragment': jsonServer,
    'masque-h3': masque({ address: 'mq.example.com', sni: 'mq.example.com', masqueUser: 'u', masquePass: 'p' }),
    'masque-h2': masque({ address: 'mq.example.com', sni: 'mq.example.com', masqueUser: 'u', masquePass: 'p', masqueHttp: 'h2', fp: 'chrome' }),
    'warp-h3': masque(warp),
    'warp-h2-cover': masque(Object.assign({}, warp, { masqueHttp: 'h2', fp: 'chrome', sni: 'www.example.com', vcn: 'www.example.com' }))
  };
  // Xray-PattN's dial tricks as a scan hands them on — applyTarget keeps a
  // server's sockopt and finalmask (upstream v1.41, xrayManager.pattnOobNeeds).
  // dialMode's OOB bytes are a sockopt key the official core does not know and
  // ignores, so that shape runs on every core; the merge mask and PattNG's
  // ClientHello splits the official core refuses ("unknown config id: merge"),
  // so those run only on the fork (FORK above; the CI's cores job says which
  // run that is). The presets are the editor's own (serverFields.js).
  const SFP = require('../src/renderer/serverFields');
  const withStream = (server, id, { sockopt, finalmask } = {}) => {
    const s = JSON.parse(JSON.stringify(server));
    s.id = id;
    s.name = id;
    const st = s.outbound.streamSettings || (s.outbound.streamSettings = {});
    if (sockopt) st.sockopt = Object.assign({}, st.sockopt, sockopt);
    if (finalmask) st.finalmask = finalmask;
    return s;
  };
  const preset = (name) => {
    const p = SFP.FINALMASK_PRESETS.find((x) => x.name === name);
    if (!p) throw new Error('no finalmask preset named ' + name);
    return JSON.parse(p.value);
  };
  servers['vless-ws-tls-dialmode'] = withStream(F.VLESS_WS_TLS, 'sv-oob', { sockopt: { dialMode: SFP.DIAL_MODE_PRESETS[0].value } });
  const pattnServers = {
    'vless-ws-tls-merge': withStream(F.VLESS_WS_TLS, 'sv-merge', { finalmask: preset('merge') }),
    'trojan-tcp-tls-merge-dialmode': withStream(F.TROJAN_TCP_TLS, 'sv-merge-oob', { finalmask: preset('merge'), sockopt: { dialMode: 'oob.0' } }),
    'vless-ws-tls-tlshello-0-len': withStream(F.VLESS_WS_TLS, 'sv-th0', { finalmask: preset('tlshello-0-len (0-104-1-0-0-114-1-1-11)') })
  };
  const variants = [
    { addr: '104.16.0.1' },
    { addr: '2606:4700::1' },
    { addr: '104.16.0.2', port: 2053 },
    { addr: '104.16.0.3', sni: 'front.example.org' }
  ];
  const scanShape = (name, server) => {
    if (!server || !server.outbound) throw new Error('scan shape ' + name + ' did not parse');
    const sniOk = sniSupport(server).ok;
    const list = variants.filter(v => !v.sni || sniOk).map(v => applyTarget(server, v));
    const before = failed, beforeSkip = skipped;
    check(`scan-${name}`, buildMultiTestConfig(list, list.map((x, i) => 47600 + i)));
    if (skipped === beforeSkip) { scanTotal++; if (failed > before) scanFailed++; }
  };
  for (const [name, server] of Object.entries(servers)) scanShape(name, server);
  for (const [name, server] of Object.entries(pattnServers)) {
    if (DRY || (FORK && !versionBelow(version, PATTN_OOB_SINCE))) scanShape(`pattn-${name}`, server);
    else {
      forkSkipped++;
      console.log(`skip scan-pattn-${name}.json — ${FORK ? `Xray-PattN ${version} is older than ${PATTN_OOB_SINCE}, which knows these masks` : `Xray-PattN's own (IRNF_XRAY_FORK=pattn runs it)`}`);
    }
  }
}

if (DRY) {
  console.log(`\n${total} configs built for xray ${version} (${srvTotal} server shapes, ${scanTotal} scan shapes) in ${work} — no core was run`);
  process.exit(0);
}
const by = `${path.basename(exe)} ${version} (${srvTotal - srvFailed}/${srvTotal} server shapes, ${scanTotal - scanFailed}/${scanTotal} scan shapes${skipped ? `, ${skipped} MASQUE shape(s) skipped: this core is older than MASQUE` : ''}${forkSkipped ? `, ${forkSkipped} Xray-PattN shape(s) skipped: IRNF_XRAY_FORK=pattn runs them` : ''}${plainToFork ? `, ${plainToFork} plaintext shape(s) left to Xray-PattN: the official core refuses them` : ''})`;
console.log(`\n${total - failed}/${total} configs accepted by ${by}`);
process.exit(failed ? 1 : 0);
