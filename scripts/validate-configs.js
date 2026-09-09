'use strict';
/**
 * Generate every plan shape × DNS mode × geo state and run `xray run -test` on
 * each. This is the only check that proves the CORE accepts what configBuilder
 * emits (dns.tag, the dns outbound, expectedIPs, DoH strings, inboundTag
 * rules) — the unit tests only pin our own output. Needs bin/xray(.exe)
 * (`npm run get-xray`).
 *
 * With IRNF_SINGBOX_EXE set, every TUN config tunSingbox.buildTunConfig can
 * emit is run through `sing-box check` as well (parse + build only — `check`
 * never creates an adapter) and counted into the same total.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { buildConfig } = require('../src/main/configBuilder');
const F = require('../tests/fixtures');

// IRNF_XRAY_EXE points the run at another core (e.g. the PattN fork in the
// app's userData bin) so both cores can be checked against the same shapes.
const exe = process.env.IRNF_XRAY_EXE || path.join(__dirname, '..', 'bin', process.platform === 'win32' ? 'xray.exe' : 'xray');
if (!fs.existsSync(exe)) { console.error('no core at ' + exe + ' — run: npm run get-xray'); process.exit(2); }

const single = { mode: 'single', server: F.VLESS_WS_TLS };
const chain = { mode: 'chain', chain: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS] };
const advanced = {
  mode: 'advanced', serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS },
  chainsById: { c1: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS] }, chain: [],
  rules: [{ type: 'domain', value: 'geosite:category-ir', target: 'direct' }, { type: 'ip', value: '10.20.0.0/16', target: 'chain:c1' }],
  def: 'sv-vless'
};
const pool = {
  mode: 'pool', entries: [{ id: 'e1', target: 'sv-trojan', socksPort: 60001, httpPort: 60002 }], primary: 'sv-vless',
  serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS }, chainsById: {}, chain: []
};

const plans = { single, chain, advanced, pool };
const dnsModes = {
  managed: { dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'], dnsDirect: ['178.22.122.100', '185.51.200.2'] },
  managedDohDirect: { dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: ['https://178.22.122.100/dns-query'] },
  unmanaged: { dnsManaged: false, dnsRemote: ['1.1.1.1', '8.8.8.8'] }
};
const routing = ['global', 'bypass-ir', 'bypass-cn', 'direct'];

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-validate-'));
const assetDir = path.dirname(exe);
let failed = 0, total = 0;
for (const [pn, plan] of Object.entries(plans)) {
  for (const [dn, dns] of Object.entries(dnsModes)) {
    for (const geoAssets of [true, false]) {
      // The advanced plan gets every routing mode too now that it can apply one
      // under its own rules (`advancedUseMode`) — those geo rules have to be
      // accepted by the core like any other.
      for (const routingMode of (pn === 'pool' ? ['global'] : routing)) {
        const useMode = pn === 'advanced' && routingMode !== 'global';
        for (const ipv6 of [false, true]) {
          total++;
          const cfg = buildConfig(plan, F.settings(Object.assign({ routingMode, geoAssets, ipv6, advancedUseMode: useMode }, dns)));
          const file = path.join(work, `${pn}-${dn}-${routingMode}${useMode ? '-usemode' : ''}-geo${geoAssets}-v6${ipv6}.json`);
          fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
          const r = spawnSync(exe, ['run', '-test', '-c', file], {
            env: Object.assign({}, process.env, { XRAY_LOCATION_ASSET: assetDir, V2RAY_LOCATION_ASSET: assetDir }),
            encoding: 'utf8', timeout: 15000, windowsHide: true
          });
          if (r.status === 0) { console.log('ok   ' + path.basename(file)); continue; }
          failed++;
          console.log('FAIL ' + path.basename(file));
          console.log('     ' + ((r.stdout || '') + (r.stderr || '')).trim().split(/\r?\n/).slice(-3).join('\n     '));
        }
      }
    }
  }
}

// One-off shapes the matrix does not reach: entry forms the free-text inputs
// accept, every advanced default, the anti-DPI dialer next to dns-out, a
// WireGuard outbound, LAN listening with custom rules, a corporate WireGuard's
// resolver (a server object with plain-CIDR expectedIPs and `domain:` entries,
// routed through the chain / the exit by an inboundTag+ip rule).
const managed = dnsModes.managed;
const advancedWgChain = {
  mode: 'advanced', serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-wgcorp': F.WG_CORP },
  chainsById: { c1: [F.VLESS_WS_TLS, F.WG_CORP] }, chain: [],
  rules: [{ type: 'ip', value: '192.168.0.0/16', target: 'chain:c1' }],
  def: 'sv-vless'
};
const shapes = {
  'single-managed-udpRemote-bypass-ir': [single, { routingMode: 'bypass-ir', dnsManaged: true, dnsRemote: ['1.1.1.1', '8.8.8.8'] }],
  'single-managed-hostPort-bypass-ir': [single, { routingMode: 'bypass-ir', dnsManaged: true, dnsRemote: ['1.1.1.1:5353'], dnsDirect: ['178.22.122.100:5353'] }],
  'single-managed-hostnameDoh-bypass-ir': [single, { routingMode: 'bypass-ir', dnsManaged: true, dnsRemote: ['https://dns.google/dns-query'], dnsDirect: ['https://free.shecan.ir/dns-query'] }],
  'single-managed-lanRemote': [single, { dnsManaged: true, dnsRemote: ['192.168.1.1', 'https://1.1.1.1/dns-query'] }],
  'single-managed-v6-bypass-ir': [single, { routingMode: 'bypass-ir', ipv6: true, dnsManaged: true, dnsRemote: ['[2001:4860:4860::8888]:53', 'https://1.1.1.1/dns-query'], dnsDirect: ['2a00:1450::1'] }],
  'single-unmanaged-hostPort': [single, { dnsManaged: false, dnsRemote: ['1.1.1.1:5353'] }],
  'single-fragment-bypass-ir': [{ mode: 'single', server: F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' }) }, Object.assign({ routingMode: 'bypass-ir' }, managed)],
  'single-wireguard-bypass-ir': [{ mode: 'single', server: F.WG_BAD_MASK }, Object.assign({ routingMode: 'bypass-ir' }, managed)],
  'single-allowLan-customRules': [single, Object.assign({ allowLan: true, customRules: [{ domain: 'geosite:google', outboundTag: 'proxy' }, { ip: '1.2.3.0/24', outboundTag: 'direct' }] }, managed)],
  'chain-fragment': [{ mode: 'chain', chain: [F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello' }), F.TROJAN_TCP_TLS] }, managed],
  'advanced-defDirect': [Object.assign({}, advanced, { def: 'direct' }), managed],
  'advanced-defBlock': [Object.assign({}, advanced, { def: 'block' }), managed],
  'advanced-defChain': [Object.assign({}, advanced, { def: 'chain:c1' }), managed],
  'advanced-cnDirect': [Object.assign({}, advanced, { rules: [{ type: 'domain', value: 'geosite:cn', target: 'direct' }] }), managed],
  'advanced-wgChainDns': [advancedWgChain, managed],
  'single-wgDns-domains': [{ mode: 'single', server: F.WG_CORP }, managed],
  'advanced-wgDefault': [Object.assign({}, advancedWgChain, { def: 'chain:c1' }), managed],
  'advanced-wgBlockDefault': [Object.assign({}, advancedWgChain, { def: 'block' }), managed],
  'pool-bypass-ir': [pool, Object.assign({ routingMode: 'bypass-ir' }, managed)],
  // a certificate pinned on first use (certPin.js) → tlsSettings.pinnedPeerCertSha256
  'single-certPin': [{ mode: 'single', server: Object.assign({}, F.VLESS_WS_TLS, { certPin: 'ab11bf7ac877baa539294f5a3c864b8ed43e6fe3a9a8230fc2db7fff85c27fde' }) }, managed],
  'chain-certPin-firstHop': [{ mode: 'chain', chain: [Object.assign({}, F.VLESS_WS_TLS, { certPin: 'AB:11:BF:7A:C8:77:BA:A5:39:29:4F:5A:3C:86:4B:8E:D4:3E:6F:E3:A9:A8:23:0F:C2:DB:7F:FF:85:C2:7F:DE' }), F.TROJAN_TCP_TLS] }, managed],
  // Under TUN every outbound that dials itself is bound to the physical NIC
  // (sockopt.interface — the core checks the field is well-formed, the NIC is
  // looked up at dial time; see configBuilder.bindDirectDials). One per plan
  // kind; the single carries the anti-DPI dialer so a bound dpi-* is covered.
  'single-bound-fragment': [{ mode: 'single', server: F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' }) }, Object.assign({ routingMode: 'bypass-ir', directInterface: 'Wi-Fi' }, managed)],
  'single-bound-wireguard': [{ mode: 'single', server: F.WG_BAD_MASK }, Object.assign({ directInterface: 'Wi-Fi' }, managed)],
  'chain-bound-wgExit': [{ mode: 'chain', chain: [F.VLESS_WS_TLS, F.WG_BAD_MASK] }, Object.assign({ directInterface: 'Wi-Fi' }, managed)],
  'advanced-bound-wgChain': [advancedWgChain, Object.assign({ directInterface: 'Wi-Fi' }, managed)],
  'pool-bound': [pool, Object.assign({ directInterface: 'Wi-Fi' }, managed)]
};
for (const [name, [plan, over]] of Object.entries(shapes)) {
  total++;
  const cfg = buildConfig(plan, F.settings(over));
  const file = path.join(work, `shape-${name}.json`);
  fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
  const r = spawnSync(exe, ['run', '-test', '-c', file], {
    env: Object.assign({}, process.env, { XRAY_LOCATION_ASSET: assetDir, V2RAY_LOCATION_ASSET: assetDir }),
    encoding: 'utf8', timeout: 15000, windowsHide: true
  });
  if (r.status === 0) { console.log('ok   ' + path.basename(file)); continue; }
  failed++;
  console.log('FAIL ' + path.basename(file));
  console.log('     ' + ((r.stdout || '') + (r.stderr || '')).trim().split(/\r?\n/).slice(-3).join('\n     '));
}

// The multi-target latency test (phase B): one core, an inbound per target
// routed by inboundTag — a server, a chain and an anti-DPI dialer together.
{
  const { buildMultiTestConfig } = require('../src/main/configBuilder');
  total++;
  const cfg = buildMultiTestConfig(
    [F.VLESS_WS_TLS, [F.TROJAN_TCP_TLS, F.SS_TCP], F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' })],
    [41001, 41002, 41003]);
  const file = path.join(work, 'multi-test.json');
  fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
  const r = spawnSync(exe, ['run', '-test', '-c', file], {
    env: Object.assign({}, process.env, { XRAY_LOCATION_ASSET: assetDir, V2RAY_LOCATION_ASSET: assetDir }),
    encoding: 'utf8', timeout: 15000, windowsHide: true
  });
  if (r.status === 0) console.log('ok   ' + path.basename(file));
  else {
    failed++;
    console.log('FAIL ' + path.basename(file));
    console.log('     ' + ((r.stdout || '') + (r.stderr || '')).trim().split(/\r?\n/).slice(-3).join('\n     '));
  }
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
  const certFile = path.join(work, 'server.crt'), keyFile = path.join(work, 'server.key');
  fs.writeFileSync(certFile, pem.certificate.join('\n') + '\n');
  fs.writeFileSync(keyFile, pem.key.join('\n') + '\n');
  for (const [name, cfg] of serverShapes({ certFile, keyFile })) {
    total++; srvTotal++;
    const file = path.join(work, `server-${name}.json`);
    fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
    const r = spawnSync(exe, ['run', '-test', '-c', file], {
      env: Object.assign({}, process.env, { XRAY_LOCATION_ASSET: assetDir, V2RAY_LOCATION_ASSET: assetDir }),
      encoding: 'utf8', timeout: 15000, windowsHide: true
    });
    if (r.status === 0) { console.log('ok   ' + path.basename(file)); continue; }
    failed++; srvFailed++;
    console.log('FAIL ' + path.basename(file));
    console.log('     ' + ((r.stdout || '') + (r.stderr || '')).trim().split(/\r?\n/).slice(-3).join('\n     '));
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
    const forPortal = X.otherSideSnippet(bridgeHere).snippet;
    forPortal.inbounds[0].tag = 'interconn-in'; forPortal.inbounds[0].listen = '127.0.0.1';
    forPortal.inbounds[0].streamSettings.realitySettings.privateKey = PRIV;
    forPortal.routing.rules[0].inboundTag = ['users-in'];
    forPortal.inbounds.push({ tag: 'users-in', listen: '127.0.0.1', port: 47461, protocol: 'vless', settings: { clients: [{ id: uuid, email: 'u' }], decryption: 'none' }, streamSettings: { network: 'tcp', security: 'none' } });
    out.push(['other-side-for-portal', Object.assign({ log: { loglevel: 'warning' }, outbounds: [{ tag: 'direct', protocol: 'freedom' }] }, forPortal)]);
    const forBridge = X.otherSideSnippet(portal).snippet;
    out.push(['other-side-for-bridge', Object.assign({ log: { loglevel: 'warning' } }, forBridge)]);
    return out;
  }
}

// sing-box TUN configs (phase 3): ipv6 × strict × exclusions (a v4 and a v6
// entry → /32 and /128), plus the darwin shape — no interface_name, because
// sing-tun there only accepts utun<N> and names the device itself.
let sbTotal = 0, sbFailed = 0;
const sb = process.env.IRNF_SINGBOX_EXE;
if (sb) {
  if (!fs.existsSync(sb)) { console.error('no sing-box at ' + sb); process.exit(2); }
  const { buildTunConfig } = require('../src/main/tunSingbox');
  const cases = [];
  for (const ipv6 of [false, true]) {
    for (const strict of [false, true]) {
      for (const excludeIps of [[], ['1.2.3.4', '2001:db8::1']]) {
        cases.push([`tun-v6${ipv6}-strict${strict}-exclude${excludeIps.length}`, { socksPort: 10808, ipv6, strict, excludeIps }]);
      }
    }
  }
  cases.push(['tun-darwin-noname', { socksPort: 10808, excludeIps: ['1.2.3.4'], interfaceName: null }]);
  for (const [name, args] of cases) {
    total++; sbTotal++;
    const file = path.join(work, `${name}.json`);
    fs.writeFileSync(file, JSON.stringify(buildTunConfig(args), null, 2));
    const r = spawnSync(sb, ['check', '-c', file], { encoding: 'utf8', timeout: 15000, windowsHide: true });
    if (r.status === 0) { console.log('ok   ' + path.basename(file)); continue; }
    failed++; sbFailed++;
    console.log('FAIL ' + path.basename(file));
    console.log('     ' + ((r.stdout || '') + (r.stderr || '')).trim().split(/\r?\n/).slice(-3).join('\n     '));
  }
}

const by = path.basename(exe) + ` (${srvTotal - srvFailed}/${srvTotal} server shapes)` + (sb ? ` + ${path.basename(sb)} (${sbTotal - sbFailed}/${sbTotal} TUN configs)` : '');
console.log(`\n${total - failed}/${total} configs accepted by ${by}`);
process.exit(failed ? 1 : 0);
