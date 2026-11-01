'use strict';
/**
 * The scan's parameter matrix (src/main/scan/variants.js): a config's
 * parameters — fingerprint, ALPN, cipherSuites, fragment, finalmask,
 * dialMode, mux, XHTTP's mode — tried as a product, on top of the targets.
 *
 * What matters: a value reads the way the app's own fields read it (presets
 * by name, custom text checked, a bad one refused alone); the product is the
 * full cartesian one with stable keys and readable labels; a dimension, a
 * value or a combination that would do nothing on this config is left out
 * with the reason and never written; each value lands where the parser and
 * configBuilder keep it — so the test config the scan runs is the one the app
 * would run — on every protocol, a JSON config's own `json` included; what
 * only Xray-PattN runs is run on PattN or not at all; and the cap takes an
 * even, repeatable sample in which every variant and every target gets its
 * share.
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const V = require('../src/main/scan/variants');
const { applyTarget } = require('../src/main/scan/substitute');
const { createServer, parseLink, buildShareLink } = require('../src/main/parser');
const { importJson } = require('../src/main/jsonImport');
const { buildMultiTestConfig } = require('../src/main/configBuilder');
const SF = require('../src/renderer/serverFields');
const F = require('./fixtures');

const clone = (o) => JSON.parse(JSON.stringify(o));
const spec = (dims, limit) => V.sanitizeSpec({ dims, limit });

const VLESS_WS = () => clone(F.VLESS_WS_TLS);
const TROJAN = () => clone(F.TROJAN_TCP_TLS);
const SS = () => clone(F.SS_TCP);
const WG = () => clone(F.WG_BAD_MASK);
const VMESS_WS = () => createServer({ protocol: 'vmess', name: 'vm', address: 'v.example.com', port: 8080, uuid: 'u-vm', network: 'ws', path: '/vm' });
const VMESS_TLS = () => parseLink('vmess://' + Buffer.from(JSON.stringify({ v: '2', ps: 'vt', add: 'vt.example.com', port: '443', id: 'u-vt', aid: '0', net: 'ws', path: '/v', host: 'vt.example.com', tls: 'tls', sni: 'vt.example.com', fp: 'chrome' })).toString('base64'));
const HY2 = () => parseLink('hy2://pass@h.example:443?sni=h.example#x');
const REALITY = () => createServer({ protocol: 'vless', name: 'r', address: 'r.example.com', port: 443, uuid: 'u', security: 'reality', pbk: 'abc', sni: 'www.microsoft.com' });
const MASQUE_H2 = () => createServer({ protocol: 'masque', name: 'mq', address: 'm.example.com', port: 443, masqueHttp: 'h2', sni: 'cover.example', vcn: 'm.example.com' });
const MASQUE_H3 = () => createServer({ protocol: 'masque', name: 'mq3', address: 'm.example.com', port: 8443 });
const XHTTP = () => parseLink('vless://u@x.example.com:443?encryption=none&type=xhttp&security=tls&sni=x.example.com&host=x.example.com&path=%2Fx&mode=auto#x');
const KCP = () => parseLink('vless://u@k.example.com:443?encryption=none&type=kcp&headerType=none&security=none#k');
const VISION = () => parseLink('vless://u@v.example.com:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=tls&sni=v.example.com&fp=chrome#v');

const jsonServer = (config) => {
  const r = importJson(JSON.stringify(config));
  assert.equal(r.errors.length, 0, JSON.stringify(r.errors));
  return r.servers[0];
};
const MAIN = (stream) => ({
  tag: 'proxy', protocol: 'vless',
  settings: { vnext: [{ address: 'j.example.com', port: 443, users: [{ id: 'u', encryption: 'none' }] }] },
  streamSettings: Object.assign({ network: 'ws', security: 'tls', tlsSettings: { serverName: 'j.example.com', fingerprint: 'chrome' }, wsSettings: { path: '/j' } }, stream || {})
});
const FRAG = { tag: 'frag', protocol: 'freedom', settings: { fragment: { packets: 'tlshello', length: '100-200', interval: '10-20' } } };
const JSON_PLAIN = () => jsonServer({ remarks: 'J', outbounds: [MAIN(), { tag: 'direct', protocol: 'freedom' }] });
const JSON_HELPER = () => jsonServer({ remarks: 'JH', outbounds: [MAIN({ sockopt: { dialerProxy: 'frag' } }), FRAG] });

/* ------------------------------- values ------------------------------- */

test('a value reads as the app’s fields read it: presets by name, custom text checked, `none` removes, a bad one refused alone', () => {
  assert.deepEqual(V.readValue('fingerprint', 'HelloChrome_120'), { id: 'hellochrome_120', value: 'hellochrome_120', raw: 'hellochrome_120' });
  assert.match(V.readValue('fingerprint', 'chrome_999').error, /not one of/);
  assert.deepEqual(V.readValue('alpn', ' h2 , http/1.1 '), { id: 'h2,http/1.1', value: 'h2,http/1.1', raw: 'h2,http/1.1' });
  assert.deepEqual(V.readValue('alpn', 'none'), { id: 'none', value: null, raw: 'none' });
  assert.match(V.readValue('alpn', 'h2;x y').error, /ALPN/);

  const ff = V.readValue('cipherSuites', 'real-firefox');
  assert.equal(ff.id, 'real-firefox');
  assert.equal(ff.value.split(':').length, 12);
  assert.ok(ff.value.startsWith('TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:'));
  assert.equal(V.readValue('cipherSuites', V.CIPHER_PRESETS['semi-python']).id, 'semi-python', 'the list itself is the preset');
  const own = V.readValue('cipherSuites', 'TLS_AES_128_GCM_SHA256 : TLS_CHACHA20_POLY1305_SHA256');
  assert.equal(own.value, 'TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256');
  assert.match(own.id, /^custom-[0-9a-f]{6}$/);
  assert.match(V.readValue('cipherSuites', 'tls_aes;x').error, /cipherSuites/);

  assert.deepEqual(V.readValue('fragment', 'tlshello, 100-200, 10-20'), { id: 'tlshello,100-200,10-20', value: 'tlshello,100-200,10-20', raw: 'tlshello,100-200,10-20' });
  assert.equal(V.readValue('fragment', 'OFF').value, null);
  assert.ok(V.readValue('fragment', '1-3,1-5').value);
  for (const bad of ['hello,1-2,1', 'tlshello,a-b', '1,2,3,4']) assert.match(V.readValue('fragment', bad).error, /fragment/, bad);

  const fm = V.readValue('finalMask', 'tlshello-0-len');
  assert.deepEqual(fm.value.tcp[0].settings.lengths, ['0', '104', '1']);
  assert.deepEqual(V.readValue('finalMask', 'tlshello').value.tcp[0].settings.lengths, ['6', '98', '1']);
  assert.equal(V.readValue('finalMask', 'udp-noise').value.udp[0].settings.noise.length, 24);
  assert.equal(V.readValue('finalMask', JSON.stringify(V.FINALMASK_PRESETS.merge)).id, 'merge', 'the JSON of a preset is the preset, key order aside');
  const custom = V.readValue('finalMask', '{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["3-5"],"delays":["10-20"]}}]}');
  assert.match(custom.id, /^custom-[0-9a-f]{6}$/);
  assert.equal(JSON.parse(custom.raw).tcp[0].type, 'fragment');
  for (const bad of ['{', '[]', '{"quicParams":{}}', '{"tcp":[]}', '{"tcp":[{"settings":{}}]}']) assert.ok(V.readValue('finalMask', bad).error, bad);

  assert.deepEqual(V.readValue('dialMode', 'OOB.0,32,65'), { id: 'oob.0,32,65', value: 'oob.0,32,65', raw: 'oob.0,32,65' });
  for (const bad of ['oob', 'oob.256', 'oob.1,', 'urg.1']) assert.match(V.readValue('dialMode', bad).error, /dialMode/, bad);
  assert.equal(V.readValue('mux', 'ON').value, 'on');
  assert.ok(V.readValue('xhttpMode', 'stream-one').value);
  assert.ok(V.readValue('xhttpMode', 'stream').error);
  assert.ok(V.readValue('nope', 'x').error);
});

test('sanitizeSpec keeps the dimensions with values, each value once, the errors apart, and a limit of 300 unless told', () => {
  const s = spec({ fingerprint: ['chrome', 'CHROME', 'bogus'], alpn: [], dialMode: ['none', 'oob.0'], junk: ['x'] });
  assert.deepEqual(s.dims.map((d) => [d.id, d.values.map((v) => v.id)]), [['fingerprint', ['chrome']], ['dialMode', ['none', 'oob.0']]]);
  assert.deepEqual(s.errors.map((e) => [e.dim, e.value]), [['fingerprint', 'bogus']]);
  assert.equal(s.limit, 300);
  assert.equal(spec({}, 0).limit, 1);
  assert.equal(spec({}, 1e12).limit, V.MAX_LIMIT);
  assert.equal(V.sanitizeSpec(null).dims.length, 0);
});

test('the presets are the synced editor’s (serverFields), under their short names, and still PattNG’s values', () => {
  assert.deepEqual(Object.keys(V.FINALMASK_PRESETS), ['tlshello-0-len', 'tlshello', 'udp-noise', 'merge']);
  assert.deepEqual(Object.keys(V.CIPHER_PRESETS).sort(), ['real-firefox', 'semi-python']);
  for (const p of SF.FINALMASK_PRESETS) assert.ok(Object.values(V.FINALMASK_PRESETS).some((v) => V.canon(v) === V.canon(JSON.parse(p.value))), p.name);
  assert.deepEqual(V.FINGERPRINTS, SF.FINGERPRINTS);
  assert.ok(V.FINGERPRINTS.includes('hellochrome_120'));
  // the brief's values, so a sync that changed them would say so here
  const fm = V.FINALMASK_PRESETS;
  assert.deepEqual(fm['tlshello-0-len'], { tcp: [
    { type: 'fragment', settings: { packets: 'tlshello', lengths: ['0', '104', '1'], delays: ['0'], maxSplit: '0' } },
    { type: 'fragment', settings: { packets: '1-1', lengths: ['114', '1'], delays: ['1'], maxSplit: '11' } }] });
  assert.deepEqual(fm.tlshello.tcp[0].settings.lengths, ['6', '98', '1']);
  assert.deepEqual(fm['udp-noise'].udp[0].settings.noise, Array.from({ length: 24 }, () => ({ rand: '1200-1230', delay: '10' })));
  assert.equal(fm['udp-noise'].udp[0].settings.reset, '28');
  assert.deepEqual(fm.merge, { tcp: [{ type: 'merge', settings: { times: 100, delayMs: 30, maxBytes: 16384 } }] });
  assert.ok(V.CIPHER_PRESETS['real-firefox'].endsWith(':TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA'));
  assert.ok(V.CIPHER_PRESETS['semi-python'].endsWith(':TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'));
  assert.deepEqual(V.catalog().find((d) => d.id === 'dialMode').presets, SF.DIAL_MODE_PRESETS.map((p) => p.value));
});

/* ------------------------------- what applies ------------------------------- */

const okDims = (server) => Object.entries(V.applicability(server)).filter(([, a]) => a.ok).map(([id]) => id);

test('what applies, protocol by protocol — and the config’s own value beside it', () => {
  assert.deepEqual(okDims(VLESS_WS()), ['fingerprint', 'alpn', 'cipherSuites', 'fragment', 'finalMask', 'dialMode', 'mux']);
  const a = V.applicability(VLESS_WS());
  assert.deepEqual([a.fingerprint.current, a.alpn.current, a.cipherSuites.current, a.fragment.current, a.finalMask.current, a.dialMode.current, a.mux.current],
    ['chrome', 'none', 'none', 'off', 'none', 'none', 'off']);
  assert.match(a.xhttpMode.reason, /not an XHTTP/);

  assert.deepEqual(okDims(TROJAN()), ['fingerprint', 'alpn', 'cipherSuites', 'fragment', 'finalMask', 'dialMode'], 'trojan over raw TCP takes no mux');
  assert.match(V.applicability(TROJAN()).mux.reason, /ws or httpupgrade/);
  assert.deepEqual(okDims(VMESS_WS()), ['fragment', 'finalMask', 'dialMode', 'mux'], 'no TLS: no fingerprint, ALPN or ciphers');
  assert.match(V.applicability(VMESS_WS()).fingerprint.reason, /no TLS/);
  assert.deepEqual(okDims(VMESS_TLS()), ['fingerprint', 'alpn', 'cipherSuites', 'fragment', 'finalMask', 'dialMode', 'mux']);
  assert.deepEqual(okDims(SS()), ['fragment', 'finalMask', 'dialMode']);
  assert.deepEqual(okDims(VISION()), ['fingerprint', 'alpn', 'cipherSuites', 'fragment', 'finalMask', 'dialMode'], 'Vision takes no mux');

  const r = V.applicability(REALITY());
  assert.deepEqual(okDims(REALITY()), ['fingerprint', 'fragment', 'finalMask', 'dialMode']);
  assert.match(r.alpn.reason, /REALITY/);
  assert.match(r.cipherSuites.reason, /REALITY/);

  assert.deepEqual(okDims(XHTTP()), ['fingerprint', 'alpn', 'cipherSuites', 'fragment', 'finalMask', 'dialMode', 'xhttpMode']);
  assert.equal(V.applicability(XHTTP()).xhttpMode.current, 'auto');
  assert.deepEqual(okDims(KCP()), [], 'mKCP is UDP');
  assert.match(V.applicability(KCP()).fragment.reason, /UDP/);

  assert.deepEqual(okDims(HY2()), []);
  assert.match(V.applicability(HY2()).fingerprint.reason, /QUIC/);
  assert.match(V.applicability(HY2()).finalMask.reason, /its own/);
  assert.deepEqual(okDims(WG()), []);
  assert.match(V.applicability(WG()).fingerprint.reason, /WireGuard/);
  assert.deepEqual(okDims(MASQUE_H2()), ['fingerprint', 'fragment'], 'MASQUE over HTTP/2 dials TCP TLS');
  assert.match(V.applicability(MASQUE_H2()).alpn.reason, /HTTP\/2 or HTTP\/3/);
  assert.deepEqual(okDims(MASQUE_H3()), []);

  assert.deepEqual(okDims(JSON_PLAIN()), ['fingerprint', 'alpn', 'cipherSuites', 'fragment', 'finalMask', 'dialMode', 'mux']);
  const jh = V.applicability(JSON_HELPER());
  assert.equal(jh.fragment.ok, false);
  assert.match(jh.fragment.reason, /own helper outbound \(frag\)/);
  assert.equal(jh.dialMode.ok, false);
  assert.equal(jh.fingerprint.ok, true);
});

/* ------------------------------- the product ------------------------------- */

test('the product: every combination once, the last dimension fastest, a stable key and a label in a fixed order', () => {
  const b = V.buildVariants(VLESS_WS(), spec({ alpn: ['h2', 'http/1.1'], fingerprint: ['chrome', 'hellochrome_120'] }));
  assert.equal(b.total, 4);
  assert.deepEqual(b.variants.map((v) => v.label), [
    'fp=chrome · alpn=h2', 'fp=chrome · alpn=http/1.1', 'fp=hellochrome_120 · alpn=h2', 'fp=hellochrome_120 · alpn=http/1.1'
  ]);
  assert.deepEqual(b.variants.map((v) => v.key), [
    'fp=chrome~alpn=h2', 'fp=chrome~alpn=http/1.1', 'fp=hellochrome_120~alpn=h2', 'fp=hellochrome_120~alpn=http/1.1'
  ]);
  assert.deepEqual(b.variants[3].raw, { fingerprint: 'hellochrome_120', alpn: 'http/1.1' });
  for (const v of b.variants) assert.ok(!/[|#\s]/.test(v.key), v.key);
  // the brief's own example
  const one = V.variantFromRaw({ fingerprint: 'hellochrome_120', finalMask: 'tlshello', dialMode: 'oob.0' });
  assert.equal(one.label, 'fp=hellochrome_120 · fm=tlshello · oob.0');
  assert.equal(one.key, 'fp=hellochrome_120~fm=tlshello~dm=oob.0');
  assert.equal(V.buildVariants(VLESS_WS(), spec({ fingerprint: ['chrome'] })).variants[0].key, V.variantFromRaw({ fingerprint: 'chrome' }).key, 'a row’s variant read back is the same variant');
  assert.match(V.variantFromRaw({ dialMode: 'oob.999' }).error, /dialMode/);
  assert.equal(V.variantFromRaw({}).error, 'no variant');
});

test('what does not apply is skipped with the reason and never written: a dimension, a value, a combination', () => {
  const hy = V.buildVariants(HY2(), spec({ fingerprint: ['chrome', 'firefox'], fragment: ['off', 'tlshello,100-200,10-20'] }));
  assert.equal(hy.variants.length, 0);
  assert.deepEqual(hy.skippedDims.map((s) => s.dim), ['fingerprint', 'fragment']);
  assert.ok(hy.skippedDims.every((s) => s.reason));

  const udp = V.buildVariants(VLESS_WS(), spec({ finalMask: ['none', 'udp-noise', 'tlshello'] }));
  assert.deepEqual(udp.variants.map((v) => v.ids.finalMask), ['none', 'tlshello']);
  assert.deepEqual(udp.skippedValues, [{ dim: 'finalMask', value: 'udp-noise', reason: 'a UDP-only mask on a TCP transport does nothing' }]);

  // cipherSuites act only with the unsafe fingerprint
  const cs = V.buildVariants(VLESS_WS(), spec({ fingerprint: ['chrome', 'unsafe'], cipherSuites: ['none', 'real-firefox', 'semi-python'] }));
  assert.deepEqual(cs.variants.map((v) => v.label), ['fp=chrome · cs=none', 'fp=unsafe · cs=none', 'fp=unsafe · cs=real-firefox', 'fp=unsafe · cs=semi-python']);
  assert.equal(cs.dropped.cipher, 2);
  // … the config's own fingerprint counts when the dimension is off
  assert.equal(V.buildVariants(VLESS_WS(), spec({ cipherSuites: ['none', 'real-firefox'] })).dropped.cipher, 1);

  // a dialMode beside a fragment is never sent (the fragment's freedom dialer dials)
  const dm = V.buildVariants(VLESS_WS(), spec({ fragment: ['off', 'tlshello,100-200,10-20'], dialMode: ['none', 'oob.0'] }));
  assert.deepEqual(dm.variants.map((v) => v.label), ['frag=off · dm=none', 'frag=off · oob.0', 'frag=tlshello,100-200,10-20 · dm=none']);
  assert.equal(dm.dropped.dialFragment, 1);

  // a combination that writes what another one wrote is tested once
  const same = V.buildVariants(VLESS_WS(), spec({ alpn: ['h2', 'h2,'] }));
  assert.equal(same.variants.length, 1);

  const big = V.buildVariants(VLESS_WS(), spec({
    fingerprint: V.FINGERPRINTS, alpn: ['h2', 'http/1.1', 'none'], fragment: ['off', '1-1,1-2,1-2', '1-2,1-3,1-3', '1-3,1-4,1-4'],
    finalMask: ['none', 'tlshello', 'tlshello-0-len', 'merge'], mux: ['off', 'on'], dialMode: ['none', 'oob.0', 'oob.1'], cipherSuites: ['none', 'real-firefox', 'semi-python']
  }));
  assert.equal(big.error, 'too many variants');
  assert.equal(big.total, 12 * 3 * 3 * 4 * 4 * 3 * 2);
  assert.equal(big.variants.length, 0);
});

/* ------------------------------- writing ------------------------------- */

test('each value lands where the app keeps it, the record untouched; `none` and off remove; the test config carries it', () => {
  const src = Object.assign(VLESS_WS(), { muxConcurrency: 4 });
  src.outbound._fragment = 'tlshello,1-2,1-2';
  src.outbound.streamSettings.finalmask = { tcp: [{ type: 'noise' }] };
  const before = clone(src);
  const v = V.variantFromRaw({ fingerprint: 'unsafe', alpn: 'h2,http/1.1', cipherSuites: 'real-firefox', fragment: 'tlshello,100-200,10-20', finalMask: 'tlshello', mux: 'on' });
  const out = V.applyVariant(src, v);
  const st = out.outbound.streamSettings;
  assert.equal(st.tlsSettings.fingerprint, 'unsafe');
  assert.deepEqual(st.tlsSettings.alpn, ['h2', 'http/1.1']);
  assert.equal(st.tlsSettings.cipherSuites, V.CIPHER_PRESETS['real-firefox']);
  assert.equal(out.outbound._fragment, 'tlshello,100-200,10-20');
  assert.deepEqual(st.finalmask, V.FINALMASK_PRESETS.tlshello);
  assert.deepEqual(out.outbound.mux, { enabled: true, concurrency: 4, xudpConcurrency: 16, xudpProxyUDP443: 'skip' });
  assert.deepEqual(src, before, 'the input is untouched');

  const off = V.applyVariant(out, V.variantFromRaw({ alpn: 'none', cipherSuites: 'none', fragment: 'off', finalMask: 'none', mux: 'off' }));
  assert.equal(off.outbound.streamSettings.tlsSettings.alpn, undefined);
  assert.equal(off.outbound.streamSettings.tlsSettings.cipherSuites, undefined);
  assert.equal(off.outbound._fragment, undefined);
  assert.equal(off.outbound.streamSettings.finalmask, undefined);
  assert.equal(off.outbound.mux, undefined);

  // what the scan runs: buildMultiTestConfig of target + variant
  const rec = V.applyVariant(applyTarget(VLESS_WS(), { addr: '104.16.1.2', port: 2053 }), V.variantFromRaw({ fingerprint: 'firefox', fragment: 'tlshello,100-200,10-20', dialMode: 'none' }));
  const cfg = buildMultiTestConfig([rec], [41000]);
  const main = cfg.outbounds[0];
  assert.equal(main.settings.vnext[0].address, '104.16.1.2');
  assert.equal(main.streamSettings.tlsSettings.fingerprint, 'firefox');
  assert.equal(main.streamSettings.tlsSettings.serverName, 'a.example.com', 'the name stays on the host');
  const dialer = cfg.outbounds.find((o) => o.tag === main.streamSettings.sockopt.dialerProxy);
  assert.deepEqual(dialer.settings.fragment, { packets: 'tlshello', length: '100-200', interval: '10-20' });

  const dm = V.applyVariant(TROJAN(), V.variantFromRaw({ dialMode: 'oob.0' }));
  assert.equal(dm.outbound.streamSettings.sockopt.dialMode, 'oob.0');
  assert.equal(V.applyVariant(dm, V.variantFromRaw({ dialMode: 'none' })).outbound.streamSettings.sockopt, undefined, 'an emptied sockopt goes');
  assert.equal(V.applyVariant(REALITY(), V.variantFromRaw({ fingerprint: 'ios' })).outbound.streamSettings.realitySettings.fingerprint, 'ios');
  assert.equal(V.applyVariant(XHTTP(), V.variantFromRaw({ xhttpMode: 'stream-up' })).outbound.streamSettings.xhttpSettings.mode, 'stream-up');
  assert.equal(V.applyVariant(MASQUE_H2(), V.variantFromRaw({ fingerprint: 'safari' })).outbound.streamSettings.tlsSettings.fingerprint, 'safari');
  assert.equal(V.applyVariant(SS(), V.variantFromRaw({ fragment: '1-3,1-5,1-2' })).outbound._fragment, '1-3,1-5,1-2');
  const vm = V.applyVariant(VMESS_TLS(), V.variantFromRaw({ fingerprint: 'edge', mux: 'on' }));
  assert.equal(vm.outbound.streamSettings.tlsSettings.fingerprint, 'edge');
  assert.equal(vm.outbound.mux.enabled, true);
});

test('a share link carries what it can (fp, alpn, cs, fm, fragment, mode); dialMode and mux it cannot — those are copied as JSON', () => {
  const v = V.variantFromRaw({ fingerprint: 'firefox', alpn: 'h2', cipherSuites: 'semi-python', finalMask: 'tlshello', fragment: 'tlshello,100-200,10-20' });
  const link = buildShareLink(V.applyVariant(XHTTP(), Object.assign({}, v, { set: Object.assign({}, v.set, { xhttpMode: 'packet-up' }) })));
  const back = parseLink(link);
  const st = back.outbound.streamSettings;
  assert.equal(st.tlsSettings.fingerprint, 'firefox');
  assert.deepEqual(st.tlsSettings.alpn, ['h2']);
  assert.equal(st.tlsSettings.cipherSuites, V.CIPHER_PRESETS['semi-python']);
  assert.equal(V.canon(st.finalmask), V.canon(V.FINALMASK_PRESETS.tlshello));
  assert.equal(back.outbound._fragment, 'tlshello,100-200,10-20');
  assert.equal(st.xhttpSettings.mode, 'packet-up');
  assert.deepEqual(V.linkLoses(v), []);
  assert.deepEqual(V.linkLoses(V.variantFromRaw({ dialMode: 'oob.0', mux: 'on' })), ['dialMode', 'mux']);
  assert.deepEqual(V.linkLoses(V.variantFromRaw({ mux: 'off' })), []);
});

test('a JSON config: the main outbound changes and its `json` says the same, without the app’s _fragment marker', () => {
  const src = JSON_PLAIN();
  const out = V.applyVariant(src, V.variantFromRaw({ fingerprint: 'safari', fragment: 'tlshello,100-200,10-20', dialMode: 'none' }));
  assert.equal(out.outbound.streamSettings.tlsSettings.fingerprint, 'safari');
  assert.equal(out.outbound._fragment, 'tlshello,100-200,10-20');
  const inJson = out.json.outbounds[0];
  assert.equal(inJson.tag, 'proxy');
  assert.equal(inJson.streamSettings.tlsSettings.fingerprint, 'safari');
  assert.equal(inJson._fragment, undefined);
  assert.equal(src.json.outbounds[0].streamSettings.tlsSettings.fingerprint, 'chrome', 'the input is untouched');
  // after a target too (substitute first, then the variant)
  const both = V.applyVariant(applyTarget(src, { addr: '104.16.9.9' }), V.variantFromRaw({ alpn: 'http/1.1' }));
  assert.equal(both.json.outbounds[0].settings.vnext[0].address, '104.16.9.9');
  assert.deepEqual(both.json.outbounds[0].streamSettings.tlsSettings.alpn, ['http/1.1']);
});

/* ------------------------------- engines ------------------------------- */

test('what only Xray-PattN runs is run on PattN or not at all — never on the official core in its place', () => {
  const offer = (o = {}) => Object.assign({ engines: ['xray', 'xray-pattn'], installed: () => true, version: () => '26.11.1' }, o);
  const rec = (raw, base = VLESS_WS()) => { const v = V.variantFromRaw(raw); return [V.applyVariant(base, v), v]; };

  assert.equal(V.engineNeed(...rec({ fingerprint: 'firefox' })), null);
  assert.deepEqual(V.enginesFor(null, offer()), { engines: ['xray', 'xray-pattn'] });
  const dm = V.engineNeed(...rec({ dialMode: 'oob.0' }));
  assert.deepEqual(dm, { engine: 'xray-pattn', since: '26.10.27', what: ['dialMode'] });
  assert.deepEqual(V.enginesFor(dm, offer()), { engines: ['xray-pattn'] });
  assert.match(V.enginesFor(dm, offer({ version: () => '26.9.9' })).reason, /Xray-PattN 26\.9\.9 does not know dialMode oob \(26\.10\.27 and newer do\)/);
  assert.match(V.enginesFor(dm, offer({ installed: (id) => id === 'xray' })).reason, /not installed \(the official core ignores dialMode/);
  assert.match(V.enginesFor(dm, offer({ engines: ['xray'] })).reason, /tick it/);
  assert.deepEqual(V.enginesFor(dm, offer({ version: () => '' })), { engines: ['xray-pattn'] }, 'an unreadable version gets the run, as the app does');

  assert.deepEqual(V.engineNeed(...rec({ finalMask: 'merge' })), { engine: 'xray-pattn', since: '26.10.27', what: ['merge'] });
  const fm = V.engineNeed(...rec({ finalMask: 'tlshello' }));
  assert.deepEqual(fm, { engine: 'xray-pattn', since: '', what: ['finalmask'] });
  assert.deepEqual(V.enginesFor(fm, offer({ version: () => '26.9.9' })), { engines: ['xray-pattn'] }, 'any PattN runs a finalmask');
  assert.equal(V.engineNeed(...rec({ finalMask: 'none' })), null);
  // the config's own dialMode needs PattN whichever variant runs it
  const withDm = V.applyVariant(TROJAN(), V.variantFromRaw({ dialMode: 'oob.0' }));
  assert.equal(V.engineNeed(...rec({ fingerprint: 'ios' }, withDm)).since, '26.10.27');
});

/* ------------------------------- the cap ------------------------------- */

test('planTests: up to the limit the whole product, target by target; past it an even, repeatable sample', () => {
  const full = V.planTests(3, 4, 300);
  assert.equal(full.size, 12);
  assert.equal(full.sampled, false);
  assert.deepEqual(Array.from({ length: 12 }, (_, i) => full.at(i)).slice(0, 4), [{ t: 0, v: 0 }, { t: 0, v: 1 }, { t: 0, v: 2 }, { t: 1, v: 0 }]);

  // V ≤ limit: each variant ⌊L/V⌋ (+1 for the first L mod V), every target before any twice, a variant's targets distinct
  const p = V.planTests(7, 1000, 300);
  assert.equal(p.size, 300);
  assert.equal(p.sampled, true);
  assert.equal(p.total, 7000);
  const pairs = Array.from({ length: p.size }, (_, i) => p.at(i));
  const perV = new Map(), perT = new Map();
  for (const { t, v } of pairs) { perV.set(v, (perV.get(v) || []).concat(t)); perT.set(t, (perT.get(t) || 0) + 1); }
  assert.deepEqual([...perV.keys()].sort(), [0, 1, 2, 3, 4, 5, 6]);
  for (const [v, ts] of perV) {
    assert.equal(ts.length, v < 300 % 7 ? 43 : 42, 'variant ' + v);
    assert.equal(new Set(ts).size, ts.length, 'distinct targets for variant ' + v);
  }
  assert.equal(perT.size, 300, '300 different targets: none used twice while others wait');
  const ts = [...perT.keys()].sort((a, b) => a - b);
  for (let q = 0; q < 4; q++) assert.ok(ts.filter((t) => t >= q * 250 && t < (q + 1) * 250).length >= 60, 'every quarter of the range is reached');
  for (let i = 1; i < pairs.length; i++) assert.ok(pairs[i - 1].t <= pairs[i].t, 'target by target');
  assert.deepEqual(Array.from({ length: p.size }, (_, i) => p.at(i)), pairs, 'the same inputs, the same sample');

  // more targets than the limit, one variant: an even spread over a big range (no list of it is ever built)
  const huge = V.planTests(1, 16777216, 1000);
  const hs = Array.from({ length: huge.size }, (_, i) => huge.at(i).t);
  assert.equal(new Set(hs).size, 1000);
  for (let q = 0; q < 8; q++) assert.ok(hs.filter((t) => Math.floor(t / 2097152) === q).length > 80, 'eighth ' + q);
});

test('planTests with more variants than the limit: every value of every dimension tested about as often as the others', () => {
  const b = V.buildVariants(VLESS_WS(), spec({ fingerprint: ['chrome', 'firefox', 'safari', 'ios'], alpn: ['h2', 'http/1.1', 'none'], mux: ['off', 'on'], fragment: ['off', '1-3,1-5,1-2', 'tlshello,100-200,10-20'] }));
  assert.equal(b.variants.length, 72);
  const p = V.planTests(b.variants.length, 5, 24, b.variants);
  assert.equal(p.size, 24);
  const chosen = Array.from({ length: p.size }, (_, i) => b.variants[p.at(i).v]);
  assert.equal(new Set(chosen.map((v) => v.key)).size, 24, 'each variant at most once');
  const count = (dim) => { const m = new Map(); for (const v of chosen) m.set(v.ids[dim], (m.get(v.ids[dim]) || 0) + 1); return [...m.values()]; };
  assert.deepEqual(count('fingerprint'), [6, 6, 6, 6]);
  assert.deepEqual(count('alpn'), [8, 8, 8]);
  assert.deepEqual(count('mux'), [12, 12]);
  assert.deepEqual(count('fragment'), [8, 8, 8]);
  const targets = Array.from({ length: p.size }, (_, i) => p.at(i).t);
  assert.deepEqual([...new Set(targets)].sort(), [0, 1, 2, 3, 4], 'the targets dealt round-robin');
});

test('spread: a permutation of [0, T) for small and huge T alike', () => {
  for (const T of [1, 2, 3, 10, 97, 1000]) {
    const f = V.spread(T);
    assert.equal(new Set(Array.from({ length: T }, (_, j) => f(j))).size, T, 'T=' + T);
  }
  const big = V.spread(2 ** 40);
  const xs = Array.from({ length: 100 }, (_, j) => big(j));
  assert.equal(new Set(xs).size, 100);
  assert.ok(xs.every((x) => Number.isInteger(x) && x >= 0 && x < 2 ** 40));
});

test('catalog: what the page lists — options for a closed list, presets for an open one, the values pre-listed when turned on', () => {
  const c = V.catalog();
  assert.deepEqual(c.map((d) => d.id), ['fingerprint', 'alpn', 'cipherSuites', 'fragment', 'finalMask', 'dialMode', 'mux', 'xhttpMode']);
  const by = Object.fromEntries(c.map((d) => [d.id, d]));
  assert.ok(by.fingerprint.options.includes('hellochrome_120'));
  assert.deepEqual(by.finalMask.presets, ['tlshello-0-len', 'tlshello', 'udp-noise', 'merge']);
  assert.deepEqual(by.dialMode.presets, ['oob.0']);
  for (const d of c) for (const v of d.start) assert.ok(!V.readValue(d.id, v).error, d.id + ' ' + v);
});
