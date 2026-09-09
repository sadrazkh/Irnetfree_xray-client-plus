'use strict';
/**
 * plus: the Server tab's config builder. A model (spec section 2.1) goes in,
 * an Xray server config comes out. Pure on purpose: the runtime (core.js)
 * validates and builds without touching the disk, and the tests pin every
 * shape.
 *
 * Every shape here was run through `xray run -test` on both cores in bin/
 * (official 26.3.27, patterniha 26.9.1). Two things the spec did not know:
 *
 *  - Reality's destination is called `target` now; both cores still take
 *    `dest` as an alias. The model keeps `dest`, the config says `target`.
 *  - The legacy `reverse.bridges` / `reverse.portals` block is gone from the
 *    26.9 fork ("migrated to VLESS Reverse Proxy"), and both cores take the
 *    new form, so that is the only one built. The bridge's VLESS outbound
 *    carries `settings.reverse.tag`: connections the portal hands back arrive
 *    under that inbound tag and are routed like any other. Each bridge client
 *    on the portal's interconn inbound carries `reverse.tag`: an outbound tag
 *    the user inbounds route to. There is no shared domain any more, and the
 *    interconn has to be VLESS on both ends.
 */
const crypto = require('crypto');
const { parseLink, buildShareLink, buildStreamSettings } = require('../parser');
const { cloneOut, applyFragments, PRIVATE_IPS } = require('../configBuilder');

const PROTOCOLS = ['vless', 'vmess', 'trojan', 'shadowsocks'];
const NETWORKS = ['tcp', 'ws', 'grpc', 'xhttp'];
const SECURITIES = ['none', 'tls', 'reality'];
const SS_METHODS = ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', 'aes-256-gcm', 'aes-128-gcm', 'chacha20-ietf-poly1305'];
const SS2022_KEY_BYTES = { '2022-blake3-aes-128-gcm': 16, '2022-blake3-aes-256-gcm': 32 };
const ROLES = ['off', 'bridge', 'portal'];
const EXIT_TYPES = ['direct', 'server'];
const VIAS = ['server', 'link'];
// Both cores refuse REALITY over WebSocket ("only supports RAW, XHTTP and gRPC").
const REALITY_NETWORKS = ['tcp', 'grpc', 'xhttp'];

const VISION = 'xtls-rprx-vision';
const DEST_OVERRIDE = ['http', 'tls', 'quic'];
const EXIT_TAG = 'exit';
const BLOCK_TAG = 'block';
const INTERCONN_TAG = 'interconn';
const BRIDGE_TAG = 'bridge';
const PORTAL_TAG = 'portal';
const RESERVED_TAGS = [BRIDGE_TAG, PORTAL_TAG, INTERCONN_TAG, EXIT_TAG, BLOCK_TAG, 'metrics'];
const WILDCARD_LISTENS = ['', '0.0.0.0', '::', '[::]'];

/* ----------------------------- defaults ----------------------------- */

function modelDefaults() {
  return {
    autoStart: false,
    engine: 'xray',
    logLevel: 'warning',
    publicAddress: '',
    inbounds: [],
    exit: { type: 'direct', serverId: '' },
    blockPrivate: true,
    blockTorrent: false,
    reverse: {
      role: 'off',
      bridge: { via: 'server', serverId: '', link: '' },
      portal: { interconnInboundId: '', userInboundIds: [] }
    }
  };
}

function inboundDefaults() {
  return {
    id: '', tag: '', enabled: true, remark: '',
    protocol: 'vless', listen: '0.0.0.0', port: 443,
    network: 'tcp', path: '/', host: '', serviceName: '',
    security: 'none',
    tls: { certFile: '', keyFile: '', serverName: '', alpn: ['h2', 'http/1.1'] },
    reality: { dest: 'www.microsoft.com:443', serverNames: ['www.microsoft.com'], privateKey: '', publicKey: '', shortIds: [] },
    ss: { method: '2022-blake3-aes-128-gcm', password: '' },
    sniffing: true,
    clients: []
  };
}

function clientDefaults() {
  return {
    id: '', enabled: true, email: '', uuid: '', password: '', flow: '',
    expiresAt: 0, quotaBytes: 0, limitIp: 0, note: '',
    used: { up: 0, down: 0 }, disabledBy: ''
  };
}

function deepFreeze(o) {
  for (const v of Object.values(o)) if (v && typeof v === 'object') deepFreeze(v);
  return Object.freeze(o);
}

const DEFAULT_MODEL = deepFreeze(modelDefaults());

/* ----------------------------- small helpers ----------------------------- */

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v, def) => (typeof v === 'string' ? v : (typeof v === 'number' ? String(v) : def));
const bool = (v, def) => (typeof v === 'boolean' ? v : def);
function num(v, def) {
  const n = typeof v === 'string' && v.trim() !== '' ? Number(v) : v;
  return typeof n === 'number' && Number.isFinite(n) ? n : def;
}
const nonNeg = (v, def) => Math.max(0, num(v, def));
const strList = (v, def) => (Array.isArray(v) ? v.map(x => str(x, '').trim()).filter(Boolean) : def.slice());
const dedupe = (list) => list.filter((x, i) => list.indexOf(x) === i);
const lower = (v, def) => (str(v, '').trim().toLowerCase() || def);

function uid() { return crypto.randomBytes(8).toString('hex'); }

const is2022 = (method) => Object.prototype.hasOwnProperty.call(SS2022_KEY_BYTES, method);
const visionOk = (i) => i.protocol === 'vless' && i.network === 'tcp' && (i.security === 'tls' || i.security === 'reality');
const isWildcard = (listen) => WILDCARD_LISTENS.includes(listen);

/** Strict base64 of exactly `bytes` bytes — what the 2022 ciphers demand of a key. */
function isKey(s, bytes) {
  const b = Buffer.from(String(s || ''), 'base64');
  return b.length === bytes && b.toString('base64') === s;
}

const findServer = (servers, id) => (Array.isArray(servers) ? servers.find(s => s && s.id === id) : null) || null;
const isVless = (server) => !!(server && server.outbound && server.outbound.protocol === 'vless');

/* ----------------------------- ids and keys ----------------------------- */

/**
 * A tag from a remark: lower-case a-z, 0-9 and dashes, capped, with four
 * characters of the id on the end so two inbounds with one remark never
 * share a tag. A remark with nothing usable in it (Persian, say) is `in`.
 */
function slugTag(remark, id) {
  const slug = str(remark, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32).replace(/-+$/, '') || 'in';
  const suffix = str(id, '').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 4) || 'x';
  return `${slug}-${suffix}`;
}

function randomShortId() { return crypto.randomBytes(8).toString('hex'); }
function randomPassword(bytes) { return crypto.randomBytes(bytes || 16).toString('base64'); }
function randomKeyFor(method) { return randomPassword(SS2022_KEY_BYTES[method] || 16); }

/**
 * The key pair `xray x25519` prints. 26.x says `PrivateKey:` and
 * `Password (PublicKey):`; older cores said `Private key:` / `Public key:`.
 */
function parseX25519(stdout) {
  const s = str(stdout, '');
  const priv = s.match(/Private\s*Key\s*:\s*([A-Za-z0-9+/_=-]+)/i);
  const pub = s.match(/(?:Public\s*Key|\(\s*PublicKey\s*\))\s*:\s*([A-Za-z0-9+/_=-]+)/i);
  return priv && pub ? { privateKey: priv[1], publicKey: pub[1] } : null;
}

/* ----------------------------- normalize ----------------------------- */

function normalizeClient(raw) {
  const c = isObj(raw) ? raw : {};
  const used = isObj(c.used) ? c.used : {};
  return {
    id: str(c.id, '').trim() || uid(),
    enabled: bool(c.enabled, true),
    email: str(c.email, '').trim(),
    uuid: str(c.uuid, '').trim(),
    password: str(c.password, ''),
    flow: str(c.flow, '').trim(),
    expiresAt: nonNeg(c.expiresAt, 0),
    quotaBytes: nonNeg(c.quotaBytes, 0),
    limitIp: nonNeg(c.limitIp, 0),
    note: str(c.note, ''),
    used: { up: nonNeg(used.up, 0), down: nonNeg(used.down, 0) },
    disabledBy: str(c.disabledBy, '')
  };
}

function normalizeInbound(raw) {
  const i = isObj(raw) ? raw : {};
  const d = inboundDefaults();
  const tls = isObj(i.tls) ? i.tls : {};
  const reality = isObj(i.reality) ? i.reality : {};
  const ss = isObj(i.ss) ? i.ss : {};
  const id = str(i.id, '').trim() || uid();
  const remark = str(i.remark, '');
  return {
    id,
    tag: str(i.tag, '').trim() || slugTag(remark, id),
    enabled: bool(i.enabled, true),
    remark,
    protocol: lower(i.protocol, d.protocol),
    listen: str(i.listen, '').trim() || d.listen,
    port: Math.trunc(num(i.port, d.port)),
    network: lower(i.network, d.network),
    path: str(i.path, d.path),
    host: str(i.host, d.host).trim(),
    serviceName: str(i.serviceName, d.serviceName).trim(),
    security: lower(i.security, d.security),
    tls: {
      certFile: str(tls.certFile, '').trim(),
      keyFile: str(tls.keyFile, '').trim(),
      serverName: str(tls.serverName, '').trim(),
      alpn: strList(tls.alpn, d.tls.alpn)
    },
    reality: {
      dest: str(reality.dest, '').trim() || d.reality.dest,
      serverNames: strList(reality.serverNames, d.reality.serverNames),
      privateKey: str(reality.privateKey, '').trim(),
      publicKey: str(reality.publicKey, '').trim(),
      shortIds: strList(reality.shortIds, d.reality.shortIds).map(s => s.toLowerCase())
    },
    ss: { method: lower(ss.method, d.ss.method), password: str(ss.password, '') },
    sniffing: bool(i.sniffing, true),
    clients: (Array.isArray(i.clients) ? i.clients : []).map(normalizeClient)
  };
}

/** Every missing field filled from the defaults; garbage in, the default model out. Never throws. */
function normalizeModel(raw) {
  const m = isObj(raw) ? raw : {};
  const d = modelDefaults();
  const exit = isObj(m.exit) ? m.exit : {};
  const rv = isObj(m.reverse) ? m.reverse : {};
  const bridge = isObj(rv.bridge) ? rv.bridge : {};
  const portal = isObj(rv.portal) ? rv.portal : {};
  return {
    autoStart: bool(m.autoStart, d.autoStart),
    engine: str(m.engine, '').trim() || d.engine,
    logLevel: str(m.logLevel, '').trim() || d.logLevel,
    publicAddress: str(m.publicAddress, '').trim(),
    inbounds: (Array.isArray(m.inbounds) ? m.inbounds : []).map(normalizeInbound),
    exit: { type: str(exit.type, '').trim() || d.exit.type, serverId: str(exit.serverId, '').trim() },
    blockPrivate: bool(m.blockPrivate, d.blockPrivate),
    blockTorrent: bool(m.blockTorrent, d.blockTorrent),
    reverse: {
      role: str(rv.role, '').trim() || d.reverse.role,
      bridge: {
        via: str(bridge.via, '').trim() || d.reverse.bridge.via,
        serverId: str(bridge.serverId, '').trim(),
        link: str(bridge.link, '').trim()
      },
      portal: {
        interconnInboundId: str(portal.interconnInboundId, '').trim(),
        userInboundIds: dedupe(strList(portal.userInboundIds, []))
      }
    }
  };
}

/* ----------------------------- fresh things ----------------------------- */

const INBOUND_SEEDS = {
  vless: { remark: 'VLESS Reality', port: 443, network: 'tcp', security: 'reality' },
  vmess: { remark: 'VMess WS', port: 8080, network: 'ws', security: 'none' },
  trojan: { remark: 'Trojan TLS', port: 443, network: 'tcp', security: 'tls' },
  shadowsocks: { remark: 'Shadowsocks', port: 8388, network: 'tcp', security: 'none' }
};

/** A new inbound with a fresh id, its own tag and the defaults its protocol wants. Overrides win. */
function newInbound(protocol, overrides) {
  const p = PROTOCOLS.includes(protocol) ? protocol : 'vless';
  const seed = Object.assign({ id: uid(), protocol: p }, INBOUND_SEEDS[p]);
  if (p === 'vless') seed.reality = Object.assign(inboundDefaults().reality, { shortIds: [randomShortId()] });
  if (p === 'shadowsocks') seed.ss = { method: '2022-blake3-aes-128-gcm', password: randomKeyFor('2022-blake3-aes-128-gcm') };
  const merged = Object.assign(seed, isObj(overrides) ? overrides : {});
  // A method chosen without a key gets one of the right size.
  if (isObj(merged.ss) && merged.ss.method && !merged.ss.password) merged.ss = Object.assign({}, merged.ss, { password: randomKeyFor(merged.ss.method) });
  if (!str(merged.tag, '').trim()) merged.tag = slugTag(merged.remark, merged.id);
  return normalizeInbound(merged);
}

/**
 * A new client with a fresh id and the secret its protocol uses. For
 * shadowsocks `overrides.method` only sizes the 2022 key; it is not stored.
 */
function newClient(protocol, overrides) {
  const o = Object.assign({}, isObj(overrides) ? overrides : {});
  const method = o.method;
  delete o.method;
  const seed = { id: uid() };
  if (protocol === 'vless' || protocol === 'vmess') seed.uuid = crypto.randomUUID();
  else if (protocol === 'trojan') seed.password = crypto.randomBytes(16).toString('base64url');
  else if (protocol === 'shadowsocks') seed.password = randomKeyFor(method || '2022-blake3-aes-128-gcm');
  return normalizeClient(Object.assign(seed, o));
}

/* ----------------------------- validation ----------------------------- */

/** `{ ok, errors, warnings }`, each entry `{ path, msg }` with the model path it is about. */
function validateModel(model, opts) {
  const m = normalizeModel(model);
  const servers = Array.isArray(opts && opts.servers) ? opts.servers : [];
  const errors = [], warnings = [];
  const err = (path, msg) => { errors.push({ path, msg }); };
  const warn = (path, msg) => { warnings.push({ path, msg }); };

  const tags = new Set(), emails = new Set(), binds = [];
  m.inbounds.forEach((i, n) => {
    const p = `inbounds[${n}]`;
    if (!PROTOCOLS.includes(i.protocol)) err(`${p}.protocol`, `unknown protocol "${i.protocol}"`);
    if (!NETWORKS.includes(i.network)) err(`${p}.network`, `unknown transport "${i.network}"`);
    if (!SECURITIES.includes(i.security)) err(`${p}.security`, `unknown security "${i.security}"`);

    if (!/^[a-z0-9-]+$/.test(i.tag)) err(`${p}.tag`, 'a tag is lower-case letters, digits and dashes');
    else if (RESERVED_TAGS.includes(i.tag)) err(`${p}.tag`, `"${i.tag}" is reserved`);
    else if (tags.has(i.tag)) err(`${p}.tag`, `tag "${i.tag}" is used twice`);
    tags.add(i.tag);

    const portOk = Number.isInteger(i.port) && i.port >= 1 && i.port <= 65535;
    if (!portOk) err(`${p}.port`, 'port must be 1–65535');
    else if (i.enabled) {
      const clash = binds.find(b => b.port === i.port && (isWildcard(b.listen) || isWildcard(i.listen) || b.listen === i.listen));
      if (clash) err(`${p}.port`, `port ${i.port} is already taken by "${clash.tag}"`);
      binds.push({ port: i.port, listen: i.listen, tag: i.tag });
    }

    if (i.protocol === 'shadowsocks') {
      if (i.network !== 'tcp') err(`${p}.network`, 'an ss:// link carries no transport: shadowsocks is raw tcp only');
      if (i.security !== 'none') err(`${p}.security`, 'an ss:// link carries no tls or reality');
      if (!SS_METHODS.includes(i.ss.method)) err(`${p}.ss.method`, `unknown method "${i.ss.method}"`);
      else if (is2022(i.ss.method) && !isKey(i.ss.password, SS2022_KEY_BYTES[i.ss.method])) {
        err(`${p}.ss.password`, `the server key must be ${SS2022_KEY_BYTES[i.ss.method]} bytes in base64`);
      }
    }
    if (i.security === 'tls') {
      if (!i.tls.certFile) err(`${p}.tls.certFile`, 'tls needs a certificate file');
      if (!i.tls.keyFile) err(`${p}.tls.keyFile`, 'tls needs a key file');
    }
    if (i.security === 'reality') {
      if (!i.reality.privateKey) err(`${p}.reality.privateKey`, 'reality needs a private key (generate one)');
      if (!i.reality.serverNames.length) err(`${p}.reality.serverNames`, 'reality needs at least one server name');
      if (!i.reality.shortIds.length) err(`${p}.reality.shortIds`, 'reality needs at least one short id');
      else if (i.reality.shortIds.some(s => !/^([0-9a-f]{2}){1,8}$/.test(s))) err(`${p}.reality.shortIds`, 'a short id is 1–8 bytes of hex');
      if (NETWORKS.includes(i.network) && !REALITY_NETWORKS.includes(i.network)) err(`${p}.network`, 'reality works over tcp, grpc and xhttp only');
      if (i.protocol === 'vmess') err(`${p}.security`, 'a vmess:// link cannot carry reality');
    }
    if ((i.network === 'ws' || i.network === 'xhttp') && !i.path.startsWith('/')) err(`${p}.path`, `${i.network} needs a path starting with /`);

    let live = 0;
    i.clients.forEach((c, k) => {
      const cp = `${p}.clients[${k}]`;
      if (!c.email) err(`${cp}.email`, 'a client needs a name');
      else if (emails.has(c.email)) err(`${cp}.email`, `"${c.email}" is used twice; names are unique across the server`);
      emails.add(c.email);
      if ((i.protocol === 'vless' || i.protocol === 'vmess') && !c.uuid) err(`${cp}.uuid`, 'a uuid is needed');
      if (i.protocol === 'trojan' && !c.password) err(`${cp}.password`, 'a password is needed');
      if (i.protocol === 'shadowsocks') {
        if (!c.password) err(`${cp}.password`, 'a password is needed');
        else if (is2022(i.ss.method) && !isKey(c.password, SS2022_KEY_BYTES[i.ss.method])) {
          err(`${cp}.password`, `the user key must be ${SS2022_KEY_BYTES[i.ss.method]} bytes in base64`);
        }
      }
      if (c.flow && c.flow !== VISION) err(`${cp}.flow`, `unknown flow "${c.flow}"`);
      else if (c.flow === VISION && !visionOk(i)) warn(`${cp}.flow`, 'vision only works for vless over raw tcp with tls or reality; it is left out');
      if (c.enabled) live++;
    });
    if (i.enabled && !live) warn(`${p}.clients`, 'no enabled client: the inbound runs but nobody can use it');
  });

  if (!EXIT_TYPES.includes(m.exit.type)) err('exit.type', `unknown exit "${m.exit.type}"`);
  else if (m.exit.type === 'server' && !findServer(servers, m.exit.serverId)) err('exit.serverId', 'choose a stored config to exit through');

  const rv = m.reverse;
  if (!ROLES.includes(rv.role)) err('reverse.role', `unknown role "${rv.role}"`);
  if (rv.role === 'bridge') {
    const b = rv.bridge;
    if (!VIAS.includes(b.via)) err('reverse.bridge.via', `unknown via "${b.via}"`);
    else if (b.via === 'link') {
      if (!b.link) err('reverse.bridge.link', 'paste the portal\'s interconn link');
      else {
        let s = null;
        try { s = parseLink(b.link); } catch (e) { err('reverse.bridge.link', e.message); }
        if (s && !isVless(s)) err('reverse.bridge.link', 'the reverse proxy rides VLESS: the portal link must be vless://');
      }
    } else {
      const s = findServer(servers, b.serverId);
      if (!s) err('reverse.bridge.serverId', 'choose the stored config that reaches the portal');
      else if (!isVless(s)) err('reverse.bridge.serverId', 'the reverse proxy rides VLESS: choose a vless config');
    }
  }
  if (rv.role === 'portal') {
    const po = rv.portal;
    const ic = m.inbounds.find(i => i.id === po.interconnInboundId) || null;
    if (!po.interconnInboundId) err('reverse.portal.interconnInboundId', 'choose the inbound the bridge dials in on');
    else if (!ic) err('reverse.portal.interconnInboundId', 'the interconn inbound no longer exists');
    else if (!ic.enabled) err('reverse.portal.interconnInboundId', 'the interconn inbound is disabled');
    else if (ic.protocol !== 'vless') err('reverse.portal.interconnInboundId', 'the reverse proxy rides VLESS: the interconn inbound must be vless');
    else if (!ic.clients.some(c => c.enabled)) err('reverse.portal.interconnInboundId', 'the interconn inbound needs an enabled client for the bridge');
    if (!po.userInboundIds.length) err('reverse.portal.userInboundIds', 'choose the inbounds whose users go through the bridge');
    else {
      if (po.userInboundIds.includes(po.interconnInboundId)) err('reverse.portal.userInboundIds', 'the interconn inbound cannot also be a user inbound');
      for (const id of po.userInboundIds) {
        const u = m.inbounds.find(i => i.id === id);
        if (!u) err('reverse.portal.userInboundIds', 'a chosen user inbound no longer exists');
        else if (!u.enabled) err('reverse.portal.userInboundIds', `user inbound "${u.tag}" is disabled`);
      }
    }
  }

  return { ok: errors.length === 0, errors, warnings };
}

/* ----------------------------- config ----------------------------- */

/** The server side of an inbound's transport and security. */
function serverStream(i) {
  const st = { network: i.network, security: i.security };
  if (i.network === 'ws') st.wsSettings = { path: i.path, host: i.host };
  else if (i.network === 'grpc') st.grpcSettings = { serviceName: i.serviceName };
  else if (i.network === 'xhttp') st.xhttpSettings = { path: i.path, host: i.host };
  if (i.security === 'tls') {
    st.tlsSettings = { certificates: [{ certificateFile: i.tls.certFile, keyFile: i.tls.keyFile }], serverName: i.tls.serverName };
    if (i.tls.alpn.length) st.tlsSettings.alpn = i.tls.alpn.slice();
  } else if (i.security === 'reality') {
    st.realitySettings = {
      show: false, target: i.reality.dest, xver: 0,
      serverNames: i.reality.serverNames.slice(), privateKey: i.reality.privateKey, shortIds: i.reality.shortIds.slice()
    };
  }
  return st;
}

/** One client as the inbound's `settings.clients` carries it. */
function serverClient(i, c, isInterconn) {
  let o;
  if (i.protocol === 'vless') {
    o = { id: c.uuid, email: c.email };
    if (c.flow === VISION && visionOk(i)) o.flow = VISION;
    if (isInterconn) o.reverse = { tag: PORTAL_TAG };
  } else if (i.protocol === 'vmess') {
    o = { id: c.uuid, email: c.email };
  } else if (i.protocol === 'trojan') {
    o = { password: c.password, email: c.email };
  } else {
    o = is2022(i.ss.method) ? { email: c.email, password: c.password } : { email: c.email, password: c.password, method: i.ss.method };
  }
  return o;
}

function serverInbound(i, isInterconn) {
  const clients = i.clients.filter(c => c.enabled).map(c => serverClient(i, c, isInterconn));
  let settings;
  if (i.protocol === 'vless') settings = { clients, decryption: 'none' };
  else if (i.protocol === 'shadowsocks') {
    // 2022: the method and the server key at the top, keys only per user (the
    // core refuses a per-user method there); the legacy AEAD ciphers go per user.
    settings = is2022(i.ss.method)
      ? { method: i.ss.method, password: i.ss.password, clients, network: 'tcp,udp' }
      : { clients, network: 'tcp,udp' };
  } else settings = { clients };
  return {
    tag: i.tag, listen: i.listen, port: i.port, protocol: i.protocol,
    settings,
    streamSettings: serverStream(i),
    sniffing: { enabled: i.sniffing, destOverride: DEST_OVERRIDE.slice() }
  };
}

/** The flat VLESS outbound settings the core wants `reverse` on (it refuses it inside vnext). */
function flatVless(settings, reverseTag) {
  const v = (settings && settings.vnext && settings.vnext[0]) || {};
  const u = (v.users && v.users[0]) || {};
  return { address: v.address, port: v.port, id: u.id, flow: u.flow || '', encryption: u.encryption || 'none', reverse: { tag: reverseTag } };
}

/** The stored record or parsed link a bridge dials the portal with; null when there is none usable. */
function bridgeTarget(m, servers) {
  const b = m.reverse.bridge;
  let s = null;
  if (b.via === 'link') {
    if (!b.link) return null;
    try { s = parseLink(b.link); } catch { return null; }
  } else s = findServer(servers, b.serverId);
  return isVless(s) ? s : null;
}

function exitOutbound(m, servers) {
  if (m.exit.type === 'server') {
    const s = findServer(servers, m.exit.serverId);
    if (s && s.outbound) return cloneOut(s.outbound, EXIT_TAG, s);
  }
  return { tag: EXIT_TAG, protocol: 'freedom', settings: {} };
}

/**
 * The Xray config for a model. `apiPort` is the metrics listener (same shape
 * the client config uses, so stats.js reads it unchanged), `servers` the
 * stored records an exit or a bridge may point at, `geoAvailable` whether
 * geoip.dat is on disk (without it the private block is the literal list).
 */
function buildServerConfig(model, opts) {
  const m = normalizeModel(model);
  const o = isObj(opts) ? opts : {};
  const apiPort = num(o.apiPort, 10095);
  const servers = Array.isArray(o.servers) ? o.servers : [];
  const geo = o.geoAvailable !== false;
  const role = m.reverse.role;
  const interconnId = role === 'portal' ? m.reverse.portal.interconnInboundId : '';

  const live = m.inbounds.filter(i => i.enabled);
  const inbounds = live.map(i => serverInbound(i, i.id === interconnId && i.protocol === 'vless'));

  const outbounds = [exitOutbound(m, servers), { tag: BLOCK_TAG, protocol: 'blackhole', settings: { response: { type: 'http' } } }];
  const target = role === 'bridge' ? bridgeTarget(m, servers) : null;
  if (target) {
    const ic = cloneOut(target.outbound, INTERCONN_TAG, target);
    ic.settings = flatVless(ic.settings, BRIDGE_TAG);
    outbounds.push(ic);
  }

  // Order is load-bearing: the blocks first, then the reverse rules; whatever
  // matches nothing falls to the first outbound, the exit.
  const rules = [];
  if (m.blockPrivate) rules.push({ type: 'field', ip: geo ? ['geoip:private'] : PRIVATE_IPS.slice(), outboundTag: BLOCK_TAG });
  if (m.blockTorrent) rules.push({ type: 'field', protocol: ['bittorrent'], outboundTag: BLOCK_TAG });
  if (target) rules.push({ type: 'field', inboundTag: [BRIDGE_TAG], outboundTag: EXIT_TAG });
  if (role === 'portal') {
    const ids = m.reverse.portal.userInboundIds;
    const userTags = live.filter(i => i.id !== interconnId && ids.includes(i.id)).map(i => i.tag);
    if (userTags.length) rules.push({ type: 'field', inboundTag: userTags, outboundTag: PORTAL_TAG });
  }

  return {
    log: { loglevel: m.logLevel },
    metrics: { tag: 'metrics', listen: `127.0.0.1:${apiPort}` },
    stats: {},
    policy: {
      levels: { '0': { statsUserUplink: true, statsUserDownlink: true } },
      system: { statsInboundUplink: true, statsInboundDownlink: true, statsOutboundUplink: true, statsOutboundDownlink: true }
    },
    inbounds,
    outbounds: applyFragments(outbounds),
    routing: { domainStrategy: 'IPIfNonMatch', rules }
  };
}

/* ----------------------------- client side ----------------------------- */

/** The client side of an inbound's transport and security, in the parser's own shape. */
function clientStream(i) {
  const q = { type: i.network, security: i.security };
  if (i.network === 'ws' || i.network === 'xhttp') { q.path = i.path; q.host = i.host; }
  else if (i.network === 'grpc') q.serviceName = i.serviceName;
  if (i.security === 'tls') {
    q.sni = i.tls.serverName || i.host || '';
    q.fp = 'chrome';
    if (i.tls.alpn.length) q.alpn = i.tls.alpn.join(',');
  } else if (i.security === 'reality') {
    q.sni = i.reality.serverNames[0] || '';
    q.fp = 'chrome';
    q.pbk = i.reality.publicKey;
    q.sid = i.reality.shortIds[0] || '';
  }
  return buildStreamSettings(q);
}

function clientOutbound(i, c, address) {
  const port = i.port;
  if (i.protocol === 'vless') {
    const flow = c.flow === VISION && visionOk(i) ? VISION : '';
    return { protocol: 'vless', settings: { vnext: [{ address, port, users: [{ id: c.uuid, encryption: 'none', flow }] }] }, streamSettings: clientStream(i) };
  }
  if (i.protocol === 'vmess') {
    return { protocol: 'vmess', settings: { vnext: [{ address, port, users: [{ id: c.uuid, alterId: 0, security: 'auto' }] }] }, streamSettings: clientStream(i) };
  }
  if (i.protocol === 'trojan') {
    return { protocol: 'trojan', settings: { servers: [{ address, port, password: c.password }] }, streamSettings: clientStream(i) };
  }
  // 2022 multi-user: the client dials with serverKey:userKey.
  const password = is2022(i.ss.method) ? `${i.ss.password}:${c.password}` : c.password;
  return { protocol: 'shadowsocks', settings: { servers: [{ address, port, method: i.ss.method, password, uot: true }] }, streamSettings: { network: 'tcp' } };
}

/**
 * A client-side server record — the shape the store keeps — for one client
 * of one inbound, dialling `address` (the model's public address unless
 * given). buildShareLink turns it into the link.
 */
function clientServerRecord(inbound, client, model, opts) {
  const i = normalizeInbound(inbound);
  const c = normalizeClient(client);
  const m = isObj(model) ? model : {};
  const given = isObj(opts) && opts.address != null ? opts.address : m.publicAddress;
  const address = str(given, '').trim();
  if (!address) throw new Error('no public address');
  return {
    id: c.id,
    name: [i.remark, c.email].filter(Boolean).join(' - '),
    protocol: i.protocol,
    address,
    port: i.port,
    outbound: clientOutbound(i, c, address)
  };
}

function clientLink(inbound, client, model, opts) {
  return buildShareLink(clientServerRecord(inbound, client, model, opts));
}

/* ----------------------------- the other side ----------------------------- */

/** A server-side stream for the other end, from the client-side one a link carries; secrets are placeholders. */
function serverStreamFromClient(cs) {
  const st = isObj(cs) ? cs : {};
  const out = { network: st.network || 'tcp', security: st.security || 'none' };
  if (out.network === 'ws') {
    const ws = st.wsSettings || {};
    out.wsSettings = { path: ws.path || '/', host: (ws.headers && (ws.headers.Host || ws.headers.host)) || '' };
  } else if (out.network === 'grpc') {
    out.grpcSettings = { serviceName: (st.grpcSettings && st.grpcSettings.serviceName) || '' };
  } else if (out.network === 'xhttp') {
    const xs = st.xhttpSettings || {};
    out.xhttpSettings = { path: xs.path || '/', host: xs.host || '' };
  }
  if (out.security === 'tls') {
    const tls = st.tlsSettings || {};
    out.tlsSettings = { certificates: [{ certificateFile: '<cert.pem>', keyFile: '<key.pem>' }], serverName: tls.serverName || '' };
    if (Array.isArray(tls.alpn) && tls.alpn.length) out.tlsSettings.alpn = tls.alpn.slice();
  } else if (out.security === 'reality') {
    const rl = st.realitySettings || {};
    const sni = rl.serverName || '';
    out.realitySettings = {
      show: false, target: `${sni || '<server-name>'}:443`, xver: 0,
      serverNames: sni ? [sni] : [], privateKey: `<private key for ${rl.publicKey || '<public key>'}>`, shortIds: rl.shortId ? [rl.shortId] : []
    };
  }
  return out;
}

/**
 * What the other end of the reverse pair pastes into a bare xray config or
 * 3x-ui's Xray settings. A bridge here: the portal's interconn inbound (its
 * tag and the user inbounds are placeholders — only that side knows them)
 * and the rule that sends users through. A portal here: the bridge's
 * interconn outbound with the reverse tag, a direct exit, the rule, and the
 * interconn client's link for a bridge that is another IRNetFree Plus.
 */
function otherSideSnippet(model, opts) {
  const m = normalizeModel(model);
  const o = isObj(opts) ? opts : {};
  const role = m.reverse.role;
  if (role === 'bridge') {
    const target = bridgeTarget(m, Array.isArray(o.servers) ? o.servers : []);
    if (!target) throw new Error('the bridge has no usable portal target');
    const ob = target.outbound;
    const v = ob.settings.vnext[0];
    const u = v.users[0];
    const c = { id: u.id, email: 'bridge' };
    if (u.flow) c.flow = u.flow;
    c.reverse = { tag: PORTAL_TAG };
    return {
      role: 'portal',
      link: null,
      snippet: {
        inbounds: [{
          tag: '<interconn-inbound-tag>', listen: '0.0.0.0', port: v.port, protocol: 'vless',
          settings: { clients: [c], decryption: 'none' },
          streamSettings: serverStreamFromClient(ob.streamSettings)
        }],
        routing: { rules: [{ type: 'field', inboundTag: ['<user-inbound-tag>'], outboundTag: PORTAL_TAG }] }
      }
    };
  }
  if (role === 'portal') {
    const ic = m.inbounds.find(i => i.id === m.reverse.portal.interconnInboundId);
    if (!ic) throw new Error('the portal has no interconn inbound');
    const c = ic.clients.find(x => x.enabled);
    if (!c) throw new Error('the interconn inbound has no enabled client');
    const record = clientServerRecord(ic, c, m, o);
    const out = { tag: INTERCONN_TAG, protocol: 'vless', settings: flatVless(record.outbound.settings, BRIDGE_TAG), streamSettings: record.outbound.streamSettings };
    return {
      role: 'bridge',
      link: buildShareLink(record),
      snippet: {
        outbounds: [out, { tag: 'direct', protocol: 'freedom', settings: {} }],
        routing: { rules: [{ type: 'field', inboundTag: [BRIDGE_TAG], outboundTag: 'direct' }] }
      }
    };
  }
  return { role: null, snippet: null, link: null };
}

module.exports = {
  DEFAULT_MODEL,
  PROTOCOLS, NETWORKS, SECURITIES, SS_METHODS,
  normalizeModel, newInbound, newClient,
  slugTag, randomShortId, randomPassword, randomKeyFor, parseX25519,
  validateModel, buildServerConfig,
  clientServerRecord, clientLink, otherSideSnippet
};
