'use strict';
/**
 * plus: the Server tab’s model (spec 2026-09-17 section 2.2, `schema: 2`)
 * and its config builder. A model goes in, an Xray server config comes out.
 * Pure on purpose: the runtime (core.js) validates and builds without
 * touching the disk, and the tests pin every shape.
 *
 * The model is the 3x-ui one: inbounds with tags and clients, outbounds with
 * tags, routing rules that name those tags — in the order the core applies
 * them, and the first enabled outbound is the default exit. The reverse
 * proxy is not a mode any more but two tags on ordinary objects. A VLESS
 * client with a `reverseTag` makes this machine a portal for that client:
 * the core’s `clients[].reverse.tag`, an outbound tag the user inbounds
 * route to. A VLESS outbound with a `reverseTag` makes this machine a
 * bridge: the core’s `settings.reverse.tag`, an inbound tag the reversed
 * connections arrive under. What the wizards write is outbounds and rules
 * the user could have typed into the tables.
 *
 * A v1 model (`exit`, `blockPrivate`, `blockTorrent`, `reverse.role`) is
 * migrated on read by `migrateModel`; the store is never rewritten in place.
 *
 * Every shape here was run through `xray run -test` on both cores in bin/
 * (official 26.3.27, patterniha 26.9.x). Things the cores taught us:
 *
 *  - Reality’s destination is called `target` now; both cores still take
 *    `dest` as an alias. The model keeps `dest`, the config says `target`.
 *  - The legacy `reverse.bridges` / `reverse.portals` block is gone from the
 *    26.9 fork ("migrated to VLESS Reverse Proxy"), so only the VLESS form
 *    is built. The bridge’s outbound has to be the flat VLESS settings (the
 *    core refuses `reverse` inside `vnext`), and the interconn is VLESS on
 *    both ends.
 *  - From 26.9 on a freedom outbound blocks every destination that arrives
 *    through a reverse unless a final rule allows it, so a bridge’s freedom
 *    outbounds carry the allow. Older cores ignore the field.
 */
const crypto = require('crypto');
const { parseLink, buildShareLink, buildStreamSettings } = require('../parser');
const { cloneOut, applyFragments, PRIVATE_IPS } = require('../configBuilder');

const SCHEMA = 2;
const PROTOCOLS = ['vless', 'vmess', 'trojan', 'shadowsocks'];
const NETWORKS = ['tcp', 'ws', 'grpc', 'xhttp'];
const SECURITIES = ['none', 'tls', 'reality'];
const SS_METHODS = ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', 'aes-256-gcm', 'aes-128-gcm', 'chacha20-ietf-poly1305'];
const SS2022_KEY_BYTES = { '2022-blake3-aes-128-gcm': 16, '2022-blake3-aes-256-gcm': 32 };
const OUTBOUND_KINDS = ['freedom', 'blackhole', 'server', 'link'];
// Both cores refuse REALITY over WebSocket ("only supports RAW, XHTTP and gRPC").
const REALITY_NETWORKS = ['tcp', 'grpc', 'xhttp'];
const DOMAIN_STRATEGIES = ['AsIs', 'IPIfNonMatch', 'IPOnDemand'];
const RULE_NETWORKS = ['', 'tcp', 'udp', 'tcp,udp'];
// What the sniffer can name; anything else never matches.
const RULE_PROTOCOLS = ['http', 'tls', 'bittorrent', 'quic'];

const VISION = 'xtls-rprx-vision';
const DEST_OVERRIDE = ['http', 'tls', 'quic'];
// The core’s own listeners; nothing in the model may take their names.
const RESERVED_TAGS = ['metrics', 'api'];
const WILDCARD_LISTENS = ['', '0.0.0.0', '::', '[::]'];
const TAG_RE = /^[a-z0-9-]+$/;
const PORT_ITEM_RE = /^(\d{1,5})(?:-(\d{1,5}))?$/;
const DEFAULT_TAGS = { freedom: 'direct', blackhole: 'block', server: 'proxy', link: 'proxy' };

function deepFreeze(o) {
  for (const v of Object.values(o)) if (v && typeof v === 'object') deepFreeze(v);
  return Object.freeze(o);
}

/** The three block rules a click adds: what they match and how the rule reads. */
const RULE_PRESETS = deepFreeze({
  private: { comment: 'block private ranges', ip: ['geoip:private'] },
  torrent: { comment: 'block BitTorrent', protocol: ['bittorrent'] },
  ads: { comment: 'block ads', domain: ['geosite:category-ads-all'] }
});

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
/** A list field a form may hand over as one comma-separated string. */
const listOf = (v) => (Array.isArray(v) ? v : (typeof v === 'string' ? v.split(/[,\n]/) : [])).map(x => str(x, '').trim()).filter(Boolean);
const dedupe = (list) => list.filter((x, i) => list.indexOf(x) === i);
const lower = (v, def) => (str(v, '').trim().toLowerCase() || def);
const arr = (v) => (Array.isArray(v) ? v : []);

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

/** Why a tag is unusable, or null. `taken` is a Set of the tags already in the model. */
function tagProblem(tag, taken) {
  if (!TAG_RE.test(tag)) return 'a tag is lower-case letters, digits and dashes';
  if (RESERVED_TAGS.includes(tag)) return `"${tag}" is the core’s own`;
  if (taken && taken.has(tag)) return `"${tag}" is already used`;
  return null;
}

/** `base`, or `base-2`, `base-3`… — the first name not in `taken`; the name is added to it. */
function freeTag(base, taken) {
  let tag = base;
  for (let n = 2; taken.has(tag); n++) tag = `${base}-${n}`;
  taken.add(tag);
  return tag;
}

/** "443,8000-8100": numbers and ranges, each within 1–65535 and in order. */
function portSpecOk(spec) {
  return String(spec).split(',').every((part) => {
    const m = part.match(PORT_ITEM_RE);
    if (!m) return false;
    const a = Number(m[1]), b = m[2] === undefined ? a : Number(m[2]);
    return a >= 1 && a <= 65535 && b >= a && b <= 65535;
  });
}

/* ----------------------------- ids and keys ----------------------------- */

/**
 * The v1 tag from a remark: lower-case a-z, 0-9 and dashes, capped, with
 * four characters of the id on the end so two inbounds with one remark never
 * share a tag. A remark with nothing usable in it (Persian, say) is `in`.
 * v2 names a new inbound after its port (defaultTag); the migration still
 * needs this for a v1 inbound that was never tagged.
 */
function slugTag(remark, id) {
  const slug = str(remark, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32).replace(/-+$/, '') || 'in';
  const suffix = str(id, '').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 4) || 'x';
  return `${slug}-${suffix}`;
}

/** The 3x-ui tag of a new inbound: `inbound-<port>`. */
function defaultTag(inbound) {
  const i = isObj(inbound) ? inbound : {};
  return `inbound-${Math.trunc(num(i.port, 443))}`;
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

/* ----------------------------- defaults ----------------------------- */

function inboundDefaults() {
  return {
    id: '', tag: '', enabled: true, remark: '',
    protocol: 'vless', listen: '0.0.0.0', port: 443,
    network: 'tcp', path: '/', host: '', serviceName: '',
    security: 'none',
    tls: { certFile: '', keyFile: '', serverName: '', alpn: ['h2', 'http/1.1'] },
    // www.cloudflare.com: www.microsoft.com fails the REALITY handshake on both
    // cores from here ("processed invalid connection"), and the 26.9 core warns
    // against it; Cloudflare's front answers every fingerprint the same way.
    reality: { dest: 'www.cloudflare.com:443', serverNames: ['www.cloudflare.com'], privateKey: '', publicKey: '', shortIds: [] },
    ss: { method: '2022-blake3-aes-128-gcm', password: '' },
    sniffing: true,
    totalBytes: 0, expiresAt: 0,
    used: { up: 0, down: 0 },
    clients: []
  };
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
    // Informational: the core cannot enforce it without its API (the form says so).
    limitIp: nonNeg(c.limitIp, 0),
    quotaBytes: nonNeg(c.quotaBytes, 0),
    expiresAt: nonNeg(c.expiresAt, 0),
    resetDays: Math.trunc(nonNeg(c.resetDays, 0)),
    resetAt: nonNeg(c.resetAt, 0),
    comment: str(c.comment, ''),
    reverseTag: str(c.reverseTag, '').trim(),
    used: { up: nonNeg(used.up, 0), down: nonNeg(used.down, 0) },
    disabledBy: str(c.disabledBy, ''),
    lastSeenAt: nonNeg(c.lastSeenAt, 0)
  };
}

function normalizeInbound(raw) {
  const i = isObj(raw) ? raw : {};
  const d = inboundDefaults();
  const tls = isObj(i.tls) ? i.tls : {};
  const reality = isObj(i.reality) ? i.reality : {};
  const ss = isObj(i.ss) ? i.ss : {};
  const used = isObj(i.used) ? i.used : {};
  const port = Math.trunc(num(i.port, d.port));
  return {
    id: str(i.id, '').trim() || uid(),
    tag: str(i.tag, '').trim() || defaultTag({ port }),
    enabled: bool(i.enabled, true),
    remark: str(i.remark, ''),
    protocol: lower(i.protocol, d.protocol),
    listen: str(i.listen, '').trim() || d.listen,
    port,
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
    totalBytes: nonNeg(i.totalBytes, 0),
    expiresAt: nonNeg(i.expiresAt, 0),
    used: { up: nonNeg(used.up, 0), down: nonNeg(used.down, 0) },
    disabledBy: str(i.disabledBy, ''),
    clients: arr(i.clients).map(normalizeClient)
  };
}

function normalizeOutbound(raw) {
  const o = isObj(raw) ? raw : {};
  const kind = lower(o.kind, 'freedom');
  return {
    id: str(o.id, '').trim() || uid(),
    tag: str(o.tag, '').trim() || DEFAULT_TAGS[kind] || 'out',
    kind,
    serverId: str(o.serverId, '').trim(),
    link: str(o.link, '').trim(),
    reverseTag: str(o.reverseTag, '').trim(),
    enabled: bool(o.enabled, true)
  };
}

function normalizeRule(raw) {
  const r = isObj(raw) ? raw : {};
  return {
    id: str(r.id, '').trim() || uid(),
    enabled: bool(r.enabled, true),
    comment: str(r.comment, ''),
    inboundTags: dedupe(listOf(r.inboundTags)),
    outboundTag: str(r.outboundTag, '').trim(),
    domain: listOf(r.domain),
    ip: listOf(r.ip),
    port: str(r.port, '').replace(/\s+/g, ''),
    protocol: dedupe(listOf(r.protocol).map(p => p.toLowerCase())),
    network: lower(r.network, ''),
    preset: lower(r.preset, '')
  };
}

/** A v2 model with every missing field filled from the defaults. Never throws. */
function normalizeV2(raw) {
  const m = isObj(raw) ? raw : {};
  const routing = isObj(m.routing) ? m.routing : {};
  return {
    schema: SCHEMA,
    autoStart: bool(m.autoStart, false),
    engine: str(m.engine, '').trim() || 'xray',
    logLevel: str(m.logLevel, '').trim() || 'warning',
    publicAddress: str(m.publicAddress, '').trim(),
    inbounds: arr(m.inbounds).map(normalizeInbound),
    outbounds: arr(m.outbounds).map(normalizeOutbound),
    routing: {
      domainStrategy: str(routing.domainStrategy, '').trim() || 'IPIfNonMatch',
      rules: arr(routing.rules).map(normalizeRule)
    }
  };
}

/**
 * Whatever the store holds, as a v2 model: a v1 model (anything not marked
 * `schema: 2`, the empty store included) goes through the migration first.
 * Idempotent on v2; garbage in, the default model out. Never throws.
 */
function normalizeModel(raw) {
  const m = isObj(raw) ? raw : {};
  return num(m.schema, 0) === SCHEMA ? normalizeV2(m) : migrateModel(m);
}

/* ----------------------------- migration ----------------------------- */

/** The fields of a preset rule, as a fresh copy. */
function presetFields(name) {
  const p = RULE_PRESETS[name];
  if (!p) throw new Error(`unknown preset "${name}"`);
  const out = { preset: name, comment: p.comment };
  for (const k of ['domain', 'ip', 'protocol']) if (p[k]) out[k] = p[k].slice();
  return out;
}

/**
 * A v1 model (v2.0’s shape) as a v2 model. Pure and total: the input is
 * not touched and any input, `{}` included, gives a well-formed v2 (which
 * validates exactly when the v1 did). Ids of what the migration invents are
 * its tag, so the result is the same every time.
 *
 *   exit.direct           → outbounds [direct: freedom, block: blackhole]
 *   exit.server           → outbounds [exit: server(serverId), block]
 *   blockPrivate          → rule preset private   (ip geoip:private → block)
 *   blockTorrent          → rule preset torrent   (protocol bittorrent → block)
 *   reverse.role bridge   → outbound interconn (the via, reverseTag bridge) + rule bridge → the exit
 *   reverse.role portal   → the interconn’s enabled clients get reverseTag portal + rule userTags → portal
 *   client.note           → client.comment; tags, meters and disabledBy are kept
 *
 * A v1 inbound could be tagged `direct` (only the reverse names were
 * reserved), so an invented tag steps to `direct-2` when its name is taken.
 */
function migrateModel(v1) {
  const m = isObj(v1) ? v1 : {};
  if (num(m.schema, 0) === SCHEMA) return normalizeV2(m);
  const exit = isObj(m.exit) ? m.exit : {};
  const rv = isObj(m.reverse) ? m.reverse : {};
  const bridge = isObj(rv.bridge) ? rv.bridge : {};
  const portal = isObj(rv.portal) ? rv.portal : {};

  const inbounds = arr(m.inbounds).map((raw) => {
    const i = isObj(raw) ? raw : {};
    const id = str(i.id, '').trim() || uid();
    const clients = arr(i.clients).map((c) => {
      const cc = isObj(c) ? c : {};
      const out = Object.assign({}, cc, { comment: str(cc.note, '') || str(cc.comment, '') });
      delete out.note;
      return out;
    });
    return normalizeInbound(Object.assign({}, i, { id, tag: str(i.tag, '').trim() || slugTag(str(i.remark, ''), id), clients }));
  });

  const taken = new Set(inbounds.map(i => i.tag));
  const outbounds = [], rules = [];
  const viaServer = str(exit.type, '').trim() === 'server';
  const exitTag = freeTag(viaServer ? 'exit' : 'direct', taken);
  outbounds.push(viaServer
    ? { id: exitTag, tag: exitTag, kind: 'server', serverId: str(exit.serverId, '').trim() }
    : { id: exitTag, tag: exitTag, kind: 'freedom' });
  const blockTag = freeTag('block', taken);
  outbounds.push({ id: blockTag, tag: blockTag, kind: 'blackhole' });
  if (bool(m.blockPrivate, true)) rules.push(Object.assign({ id: 'rule-private', outboundTag: blockTag }, presetFields('private')));
  if (bool(m.blockTorrent, false)) rules.push(Object.assign({ id: 'rule-torrent', outboundTag: blockTag }, presetFields('torrent')));

  const role = str(rv.role, '').trim();
  if (role === 'bridge') {
    const via = str(bridge.via, '').trim() === 'link' ? 'link' : 'server';
    const icTag = freeTag('interconn', taken);
    const bridgeTag = freeTag('bridge', taken);
    outbounds.push({
      id: icTag, tag: icTag, kind: via, reverseTag: bridgeTag,
      serverId: via === 'server' ? str(bridge.serverId, '').trim() : '',
      link: via === 'link' ? str(bridge.link, '').trim() : ''
    });
    rules.push({ id: 'rule-bridge', inboundTags: [bridgeTag], outboundTag: exitTag, comment: `reverse ← ${bridgeTag}` });
  } else if (role === 'portal') {
    const ic = inbounds.find(i => i.id === str(portal.interconnInboundId, '').trim());
    if (ic) {
      const portalTag = freeTag('portal', taken);
      for (const c of ic.clients) if (c.enabled) c.reverseTag = portalTag;
      const ids = dedupe(strList(portal.userInboundIds, []));
      const userTags = inbounds.filter(i => i.id !== ic.id && ids.includes(i.id)).map(i => i.tag);
      if (userTags.length) rules.push({ id: 'rule-portal', inboundTags: userTags, outboundTag: portalTag, comment: `reverse → ${portalTag}` });
    }
  }

  return normalizeV2({
    schema: SCHEMA,
    autoStart: m.autoStart, engine: m.engine, logLevel: m.logLevel, publicAddress: m.publicAddress,
    inbounds, outbounds,
    routing: { domainStrategy: 'IPIfNonMatch', rules }
  });
}

const DEFAULT_MODEL = deepFreeze(migrateModel({}));

/* ----------------------------- fresh things ----------------------------- */

const INBOUND_SEEDS = {
  vless: { remark: 'VLESS Reality', port: 443, network: 'tcp', security: 'reality' },
  vmess: { remark: 'VMess WS', port: 8080, network: 'ws', security: 'none' },
  trojan: { remark: 'Trojan TLS', port: 443, network: 'tcp', security: 'tls' },
  shadowsocks: { remark: 'Shadowsocks', port: 8388, network: 'tcp', security: 'none' }
};

/** A new inbound with a fresh id, the tag of its port and the defaults its protocol wants. Overrides win. */
function newInbound(protocol, overrides) {
  const p = PROTOCOLS.includes(protocol) ? protocol : 'vless';
  const seed = Object.assign({ id: uid(), protocol: p }, INBOUND_SEEDS[p]);
  if (p === 'vless') seed.reality = Object.assign(inboundDefaults().reality, { shortIds: [randomShortId()] });
  if (p === 'shadowsocks') seed.ss = { method: '2022-blake3-aes-128-gcm', password: randomKeyFor('2022-blake3-aes-128-gcm') };
  const merged = Object.assign(seed, isObj(overrides) ? overrides : {});
  // A method chosen without a key gets one of the right size.
  if (isObj(merged.ss) && merged.ss.method && !merged.ss.password) merged.ss = Object.assign({}, merged.ss, { password: randomKeyFor(merged.ss.method) });
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

/** A new outbound of a kind, with a fresh id and the tag that kind usually gets. Overrides win. */
function newOutbound(kind, overrides) {
  const k = OUTBOUND_KINDS.includes(kind) ? kind : 'freedom';
  return normalizeOutbound(Object.assign({ id: uid(), kind: k }, isObj(overrides) ? overrides : {}));
}

function newRule(overrides) {
  return normalizeRule(Object.assign({ id: uid() }, isObj(overrides) ? overrides : {}));
}

/** One of the three block rules, sending to `blockTag` (`block` unless given). Throws on an unknown name. */
function presetRule(name, blockTag) {
  return newRule(Object.assign({ outboundTag: str(blockTag, '').trim() || 'block' }, presetFields(name)));
}

/** Every tag in a model, enabled or not: `{ inbounds, outbounds, clientReverse, outboundReverse }`, each a Set. */
function allTags(model) {
  const m = normalizeModel(model);
  const t = { inbounds: new Set(), outbounds: new Set(), clientReverse: new Set(), outboundReverse: new Set() };
  for (const i of m.inbounds) {
    t.inbounds.add(i.tag);
    for (const c of i.clients) if (c.reverseTag) t.clientReverse.add(c.reverseTag);
  }
  for (const o of m.outbounds) {
    t.outbounds.add(o.tag);
    if (o.reverseTag) t.outboundReverse.add(o.reverseTag);
  }
  return t;
}

const unionTags = (t) => new Set([...t.inbounds, ...t.outbounds, ...t.clientReverse, ...t.outboundReverse]);
/** The tags a client’s reverse tag may not take: everything but another client’s reverse tag. */
const unsharableTags = (t) => new Set([...t.inbounds, ...t.outbounds, ...t.outboundReverse]);

/* ----------------------------- validation ----------------------------- */

/** The stored record or parsed link an outbound dials; null when there is none usable. */
function outboundTarget(ob, servers) {
  if (ob.kind === 'server') return findServer(servers, ob.serverId);
  if (ob.kind === 'link' && ob.link) { try { return parseLink(ob.link); } catch { return null; } }
  return null;
}

/** `{ ok, errors, warnings }`, each entry `{ path, msg }` with the model path it is about. */
function validateModel(model, opts) {
  const m = normalizeModel(model);
  const servers = Array.isArray(opts && opts.servers) ? opts.servers : [];
  const errors = [], warnings = [];
  const err = (path, msg) => { errors.push({ path, msg }); };
  const warn = (path, msg) => { warnings.push({ path, msg }); };

  // One namespace for inbound tags, outbound tags and both kinds of reverse
  // tag: the core sees them all as inbound or outbound names. The one thing
  // that may repeat is a client’s reverse tag on another client — several
  // bridge credentials answering to one portal outbound, as the v1 portal
  // did with every one of its bridges.
  const seen = new Set(), shared = new Set();
  const claim = (path, tag, sharable) => {
    const problem = tagProblem(tag, seen);
    if (problem && !(sharable && shared.has(tag))) { err(path, problem); return; }
    seen.add(tag);
    if (sharable) shared.add(tag);
  };

  const emails = new Set(), binds = [];
  m.inbounds.forEach((i, n) => {
    const p = `inbounds[${n}]`;
    if (!PROTOCOLS.includes(i.protocol)) err(`${p}.protocol`, `unknown protocol "${i.protocol}"`);
    if (!NETWORKS.includes(i.network)) err(`${p}.network`, `unknown transport "${i.network}"`);
    if (!SECURITIES.includes(i.security)) err(`${p}.security`, `unknown security "${i.security}"`);
    claim(`${p}.tag`, i.tag);

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
      if (c.reverseTag) {
        if (i.protocol !== 'vless') err(`${cp}.reverseTag`, 'the reverse proxy rides VLESS: only a vless client can be a bridge’s credential');
        else claim(`${cp}.reverseTag`, c.reverseTag, true);
      }
      if (c.enabled) live++;
    });
    if (i.enabled && !live) warn(`${p}.clients`, 'no enabled client: the inbound runs but nobody can use it');
  });

  let liveOut = 0;
  m.outbounds.forEach((ob, n) => {
    const p = `outbounds[${n}]`;
    claim(`${p}.tag`, ob.tag);
    if (!OUTBOUND_KINDS.includes(ob.kind)) { err(`${p}.kind`, `unknown kind "${ob.kind}"`); return; }
    let target = null;
    if (ob.kind === 'server') {
      target = findServer(servers, ob.serverId);
      if (!target) err(`${p}.serverId`, 'choose a stored config');
    } else if (ob.kind === 'link') {
      if (!ob.link) err(`${p}.link`, 'paste a link');
      else { try { target = parseLink(ob.link); } catch (e) { err(`${p}.link`, e.message); } }
    }
    if (ob.reverseTag) {
      if (ob.kind === 'freedom' || ob.kind === 'blackhole') err(`${p}.reverseTag`, 'only an outbound that dials a portal can carry a reverse tag');
      else {
        if (target && !isVless(target)) err(`${p}.reverseTag`, 'the reverse proxy rides VLESS: the portal must be a vless config');
        claim(`${p}.reverseTag`, ob.reverseTag);
      }
    }
    if (ob.enabled) liveOut++;
  });
  if (!liveOut) err('outbounds', 'at least one enabled outbound is needed: the first one is the default exit');

  // Rules name tags: a source is an inbound or the inbound a bridge outbound
  // creates; a target is an enabled outbound or the outbound an enabled
  // bridge credential creates. A disabled rule is inert, whatever it says.
  const inboundTags = new Set(m.inbounds.map(i => i.tag));
  const reversedIn = new Set(m.outbounds.filter(o => o.reverseTag).map(o => o.reverseTag));
  const liveReversedIn = new Set(m.outbounds.filter(o => o.enabled && o.reverseTag).map(o => o.reverseTag));
  const exits = new Set(m.outbounds.filter(o => o.enabled).map(o => o.tag));
  const portals = new Set();
  for (const i of m.inbounds) if (i.enabled && i.protocol === 'vless') for (const c of i.clients) if (c.enabled && c.reverseTag) portals.add(c.reverseTag);
  if (!DOMAIN_STRATEGIES.includes(m.routing.domainStrategy)) err('routing.domainStrategy', `unknown domain strategy "${m.routing.domainStrategy}"`);
  const targets = new Set(), sources = new Set();
  m.routing.rules.forEach((r, n) => {
    const p = `routing.rules[${n}]`;
    if (!r.enabled) return;
    if (!(r.inboundTags.length || r.domain.length || r.ip.length || r.port || r.protocol.length || r.network)) {
      err(p, 'a rule needs something to match: inbound tags, domains, ips, ports, a protocol or a network');
    }
    for (const t of r.inboundTags) if (!inboundTags.has(t) && !reversedIn.has(t)) err(`${p}.inboundTags`, `"${t}" is no inbound tag and no outbound’s reverse tag`);
    if (!r.outboundTag) err(`${p}.outboundTag`, 'choose where the traffic goes');
    else if (!exits.has(r.outboundTag) && !portals.has(r.outboundTag)) err(`${p}.outboundTag`, `"${r.outboundTag}" is no enabled outbound and no enabled vless client’s reverse tag`);
    if (r.port && !portSpecOk(r.port)) err(`${p}.port`, 'ports are numbers and ranges: 443,8000-8100');
    if (!RULE_NETWORKS.includes(r.network)) err(`${p}.network`, 'network is tcp, udp or tcp,udp');
    for (const x of r.protocol) if (!RULE_PROTOCOLS.includes(x)) err(`${p}.protocol`, `unknown protocol "${x}" (http, tls, bittorrent, quic)`);
    if (r.preset && !RULE_PRESETS[r.preset]) err(`${p}.preset`, `unknown preset "${r.preset}"`);
    targets.add(r.outboundTag);
    for (const t of r.inboundTags) sources.add(t);
  });
  for (const t of portals) if (!targets.has(t)) warn('routing.rules', `no rule sends anyone to "${t}": the bridge behind it carries nothing`);
  for (const t of liveReversedIn) if (!sources.has(t)) warn('routing.rules', `no rule names "${t}": what the portal hands back takes the default exit`);

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
function serverClient(i, c) {
  let o;
  if (i.protocol === 'vless') {
    o = { id: c.uuid, email: c.email };
    if (c.flow === VISION && visionOk(i)) o.flow = VISION;
    if (c.reverseTag) o.reverse = { tag: c.reverseTag };
  } else if (i.protocol === 'vmess') {
    o = { id: c.uuid, email: c.email };
  } else if (i.protocol === 'trojan') {
    o = { password: c.password, email: c.email };
  } else {
    o = is2022(i.ss.method) ? { email: c.email, password: c.password } : { email: c.email, password: c.password, method: i.ss.method };
  }
  return o;
}

function serverInbound(i) {
  const clients = i.clients.filter(c => c.enabled).map(c => serverClient(i, c));
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

/**
 * One model outbound as the config carries it; null when it cannot be built
 * (validation is what reports that). `bridging`: the model has a reverse
 * outbound, so every freedom exit opts in to carrying what the portal hands
 * back — from 26.9 on the core refuses those destinations otherwise
 * ("proxy/freedom: blocked target", then a penalty on the source). The
 * block rules still come first in routing. Older cores ignore the field.
 */
function serverOutbound(ob, servers, bridging) {
  if (ob.kind === 'freedom') return { tag: ob.tag, protocol: 'freedom', settings: bridging ? { finalRules: [{ action: 'allow' }] } : {} };
  if (ob.kind === 'blackhole') return { tag: ob.tag, protocol: 'blackhole', settings: { response: { type: 'http' } } };
  const target = outboundTarget(ob, servers);
  if (!target || !target.outbound) return null;
  if (ob.reverseTag && !isVless(target)) return null;
  const out = cloneOut(target.outbound, ob.tag, target);
  if (ob.reverseTag) out.settings = flatVless(out.settings, ob.reverseTag);
  return out;
}

/**
 * One enabled model rule as the config carries it, empty fields left out;
 * null when nothing is left to match. Without geoip.dat / geosite.dat the
 * core refuses the whole config, so `geoip:private` becomes the literal list
 * and every other geo entry goes.
 */
function serverRule(r, geo) {
  const rule = { type: 'field' };
  if (r.inboundTags.length) rule.inboundTag = r.inboundTags.slice();
  let domain = r.domain.slice(), ip = r.ip.slice();
  if (!geo) {
    domain = domain.filter(d => !/^geosite:/i.test(d));
    ip = ip.flatMap(x => (/^geoip:private$/i.test(x) ? PRIVATE_IPS.slice() : (/^geoip:/i.test(x) ? [] : [x])));
  }
  if (domain.length) rule.domain = domain;
  if (ip.length) rule.ip = ip;
  if (r.port) rule.port = r.port;
  if (r.protocol.length) rule.protocol = r.protocol.slice();
  if (r.network) rule.network = r.network;
  if (Object.keys(rule).length === 1) return null;
  rule.outboundTag = r.outboundTag;
  return rule;
}

/**
 * The Xray config for a model. `apiPort` is the metrics listener (same shape
 * the client config uses, so stats.js reads it unchanged), `servers` the
 * stored records an outbound may point at, `geoAvailable` whether geoip.dat
 * is on disk. Inbounds, outbounds and rules come out in the model’s order
 * with the disabled ones absent.
 */
function buildServerConfig(model, opts) {
  const m = normalizeModel(model);
  const o = isObj(opts) ? opts : {};
  const apiPort = num(o.apiPort, 10095);
  const servers = Array.isArray(o.servers) ? o.servers : [];
  const geo = o.geoAvailable !== false;

  const inbounds = m.inbounds.filter(i => i.enabled).map(serverInbound);
  const bridging = m.outbounds.some(ob => ob.enabled && !!ob.reverseTag);
  const outbounds = [];
  for (const ob of m.outbounds) {
    if (!ob.enabled) continue;
    const built = serverOutbound(ob, servers, bridging);
    if (built) outbounds.push(built);
  }
  const rules = m.routing.rules.filter(r => r.enabled).map(r => serverRule(r, geo)).filter(Boolean);

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
    routing: { domainStrategy: m.routing.domainStrategy, rules }
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
 * What the other end of each reverse pair pastes into a bare xray config or
 * 3x-ui’s Xray settings — `{ items }`, one per tag, in model order.
 *
 * A client with a `reverseTag` makes this machine the portal for it, so the
 * item (`kind: 'bridge-side'`) is what the bridge pastes: the interconn
 * outbound in the flat VLESS form, a direct exit with the allow, the rule —
 * and the client’s link for a bridge that is another IRNetFree Plus. The
 * bridge’s own reverse tag is given the same name so the pair reads as one.
 *
 * An outbound with a `reverseTag` makes this machine a bridge, so the item
 * (`kind: 'portal-side'`) is the portal’s interconn inbound with the client
 * carrying `reverse.tag` and the rule that sends users through; the inbound
 * tag, the user inbounds and the secrets are placeholders only that side
 * knows. Without a public address the bridge-side snippet says
 * `<public-address>` and has no link.
 */
function otherSideSnippet(model, opts) {
  const m = normalizeModel(model);
  const o = isObj(opts) ? opts : {};
  const servers = Array.isArray(o.servers) ? o.servers : [];
  const address = str(o.address != null ? o.address : m.publicAddress, '').trim();
  const items = [];
  for (const i of m.inbounds) {
    if (!i.enabled || i.protocol !== 'vless') continue;
    for (const c of i.clients) {
      if (!c.enabled || !c.reverseTag) continue;
      const record = clientServerRecord(i, c, m, { address: address || '<public-address>' });
      const interconn = { tag: 'interconn', protocol: 'vless', settings: flatVless(record.outbound.settings, c.reverseTag), streamSettings: record.outbound.streamSettings };
      items.push({
        kind: 'bridge-side', tag: c.reverseTag, inboundId: i.id, clientId: c.id, email: c.email,
        link: address ? buildShareLink(record) : null,
        snippet: {
          outbounds: [interconn, { tag: 'direct', protocol: 'freedom', settings: { finalRules: [{ action: 'allow' }] } }],
          routing: { rules: [{ type: 'field', inboundTag: [c.reverseTag], outboundTag: 'direct' }] }
        }
      });
    }
  }
  for (const ob of m.outbounds) {
    if (!ob.enabled || !ob.reverseTag) continue;
    const target = outboundTarget(ob, servers);
    if (!isVless(target)) continue;
    const v = target.outbound.settings.vnext[0];
    const u = v.users[0];
    const c = { id: u.id, email: 'bridge' };
    if (u.flow) c.flow = u.flow;
    c.reverse = { tag: ob.reverseTag };
    items.push({
      kind: 'portal-side', tag: ob.reverseTag, outboundId: ob.id, outboundTag: ob.tag, link: null,
      snippet: {
        inbounds: [{
          tag: '<interconn-inbound-tag>', listen: '0.0.0.0', port: v.port, protocol: 'vless',
          settings: { clients: [c], decryption: 'none' },
          streamSettings: serverStreamFromClient(target.outbound.streamSettings)
        }],
        routing: { rules: [{ type: 'field', inboundTag: ['<user-inbound-tag>'], outboundTag: ob.reverseTag }] }
      }
    });
  }
  return { items };
}

/* ----------------------------- wizards ----------------------------- */

const sameSet = (a, b) => a.length === b.length && a.every(x => b.includes(x));

/**
 * This machine is the portal: the chosen VLESS client becomes a bridge’s
 * credential (`reverseTag: tag`) and a rule sends the chosen user inbounds
 * to it. The rule goes before the first rule that names any of those
 * inbounds, so it wins; otherwise at the end. Running it again with the same
 * choice adds nothing. The tag defaults to the first free `bridge-N`; a tag
 * another client already carries is allowed and means both bridges answer
 * to the same outbound. Returns `{ model, link }` — a new model, the input
 * untouched, and the link the bridge pastes (null without a public address).
 * Throws, in plain words, on anything that would not validate.
 */
function wizardPortal(model, args) {
  const a = isObj(args) ? args : {};
  const next = normalizeModel(model);
  const tags = allTags(next);
  const ic = next.inbounds.find(i => i.id === str(a.inboundId, '').trim());
  if (!ic) throw new Error('the interconn inbound was not found');
  if (ic.protocol !== 'vless') throw new Error('the reverse proxy rides VLESS: the interconn inbound must be vless');
  if (!ic.enabled) throw new Error('the interconn inbound is disabled');
  const c = ic.clients.find(x => x.id === str(a.clientId, '').trim());
  if (!c) throw new Error('the bridge’s client was not found');
  if (!c.enabled) throw new Error('the bridge’s client is disabled');
  // No tag given: the one the client already has, else the first free bridge-N.
  let tag = str(a.tag, '').trim() || c.reverseTag;
  if (!tag) {
    const all = unionTags(tags);
    for (let n = 1; !tag || all.has(tag); n++) tag = `bridge-${n}`;
  }
  const ids = dedupe(strList(a.userInboundIds, []));
  if (ids.includes(ic.id)) throw new Error('the interconn inbound cannot also be a user inbound');
  if (!ids.length) throw new Error('choose the inbounds whose users go through the bridge');
  const users = next.inbounds.filter(i => ids.includes(i.id));
  if (users.length !== ids.length) throw new Error('a chosen user inbound no longer exists');
  if (c.reverseTag !== tag) {
    const problem = tagProblem(tag, unsharableTags(tags));
    if (problem) throw new Error(problem);
    c.reverseTag = tag;
  }
  const userTags = users.map(i => i.tag);
  const rules = next.routing.rules;
  if (!rules.some(r => r.outboundTag === tag && sameSet(r.inboundTags, userTags))) {
    const rule = newRule({ inboundTags: userTags, outboundTag: tag, comment: `reverse → ${tag}` });
    const at = rules.findIndex(r => r.inboundTags.some(t => userTags.includes(t)));
    if (at === -1) rules.push(rule); else rules.splice(at, 0, rule);
  }
  let link = null;
  try { link = clientLink(ic, c, next); } catch { /* no public address yet: the model is still right */ }
  return { model: next, link };
}

/**
 * This machine is the bridge: an outbound that dials the portal (`link` or
 * a stored `serverId`) with `reverseTag`, and a rule that sends what the
 * portal hands back to `exitOutboundTag` — the first enabled freedom
 * outbound unless given, created as `direct` when there is none. `servers`
 * (optional) lets a stored config be checked here; validation checks it
 * anyway. Returns `{ model }`, a new model. Throws on anything that would
 * not validate.
 */
function wizardBridge(model, args) {
  const a = isObj(args) ? args : {};
  const next = normalizeModel(model);
  const tag = str(a.tag, '').trim() || 'interconn';
  const reverseTag = str(a.reverseTag, '').trim() || 'bridge';
  const link = str(a.link, '').trim();
  const serverId = str(a.serverId, '').trim();
  const servers = Array.isArray(a.servers) ? a.servers : null;
  if (!link && !serverId) throw new Error('paste the portal’s link or choose a stored config');
  if (link) {
    let s;
    try { s = parseLink(link); } catch (e) { throw new Error('the link does not parse: ' + e.message); }
    if (!isVless(s)) throw new Error('the reverse proxy rides VLESS: the portal link must be vless://');
  } else if (servers) {
    const s = findServer(servers, serverId);
    if (!s) throw new Error('choose the stored config that reaches the portal');
    if (!isVless(s)) throw new Error('the reverse proxy rides VLESS: choose a vless config');
  }
  const taken = unionTags(allTags(next));
  for (const t of [tag, reverseTag]) {
    const problem = tagProblem(t, taken);
    if (problem) throw new Error(problem);
    taken.add(t);
  }
  let exitTag = str(a.exitOutboundTag, '').trim();
  if (exitTag) {
    const exit = next.outbounds.find(o => o.enabled && o.tag === exitTag);
    if (!exit) throw new Error(`no enabled outbound "${exitTag}" to use as the exit`);
    if (exit.kind === 'blackhole') throw new Error('the exit must be a freedom, server or link outbound');
  } else {
    const freedom = next.outbounds.find(o => o.enabled && o.kind === 'freedom');
    exitTag = freedom ? freedom.tag : freeTag('direct', taken);
    if (!freedom) next.outbounds.push(newOutbound('freedom', { tag: exitTag }));
  }
  next.outbounds.push(newOutbound(link ? 'link' : 'server', { tag, link, serverId, reverseTag }));
  const rules = next.routing.rules;
  if (!rules.some(r => r.outboundTag === exitTag && sameSet(r.inboundTags, [reverseTag]))) {
    rules.push(newRule({ inboundTags: [reverseTag], outboundTag: exitTag, comment: `reverse ← ${reverseTag}` }));
  }
  return { model: next };
}

module.exports = {
  SCHEMA, DEFAULT_MODEL,
  PROTOCOLS, NETWORKS, SECURITIES, SS_METHODS, OUTBOUND_KINDS, RULE_PRESETS,
  normalizeModel, migrateModel,
  newInbound, newClient, newOutbound, newRule, presetRule,
  defaultTag, allTags,
  slugTag, randomShortId, randomPassword, randomKeyFor, parseX25519,
  validateModel, buildServerConfig,
  clientServerRecord, clientLink, otherSideSnippet,
  wizardPortal, wizardBridge
};
