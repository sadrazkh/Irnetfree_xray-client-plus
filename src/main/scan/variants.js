'use strict';
/**
 * plus: the parameter matrix of a scan (2026-11-01, the owner: "test the
 * options like fragment and patterniha's too — not only IPs: a config's
 * parameters on one IP or several, all their permutations"). Pure.
 *
 * A DIMENSION is one thing a config can be dialled with — its TLS
 * fingerprint, its ALPN, cipherSuites, the app's TLS fragment, finalmask,
 * Xray-PattN's dialMode, mux, XHTTP's mode — and the user turns on the ones
 * worth trying, each with a list of values. A VARIANT is one value of every
 * dimension that is on; the variants are their cartesian product. A scan then
 * runs variants × targets (targets.js: addresses × ports × SNIs), at most
 * `limit` of them (planTests).
 *
 * Everything is written where the app itself keeps it, so a variant that
 * wins is exactly a config IRNetFree runs:
 *  - fingerprint, alpn, cipherSuites: streamSettings.tlsSettings (REALITY's
 *    fingerprint: realitySettings) — the parser's `fp`, `alpn`, `cs`;
 *  - fragment: the outbound's `_fragment` marker ("packets,length,interval",
 *    the link's `fragment=`) — configBuilder.applyFragments turns it into a
 *    freedom dialer when the test config is built, as for a link;
 *  - finalMask: streamSettings.finalmask (the link's `fm`), the whole object;
 *  - dialMode: streamSettings.sockopt.dialMode (Xray-PattN 26.10.27+, the
 *    editor's field; no share link carries it);
 *  - mux: the outbound's `mux` object (mux.js's MUX, the server's own
 *    concurrency where it has one; no share link carries it either);
 *  - xhttpMode: streamSettings.xhttpSettings.mode (the link's `mode`).
 *
 * A dimension that does not apply to a config is SKIPPED with the reason and
 * never written (applicability): no TLS → no fingerprint, ALPN or ciphers; a
 * UDP transport (Hysteria2, WireGuard, mKCP, MASQUE over HTTP/3) → no TCP
 * fragment, dialMode or TCP masks; a JSON config that dials through its own
 * helper outbound → its fragment and dialMode belong to that helper; mux only
 * where mux.js's muxEligible says the app would put it. A VALUE that would do
 * nothing is skipped the same way (a UDP-only mask on a TCP transport), and
 * so is a COMBINATION that would only repeat another one: cipherSuites take
 * effect with the fingerprint `unsafe` alone (uTLS writes its own suites for
 * every other one), and a dialMode next to a fragment is never sent — the
 * fragment's freedom dialer makes the TCP connection, not the outbound that
 * carries the dialMode.
 *
 * Engines: a variant that writes something only Xray-PattN runs NEEDS it
 * (engineNeed): a dialMode or the merge mask — PattN 26.10.27 and newer
 * (xrayManager PATTN_OOB_SINCE; the official core ignores dialMode silently
 * and does not know merge) — and any finalmask the scan writes (the app runs
 * a finalmask config on PattN whenever PattN is there: validateWithFallback).
 * The config's own values are the user's and are left to the run's cores, as
 * without variants.
 */
const crypto = require('crypto');
const { MUX, muxEligible } = require('../mux');
const SF = require('../../renderer/serverFields');
const { PATTN_OOB_SINCE, pattnOobNeeds, versionBelow } = require('../xrayManager');
const { protocolOf, transportOf, mirrorIntoJson } = require('./substitute');

const { masqueHttpOf } = SF;
const PATTN = 'xray-pattn';

/** At most this many variants in one run: the product of the dimensions' values is refused past it. */
const MAX_VARIANTS = 5000;
/** The default and the bounds of how many variant × target tests a run takes. */
const DEFAULT_LIMIT = 300;
const MAX_LIMIT = 1000000;

const STREAM = new Set(['vless', 'vmess', 'trojan', 'shadowsocks']);

/**
 * The presets are the editor's own (upstream serverFields, synced verbatim:
 * PattNG's values, name for name), read here, never copied — a sync that
 * changes one changes the scan's with it. Their names are the editor's labels
 * ("tlshello-0-len (0-104-1-0-0-114-1-1-11)", "semi-python-cipherSuites");
 * the scan names a value by the label's first word, without "-cipherSuites"
 * ("tlshello-0-len", "semi-python"), short enough for a variant's label.
 *
 * Fingerprints: the cores' uTLS names (hellochrome_120 is one of the official
 * core's ModernFingerprints); a core that does not know one refuses the config
 * at start, and the scanner then names the variant that did it (scanner.js).
 */
const shortName = (name) => String(name).split(' ')[0].replace(/-cipherSuites$/, '');
const FINGERPRINTS = SF.FINGERPRINTS.slice();
const FINALMASK_PRESETS = Object.fromEntries(SF.FINALMASK_PRESETS.map((p) => [shortName(p.name), JSON.parse(p.value)]));
const CIPHER_PRESETS = Object.fromEntries(SF.CIPHER_PRESETS.map((p) => [shortName(p.name), p.value]));
const DIAL_PRESETS = SF.DIAL_MODE_PRESETS.map((p) => p.value);

/**
 * The dimensions, in the order a label names them. `none` is the value that
 * removes the setting; `presets` are offered one tap away on the page (the
 * first ones pre-listed when the dimension is turned on: `start`); `options`
 * is a closed list — nothing else is taken.
 */
const DIMENSIONS = [
  { id: 'fingerprint', short: 'fp', options: FINGERPRINTS, start: ['chrome', 'firefox'] },
  { id: 'alpn', short: 'alpn', none: 'none', presets: ['h2', 'http/1.1', 'h2,http/1.1'], start: ['h2', 'http/1.1'] },
  { id: 'cipherSuites', short: 'cs', none: 'none', presets: Object.keys(CIPHER_PRESETS), start: ['none', 'real-firefox'] },
  { id: 'fragment', short: 'frag', none: 'off', presets: ['tlshello,100-200,10-20', 'tlshello,10-20,10-20', '1-3,1-5,1-2'], start: ['off', 'tlshello,100-200,10-20'] },
  { id: 'finalMask', short: 'fm', none: 'none', presets: Object.keys(FINALMASK_PRESETS), start: ['none', 'tlshello'] },
  { id: 'dialMode', short: 'dm', none: 'none', presets: DIAL_PRESETS, start: ['none'].concat(DIAL_PRESETS.slice(0, 1)) },
  { id: 'mux', short: 'mux', options: ['off', 'on'], start: ['off', 'on'] },
  { id: 'xhttpMode', short: 'mode', options: ['auto', 'packet-up', 'stream-up', 'stream-one'], start: ['auto', 'packet-up'] }
];
const DIM = new Map(DIMENSIONS.map((d) => [d.id, d]));
const DIM_IDS = DIMENSIONS.map((d) => d.id);

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const clone = (v) => JSON.parse(JSON.stringify(v));
const hash6 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex').slice(0, 6);

/** Key order aside, the same JSON. */
function canon(v) {
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (isObj(v)) return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  return JSON.stringify(v);
}


/* ------------------------------- values ------------------------------- */

const RANGE = /^\d{1,5}(-\d{1,5})?$/;

/**
 * readValue(dimId, raw) → { id, value, raw } | { error }. `id` is short and
 * stable (a preset's name, the value itself when it is short and plain, else
 * `custom-<hash>`), `value` what is written (null removes the setting), `raw`
 * the text as the page sends it back.
 */
function readValue(dimId, raw) {
  const d = DIM.get(dimId);
  if (!d) return { error: 'unknown dimension: ' + dimId };
  const text = typeof raw === 'string' ? raw.trim() : (isObj(raw) ? JSON.stringify(raw) : String(raw == null ? '' : raw).trim());
  if (!text) return { error: 'empty value' };
  if (d.none && text.toLowerCase() === d.none) return { id: d.none, value: null, raw: d.none };
  if (d.options) {
    const v = text.toLowerCase();
    return d.options.includes(v) ? { id: v, value: v, raw: v } : { error: `not one of ${d.options.join(', ')}: ${text}` };
  }
  switch (dimId) {
    case 'alpn': {
      const parts = text.split(',').map((s) => s.trim()).filter(Boolean);
      if (!parts.length || !parts.every((p) => /^[A-Za-z0-9./_-]{1,32}$/.test(p))) return { error: 'ALPN: names separated by commas (h2, http/1.1): ' + text };
      const v = parts.join(',');
      return { id: v, value: v, raw: v };
    }
    case 'cipherSuites': {
      if (CIPHER_PRESETS[text]) return { id: text, value: CIPHER_PRESETS[text], raw: text };
      const v = text.split(':').map((s) => s.trim()).filter(Boolean).join(':');
      if (!/^[A-Z0-9_]+(:[A-Z0-9_]+)*$/.test(v)) return { error: 'cipherSuites: names joined by ":" (TLS_AES_128_GCM_SHA256:…): ' + text };
      const preset = Object.keys(CIPHER_PRESETS).find((k) => CIPHER_PRESETS[k] === v);
      return { id: preset || 'custom-' + hash6(v), value: v, raw: preset || v };
    }
    case 'fragment': {
      const parts = text.split(',').map((s) => s.trim());
      if (parts.length > 3 || !parts[0] || !(parts[0] === 'tlshello' || RANGE.test(parts[0])) || parts.slice(1).some((p) => !RANGE.test(p))) {
        return { error: 'fragment: packets,length,interval (tlshello,100-200,10-20): ' + text };
      }
      const v = parts.join(',');
      return { id: v, value: v, raw: v };
    }
    case 'finalMask': {
      if (FINALMASK_PRESETS[text]) return { id: text, value: clone(FINALMASK_PRESETS[text]), raw: text };
      let o;
      try { o = JSON.parse(text); } catch { return { error: 'finalMask: a preset name or JSON ({"tcp":[…]}): ' + text.slice(0, 40) }; }
      const keys = isObj(o) ? Object.keys(o) : [];
      if (!keys.length || keys.some((k) => !['tcp', 'udp'].includes(k)) || keys.some((k) => !Array.isArray(o[k]) || !o[k].length || !o[k].every((m) => isObj(m) && typeof m.type === 'string' && m.type))) {
        return { error: 'finalMask: an object of "tcp" and/or "udp" lists of masks, each with a "type": ' + text.slice(0, 40) };
      }
      const preset = Object.keys(FINALMASK_PRESETS).find((k) => canon(FINALMASK_PRESETS[k]) === canon(o));
      return { id: preset || 'custom-' + hash6(canon(o)), value: o, raw: preset || JSON.stringify(o) };
    }
    case 'dialMode': {
      const v = text.toLowerCase();
      // the editor's own reading (serverFields.readDialMode): oob.<byte>[,<byte>…], each 0–255
      const read = SF.readDialMode(v);
      if (!read || read.bad) {
        return { error: 'dialMode: oob.<byte>[,<byte>…], each byte 0–255 (oob.0): ' + text };
      }
      return { id: v, value: v, raw: v };
    }
    default: return { error: 'unknown dimension: ' + dimId };
  }
}

/**
 * sanitizeSpec(raw) → { dims: [{ id, values: [readValue…] }], limit, errors }
 * What the page sent: `{ dims: { fingerprint: ['chrome', …], … }, limit }`.
 * A dimension with no value left is off; a value written twice is taken once;
 * a value that does not read is an error for that value only.
 */
function sanitizeSpec(raw) {
  const r = isObj(raw) ? raw : {};
  const src = isObj(r.dims) ? r.dims : {};
  const dims = [], errors = [];
  for (const id of DIM_IDS) {
    const list = Array.isArray(src[id]) ? src[id] : [];
    const values = [], seen = new Set();
    for (const v of list.slice(0, 64)) {
      const got = readValue(id, v);
      if (got.error) { errors.push({ dim: id, value: String(typeof v === 'string' ? v : JSON.stringify(v)).slice(0, 80), msg: got.error }); continue; }
      if (seen.has(got.id)) continue;
      seen.add(got.id);
      values.push(got);
    }
    if (values.length) dims.push({ id, values });
  }
  const n = Math.floor(Number(r.limit));
  const limit = Number.isFinite(n) ? Math.min(MAX_LIMIT, Math.max(1, n)) : DEFAULT_LIMIT;
  return { dims, limit, errors };
}

/* ------------------------------- what applies ------------------------------- */

/** What a config is, in the terms the rules below read. */
function contextOf(server) {
  const ob = server && isObj(server.outbound) ? server.outbound : {};
  const proto = protocolOf(server);
  const st = isObj(ob.streamSettings) ? ob.streamSettings : {};
  const stream = STREAM.has(proto);
  const sec = stream ? String(st.security || 'none').toLowerCase() : ((proto === 'hysteria2' || proto === 'masque') ? 'tls' : 'none');
  let net = String(st.network || 'tcp').toLowerCase();
  if (net === 'raw') net = 'tcp';
  if (net === 'splithttp') net = 'xhttp';
  const so = isObj(st.sockopt) ? st.sockopt : {};
  const helper = typeof so.dialerProxy === 'string' && so.dialerProxy ? so.dialerProxy : '';
  const masqueH2 = proto === 'masque' && masqueHttpOf(st.tlsSettings) === 'h2';
  return { ob, st, proto, stream, sec, net, transport: server ? transportOf(server) : 'tcp', helper, masqueH2, json: !!server && server.source === 'json' };
}

const REASONS = {
  noTls: 'no TLS: the config sends no ClientHello to shape',
  quic: 'QUIC (Hysteria2, MASQUE over HTTP/3): uTLS shapes TCP TLS only',
  wireguard: 'WireGuard has no TLS and dials UDP',
  reality: 'REALITY: the server’s camouflage handshake has no ALPN or ciphers of its own to vary',
  masqueAlpn: 'MASQUE: its ALPN picks HTTP/2 or HTTP/3, so it is not varied',
  udp: 'UDP transport: a TCP fragment, dialMode or TCP mask does nothing here',
  helper: (t) => `this JSON config dials through its own helper outbound (${t}): its fragment and dialMode are that helper’s`,
  ownMasks: 'this protocol’s finalmask is its own (Hysteria2’s salamander, mKCP’s header, MASQUE’s quicParams): not varied',
  mux: 'mux goes on VLESS without flow, VMess and Trojan over ws or httpupgrade only (gRPC, XHTTP and H2 multiplex already)',
  xhttp: 'not an XHTTP config',
  stream: 'this protocol has no such setting'
};

/** The TLS block a fingerprint goes into, or null. */
function fpBlock(c) {
  if (c.stream && c.sec === 'tls') return c.st.tlsSettings || null;
  if (c.stream && c.sec === 'reality') return c.st.realitySettings || null;
  if (c.masqueH2) return c.st.tlsSettings || null;
  return null;
}

/**
 * applicability(server) → { [dimId]: { ok, reason?, current } }: which
 * dimensions this config takes, why not, and the value it has today (for the
 * page: "this config: chrome").
 */
function applicability(server) {
  const c = contextOf(server);
  const out = {};
  const tls = c.st.tlsSettings || {};
  const no = (reason, current) => ({ ok: false, reason, current: current == null ? '' : current });
  const yes = (current) => ({ ok: true, current: current == null ? '' : current });
  const tlsReason = () => (c.proto === 'wireguard' ? REASONS.wireguard : ((c.proto === 'hysteria2' || c.proto === 'masque') ? REASONS.quic : REASONS.noTls));

  // fingerprint
  const fpb = fpBlock(c);
  out.fingerprint = (c.stream && (c.sec === 'tls' || c.sec === 'reality')) || c.masqueH2
    ? yes(fpb && fpb.fingerprint ? fpb.fingerprint : '')
    : no(tlsReason());
  // alpn, cipherSuites: TLS over a stream protocol only
  const tlsOnly = (current) => {
    if (c.stream && c.sec === 'tls') return yes(current);
    if (c.stream && c.sec === 'reality') return no(REASONS.reality);
    if (c.proto === 'masque') return no(REASONS.masqueAlpn);
    return no(tlsReason());
  };
  out.alpn = tlsOnly(Array.isArray(tls.alpn) ? tls.alpn.join(',') : String(tls.alpn || ''));
  if (out.alpn.ok && !out.alpn.current) out.alpn.current = 'none';
  if (!out.alpn.ok && c.proto === 'masque') out.alpn.reason = REASONS.masqueAlpn;
  const cs = String(tls.cipherSuites || '');
  out.cipherSuites = tlsOnly(cs ? (Object.keys(CIPHER_PRESETS).find((k) => CIPHER_PRESETS[k] === cs) || 'custom') : 'none');
  if (!out.cipherSuites.ok && c.proto === 'masque') out.cipherSuites.reason = REASONS.stream;
  // fragment: a TCP dial the app's own dialer can make
  const fr = c.ob._fragment ? String(c.ob._fragment) : 'off';
  if (c.helper) out.fragment = no(REASONS.helper(c.helper), fr);
  else if (c.masqueH2 || (c.stream && c.transport === 'tcp')) out.fragment = yes(fr);
  else out.fragment = no(c.stream || c.proto === 'masque' || c.proto === 'hysteria2' || c.proto === 'wireguard' ? REASONS.udp : REASONS.stream, fr);
  // finalMask: the TCP masks of a stream protocol over TCP
  const fmNow = isObj(c.st.finalmask) && Object.keys(c.st.finalmask).length
    ? (Object.keys(FINALMASK_PRESETS).find((k) => canon(FINALMASK_PRESETS[k]) === canon(c.st.finalmask)) || 'custom') : 'none';
  if (c.stream && c.transport === 'tcp') out.finalMask = yes(fmNow);
  else if (c.stream || c.proto === 'hysteria2' || c.proto === 'masque') out.finalMask = no(REASONS.ownMasks, fmNow);
  else out.finalMask = no(c.proto === 'wireguard' ? REASONS.wireguard : REASONS.stream, fmNow);
  // dialMode: the outbound's own TCP dial
  const dm = isObj(c.st.sockopt) && c.st.sockopt.dialMode ? String(c.st.sockopt.dialMode) : 'none';
  if (c.helper) out.dialMode = no(REASONS.helper(c.helper), dm);
  else if (c.stream && c.transport === 'tcp') out.dialMode = yes(dm);
  else out.dialMode = no(c.stream || c.proto === 'hysteria2' || c.proto === 'masque' || c.proto === 'wireguard' ? REASONS.udp : REASONS.stream, dm);
  // mux: where the app would put it
  const muxNow = isObj(c.ob.mux) && c.ob.mux.enabled ? 'on' : 'off';
  out.mux = muxEligible(c.ob) ? yes(muxNow) : no(REASONS.mux, muxNow);
  // xhttp's mode
  out.xhttpMode = c.stream && c.net === 'xhttp'
    ? yes(String((isObj(c.st.xhttpSettings) && c.st.xhttpSettings.mode) || 'auto'))
    : no(REASONS.xhttp);
  return out;
}

/** A value that would do nothing on this config, with the reason; '' when it acts. */
function valueSkip(dimId, value, c) {
  if (dimId === 'finalMask' && value.value && c.transport === 'tcp' && !Array.isArray(value.value.tcp)) {
    return 'a UDP-only mask on a TCP transport does nothing';
  }
  return '';
}

/* ------------------------------- variants ------------------------------- */

const ORDER = new Map(DIM_IDS.map((id, i) => [id, i]));

/** "fp=hellochrome_120 · fm=tlshello · oob.0" — the dimensions in their fixed order; a dialMode names itself. */
function labelOf(values) {
  return DIM_IDS.filter((id) => values[id] !== undefined).map((id) => {
    const v = values[id];
    if (id === 'dialMode' && v !== 'none') return v;
    return `${DIM.get(id).short}=${v}`;
  }).join(' · ');
}

/** The stable key: short codes and value ids — no '|' or '#', which the row keys use. */
function keyOf(values) {
  return DIM_IDS.filter((id) => values[id] !== undefined).map((id) => `${DIM.get(id).short}=${String(values[id]).replace(/[|#\s]/g, '_')}`).join('~');
}

/**
 * buildVariants(server, spec) → { variants, dims, skippedDims, skippedValues, dropped, total, error? }
 *
 * `spec` is sanitizeSpec's. Each variant is `{ key, label, ids, raw, set }`:
 * `ids` the value id per dimension, `raw` what the page sends back for it
 * (retest, copy, save), `set` what is written. `dims` are the dimensions that
 * applied, with the values kept; `skippedDims` [{ dim, reason }] and
 * `skippedValues` [{ dim, value, reason }] what was not; `dropped` counts the
 * combinations left out (`cipher`: cipherSuites without the unsafe
 * fingerprint; `dialFragment`: a dialMode next to a fragment; `same`: a
 * combination that wrote the very config another one did). `total` is the
 * product before those drops; more than MAX_VARIANTS is `error: 'too many
 * variants'` and nothing is built.
 */
function buildVariants(server, spec) {
  const s = spec && Array.isArray(spec.dims) ? spec : sanitizeSpec(spec);
  const app = applicability(server);
  const c = contextOf(server);
  const dims = [], skippedDims = [], skippedValues = [];
  for (const d of s.dims) {
    const a = app[d.id];
    if (!a || !a.ok) { skippedDims.push({ dim: d.id, reason: (a && a.reason) || REASONS.stream }); continue; }
    const values = [];
    for (const v of d.values) {
      const why = valueSkip(d.id, v, c);
      if (why) skippedValues.push({ dim: d.id, value: v.id, reason: why }); else values.push(v);
    }
    if (values.length) dims.push({ id: d.id, values });
    else skippedDims.push({ dim: d.id, reason: skippedValues.filter((x) => x.dim === d.id).map((x) => x.reason)[0] || REASONS.stream });
  }
  const dropped = { cipher: 0, dialFragment: 0, same: 0 };
  const base = { dims, skippedDims, skippedValues, dropped };
  if (!dims.length) return Object.assign(base, { variants: [], total: 0 });
  const total = dims.reduce((p, d) => p * d.values.length, 1);
  if (total > MAX_VARIANTS) return Object.assign(base, { variants: [], total, error: 'too many variants' });

  const ownFp = (() => { const b = fpBlock(c); return b && b.fingerprint ? String(b.fingerprint) : ''; })();
  const ownFragment = !!c.ob._fragment;
  const variants = [], seen = new Set();
  const digits = new Array(dims.length).fill(0);
  for (let n = 0; n < total; n++) {
    // mixed radix, the last dimension fastest
    let rest = n;
    for (let k = dims.length - 1; k >= 0; k--) { digits[k] = rest % dims[k].values.length; rest = Math.floor(rest / dims[k].values.length); }
    const ids = {}, raw = {}, set = {};
    dims.forEach((d, k) => { const v = d.values[digits[k]]; ids[d.id] = v.id; raw[d.id] = v.raw; set[d.id] = v.value; });
    const fp = set.fingerprint !== undefined ? set.fingerprint : ownFp;
    if (set.cipherSuites && fp !== 'unsafe') { dropped.cipher++; continue; }
    const fragments = set.fragment !== undefined ? !!set.fragment : ownFragment;
    if (set.dialMode && fragments) { dropped.dialFragment++; continue; }
    const v = { key: keyOf(ids), label: labelOf(ids), ids, raw, set };
    let sig;
    try { sig = canon(applyVariant(server, v).outbound); } catch { sig = v.key; }
    if (seen.has(sig)) { dropped.same++; continue; }
    seen.add(sig);
    variants.push(v);
  }
  return Object.assign(base, { variants, total });
}

/**
 * variantFromRaw(raw) → a variant, or { error } — the page sending a row's
 * variant back (`{ fingerprint: 'chrome', finalMask: 'tlshello', … }`), read
 * again value by value: nothing it sends is written unread.
 */
function variantFromRaw(raw) {
  if (!isObj(raw)) return { error: 'no variant' };
  const ids = {}, rawOut = {}, set = {};
  let any = false;
  for (const id of DIM_IDS) {
    if (raw[id] === undefined || raw[id] === null) continue;
    const v = readValue(id, raw[id]);
    if (v.error) return { error: v.error };
    ids[id] = v.id; rawOut[id] = v.raw; set[id] = v.value;
    any = true;
  }
  if (!any) return { error: 'no variant' };
  return { key: keyOf(ids), label: labelOf(ids), ids, raw: rawOut, set };
}

/* ------------------------------- writing one ------------------------------- */

/**
 * applyVariant(server, variant) → a deep copy of `server` with the variant's
 * values written (see the header for where). Pure; a JSON config's `json`
 * gets the same main outbound (substitute.mirrorIntoJson) without the
 * `_fragment` marker, which is the app's and no core's.
 */
function applyVariant(server, variant) {
  const set = (variant && variant.set) || {};
  const out = clone(server);
  const ob = out.outbound;
  if (!isObj(ob)) return out;
  const c = contextOf(out);
  const st = isObj(ob.streamSettings) ? ob.streamSettings : (ob.streamSettings = {});
  const tlsBlock = () => (isObj(st.tlsSettings) ? st.tlsSettings : (st.tlsSettings = {}));
  for (const id of Object.keys(set)) {
    const v = set[id];
    switch (id) {
      case 'fingerprint': {
        const b = c.stream && c.sec === 'reality' ? (st.realitySettings || (st.realitySettings = {})) : tlsBlock();
        b.fingerprint = v;
        break;
      }
      case 'alpn':
        if (v) tlsBlock().alpn = v.split(','); else if (isObj(st.tlsSettings)) delete st.tlsSettings.alpn;
        break;
      case 'cipherSuites':
        if (v) tlsBlock().cipherSuites = v; else if (isObj(st.tlsSettings)) delete st.tlsSettings.cipherSuites;
        break;
      case 'fragment':
        if (v) ob._fragment = v; else delete ob._fragment;
        break;
      case 'finalMask':
        if (v) st.finalmask = clone(v); else delete st.finalmask;
        break;
      case 'dialMode':
        if (v) st.sockopt = Object.assign({}, isObj(st.sockopt) ? st.sockopt : {}, { dialMode: v });
        else if (isObj(st.sockopt)) { delete st.sockopt.dialMode; if (!Object.keys(st.sockopt).length) delete st.sockopt; }
        break;
      case 'mux':
        if (v === 'on') {
          ob.mux = Object.assign({}, MUX);
          const n = (x) => (Number.isInteger(Number(x)) && Number(x) > 0 ? Number(x) : null);
          if (n(server.muxConcurrency)) ob.mux.concurrency = n(server.muxConcurrency);
          if (n(server.xudpConcurrency)) ob.mux.xudpConcurrency = n(server.xudpConcurrency);
        } else delete ob.mux;
        break;
      case 'xhttpMode':
        st.xhttpSettings = Object.assign({}, isObj(st.xhttpSettings) ? st.xhttpSettings : {}, { mode: v });
        break;
      default: break;
    }
  }
  if (out.source === 'json' && isObj(server.outbound)) {
    mirrorIntoJson(out, server.outbound);
    for (const o of (isObj(out.json) && Array.isArray(out.json.outbounds) ? out.json.outbounds : [])) if (isObj(o)) delete o._fragment;
  }
  return out;
}

/**
 * What a share link cannot carry: dialMode and mux live in the record only
 * (the editor's local fields). A variant with either is copied as JSON.
 */
function linkLoses(variant) {
  const set = (variant && variant.set) || {};
  const out = [];
  if (set.dialMode) out.push('dialMode');
  if (set.mux === 'on') out.push('mux');
  return out;
}

/* ------------------------------- engines ------------------------------- */

/**
 * engineNeed(record, variant) → null | { engine: 'xray-pattn', since, what }
 * What core the variant's config must run on: a dialMode or the merge mask
 * (in the record, whoever wrote it) → Xray-PattN `since` 26.10.27; any other
 * finalmask the VARIANT wrote → Xray-PattN of any version. `what` names it.
 */
function engineNeed(record, variant) {
  // the app's own question (xrayManager.pattnOobNeeds), asked of this one outbound
  const what = record && isObj(record.outbound) ? pattnOobNeeds({ outbounds: [record.outbound] }) : [];
  if (what.length) return { engine: PATTN, since: PATTN_OOB_SINCE, what };
  const set = (variant && variant.set) || {};
  if (set.finalMask) return { engine: PATTN, since: '', what: ['finalmask'] };
  return null;
}

/**
 * enginesFor(need, offer) → { engines } | { reason }: the run's cores this
 * variant may use. `offer` = { engines: the run's cores, installed(id),
 * version(id) — '' when unreadable }. No need → every core of the run. A need
 * → PattN alone, when the run has it, it is installed and (for `since`) new
 * enough; else the reason, and the variant is not run at all — never on the
 * official core in its place.
 */
function enginesFor(need, offer) {
  const engines = (offer && Array.isArray(offer.engines)) ? offer.engines : [];
  if (!need) return { engines: engines.slice() };
  const what = need.what.map((w) => (w === 'dialMode' ? 'dialMode oob' : (w === 'merge' ? 'the merge mask' : 'finalmask'))).join(' and ');
  const installed = offer && typeof offer.installed === 'function' ? offer.installed(need.engine) : engines.includes(need.engine);
  if (!installed) {
    const why = need.what.includes('dialMode') ? 'the official core ignores dialMode and would dial without it' : 'the app runs it on Xray-PattN';
    return { reason: `${what} needs Xray-PattN${need.since ? ' ' + need.since + '+' : ''} — not installed (${why}); install it under Settings → Cores` };
  }
  if (!engines.includes(need.engine)) return { reason: `${what} needs Xray-PattN — tick it under Cores` };
  const v = offer && typeof offer.version === 'function' ? String(offer.version(need.engine) || '') : '';
  if (need.since && /\d+\.\d+\.\d+/.test(v) && versionBelow(v, need.since)) {
    return { reason: `Xray-PattN ${v} does not know ${what} (${need.since} and newer do) — update it under Settings → Cores` };
  }
  return { engines: [need.engine] };
}

/* ------------------------------- the product ------------------------------- */

function gcd(a, b) { while (b) { const t = a % b; a = b; b = t; } return a; }

/**
 * spread(T) → j ↦ a position in [0, T): a Weyl sequence, j × g mod T with g
 * the integer nearest T/φ that is coprime to T. Consecutive j land far apart
 * and the first k of them cover [0, T) about evenly for every k, so a sample
 * dealt in this order reaches every part of an address range, not its first
 * corner. BigInt past 2^26, where j × g would lose digits.
 */
function spread(T) {
  if (T <= 2) return (j) => j % Math.max(1, T);
  let g = Math.max(1, Math.round(T / 1.618033988749895));
  while (gcd(g, T) !== 1) g++;
  if (T < 67108864) return (j) => (j * g) % T;
  const bT = BigInt(T), bg = BigInt(g);
  return (j) => Number((BigInt(j) * bg) % bT);
}

/**
 * The variants a sample keeps when there are more of them than tests: one
 * at a time, the one whose values have been chosen least so far (each value
 * of each dimension counted), the lowest index on a tie — so every value of
 * every dimension is tested about as often as the others.
 */
function balancedPick(variants, L) {
  const dimsOf = (v) => Object.keys(v.ids).map((d) => d + '=' + v.ids[d]);
  const counts = new Map();
  const tags = variants.map(dimsOf);
  const taken = new Uint8Array(variants.length);
  const out = [];
  for (let step = 0; step < L; step++) {
    let best = -1, bestScore = Infinity;
    for (let i = 0; i < variants.length; i++) {
      if (taken[i]) continue;
      let s = 0;
      for (const t of tags[i]) s += counts.get(t) || 0;
      if (s < bestScore) { bestScore = s; best = i; if (s === 0) break; }
    }
    if (best === -1) break;
    taken[best] = 1;
    out.push(best);
    for (const t of tags[best]) counts.set(t, (counts.get(t) || 0) + 1);
  }
  return out.sort((a, b) => a - b);
}

/**
 * planTests(V, T, limit, variants?) → { size, total, sampled, at(i) → { t, v } }
 *
 * The tests a run makes out of V variants and T targets (T may be millions:
 * targets.js hands out an indexable space, nothing here lists it). Up to
 * `limit` the whole product, target by target (each target with every
 * variant next to each other — one TCP pre-check per target, one core batch
 * carrying its variants). Past `limit` an EVEN, deterministic sample, not a
 * random one — the same inputs test the same pairs on the next run, so two
 * runs compare, and no variant is left out by chance:
 *  - V ≤ limit: every variant gets ⌊limit/V⌋ targets (the first limit mod V
 *    one more), the targets dealt round-robin in spread order — every target
 *    is used before any is used twice, and each variant's targets lie across
 *    the whole range;
 *  - V > limit: `limit` variants (balancedPick: every value of every
 *    dimension about equally often), one target each, dealt the same way.
 * `variants` is needed only for the second case.
 */
function planTests(V, T, limit, variants) {
  const total = V * T;
  const L = Math.max(1, Math.min(MAX_LIMIT, Math.floor(Number(limit) || DEFAULT_LIMIT)));
  if (!V || !T) return { size: 0, total, sampled: false, at: () => null };
  if (total <= L) return { size: total, total, sampled: false, at: (i) => ({ t: Math.floor(i / V), v: i % V }) };
  const sp = spread(T);
  const ts = [], vs = [];
  if (V <= L) {
    const per = Math.floor(L / V), extra = L % V;
    let cursor = 0;
    for (let v = 0; v < V; v++) {
      const k = Math.min(T, per + (v < extra ? 1 : 0));
      for (let j = 0; j < k; j++) { ts.push(sp((cursor + j) % T)); vs.push(v); }
      cursor = (cursor + k) % T;
    }
  } else {
    const picked = balancedPick(variants || Array.from({ length: V }, (_, i) => ({ ids: { i } })), L);
    picked.forEach((v, k) => { ts.push(sp(k % T)); vs.push(v); });
  }
  // target by target, as the full product goes
  const idx = ts.map((_, i) => i).sort((a, b) => (ts[a] - ts[b]) || (vs[a] - vs[b]));
  const T2 = Float64Array.from(idx, (i) => ts[i]), V2 = Uint32Array.from(idx, (i) => vs[i]);
  return { size: T2.length, total, sampled: true, at: (i) => ({ t: T2[i], v: V2[i] }) };
}

/** The dimensions as the page lists them: id, presets or options, the ones pre-listed, `none`. */
function catalog() {
  return DIMENSIONS.map((d) => ({
    id: d.id, short: d.short, none: d.none || '', options: d.options ? d.options.slice() : null,
    presets: d.presets ? d.presets.slice() : null, start: d.start.slice()
  }));
}

module.exports = {
  DIMENSIONS, DIM_IDS, FINGERPRINTS, FINALMASK_PRESETS, CIPHER_PRESETS, PATTN_OOB_SINCE, MAX_VARIANTS, DEFAULT_LIMIT, MAX_LIMIT,
  readValue, sanitizeSpec, applicability, buildVariants, variantFromRaw, applyVariant, linkLoses, engineNeed, enginesFor,
  planTests, spread, labelOf, keyOf, catalog, canon
};
