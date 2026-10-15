'use strict';
/**
 * plus: the configs list — what the Scan tab dials and the Server tab's exits
 * point at. Stored under `servers`, the key Plus v2 (and IRNetFree) used, so a
 * v2 store keeps its configs. Records are upstream's own shape (parser.js).
 *
 * Three ways in: text pasted or read from a file (links, a subscription body,
 * a JSON config, a WireGuard .conf — parser.parseMany reads them all), a
 * winning scan row ("save to configs"), and a read-only import of the configs
 * IRNetFree itself holds on this machine. Nothing here talks to the network.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { parseMany, buildShareLink, migrateStoredServer } = require('../parser');

const STORE_KEY = 'servers';
const IMPORTED_SOURCE = 'irnetfree';

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const newId = () => 'sv-' + crypto.randomBytes(6).toString('hex');

/** A stored record as the list shows it: no keys, no outbound — those stay in main. */
function summary(s) {
  return {
    id: s.id, name: s.name || '', protocol: s.protocol || (s.outbound && s.outbound.protocol) || '',
    address: s.address || '', port: s.port || 0, source: s.source === 'json' ? 'json' : (s.importedFrom || 'manual'),
    sub: s.importedSub || ''
  };
}

/**
 * The store file of IRNetFree on this machine. The desktop Plus keeps its data
 * beside IRNetFree's (`irnetfree-plus` next to `irnetfree` in the OS's app-data
 * folder); a headless Plus keeps it anywhere, so then the OS's own app-data
 * folder is asked: %APPDATA% on Windows, Application Support on macOS,
 * $XDG_CONFIG_HOME or ~/.config elsewhere.
 */
function irnetfreeStorePath(plusDataDir, env = process.env, platform = process.platform, home = os.homedir()) {
  if (path.basename(String(plusDataDir || '')).toLowerCase() === 'irnetfree-plus') {
    return path.join(path.dirname(plusDataDir), 'irnetfree', 'store.json');
  }
  const appData = platform === 'win32' ? (env.APPDATA || path.join(home, 'AppData', 'Roaming'))
    : platform === 'darwin' ? path.join(home, 'Library', 'Application Support')
      : (env.XDG_CONFIG_HOME || path.join(home, '.config'));
  return path.join(appData, 'irnetfree', 'store.json');
}

/**
 * createConfigs({ store, dataDir, log, readFile }) → { list, all, find, add, addServer, remove, importIrnetfree }
 * `readFile` is the tests' seam for the IRNetFree store.
 */
function createConfigs({ store, dataDir, log = () => {}, readFile = (p) => fs.readFileSync(p, 'utf8') }) {
  const all = () => {
    const list = store.get(STORE_KEY, []);
    return Array.isArray(list) ? list.filter(s => isObj(s) && s.id && isObj(s.outbound)) : [];
  };
  const save = (list) => store.set(STORE_KEY, list);
  const find = (id) => all().find(s => s.id === id) || null;

  /** One record in, made safe to keep: a fresh id when it has none or one already taken, its share link rebuilt when it has none. */
  function keep(list, rec, extra) {
    let s;
    try { s = migrateStoredServer(JSON.parse(JSON.stringify(rec))); } catch { s = JSON.parse(JSON.stringify(rec)); }
    Object.assign(s, extra || {});
    if (!s.id || list.some(x => x.id === s.id)) s.id = newId();
    if (!s.raw) { try { s.raw = buildShareLink(s); } catch { /* a JSON config shares as itself */ } }
    list.push(s);
    return s;
  }

  /** Pasted text → { added: [summary], errors: [{ line, error }] }. */
  function add(text) {
    const parsed = parseMany(String(text || ''));
    const list = all();
    const added = [];
    for (const s of parsed.servers || []) added.push(summary(keep(list, s)));
    if (added.length) save(list);
    if (added.length) log(`Configs: ${added.length} added`, 'info');
    return { added, errors: parsed.errors || [] };
  }

  /** A whole record (a scan's winning row). */
  function addServer(rec) {
    const list = all();
    const s = keep(list, rec);
    save(list);
    return s;
  }

  function remove(ids) {
    const drop = new Set(Array.isArray(ids) ? ids : [ids]);
    const list = all();
    const next = list.filter(s => !drop.has(s.id));
    if (next.length !== list.length) save(next);
    return { removed: list.length - next.length };
  }

  /**
   * Read-only: the configs IRNetFree holds here, added once each. A config
   * imported before (same IRNetFree id) is replaced by its current form, so
   * a second import picks up what the client's subscriptions updated.
   */
  function importIrnetfree(opts = {}) {
    const file = opts.path || irnetfreeStorePath(dataDir);
    let data;
    try { data = JSON.parse(readFile(file)); } catch (e) {
      return { error: e && e.code === 'ENOENT' ? 'not found' : 'unreadable', path: file };
    }
    const theirs = Array.isArray(data && data.servers) ? data.servers.filter(s => isObj(s) && s.id && isObj(s.outbound)) : [];
    const subs = new Map((Array.isArray(data && data.subscriptions) ? data.subscriptions : []).filter(isObj).map(x => [x.id, x.name || '']));
    let list = all();
    let added = 0, updated = 0;
    for (const s of theirs) {
      const extra = { importedFrom: IMPORTED_SOURCE, importedId: s.id, importedSub: s.subId ? (subs.get(s.subId) || '') : '' };
      const at = list.findIndex(x => x.importedFrom === IMPORTED_SOURCE && x.importedId === s.id);
      if (at !== -1) {
        const keepId = list[at].id;
        list = list.filter((x, i) => i !== at);
        const rec = keep(list, Object.assign({}, s, { id: keepId }), extra);
        // keep() appends: put it back where it was
        list.splice(list.indexOf(rec), 1);
        list.splice(at, 0, rec);
        updated++;
      } else {
        keep(list, Object.assign({}, s, { id: '' }), extra);
        added++;
      }
    }
    if (added || updated) save(list);
    log(`Configs: imported from IRNetFree — ${added} new, ${updated} updated (${file})`, 'info');
    return { added, updated, total: theirs.length, path: file };
  }

  // the window gets whole records: the Server tab builds its exits' pickers from them, as it did in v2
  return { list: all, all, find, add, addServer, remove, importIrnetfree };
}

module.exports = { createConfigs, irnetfreeStorePath, summary };
