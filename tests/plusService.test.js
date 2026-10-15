'use strict';
/**
 * The one service behind both front ends (src/main/plus/service.js) and the
 * configs list (src/main/plus/configs.js), against a temp data folder and a
 * fake downloader — no core is started, nothing reaches the network.
 *
 * What matters: the channels the page calls exist; settings keep only what
 * Plus knows and leave a v2 store's client keys alone; configs come in from
 * pasted text, from a scan and from IRNetFree's own store (read-only, re-import
 * updates in place); a v2 store's configs, server model and scan memory carry
 * over; and the update check says newer or not without installing anything.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createPlusService, cmpVersion, DEFAULT_SETTINGS } = require('../src/main/plus/service');
const { createConfigs, irnetfreeStorePath } = require('../src/main/plus/configs');
const { INVOKE } = require('../src/main/plus/apiMap');
const F = require('./fixtures');

const VLESS = 'vless://b170ff6b-e6c0-4a79-ae5b-fca1187c2075@example.com:443?type=ws&security=tls&sni=example.com&host=example.com&path=%2Fws#probe-ws';
const HY2 = 'hy2://pass@h.example.com:443?sni=h.example.com#probe-hy2';

function tmpDir(t) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-plus-svc-'));
  t.after(() => { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* a lazy write closing */ } });
  return d;
}

function fakeDownloader(over = {}) {
  return (opts) => Object.assign({
    opts,
    fetchJSON: async () => ({ tag_name: 'v3.1.0', html_url: 'https://github.com/x/y/releases/tag/v3.1.0' }),
    latestVersion: async () => '26.10.10',
    download: async (id) => ({ files: [id] }),
    listReleases: async () => ({ releases: [], latestTag: '', fetchedAt: 0 })
  }, over);
}

function service(t, opts = {}) {
  const dataDir = opts.dataDir || tmpDir(t);
  const events = [];
  const s = createPlusService(Object.assign({
    dataDir, version: '3.0.0', platform: 'linux', send: (ch, p) => events.push([ch, p]),
    deps: Object.assign({ downloader: fakeDownloader(), runAdmin: async () => ({ err: null, stdout: '', stderr: '' }) }, opts.deps)
  }, opts.over));
  t.after(() => s.shutdown());
  return { s, events, dataDir };
}

test('every channel the page calls is one the service answers (the Electron window adds win:* itself; the headless server app:quit)', (t) => {
  const { s } = service(t);
  for (const [name, [channel]] of Object.entries(INVOKE)) assert.ok(s.has(channel), `${name} → ${channel}`);
});

test('app:init — the version, the platform, the settings with defaults, the configs, the cores, the data folder', async (t) => {
  const { s, dataDir } = service(t);
  const init = await s.invoke('app:init');
  assert.deepEqual(Object.keys(init).sort(), ['assets', 'dataDir', 'engines', 'isElectron', 'platform', 'repo', 'servers', 'settings', 'version', 'xrayReady']);
  assert.equal(init.version, '3.0.0');
  assert.equal(init.repo, 'sadrazkh/Irnetfree_xray-client-plus');
  assert.deepEqual(init.settings, DEFAULT_SETTINGS);
  assert.deepEqual(init.servers, []);
  assert.equal(init.dataDir, dataDir);
  assert.deepEqual(init.engines.map(e => e.id), ['xray', 'xray-pattn']);
  assert.deepEqual(Object.keys(init.assets).sort(), ['geoip', 'geosite', 'xray', 'xray-pattn']);
});

test('settings:set keeps only what Plus knows, cleaned; a v2 store’s client settings stay in the file untouched', async (t) => {
  const dataDir = tmpDir(t);
  fs.writeFileSync(path.join(dataDir, 'store.json'), JSON.stringify({ settings: { lang: 'en', socksPort: 10818, routingMode: 'bypass-ir' }, servers: [] }));
  const { s } = service(t, { dataDir });
  assert.deepEqual(await s.invoke('settings:get'), Object.assign({}, DEFAULT_SETTINGS, { lang: 'en' }));
  const next = await s.invoke('settings:set', { theme: 'light', skin: 'nope', lang: 'xx', openAtLogin: 1, socksPort: 1 });
  assert.deepEqual(next, { lang: 'fa', theme: 'light', skin: 'console', openAtLogin: true });
  const raw = s.store.get('settings');
  assert.equal(raw.socksPort, 10818, 'the client’s key is left as it was');
  assert.equal(raw.routingMode, 'bypass-ir');
});

test('configs: pasted links come in, bad lines are counted, a removal drops exactly the ids named', async (t) => {
  const { s } = service(t);
  const a = await s.invoke('configs:add', `${VLESS}\n${HY2}\nvmess://%%%`);
  assert.equal(a.added.length, 2);
  assert.equal(a.errors.length, 1);
  assert.deepEqual(a.servers.map(x => x.protocol), ['vless', 'hysteria2']);
  assert.ok(a.servers.every(x => x.id && x.raw && x.outbound), 'whole records, each with an id and its link');
  const gone = await s.invoke('configs:remove', [a.servers[0].id, 'not-there']);
  assert.equal(gone.removed, 1);
  assert.deepEqual(gone.servers.map(x => x.name), ['probe-hy2']);
  assert.equal((await s.invoke('configs:add', 'nothing to see')).added.length, 0);
});

test('configs: a v2 store’s configs, server model and scan memory carry over unchanged', async (t) => {
  const dataDir = tmpDir(t);
  const v2 = { servers: [F.VLESS_WS_TLS], xserver: { schema: 2, inbounds: [] }, scan: { ipsText: '1.1.1.1' }, scanTested: [16843009] };
  fs.writeFileSync(path.join(dataDir, 'store.json'), JSON.stringify(v2));
  const { s } = service(t, { dataDir });
  assert.deepEqual((await s.invoke('configs:list')).map(x => x.id), ['sv-vless']);
  assert.equal((await s.invoke('scan:presets')).last.ipsText, '1.1.1.1');
  assert.equal((await s.invoke('scan:presets')).tested, 1, 'the v2.2 integer history is read');
  assert.equal(s.store.get('xserver').schema, 2);
});

test('configs: IRNetFree’s store is read, never written; a second import replaces the same config in place', async (t) => {
  const dataDir = path.join(tmpDir(t), 'irnetfree-plus');
  fs.mkdirSync(dataDir);
  const file = path.join(path.dirname(dataDir), 'irnetfree', 'store.json');
  fs.mkdirSync(path.dirname(file));
  const theirs = { servers: [Object.assign({}, F.VLESS_WS_TLS, { subId: 's1' }), F.TROJAN_TCP_TLS], subscriptions: [{ id: 's1', name: 'My sub' }] };
  fs.writeFileSync(file, JSON.stringify(theirs));
  const before = fs.readFileSync(file, 'utf8');
  const { s } = service(t, { dataDir });
  const r = await s.invoke('configs:import', {});
  assert.deepEqual([r.added, r.updated, r.total, r.path], [2, 0, 2, file]);
  assert.equal(fs.readFileSync(file, 'utf8'), before, 'IRNetFree’s file is untouched');
  const list = r.servers;
  assert.deepEqual(list.map(x => [x.importedFrom, x.importedId, x.importedSub]), [['irnetfree', 'sv-vless', 'My sub'], ['irnetfree', 'sv-trojan', '']]);
  assert.ok(list.every(x => x.id !== x.importedId), 'Plus gives them its own ids');

  theirs.servers[0].name = 'renamed by the subscription';
  fs.writeFileSync(file, JSON.stringify(theirs));
  const again = await s.invoke('configs:import', {});
  assert.deepEqual([again.added, again.updated], [0, 2]);
  assert.equal(again.servers.length, 2);
  assert.equal(again.servers[0].name, 'renamed by the subscription');
  assert.equal(again.servers[0].id, list[0].id, 'the same Plus id, in the same place');

  const none = await s.invoke('configs:import', { path: path.join(dataDir, 'nope.json') });
  assert.equal(none.error, 'not found');
});

test('irnetfreeStorePath: beside a desktop Plus, else the OS’s app-data folder', () => {
  assert.equal(irnetfreeStorePath(path.join('A', 'AppData', 'Roaming', 'irnetfree-plus')), path.join('A', 'AppData', 'Roaming', 'irnetfree', 'store.json'));
  assert.equal(irnetfreeStorePath('/srv/plus', { APPDATA: 'C:\\U\\AppData\\Roaming' }, 'win32', 'C:\\U'), path.join('C:\\U\\AppData\\Roaming', 'irnetfree', 'store.json'));
  assert.equal(irnetfreeStorePath('/srv/plus', {}, 'darwin', '/Users/u'), path.join('/Users/u', 'Library', 'Application Support', 'irnetfree', 'store.json'));
  assert.equal(irnetfreeStorePath('/srv/plus', { XDG_CONFIG_HOME: '/x' }, 'linux', '/home/u'), path.join('/x', 'irnetfree', 'store.json'));
  assert.equal(irnetfreeStorePath('/srv/plus', {}, 'linux', '/home/u'), path.join('/home/u', '.config', 'irnetfree', 'store.json'));
});

test('a scan’s winning row goes into the configs through the same list (scan:apply → configs)', async (t) => {
  const { s } = service(t);
  const a = await s.invoke('configs:add', VLESS);
  const id = a.servers[0].id;
  const r = await s.invoke('scan:apply', { serverId: id, addr: '104.16.0.9', port: 2053 });
  assert.equal(r.error, undefined, JSON.stringify(r));
  assert.match(r.name, /\[104\.16\.0\.9:2053\]$/);
  assert.equal((await s.invoke('configs:list')).length, 2);
});

test('assets:download takes the cores and the geo files only; a core is not swapped while the server runs on it', async (t) => {
  const { s } = service(t);
  assert.deepEqual(await s.invoke('assets:download', 'tun2socks'), { ok: false, error: 'unknown component: tun2socks' });
  const ok = await s.invoke('assets:download', 'xray');
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.files, ['xray']);
});

test('app:checkUpdate says newer or not, with the release page — it never downloads', async (t) => {
  const { s } = service(t);
  assert.deepEqual(await s.invoke('app:checkUpdate'), { ok: true, current: '3.0.0', latest: '3.1.0', newer: true, url: 'https://github.com/x/y/releases/tag/v3.1.0' });
  const same = service(t, { deps: { downloader: fakeDownloader({ fetchJSON: async () => ({ tag_name: 'v3.0.0' }) }) } });
  assert.equal((await same.s.invoke('app:checkUpdate')).newer, false);
  const off = service(t, { deps: { downloader: fakeDownloader({ fetchJSON: async () => { throw new Error('offline'); } }) } });
  assert.deepEqual(await off.s.invoke('app:checkUpdate'), { ok: false, error: 'offline' });
});

test('the log keeps the newest lines, goes out as events, and clears', async (t) => {
  const { s, events } = service(t);
  for (let i = 0; i < 520; i++) s.log('line ' + i, i % 2 ? 'info' : 'warn');
  const lines = await s.invoke('log:get');
  assert.equal(lines.length, 500);
  assert.equal(lines[0].line, 'line 20');
  assert.ok(events.filter(e => e[0] === 'log').length >= 520);
  await s.invoke('log:clear');
  assert.deepEqual(await s.invoke('log:get'), []);
});

test('an unknown channel is a rejection, not a crash', async (t) => {
  const { s } = service(t);
  await assert.rejects(s.invoke('connect', 'x'), /unknown channel: connect/);
});

test('cmpVersion', () => {
  assert.equal(cmpVersion('3.0.0', '2.10.1'), 1);
  assert.equal(cmpVersion('v2.9.0', '2.10.0'), -1);
  assert.equal(cmpVersion('3.0.0', 'v3.0.0'), 0);
  assert.equal(cmpVersion('', '0.0.1'), -1);
});

test('createConfigs on its own: addServer keeps a record whole and gives it an id when it has none', () => {
  const data = {};
  const store = { get: (k, d) => (k in data ? data[k] : d), set: (k, v) => { data[k] = v; return true; } };
  const c = createConfigs({ store, dataDir: os.tmpdir() });
  const rec = c.addServer(Object.assign({}, F.VLESS_WS_TLS, { id: '' }));
  assert.match(rec.id, /^sv-[0-9a-f]{12}$/);
  assert.equal(c.find(rec.id).address, 'a.example.com');
  const dup = c.addServer(Object.assign({}, F.VLESS_WS_TLS, { id: rec.id }));
  assert.notEqual(dup.id, rec.id, 'a taken id is replaced');
});
