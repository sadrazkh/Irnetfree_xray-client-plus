'use strict';
/**
 * The shell's seams: the shared API map against both bridges (the Electron
 * preload and the headless page's shim), the elevation helper behind the
 * firewall button, the upstream sync manifest, and that every file the app
 * ships parses.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..');
const { INVOKE, EVENTS, WINDOW, argOf } = require('../src/main/plus/apiMap');
const { createRunAdmin, elevatedCommand, psQuote } = require('../src/main/plus/elevate');
const { verify, missingRequires, readManifest, hashOf } = require('../scripts/sync-upstream');

/* ----------------------------- the API map ----------------------------- */

test('argOf: one argument, none, and the core picker’s two-argument calls', () => {
  assert.equal(argOf('one', ['x', 'y']), 'x');
  assert.equal(argOf('none', ['x']), undefined);
  assert.deepEqual(argOf('versions', ['xray', { prerelease: true }]), { prerelease: true, component: 'xray' });
  assert.deepEqual(argOf('install', ['xray-pattn', 'v26.10.13']), { component: 'xray-pattn', tag: 'v26.10.13' });
});

test('the preload exposes exactly the map, and invokes each channel with the argument argOf makes', async () => {
  const invoked = [], listened = [];
  let exposed = null;
  const electron = {
    contextBridge: { exposeInMainWorld: (k, v) => { assert.equal(k, 'api'); exposed = v; } },
    ipcRenderer: { invoke: async (ch, arg) => { invoked.push([ch, arg]); return 'ok'; }, on: (ch) => listened.push(ch) }
  };
  const src = fs.readFileSync(path.join(ROOT, 'src', 'preload', 'preload.js'), 'utf8');
  const req = (m) => (m === 'electron' ? electron : require(path.join(ROOT, 'src', 'preload', m)));
  new vm.Script(`(function (require) {${src}\n})`).runInThisContext()(req);
  const want = ['headless', ...Object.keys(INVOKE), ...Object.keys(EVENTS), ...Object.keys(WINDOW)].sort();
  assert.deepEqual(Object.keys(exposed).sort(), want);
  await exposed.coreVersions('xray', { prerelease: false });
  await exposed.scanStart({ ipsText: '1.1.1.1' });
  await exposed.init();
  assert.deepEqual(invoked, [['cores:versions', { prerelease: false, component: 'xray' }], ['scan:start', { ipsText: '1.1.1.1' }], ['app:init', undefined]]);
  exposed.onScanProgress(() => {});
  assert.deepEqual(listened, ['scan-progress']);
});

test('the headless shim offers the same methods, over /rpc with the token, and window controls are no-ops', async () => {
  const calls = [];
  const window = {
    __PLUS_API__: JSON.parse(JSON.stringify({ INVOKE, EVENTS, WINDOW })),
    open: (u) => calls.push(['open', u])
  };
  const ctx = {
    window, location: { search: '?token=abc' },
    sessionStorage: { getItem: () => null, setItem: () => {} },
    URLSearchParams,
    fetch: async (url, init) => { calls.push(['fetch', url, JSON.parse(init.body)]); return { json: async () => ({ result: 42 }) }; },
    EventSource: function EventSource(url) { calls.push(['sse', url]); }
  };
  vm.runInNewContext(fs.readFileSync(path.join(ROOT, 'src', 'server', 'web-api.js'), 'utf8'), ctx);
  const api = window.api;
  assert.equal(api.headless, true);
  const want = ['headless', ...Object.keys(INVOKE), ...Object.keys(EVENTS), ...Object.keys(WINDOW)].sort();
  assert.deepEqual(Object.keys(api).sort(), want);
  assert.equal(await api.installCoreVersion('xray', 'v26.10.10'), 42);
  await api.winClose();
  await api.openExternal('https://github.com/x');
  await api.openExternal('javascript:alert(1)');
  assert.deepEqual(calls, [
    ['sse', 'events?token=abc'],
    ['fetch', 'rpc?token=abc', { channel: 'cores:install', arg: { component: 'xray', tag: 'v26.10.10' } }],
    ['open', 'https://github.com/x']
  ]);
});

test('every window.api method the pages call is in the map', () => {
  const dir = path.join(ROOT, 'src', 'renderer');
  const files = ['app.js', 'corePicker.js', ...fs.readdirSync(path.join(dir, 'plus')).filter(f => f.endsWith('.js')).map(f => 'plus/' + f)];
  const known = new Set([...Object.keys(INVOKE), ...Object.keys(EVENTS), ...Object.keys(WINDOW), 'headless']);
  const unknown = [];
  for (const f of files) {
    const src = fs.readFileSync(path.join(dir, f), 'utf8');
    for (const m of src.matchAll(/window\.api\.([A-Za-z]+)\s*\(/g)) if (!known.has(m[1]) && !['onStatus', 'onXrayStatus', 'assetsStatus'].includes(m[1])) unknown.push(`${f}: ${m[1]}`);
  }
  assert.deepEqual(unknown, []);
});

/* ----------------------------- elevation ----------------------------- */

test('elevatedCommand quotes every argument as a PowerShell literal and returns netsh’s exit code', () => {
  assert.equal(psQuote("it's"), "'it''s'");
  const cmd = elevatedCommand('netsh', ['advfirewall', 'firewall', 'add', 'rule', "name=IRNetFree Plus in'x"]);
  assert.equal(cmd, "$p = Start-Process -FilePath 'netsh' -ArgumentList @('advfirewall','firewall','add','rule','name=IRNetFree Plus in''x') -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode");
});

test('runAdmin: tried as is first; asked again through UAC only when Windows says it needs elevation', async () => {
  const runs = [];
  const exec = (answers) => (bin, args, opts, cb) => { runs.push([bin, args[args.length - 1]]); const a = answers.shift(); cb(a.err ? Object.assign(new Error(a.err), { code: 1 }) : null, a.stdout || '', a.stderr || ''); };

  const fine = createRunAdmin({ platform: 'win32', execFile: exec([{ stdout: 'Ok.' }]) });
  assert.deepEqual(await fine('netsh', ['x']), { err: null, stdout: 'Ok.', stderr: '', elevated: false });

  runs.length = 0;
  const elevate = createRunAdmin({ platform: 'win32', execFile: exec([{ err: 'Command failed', stdout: 'The requested operation requires elevation (Run as administrator).' }, { stdout: '' }]) });
  const r = await elevate('netsh', ['advfirewall']);
  assert.equal(r.err, null);
  assert.equal(r.elevated, true);
  assert.equal(runs[1][0], 'powershell.exe');
  assert.match(runs[1][1], /Start-Process -FilePath 'netsh'/);

  const declined = createRunAdmin({ platform: 'win32', execFile: exec([{ err: 'x', stdout: 'requires elevation' }, { err: 'x', stderr: 'This command cannot be run due to the error: The operation was canceled by the user.' }]) });
  assert.equal((await declined('netsh', ['a'])).err.message, 'the administrator prompt was declined');

  runs.length = 0;
  const other = createRunAdmin({ platform: 'win32', execFile: exec([{ err: 'x', stdout: 'The syntax supplied for this command is not valid.' }]) });
  assert.ok((await other('netsh', ['bad'])).err, 'any other failure is reported as it is');
  assert.equal(runs.length, 1, 'and not retried elevated');

  const linux = createRunAdmin({ platform: 'linux', execFile: exec([{ err: 'x', stdout: 'requires elevation' }]) });
  assert.equal((await linux('netsh', ['a'])).elevated, false);
});

/* ----------------------------- the upstream sync ----------------------------- */

test('every synced file is exactly the upstream one the manifest records, and every require() resolves', () => {
  const m = readManifest();
  assert.ok(Object.keys(m.files).length >= 25);
  assert.match(m.ref, /^v\d+\.\d+\.\d+/);
  assert.match(m.commit, /^[0-9a-f]{40}$/);
  assert.deepEqual(verify(m), [], 'a synced file was edited — wrap it instead (docs/SYNC.md)');
  assert.deepEqual(missingRequires(), []);
});

test('hashOf ignores line endings, so a CRLF checkout matches', () => {
  assert.equal(hashOf('a\r\nb\r\n'), hashOf('a\nb\n'));
  assert.notEqual(hashOf('a\nb'), hashOf('a\nc'));
});

/* ----------------------------- every shipped file parses ----------------------------- */

test('every .js under src/ and scripts/ parses', () => {
  const bad = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.js')) {
        const src = fs.readFileSync(p, 'utf8').replace(/^#!.*/, '');
        try { new vm.Script(`(function (exports, require, module, __filename, __dirname) {${src}\n})`, { filename: p }); }
        catch (err) { bad.push(`${path.relative(ROOT, p)}: ${err.message}`); }
      }
    }
  };
  walk(path.join(ROOT, 'src'));
  walk(path.join(ROOT, 'scripts'));
  assert.deepEqual(bad, []);
});
