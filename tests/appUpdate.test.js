'use strict';
/**
 * In-app update: the right installer for this machine, and a checksum that
 * has to match before anything is opened.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pickUpdateAsset, parseSha256Sums, sha256File } = require('../src/main/appUpdate');

// plus: the artifact names carry "Plus" (package.json → build), so these are
// the names a Plus release publishes.
const assets = [
  { name: 'IRNetFree-Plus-Setup-2.1.0.exe', browser_download_url: 'u1', size: 1 },
  { name: 'IRNetFree-Plus-Portable-2.1.0.exe', browser_download_url: 'u2', size: 2 },
  { name: 'IRNetFree-Plus-2.1.0-arm64.dmg', browser_download_url: 'u3', size: 3 },
  { name: 'IRNetFree-Plus-2.1.0-x64.dmg', browser_download_url: 'u4', size: 4 },
  { name: 'IRNetFree-Plus-2.1.0.AppImage', browser_download_url: 'u5', size: 5 },
  { name: 'IRNetFree-2.1.0.apk', browser_download_url: 'u6', size: 6 },
  { name: 'SHA256SUMS-windows-latest.txt', browser_download_url: 'u7', size: 7 }
];

test('pickUpdateAsset: the installer for this platform and arch, never the portable or the APK', () => {
  assert.equal(pickUpdateAsset(assets, 'win32', 'x64').name, 'IRNetFree-Plus-Setup-2.1.0.exe');
  assert.equal(pickUpdateAsset(assets, 'darwin', 'arm64').name, 'IRNetFree-Plus-2.1.0-arm64.dmg');
  assert.equal(pickUpdateAsset(assets, 'darwin', 'x64').name, 'IRNetFree-Plus-2.1.0-x64.dmg');
  assert.equal(pickUpdateAsset(assets, 'linux', 'x64').name, 'IRNetFree-Plus-2.1.0.AppImage');
  assert.equal(pickUpdateAsset([], 'win32', 'x64'), null);
  assert.equal(pickUpdateAsset(null, 'win32', 'x64'), null);
});

// The two apps live side by side: an installer of the ORIGINAL app must never
// be offered as an update for Plus, or an "update" would replace the other app.
test('pickUpdateAsset: the original IRNetFree assets are not installers for Plus', () => {
  const original = [
    { name: 'IRNetFree-Setup-1.6.0.exe', browser_download_url: 'o1', size: 1 },
    { name: 'IRNetFree-1.6.0-x64.dmg', browser_download_url: 'o2', size: 2 },
    { name: 'IRNetFree-1.6.0.AppImage', browser_download_url: 'o3', size: 3 }
  ];
  assert.equal(pickUpdateAsset(original, 'win32', 'x64'), null);
  assert.equal(pickUpdateAsset(original, 'darwin', 'x64'), null);
  assert.equal(pickUpdateAsset(original, 'linux', 'x64'), null);
});

test('parseSha256Sums and sha256File agree; malformed lines are ignored; names keep their case', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-upd-'));
  try {
    const f = path.join(dir, 'IRNetFree-Setup-1.6.0.exe');
    fs.writeFileSync(f, 'hello');
    const sums = parseSha256Sums([
      '2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824 *IRNetFree-Setup-1.6.0.exe',
      'abc  b.bin',
      '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  IRNetFree-1.6.0-x64.dmg',
      ''
    ].join('\n'));
    assert.equal(await sha256File(f), sums['IRNetFree-Setup-1.6.0.exe']);
    assert.equal(sums['IRNetFree-1.6.0-x64.dmg'], '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    assert.equal(sums['b.bin'], undefined, 'not a sha256');
    assert.deepEqual(parseSha256Sums(''), {});
    await assert.rejects(sha256File(path.join(dir, 'missing')), /ENOENT/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * plus: the release pipeline's own contract, checked without a runner.
 *
 * The in-app updater matches release assets by name, electron-builder names
 * them from package.json, and the workflow both publishes them and writes the
 * sums. Nothing connects those three, and a mismatch only shows on a real
 * release: upstream shipped one whose Windows installers were missing because
 * this part of the pipeline failed unnoticed.
 */
const render = (pattern, version, arch, ext) => pattern
  .replace('${version}', version)
  .replace('${arch}', arch)
  .replace('${ext}', ext);

test('plus: electron-builder\'s artifact names are the names the updater looks for', () => {
  const build = require('../package.json').build;
  const v = '2.3.4';
  const setup = render(build.nsis.artifactName, v, '', 'exe');
  const dmgX64 = render(build.dmg.artifactName, v, 'x64', 'dmg');
  const dmgArm = render(build.dmg.artifactName, v, 'arm64', 'dmg');
  const appImage = render(build.linux.artifactName, v, 'x86_64', 'AppImage');
  const assets = [setup, dmgX64, dmgArm, appImage].map((name) => ({ name }));

  assert.equal(pickUpdateAsset(assets, 'win32', 'x64').name, setup);
  assert.equal(pickUpdateAsset(assets, 'darwin', 'x64').name, dmgX64);
  assert.equal(pickUpdateAsset(assets, 'darwin', 'arm64').name, dmgArm);
  assert.equal(pickUpdateAsset(assets, 'linux', 'x64').name, appImage);
});

test('plus: the release workflow publishes every asset the updater reads, and its checksums cannot sink a build', () => {
  const yml = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'release.yml'), 'utf8');
  for (const glob of ['dist/*.exe', 'dist/*.dmg', 'dist/*.AppImage', 'dist/*.deb', 'dist/SHA256SUMS-*.txt']) {
    assert.ok(yml.includes(glob), 'the release does not publish ' + glob);
  }
  const step = yml.slice(yml.indexOf('- name: Checksums'), yml.indexOf('- name: Upload build artifacts'));
  assert.match(step, /continue-on-error:\s*true/, 'a failed checksum step must not cost the installers');
  assert.match(step, /command -v sha256sum/, 'prefer the hasher that is always on the Windows runner');
  assert.match(step, /shopt -s nullglob/, 'an unmatched pattern must not reach the hasher');
  assert.ok(step.includes('SHA256SUMS-${{ matrix.os }}.txt'), 'one sums file per runner');
});
