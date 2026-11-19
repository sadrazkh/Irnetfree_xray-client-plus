'use strict';
/**
 * The GitHub Pages site (site/, scripts/build-site.js, .github/workflows/pages.yml), the same design as
 * IRNetFree's own site.
 *
 * Built into a temp folder with a made-up release, no network: every local link and image resolves, the Persian
 * and English pages keep the same sections, nothing loads from another host, the download buttons find their
 * files among a release's real asset names, and the guide anchors are ones the README already uses.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const site = require('../scripts/build-site.js');
const page = require('../site/assets/site.js');

const ROOT = path.join(__dirname, '..');
const BASE = '/Irnetfree_xray-client-plus/';

// The asset names of v3.3.3, as release.yml publishes them (the zips carry the product name, with a dot).
const ASSETS = [
  'IRNetFree-Plus-3.3.3-amd64.deb', 'IRNetFree-Plus-3.3.3-arm64.dmg', 'IRNetFree-Plus-3.3.3-x64.dmg',
  'IRNetFree-Plus-3.3.3-x86_64.AppImage', 'IRNetFree-Plus-Portable-3.3.3.exe', 'IRNetFree-Plus-Setup-3.3.3.exe',
  'IRNetFree.Plus-3.3.3-arm64-mac.zip', 'IRNetFree.Plus-3.3.3-mac.zip',
  'SHA256SUMS-macos-latest.txt', 'SHA256SUMS-ubuntu-latest.txt', 'SHA256SUMS-windows-latest.txt',
];
const API_BODY = {
  tag_name: 'v3.3.3', published_at: '2026-11-08T12:51:07Z', html_url: 'https://github.com/sadrazkh/Irnetfree_xray-client-plus/releases/tag/v3.3.3',
  assets: ASSETS.map((name, i) => ({ name, size: 1000 + i, browser_download_url: `https://github.com/sadrazkh/Irnetfree_xray-client-plus/releases/download/v3.3.3/${name}` })),
};

let out;
let files;
test.before(() => {
  out = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-plus-site-'));
  files = site.build(out, page.slimRelease(API_BODY));
});
test.after(() => { fs.rmSync(out, { recursive: true, force: true }); });

const read = (p) => fs.readFileSync(path.join(out, p), 'utf8');
const HTML = ['index.html', 'en/index.html', '404.html'];
const attrs = (html, name) => [...html.matchAll(new RegExp(`\\s${name}="([^"]*)"`, 'g'))].map((m) => m[1]);
const ids = (html) => new Set(attrs(html, 'id'));

test('the build holds the pages, the assets, the screenshots and the generated files', () => {
  for (const f of [...HTML, 'assets/site.css', 'assets/site.js', 'assets/icons.svg', 'assets/og.png', 'assets/logo.svg',
    'assets/icon.png', 'release.json', 'robots.txt', 'sitemap.xml',
    'shots/scan.png', 'shots/results.png', 'shots/params.png', 'shots/server.png', 'shots/reverse.png', 'shots/configs.png']) {
    assert.ok(files.includes(f), `${f} is not in the build`);
  }
  assert.ok(!files.some((f) => /(^|\/)_/.test(f)), 'a source file starting with "_" was published');
  const rel = JSON.parse(read('release.json'));
  assert.equal(rel.tag, 'v3.3.3');
  assert.equal(rel.version, '3.3.3');
  assert.equal(rel.assets.length, ASSETS.length);
  assert.ok(read('sitemap.xml').includes('https://sadrazkh.github.io/Irnetfree_xray-client-plus/en/'));
});

test('every local link, image, script and stylesheet resolves inside the build', () => {
  for (const p of HTML) {
    const html = read(p);
    const dir = path.posix.dirname(p);
    for (const ref of [...attrs(html, 'href'), ...attrs(html, 'src')]) {
      if (/^(https?:|mailto:)/.test(ref)) continue;
      const [file, frag] = ref.split('#');
      if (!file) { // a link inside the page
        if (frag) assert.ok(ids(html).has(frag), `${p}: #${frag} has no element`);
        continue;
      }
      let target = file.startsWith(BASE) ? file.slice(BASE.length) : path.posix.normalize(path.posix.join(dir, file));
      if (target === '.' || target === '') target = 'index.html';
      if (target.endsWith('/')) target += 'index.html';
      if (!path.posix.extname(target)) target += '/index.html';
      target = path.posix.normalize(target).replace(/^\.\//, '');
      assert.ok(files.includes(target), `${p}: ${ref} → ${target} is not in the build`);
      if (frag && target.endsWith('.svg')) assert.ok(read(target).includes(`id="${frag}"`), `${p}: ${ref} names no symbol`);
      else if (frag) assert.ok(ids(read(target)).has(frag), `${p}: ${ref} → no #${frag} there`);
    }
  }
});

test('nothing on the pages loads from another host (fonts, scripts, styles, images)', () => {
  for (const p of HTML) {
    const html = read(p);
    for (const m of html.matchAll(/<(script|img|link|iframe|source|video|audio)\b[^>]*>/g)) {
      const tag = m[0];
      if (/rel="(canonical|alternate)"/.test(tag)) continue; // addresses, not loads
      const ref = (/\s(?:src|href)="([^"]*)"/.exec(tag) || [])[1];
      if (ref) assert.ok(!/^(https?:)?\/\//.test(ref), `${p} loads ${ref}`);
    }
  }
  assert.doesNotMatch(read('assets/site.css'), /@import|url\(\s*["']?https?:/, 'the stylesheet loads from another host');
});

test('the Persian and English pages have the same sections, tabs and download buttons', () => {
  const fa = read('index.html');
  const en = read('en/index.html');
  assert.deepEqual([...ids(fa)].sort(), [...ids(en)].sort());
  assert.deepEqual(attrs(fa, 'data-asset'), attrs(en, 'data-asset'));
  assert.ok(fa.includes('<html lang="fa" dir="rtl" data-root=".">'));
  assert.ok(en.includes('<html lang="en" dir="ltr" data-root="..">'));
});

test('every download button finds its file among a release\'s asset names', () => {
  const slots = page.slotsOf(API_BODY.assets.map((a) => ({ name: a.name, size: a.size, url: a.browser_download_url })));
  const want = {
    'win-setup': 'IRNetFree-Plus-Setup-3.3.3.exe', 'win-portable': 'IRNetFree-Plus-Portable-3.3.3.exe',
    'mac-arm64': 'IRNetFree-Plus-3.3.3-arm64.dmg', 'mac-x64': 'IRNetFree-Plus-3.3.3-x64.dmg',
    'mac-arm64-zip': 'IRNetFree.Plus-3.3.3-arm64-mac.zip', 'mac-x64-zip': 'IRNetFree.Plus-3.3.3-mac.zip',
    deb: 'IRNetFree-Plus-3.3.3-amd64.deb', appimage: 'IRNetFree-Plus-3.3.3-x86_64.AppImage',
  };
  for (const [slot, name] of Object.entries(want)) assert.equal(slots[slot] && slots[slot].name, name, slot);
  for (const slot of new Set(attrs(read('index.html'), 'data-asset'))) assert.ok(want[slot], `button ${slot} has no file pattern`);
  for (const slot of Object.values(page.HERO_SLOT)) assert.ok(want[slot], `the hero's ${slot} has no file pattern`);
});

test('electron-builder\'s artifact names still match the button patterns', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  assert.equal(pkg.build.portable.artifactName, 'IRNetFree-Plus-Portable-${version}.${ext}');
  assert.equal(pkg.build.nsis.artifactName, 'IRNetFree-Plus-Setup-${version}.${ext}');
  assert.equal(pkg.build.linux.artifactName, 'IRNetFree-Plus-${version}-${arch}.${ext}');
  assert.equal(pkg.build.dmg.artifactName, 'IRNetFree-Plus-${version}-${arch}.${ext}');
});

test('a phone is sent to IRNetFree\'s site: Plus has no phone version', () => {
  assert.equal(page.HERO_SLOT.android, undefined);
  assert.equal(page.HERO_SLOT.ios, undefined);
  assert.equal(page.CLIENT_SITE, 'https://sadrazkh.github.io/Irnetfree_xray-client/');
});

test('the hero picks the right file for each system', () => {
  const cases = [
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36', 'Win32', 0, 'windows'],
    ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15', 'MacIntel', 0, 'mac'],
    ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15', 'MacIntel', 5, 'ios'],
    ['Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/140 Mobile Safari/537.36', 'Linux armv8l', 5, 'android'],
    ['Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/140 Safari/537.36', 'Linux x86_64', 0, 'linux'],
    ['', '', 0, ''],
  ];
  for (const [ua, platform, touch, want] of cases) assert.equal(page.detectOS(ua, platform, touch), want, ua);
});

test('sizes and dates read the way each page writes numbers', () => {
  assert.equal(page.formatSize(78825971, 'en'), '75 MB');
  assert.equal(page.formatSize(78825971, 'fa'), '۷۵ مگابایت');
  assert.equal(page.formatSize(0, 'en'), '');
  assert.equal(page.formatDate('2026-11-08T12:51:07Z', 'en'), 'November 8, 2026');
  assert.equal(page.formatDate('not a date', 'en'), '');
  assert.equal(page.slimRelease(null), null);
});

test('links into GUIDE.md use anchors the README already uses', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const prefix = 'https://github.com/sadrazkh/Irnetfree_xray-client-plus/blob/main/';
  for (const p of ['index.html', 'en/index.html']) {
    for (const ref of attrs(read(p), 'href')) {
      if (!ref.startsWith(prefix) || !ref.includes('#')) continue;
      const local = ref.slice(prefix.length);
      assert.ok(readme.includes(`(${local})`), `${p}: ${local} is not an anchor README.md links to`);
    }
  }
});

test('the Pages workflow builds after a site change and after every release, and deploys from Actions', () => {
  const wf = fs.readFileSync(path.join(ROOT, '.github/workflows/pages.yml'), 'utf8');
  assert.ok(wf.includes("workflows: ['Build & Release']"));
  const rel = fs.readFileSync(path.join(ROOT, '.github/workflows/release.yml'), 'utf8');
  assert.match(rel, /^name: Build & Release\r?$/m, 'pages.yml waits on a workflow by this name');
  assert.ok(wf.includes('node scripts/build-site.js --out _site --require-release'));
  assert.ok(wf.includes('actions/upload-pages-artifact@'));
  assert.ok(wf.includes('actions/deploy-pages@'));
  assert.ok(wf.includes('pages: write'));
  assert.ok(wf.includes('id-token: write'));
  const dev = fs.readFileSync(path.join(ROOT, '.github/workflows/dev-release.yml'), 'utf8');
  assert.ok(dev.includes("- 'site/**'"), 'a site change must not rebuild the dev app');
});
