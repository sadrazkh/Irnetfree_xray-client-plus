'use strict';
/**
 * The page's contract (src/renderer): what the scripts look up is in the
 * markup, what is on screen says something in both languages, and the CSS
 * follows the rules every Plus stylesheet keeps. Static reads only — no DOM.
 *
 * The dictionaries are Plus's (plus/i18n.js and plus/*.i18n.js) with
 * upstream's i18n.js behind them (the core picker's cv.*, the core rows'
 * comp.*, the window buttons' tb.*); a key must be in one of them, in fa AND
 * in en.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const DIR = path.join(__dirname, '..', 'src', 'renderer');
const read = (f) => fs.readFileSync(path.join(DIR, f), 'utf8');
const HTML = read('index.html');
const PLUS_JS = fs.readdirSync(path.join(DIR, 'plus')).filter(f => f.endsWith('.js') && !f.endsWith('.i18n.js') && f !== 'i18n.js').map(f => 'plus/' + f);
const PAGE_JS = ['app.js', ...PLUS_JS];
const JS = PAGE_JS.map(read).join('\n');
const PLUS_CSS = fs.readdirSync(path.join(DIR, 'plus')).filter(f => f.endsWith('.css')).map(f => 'plus/' + f);
const ALL_CSS = [...fs.readdirSync(DIR).filter(f => f.endsWith('.css')), ...PLUS_CSS].map(read).join('\n');

/** { fa: Set, en: Set } of the keys a dictionary file defines; `dupes` lists a key defined twice in one language. */
function dictKeys(whole, { plus }) {
  // the dictionaries only: plus/i18n.js has code before its extend({ … })
  const from = whole.search(/extend\(\{|const I18N = \{/);
  const src = from === -1 ? whole : whole.slice(from);
  const enAt = src.search(/\n\s{2,4}en:\s*\{/);
  if (enAt === -1) throw new Error('no en block');
  const parts = { fa: src.slice(0, enAt), en: src.slice(enAt) };
  const out = { fa: new Set(), en: new Set(), dupes: [] };
  for (const lang of ['fa', 'en']) {
    for (const m of parts[lang].matchAll(/'([A-Za-z0-9_.-]+)'\s*:/g)) {
      if (plus && out[lang].has(m[1])) out.dupes.push(`${lang}:${m[1]}`);
      out[lang].add(m[1]);
    }
  }
  return out;
}

const UPSTREAM = dictKeys(read('i18n.js'), { plus: false });
const PLUS_DICTS = ['plus/i18n.js', 'plus/scan.i18n.js', 'plus/xserver.i18n.js'].map(f => ({ f, d: dictKeys(read(f), { plus: true }) }));
const has = (lang, key) => UPSTREAM[lang].has(key) || PLUS_DICTS.some(x => x.d[lang].has(key));

test('every id the page scripts look up is in the markup, and no id is there twice', () => {
  const ids = [...HTML.matchAll(/\sid="([^"]+)"/g)].map(m => m[1]);
  const dup = ids.filter((id, i) => ids.indexOf(id) !== i);
  assert.deepEqual(dup, [], 'duplicate ids');
  const have = new Set(ids);
  const missing = new Set();
  for (const m of JS.matchAll(/\$\$?\(\s*['"`]#([A-Za-z][\w-]*)/g)) if (!have.has(m[1])) missing.add(m[1]);
  for (const m of JS.matchAll(/getElementById\(\s*['"]([\w-]+)['"]/g)) if (!have.has(m[1])) missing.add(m[1]);
  assert.deepEqual([...missing].sort(), []);
});

test('every key on screen says something in fa and in en', () => {
  const used = new Set();
  for (const m of HTML.matchAll(/data-i18n(?:-ph|-title)?="([^"]+)"/g)) used.add(m[1]);
  for (const m of JS.matchAll(/\bt\(\s*'([A-Za-z0-9_.-]+)'\s*\)/g)) used.add(m[1]);
  for (const m of JS.matchAll(/dataset\.i18n(?:Title)?\s*=\s*'([A-Za-z0-9_.-]+)'/g)) if (!m[1].endsWith('.')) used.add(m[1]);
  for (const m of JS.matchAll(/data-i18n(?:-title)?="([A-Za-z0-9_.-]+)"/g)) used.add(m[1]);
  // keys the scripts build: their every value is listed here
  for (const id of ['tcp', 'delay', 'down', 'up']) used.add('scan.test.' + id);
  for (const c of ['reality', 'ech', 'notls', 'unsupported']) used.add('scan.fact.sni.' + c);
  for (const k of ['scan.err.busy', 'scan.err.noServer', 'scan.err.notFound', 'scan.err.proto', 'scan.err.chain', 'scan.err.noTargets', 'scan.err.noEngine', 'scan.err.coreOld', 'scan.err.noTests', 'scan.err.noRows', 'scan.err.sni']) used.add(k);
  const missing = [];
  for (const k of used) for (const lang of ['fa', 'en']) if (!has(lang, k)) missing.push(`${lang}:${k}`);
  assert.deepEqual(missing.sort(), []);
});

test('a Plus dictionary defines each key once per language, and both languages carry the same keys', () => {
  for (const { f, d } of PLUS_DICTS) {
    assert.deepEqual(d.dupes, [], f);
    const onlyFa = [...d.fa].filter(k => !d.en.has(k));
    const onlyEn = [...d.en].filter(k => !d.fa.has(k));
    assert.deepEqual([onlyFa, onlyEn], [[], []], f);
  }
  // across Plus files a key is defined once: extend() would complain at run time
  const seen = new Map();
  for (const { f, d } of PLUS_DICTS) for (const k of d.fa) { assert.ok(!seen.has(k), `${k} in ${seen.get(k)} and ${f}`); seen.set(k, f); }
});

test('no inline styles in the markup; the scripts style only through classes, bar widths aside', () => {
  assert.equal(/\sstyle="/.test(HTML), false);
  const sets = [...JS.matchAll(/\.style\.([a-zA-Z]+)\s*=/g)].map(m => m[1]);
  assert.deepEqual([...new Set(sets)].sort(), ['inlineSize']);
});

test('Plus stylesheets use logical properties and tokens', () => {
  for (const f of PLUS_CSS) {
    const css = read(f).replace(/\/\*[\s\S]*?\*\//g, '');
    assert.equal(/(?:^|[\s;{])(?:margin|padding|border)-(?:left|right)\s*:/m.test(css), false, f + ': physical margin/padding/border');
    assert.equal(/(?:^|[\s;{])(?:left|right)\s*:/m.test(css), false, f + ': left/right');
    assert.equal(/text-align\s*:\s*(?:left|right)/.test(css), false, f + ': text-align left/right');
    assert.equal(/float\s*:/.test(css), false, f + ': float');
    // colours come from the tokens
    assert.equal(/#[0-9a-fA-F]{3,8}\b/.test(css), false, f + ': a raw colour');
  }
});

test('every class in the markup has a rule somewhere', () => {
  // state and hook classes the scripts toggle or read, styled through their parents or not at all
  const HOOKS = new Set(['active', 'view', 'nav-ico', 'vis-hidden', 'conn-off', 'xs-panel', 'xs-errors-card']);
  const classes = new Set();
  for (const m of HTML.matchAll(/class="([^"]+)"/g)) for (const c of m[1].split(/\s+/)) if (c) classes.add(c);
  const unstyled = [...classes].filter(c => !HOOKS.has(c) && !new RegExp('\\.' + c.replace(/[-]/g, '\\-') + '(?![\\w-])').test(ALL_CSS));
  assert.deepEqual(unstyled.sort(), []);
});

test('the scripts load in the order the pages need: upstream i18n, the wrapper, the dictionaries, the picker, the shell, the pages', () => {
  const order = [...HTML.matchAll(/<script src="([^"]+)"/g)].map(m => m[1]);
  assert.deepEqual(order, ['theme-boot.js', 'vendor/qrcode.js', 'i18n.js', 'plus/i18n.js', 'plus/xserver.i18n.js', 'plus/scan.i18n.js', 'corePicker.js', 'app.js', 'plus/configs.js', 'plus/xserver.js', 'plus/scan.js']);
});
