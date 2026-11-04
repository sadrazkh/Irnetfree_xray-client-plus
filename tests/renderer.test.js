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

/* ----------------------------- the Scan page’s rows and parameters (2026-11-01) ----------------------------- */

const SCAN_JS = read('plus/scan.js');

test('the Scan page’s defaults: every input a row with a switch — the addresses on, the ports and SNIs off, the parameters folded', () => {
  const box = (id) => (new RegExp(`<input[^>]*id="${id}"[^>]*>`).exec(HTML) || [''])[0];
  assert.match(box('scanUseAddrs'), /type="checkbox"/);
  assert.match(box('scanUseAddrs'), /\schecked/);
  for (const id of ['scanUsePorts', 'scanUseSnis']) {
    assert.match(box(id), /type="checkbox"/);
    assert.doesNotMatch(box(id), /\schecked/, id + ' starts off: the config’s own value');
  }
  assert.match(HTML, /<div class="scan-inrow-body" id="scanPortsBody" hidden>/);
  assert.match(HTML, /<div class="scan-inrow-body" id="scanSnisBody" hidden>/);
  const params = (/<details class="scan-params" id="scanParams"[^>]*>/.exec(HTML) || [''])[0];
  assert.ok(params, 'the parameters section is a <details>');
  assert.doesNotMatch(params, /\sopen/, 'folded by default');
  // the four address picks and the summary line above the forms
  assert.deepEqual([...HTML.matchAll(/data-pick="(\w+)"/g)].map((m) => m[1]), ['all', 'sample', 'random', 'block']);
  const { BLOCK_PREFIXES } = require('../src/main/scan/targets');
  assert.deepEqual([...HTML.matchAll(/<option value="(\d+)"[^>]*>[\d,]+ \(\/\d+\)</g)].map((m) => Number(m[1])), BLOCK_PREFIXES, 'the block sizes on the page are the ones main takes');
  // the CDN lists beside Cloudflare's, and the button that updates them
  assert.deepEqual([...HTML.matchAll(/data-preset="([\w-]+)" data-i18n="scan\.p\./g)].map((m) => m[1]), ['cf', 'fastly', 'cloudfront', 'cloudfront-regional', 'gcore', 'warp-masque', 'warp-wg']);
  assert.match(HTML, /id="btnScanCdnUpdate"/);
  assert.ok(HTML.indexOf('id="scanSummary"') < HTML.indexOf('class="scan-forms"'), 'the summary sits above the forms');
  assert.match(read('plus/scan.css'), /\.scan-summary \{[^}]*position: sticky/);
});

test('the keys the Scan page builds — each dimension’s name, hint and plural, each failure reason — say something in fa and in en', () => {
  const V = require('../src/main/scan/variants');
  const { REASONS } = require('../src/main/scan/probes');
  const keys = [];
  for (const id of V.DIM_IDS) keys.push(`scan.dim.${id}`, `scan.dim.${id}.hint`, `scan.dim.${id}.many`);
  for (const r of REASONS) keys.push(`scan.reason.${r}`);
  for (const k of ['scan.err.singbox', 'scan.err.tooMany', 'scan.err.noVariant', 'scan.pick.sample', 'scan.pickN', 'scan.perRange']) keys.push(k);
  const missing = [];
  for (const k of keys) for (const lang of ['fa', 'en']) if (!has(lang, k)) missing.push(`${lang}:${k}`);
  assert.deepEqual(missing, []);
  // and the page's own maps name exactly main's dimensions and reasons
  for (const id of V.DIM_IDS) assert.ok(SCAN_JS.includes(`${/^[a-z]+$/i.test(id) ? id : `'${id}'`}: ['scan.dim.${id}', 'scan.dim.${id}.hint', 'scan.dim.${id}.many']`), 'DIM_KEYS: ' + id);
  for (const r of REASONS) assert.ok(SCAN_JS.includes(`'scan.reason.${r}'`), 'REASON_KEYS: ' + r);
  // main's refusal codes the page turns into sentences
  for (const code of ['singbox only', 'too many variants', 'no variant runs']) assert.ok(SCAN_JS.includes(`'${code}': 'scan.err.`), code);
});

test('the Scan page’s scripts parse, and no Persian string carries a straight apostrophe', () => {
  const vm = require('node:vm');
  for (const f of ['plus/scan.js', 'plus/scan.i18n.js']) assert.doesNotThrow(() => new vm.Script(read(f), { filename: f }), f);
  for (const [k, v] of read('plus/scan.i18n.js').matchAll(/'([A-Za-z0-9_.-]+)':\s*'([^'\n]*)'/g)) assert.ok(!/[؀-ۿ]'/.test(v), k);
});

test('a Server table row stays a table row: a field with a button has a class of its own, and the clients table cannot widen the table around it', () => {
  // .xs-row is the rows of the inbound, client, outbound and rule tables. display:flex on a <tr> takes
  // it out of the table: the headers stop lining up with their columns and the table overflows its box.
  const rules = [...ALL_CSS.replace(/\/\*[\s\S]*?\*\//g, '').matchAll(/([^{}]+)\{([^{}]*)\}/g)];
  const onRow = rules.filter(([, sel, body]) => /\.xs-row(?![\w-])/.test(sel) && /(^|[\s;])display\s*:/.test(body));
  assert.deepEqual(onRow.map(([, sel]) => sel.trim()), [], 'nothing sets display on .xs-row');
  assert.match(read('plus/xserver.css'), /\.xs-row-field \{[^}]*display: flex/);
  // the class goes on table rows only, in the markup and in what the script builds
  const notRows = [...HTML.matchAll(/<(\w+)[^>]*\sclass="(?:[^"]*\s)?xs-row(?![\w-])[^>]*>/g)].map((m) => m[0]);
  assert.deepEqual(notRows, [], 'no element in the markup is .xs-row');
  assert.equal(HTML.match(/<div class="xs-row-field">/g).length, 4, 'the link and the three generated secrets');
  const built = [...read('plus/xserver.js').matchAll(/(\w+)\.className = 'xs-row(?![\w-])/g)].map((m) => m[1]);
  assert.deepEqual(built, ['tr', 'tr', 'tr', 'tr'], 'client, inbound, outbound, rule');
  // 980px of clients sit inside one cell: without this they set the width of every column above them
  assert.match(read('plus/xserver.css'), /\.xs-clients-wrap \{[^}]*inline-size: 0;[^}]*min-inline-size: 100%/);
  // a left-to-right cell starts where its header starts: `start` on it alone is the far side in Persian
  const ltrCells = rules.filter(([, sel, body]) => /^\s*\.xs-c-[\w-]+\s*$/.test(sel) && /direction: ltr/.test(body)).map(([, sel]) => sel.trim());
  const inRtl = read('plus/xserver.css').match(/\[dir="rtl"\] :is\(([^)]*)\) \{ text-align: end; \}/);
  assert.ok(inRtl, 'the rule for a right-to-left page');
  assert.deepEqual(inRtl[1].split(', ').sort(), ltrCells.sort());
});

test('the request the page sends reads as main sanitizes it: the variants, the pick with its count, the accuracy options', () => {
  // the names buildReq/buildOpts write, as main's sanitizers read them
  for (const name of ['variants: buildSpec()', 'count: pickCount()', 'o.passRatio', 'o.delayExpect', 'o.prefilterTls', "'prefilterConcurrency'"]) assert.ok(SCAN_JS.includes(name), name);
  const { sanitizeOpts, sanitizePick } = require('../src/main/scan/index');
  const o = sanitizeOpts({ passRatio: 1, delayExpect: '200-299', prefilterTls: true, prefilterConcurrency: 300 });
  assert.deepEqual([o.passRatio, o.delayExpect, o.prefilterTls, o.prefilterConcurrency], [1, '200-299', true, 300]);
  assert.equal(sanitizeOpts({ delayExpect: 'nonsense' }).delayExpect, '204', 'an expectation that does not read falls back to the default page’s');
  assert.equal(sanitizeOpts({ delayHost: 'example.org' }).delayExpect, '', 'another page: any 2xx/3xx');
  assert.deepEqual(sanitizePick({ mode: 'sample', count: 500 }), { mode: 'sample', perRange: 20, count: 500, perBlock: 5, block: 24, fresh: true });
});
