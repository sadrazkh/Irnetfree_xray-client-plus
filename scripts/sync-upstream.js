#!/usr/bin/env node
'use strict';
/**
 * Take the protocol code Plus shares with IRNetFree — verbatim — from an
 * upstream ref (docs/SYNC.md).
 *
 *   node scripts/sync-upstream.js              # the newest upstream tag
 *   node scripts/sync-upstream.js v1.26.0      # a tag, a branch (upstream/main) or a commit
 *   node scripts/sync-upstream.js --check      # only verify the recorded hashes (what the test does)
 *
 * upstream-sync.json lists every synced file with the sha256 of its content
 * (line endings normalised to LF, so a CRLF checkout hashes the same). A sync
 * checks the files out of the ref, records the new hashes, the ref and its
 * commit, and then looks at every relative require() in src/: one that names a
 * file which is not there means the new upstream code needs a file the list
 * does not have yet — it is printed, with the files that need it, and the run
 * fails so it is added (to `files`) and the sync run again. Plus never edits a
 * synced file; it wraps one (src/renderer/plus/i18n.js wraps i18n.js).
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const MANIFEST = path.join(ROOT, 'upstream-sync.json');

const git = (args, opts = {}) => execFileSync('git', args, Object.assign({ cwd: ROOT, encoding: 'utf8' }, opts)).trim();
const hashOf = (text) => crypto.createHash('sha256').update(String(text).replace(/\r\n/g, '\n')).digest('hex');

function readManifest() {
  return JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
}

/** The relative require()s of every .js under src/ that resolve to nothing: [{ from, request }]. */
function missingRequires() {
  const out = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.js')) {
        const src = fs.readFileSync(p, 'utf8');
        for (const m of src.matchAll(/require\(\s*['"](\.{1,2}\/[^'"]+)['"]\s*\)/g)) {
          const base = path.resolve(path.dirname(p), m[1]);
          const found = [base, base + '.js', base + '.json', path.join(base, 'index.js')].some((c) => fs.existsSync(c) && fs.statSync(c).isFile());
          if (!found) out.push({ from: path.relative(ROOT, p).split(path.sep).join('/'), request: m[1] });
        }
      }
    }
  };
  walk(path.join(ROOT, 'src'));
  return out;
}

/** Files whose content no longer matches the manifest: [{ file, why }]. */
function verify(manifest) {
  const bad = [];
  for (const [file, want] of Object.entries(manifest.files)) {
    const p = path.join(ROOT, file);
    if (!fs.existsSync(p)) { bad.push({ file, why: 'missing' }); continue; }
    if (hashOf(fs.readFileSync(p, 'utf8')) !== want) bad.push({ file, why: 'edited (its hash is not the recorded one)' });
  }
  return bad;
}

function newestTag(remote) {
  const tags = git(['tag', '--list', 'v*', '--sort=-v:refname', '--merged', `${remote}/main`]).split(/\r?\n/).filter(Boolean);
  if (!tags.length) throw new Error(`no v* tag reachable from ${remote}/main`);
  return tags[0];
}

function sync(refArg) {
  const manifest = readManifest();
  const remote = manifest.remote || 'upstream';
  const remotes = git(['remote']).split(/\r?\n/);
  if (!remotes.includes(remote)) git(['remote', 'add', remote, manifest.url]);
  git(['fetch', '--quiet', '--tags', remote]);
  const ref = refArg || newestTag(remote);
  const commit = git(['rev-parse', '--verify', `${ref}^{commit}`]);
  const files = Object.keys(manifest.files);
  git(['checkout', commit, '--', ...files]);
  const before = Object.assign({}, manifest.files);
  for (const f of files) manifest.files[f] = hashOf(fs.readFileSync(path.join(ROOT, f), 'utf8'));
  manifest.ref = ref;
  manifest.commit = commit;
  manifest.syncedAt = new Date().toISOString().slice(0, 10);
  fs.writeFileSync(MANIFEST, JSON.stringify(manifest, null, 2) + '\n');
  const changed = files.filter((f) => before[f] !== manifest.files[f]);
  console.log(`synced ${files.length} file(s) from ${ref} (${commit.slice(0, 7)}); ${changed.length} changed`);
  for (const f of changed) console.log('  ~ ' + f);
  const missing = missingRequires();
  if (missing.length) {
    console.log('\nThese require()s name files that are not here — add them to upstream-sync.json `files` and sync again:');
    for (const m of missing) console.log(`  ${m.from}: ${m.request}`);
    process.exit(1);
  }
  console.log('\nnext: npm test && npm run validate');
}

if (require.main === module) {
  const arg = process.argv[2];
  if (arg === '--check') {
    const bad = verify(readManifest());
    const missing = missingRequires();
    for (const b of bad) console.log(`${b.file}: ${b.why}`);
    for (const m of missing) console.log(`${m.from}: requires ${m.request}, which is not here`);
    if (bad.length || missing.length) process.exit(1);
    console.log('every synced file matches upstream-sync.json, and every require() resolves');
  } else {
    try { sync(arg); } catch (e) { console.error(e.message); process.exit(1); }
  }
}

module.exports = { hashOf, verify, missingRequires, readManifest };
