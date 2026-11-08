Last verified: 2026-11-08
Scope checked: `CLAUDE.md`, `DOCUMENTATION_RULES.md`, `tests/renderer.test.js`, `tests/plusShell.test.js`, `tests/noNetwork.preload.js`, the Global Constraints in `docs/superpowers/plans/`, and git log. Labels: V / A / R, see `MASTER_CONTEXT.md`.

# AI working guidelines

For humans and AI assistants changing this repository.

## The one hard rule

**Never edit a file listed in `upstream-sync.json`.** Check the manifest first: synced files sit beside own files. A test fails on any change. To change behaviour, wrap the file or build on its exports; to fix a bug in one, fix it in the upstream client repository and sync. [V: `tests/plusShell.test.js`, `docs/SYNC.md`]

## Documentation

Follow `DOCUMENTATION_RULES.md`. Use Mode B: update only the docs a change affects, in the same change. Label claims V / A / R. Never invent details. [V: `CLAUDE.md`]

## Public repository

Examples, fixtures, docs and commit messages must never contain a real hostname, IP address, server or subscription name, account, key, token, employer name, personal network detail, or anything about where the owner or a user is. Use reserved names and RFC 5737 addresses. [R, from the owner's brief for this baseline]

## Changing the code

| Task | Rule | Status |
|---|---|---|
| New feature | It goes in the service; both front ends get it through `apiMap.js` | V: D-003 |
| New channel | Add it to `INVOKE` or `EVENTS` and register it with `ctx.handle`. Tests check the map against the page | V: `tests/plusShell.test.js`, `tests/plusService.test.js` |
| Handler | One argument. Answer with a value; a failure is `{ error }` or `{ ok: false, error }` | V: `service.js` header, `xserver/index.js` |
| New runtime dependency | Not allowed: Node core only | V: D-017 |
| Scan targets | Never expand a space into a list | V: D-008 |
| Timers, spawn, network in `core.js`, `scanner.js`, `service.js` | Inject them through the existing `deps` seams | V: those files' headers |
| Server model | Only `xserver:set` writes it. Rule order is load-bearing | V: `plus/xserver.js`, D-015 |
| Store keys | Do not rename them; v2 data depends on them | V: D-005 |
| `scan/score.js` order | The owner's stated order; do not reorder it without asking | V: D-009 |

## The page

Rules pinned by `tests/renderer.test.js` [V]:

- Every id the scripts look up is in `index.html`, and no id appears twice.
- Every key is in `fa` and in `en`, once per language, in `plus/*.i18n.js`. Use `t()`.
- No inline styles in the markup. Scripts style through classes, bar widths aside.
- Plus stylesheets use logical properties and tokens. Every class in the markup has a rule.
- Script load order is fixed.
- A Persian string must not contain a straight apostrophe; use `’`.
- In Persian, a sentence with embedded numbers or dates needs its own direction, and isolates are written as escapes, not as invisible characters (commit `503bb53`).
- A `tr` stays a table row. A field with a button gets a class of its own.

## Safety when running things

| Rule | Status |
|---|---|
| Run tests only through `npm test` | V: D-025 |
| In a test or probe, never bind a wildcard address, run `netsh` or `schtasks`, or kill anything you did not start | V: plan Global Constraints; probe headers |
| Headless checks use a temporary `--data-dir` and a high port | V: plan Global Constraints |
| `npm run update-cdn-ranges`, `validate` with real cores and the probes spawn or reach out. Do not run them unless asked | A |

## Gates before a release

`npm test`, `npm run validate` on both cores, `npm run probe:reverse`, `node scripts/probe-scan.js`. After a sync, the same gates. [V: `docs/SYNC.md`]

Push one release tag at a time, never `--tags`. [V: D-020]

## Commits

| Item | Status |
|---|---|
| Commits in the owner's name only, without `Co-Authored-By`; subagents do not commit | V: plan Global Constraints |
| Subject is a full sentence on what changed and why | V: git log |
| A release is merged as `Merge: Plus vX.Y.Z - ...` | V: git log |
| A sync is its own commit: `Sync upstream vX.Y.Z - ...` | V: `docs/SYNC.md` |
| Semantic rule for version numbers | Unknown from the repo (A: patch for fixes, minor for capabilities, judging by v3.1 to v3.3.3) |
