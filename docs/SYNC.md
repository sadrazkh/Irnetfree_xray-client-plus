# Keeping Plus in step with IRNetFree

Plus v3 is a tool app (Scan, Server, Configs, Settings, Log), not a fork of the client. It **shares** IRNetFree's
protocol code — the link parser, the config builder, the core runner, the core downloader and version picker, the
stylesheets — **verbatim**, and owns everything else. There is no `git merge upstream/main` any more: a sync is one
command and cannot conflict.

## The rule

A file listed in [`upstream-sync.json`](../upstream-sync.json) is upstream's. Plus never edits it — not one line. When
Plus needs something different, it wraps the file instead (as `src/renderer/plus/i18n.js` wraps `i18n.js`) or builds on
its exported functions (as the Server tab builds its exits through `buildMultiTestConfig`).
`tests/plusShell.test.js` fails when a synced file's content no longer matches its recorded hash.

## Syncing

```bash
npm run sync-upstream              # the newest upstream tag
npm run sync-upstream -- v1.26.0   # a tag, a branch (upstream/main) or a commit
npm test && npm run validate && npm run probe:reverse && node scripts/probe-scan.js
```

The script adds the `upstream` remote when it is missing, fetches, checks the listed files out of the ref, records the
new hashes, the ref and its commit, and then checks every relative `require()` under `src/`. When upstream's code now
needs a file that is not on the list, it prints the file and the code that needs it and exits 1: add that path to
`files` in `upstream-sync.json` (any hash; the next sync writes the real one) and run it again.

Then read what changed (`git diff --stat`), run the gates above, and commit the sync on its own:
`Sync upstream vX.Y.Z — <what moved>`.

## What is synced (v1.25.0)

| Area | Files |
|---|---|
| Protocols and configs | `src/main/parser.js`, `jsonImport.js`, `configBuilder.js`, `dnsBuilder.js`, `routingProfiles.js`, `mux.js`, `certPin.js`, `coreCompat.js`, `engineChoice.js`, `engines.js`, `src/renderer/serverFields.js` |
| Cores | `src/main/xrayManager.js`, `downloader.js`, `coreVersions.js`, `assets.js`, `assetUpdater.js`, `netutils.js`, `store.js` |
| Page | `src/renderer/i18n.js`, `corePicker.js`, `theme-boot.js`, `styles.css`, `skins.css`, `settings.css`, `lists.css`, `home.css`, `vendor/qrcode.js` |
| Headless | `src/server/guard.js` |
| Scripts | `scripts/download-xray.js`, `scripts/gen-icons.js` |

## What is Plus's own

| Path | Role |
|---|---|
| `src/main/main.js` | the Electron shell: window, tray, IPC to the service |
| `src/main/plus/` | `service.js` (one service for the window and the headless server), `configs.js`, `apiMap.js` (the page's `window.api`), `elevate.js` (the one admin command) |
| `src/main/scan/`, `src/main/xserver/` | the two tools |
| `src/preload/preload.js`, `src/server/server.js`, `src/server/web-api.js` | the two bridges |
| `src/renderer/index.html`, `app.js`, `plus/` | the pages |
| `scripts/validate-configs.js`, `probe-reverse.js`, `probe-scan.js`, `sync-upstream.js` | the gates |
| `tests/` | Plus's suite |

## History

Until v2.2 Plus was a full fork of the client with two extra tabs, kept mergeable by marking every Plus line in
upstream files (`docs/FORK.md` in v2.x). Each sync was a merge with about eleven conflicts plus identity fixes in
upstream's tests, and Plus built Android and router packages it never needed. On 2026-10-15 the owner chose to drop the
client (*"فقط ابزار، بدون کلاینت"*); v1.25.0 was the last full merge (`e4d71b1`), and v3.0.0 is the tool app.
