Last verified: 2026-11-08
Scope checked: code and tests at v3.3.3 plus git history. **No test, core or app was run for this baseline**, so "tests exist" never means "tests pass". Labels: V / A / R, see `MASTER_CONTEXT.md`.

# Implementation status

**Done**: the code is complete and logic-only, or covered by a test or CI probe that fully exercises it. **Partial**: only partly built, or depends on a real network, OS or device and the repo holds no evidence of it working there. **Not started**: no code.

CI proof that exists: `npm test` on Windows, macOS and Linux with Node 22; on Linux, real suggested cores run `xray run -test` over every config shape, and two probes run real cores on loopback (`.github/workflows/test.yml`). Whether those jobs are green today is unknown without network access.

## Scan

| Feature | Status | Evidence (V) and reason |
|---|---|---|
| Target grammar, lazy spaces, four pick modes | Done | `scan/targets.js`; `tests/scan.targets.test.js`, `tests/scan.spaces.test.js` |
| Tested-address history, `scan:forget` | Done | `scan/index.js` `rememberTested`, `forget`. Not kept for runs over 50,000 rows (`remember`) |
| Putting a target into each protocol | Done | `scan/substitute.js`; `tests/scan.substitute.test.js`; every shape through `xray run -test` in CI |
| Parameter matrix and even sampling | Done | `scan/variants.js`; `tests/scanVariants.test.js` |
| Pass rule, score, failure reasons | Done | `scan/score.js`, `scan/probes.js`; `tests/scan.score.test.js`, `tests/scan.probes.test.js` |
| Two-phase runner, batches, cancel | Done | `scan/scanner.js`; `tests/scan.scanner.test.js`, `tests/scan.pipeline.test.js`; end to end on loopback in `scripts/probe-scan.js` |
| Results: link, JSON, CSV, save, best-N | Done | `scan/index.js` `recordFor`, `links`, `copy`, `exportText` |
| Scanning real servers by protocol (MASQUE, WARP, Hysteria2, WireGuard, ECH, REALITY) | **Partial** | CI proves the core accepts each config; the only end-to-end scan is VLESS on loopback. No repo evidence for real endpoints of the others |
| ECH fetched once | **Partial** | `scan/ech.js`, canned-message tests in `tests/scan.ech.test.js`; real resolver use is not shown |
| Path check | **Partial** | `scan/upstream.js`. One real observation is recorded in that file's header; tests use fakes. Cannot see a kernel VPN (KI-13) |
| Scan through a SOCKS port | **Partial** | Loopback SOCKS in `probe-scan.js` `upstreamRun`. Use through a real direct port of IRNetFree is not shown; a config's own tricks do not reach the real line by design |
| CDN lists, shipped and updated | **Partial** | Shipped list fetched 2026-11-02 (`cdnRanges.data.json`). The in-app update is tested with fakes; the Update button on a real network is not shown. Cloudflare's list is updated by hand (KI-16) |
| TUIC / AnyTLS configs | Not started | Refused as `singbox only`. sing-box is not a scan engine |

## Server

| Feature | Status | Evidence (V) and reason |
|---|---|---|
| Model, validation, migration, config generation | Done | `xserver/config.js`; `tests/xserver.config.test.js`, `tests/xserver.migrate.test.js`; shapes through `xray run -test` |
| Core lifecycle, crash back-off | Done | `xserver/core.js`; `tests/xserver.core.test.js` with fakes; a real core on loopback in the probes |
| Client links and QR | Done | `clientLink`; `tests/xserver.links.test.js` |
| Serving real clients from a public address (TLS, REALITY) | **Partial** | Only loopback proof exists. A real VPS or real client app is not shown |
| Quota, expiry, reset cycle | **Partial** | `_enforce`, `_tick` tested with fakes. Accuracy limits in KI-11 |
| `limitIp` | **Partial** | Stored and shown only. Not enforced (`normalizeClient` comment) |
| Reverse proxy, portal and bridge | **Partial** | `scripts/probe-reverse.js` proves it on loopback. Across a real NAT is not shown |
| Windows firewall button | **Partial** | `plus/elevate.js`, tested with fake `execFile`; the real UAC flow is not shown. TCP only, no way to remove a rule from the page (KI-01) |

## Configs, shell, platforms

| Feature | Status | Evidence (V) and reason |
|---|---|---|
| Add by text or file, remove, save from scan | Done | `plus/configs.js`; `tests/plusService.test.js` |
| Import from IRNetFree on the same machine | **Partial** | Tested with a fake store. The default store path is unconfirmed on a real install (KI-14) |
| Settings: language, theme, skin | Done | `service.js`, `app.js`; static contract in `tests/renderer.test.js` |
| Core download and version picker | **Partial** | Synced code, driven from `service.js`, tested only with a fake downloader. CI fetches its cores with `curl`, so the in-app download is not exercised |
| Update check (a link only) | **Partial** | `app:checkUpdate`, tested with a fake answer. The real GitHub call is not shown |
| Log page | Done | `service.js` `log`, `app.js` `addLog` |
| v2 store carries over | Done | `tests/plusService.test.js`, `tests/xserver.migrate.test.js` |
| Electron shell, tray, close-to-tray, start at login | **Partial** | `tests/mainShell.test.js` runs `main.js` against a stubbed `electron`. No automated run in real Electron. README says its screenshots come from the app itself |
| Windows installers | **Partial** | Built by `release.yml` and `dev-release.yml`. Launching them is not part of any job. Unsigned |
| macOS and Linux packages | **Partial** | Built by `release.yml`, and by `dev-release.yml` only on a manual all-platforms run. Never launched by CI. The macOS build is unsigned (`hardenedRuntime: false`, README) |
| Headless server | **Partial** | `web-api.js` tested in a VM; `guard.js` is synced. **`server.js` itself is never booted by a test** (KI-06). Spec lists a manual walkthrough as a v3.0 gate; its result is not recorded |
| Page rendering in fa and en | **Partial** | `tests/renderer.test.js` is static with no DOM. Commit `6d44702` records fixes made from headless screenshots, but no automated visual check exists |

## Project machinery

| Feature | Status | Evidence (V) and reason |
|---|---|---|
| Verbatim upstream sync | Done | `scripts/sync-upstream.js`; 41 of 41 hashes match (recomputed for this baseline) |
| Test guard against touching the machine | Done | `tests/noNetwork.preload.js` |
| CI tests and core gates | Done | `.github/workflows/test.yml` |
| Release pipeline | **Partial** | `release.yml` builds and publishes, but runs no tests or core gates (KI-02) |
