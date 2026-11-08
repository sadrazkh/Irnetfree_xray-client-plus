Last verified: 2026-11-08
Scope checked: `README.en.md`, `GUIDE.md`, `docs/superpowers/specs/*`, the page in `src/renderer/`, and the services behind it. Labels: V / A / R, see `MASTER_CONTEXT.md`.

# Product specification

The feature list and walkthrough for users are in [README.en.md](../README.en.md) and [GUIDE.md](../GUIDE.md). This page states what the product must do and the rules behind it.

## Vision

The toolbox beside IRNetFree: find addresses and parameters that really work for a given Xray config, and run your own Xray server without a web panel or database. [V: README.en.md, `package.json` `description`]

Users: people who already hold configs and use IRNetFree or another client, and people running their own server. [A: no user research in the repo]

## Non-goals

| Non-goal | Status |
|---|---|
| Connecting the device: no VPN, TUN or system proxy | V: spec 2026-10-15 §1, §6 |
| Subscription fetch by URL | V: same; import from IRNetFree or paste the content |
| Android or router builds | V: same; README |
| Self-installing updates | V: D-019 |
| Telemetry | V for own code (a grep of its network calls finds only those below); A for the synced files, which were not traced call by call |

## Requirements by page

### Scan
- One config, stored or pasted. Refuse what cannot be dialed, and say why. [V: `scan/index.js` `refusal`]
- Test addresses x ports x SNIs x parameter values on every chosen core. [V: `shape`]
- Every input row has a switch: on, its values multiply the run; off, the config's own value. [V: `plus/scan.js` header; `tests/renderer.test.js`]
- A live line says how many tests a run will make, before it starts. Nothing is expanded to compute it. [V: `scan:plan`]
- Results: per-row score and failure reason, a summary per combination, copy link or JSON, copy the best links, save to Configs, re-test speed, CSV and JSON export. [V: `recordFor`, `links`, `copy`, `exportText`, `variantStats`]
- Stop at any time. One run at a time. [V: `stop`, `start`]

### Server
Seven sub-tabs: overview, inbounds, outbounds, routing, reverse, settings, log. [V: `index.html` `xsTab*`]
- Inbounds with clients, quota, expiry, reset cycle, link and QR. A client who runs out is turned off automatically and returns when the reason ends. [V: `xserver/core.js` `_enforce`]
- A refused edit writes nothing and points at the field that is wrong. [V: `plus/xserver.js` header, `validateModel`]
- Closing the window while the server runs keeps it in the tray. [V: `main.js`]

### Configs
Add by pasting links, subscription text, JSON or a WireGuard file; import read-only from IRNetFree on the same machine, where a re-import updates in place. [V: `plus/configs.js`]

### Settings and Log
Language (Persian default, English), theme, skin, core management, start with the OS (desktop only), update check. A log ring of 500 lines. [V: `service.js`, `app.js`]

## Business rules

| Rule | Status |
|---|---|
| A pass is the expected answer through the tunnel on at least two of three samples by default | V: D-009 |
| Ranking: success, then median latency, then jitter. Download speed does not change the score, but a failed download scores 0 | V: `score.js` |
| A config's SNI is not changed for REALITY, ECH or no TLS | V: `substitute.js` `sniSupport` |
| A value only Xray-PattN runs is tested on that core alone, never silently on another | V: `variants.js` `enginesFor` |
| A core too old for the config is left out, with the reason | V: `scan/index.js` `gateEngines` |
| A result holds for the config scanned | V: README FAQ |
| Results are never stored; only the addresses tested and the last request are | V: D-007 |
| A file is not swapped under a running core | V: `service.js` `coreBusy` |
| A client the user disabled stays disabled | V: `_enforce` |

## Network destinations

Everything stays on the device except these, and [GUIDE.md](../GUIDE.md) has the user-facing table. [V: `scan/index.js`, `scan/upstream.js`, `scan/ech.js`, `scan/cdnRanges.js`, `service.js`]

| Destination | When |
|---|---|
| GitHub | Core downloads, update check |
| The addresses the user gives | During a scan |
| A public connectivity page and a speed endpoint, through the tunnel; changeable under Advanced | During a scan |
| Reserved documentation addresses | The path check |
| The ECH config's own DNS resolver | Only for a config using an ECH query |
| Each CDN's public list | Only on Update |

## Compatibility promises

Settings, configs, the server model and scan memory carry forward across v2 and v3. [V: D-005] IPv4, IPv6 and host-name targets are all accepted. [V: `targets.js`]
