Last verified: 2026-11-08
Scope checked: every tracked file at `docs/baseline` HEAD (code identical to tag `v3.3.3`: `git diff v3.3.3..HEAD` touches only `CLAUDE.md` and `DOCUMENTATION_RULES.md`). Nothing was executed: no app, test, core or scan.

# IRNetFree Plus: master context

**Labels used in all docs.** `V` Verified against the code, with the file and symbol named. `A` Assumption. `R` Recommendation. A rule for reading them: `V` means the code says so, not that it was seen working on real hardware. `IMPLEMENTATION_STATUS.md` covers that gap.

## What this is

A tool app beside the IRNetFree VPN client. It finds working addresses and parameters for an Xray config (**Scan**), runs this machine as an Xray server with a 3x-ui-style panel (**Server**), and keeps a list of configs (**Configs**), plus **Settings** and **Log**. [V: `src/renderer/index.html` `view-scan`, `view-xserver`, `view-configs`, `view-settings`, `view-logs`]

It is not a client. No connect button, TUN, system proxy, subscription fetch by URL, Android or router package. What it finds goes back to IRNetFree as share links. [V: `docs/superpowers/specs/2026-10-15-plus-v3-tool-app-design.md` §1 and §6, and no such channel in `src/main/plus/apiMap.js` `INVOKE`]

## Current state

| Fact | Value | Status |
|---|---|---|
| Version | 3.3.3 | V: `package.json` `version`, tag `v3.3.3` |
| Upstream code synced from | client tag `v1.41.0`, on 2026-11-01 | V: `upstream-sync.json` `ref`, `syncedAt` |
| Synced files | 41, all hashes match this checkout | V: `upstream-sync.json` `files`, recomputed with the `hashOf` rule of `scripts/sync-upstream.js` |
| Own files under `src/` and `scripts/` | 38 | V: `git ls-files` minus the manifest |
| Runtime npm dependencies | none; dev only: Electron and electron-builder | V: `package.json` has no `dependencies` |
| Automated tests | 21 files, 416 `test()` call sites (counted, not run here) | V: `tests/*.test.js` |
| Real-hardware acceptance | mostly unproven by anything in the repo | see `IMPLEMENTATION_STATUS.md` |

## Two kinds of code

This is the most important fact about the repository.

| Kind | What | Rule |
|---|---|---|
| **Synced verbatim** | The 41 files in `upstream-sync.json` `files`: parser, config builder, core runner, downloader, version picker, stylesheets, `src/server/guard.js` and others | **Never edit here, not one line.** `tests/plusShell.test.js` fails on any change. Wrap the file, or fix it upstream and sync. Details: [SYNC.md](SYNC.md) |
| **This project's own** | `src/main/main.js`, `src/main/plus/`, `src/main/scan/`, `src/main/xserver/`, `src/preload/`, `src/server/server.js`, `src/server/web-api.js`, `src/renderer/index.html`, `src/renderer/app.js`, `src/renderer/plus/`, five scripts, `tests/` | Edit freely, under `AI_WORKING_GUIDELINES.md` |

Synced files sit in the same folders as own code (`src/server/guard.js` beside `server.js`, `src/renderer/*.css` beside `app.js`), so check the manifest, not the directory. The split path by path is in `ARCHITECTURE.md`.

## Entry points

| Front end | File | Notes |
|---|---|---|
| Desktop | `src/main/main.js` (`package.json` `main`) | Electron window, tray, IPC |
| Headless | `src/server/server.js` (`npm run server`) | HTTP RPC plus Server-Sent Events, no npm install needed |
| Both | `src/main/plus/service.js` `createPlusService` | The one service. Every feature lives behind it |
| The page | `src/renderer/index.html` then `app.js`, then `plus/*.js` | The same page for both front ends |

## Doc index

| Doc | Read it for |
|---|---|
| `ARCHITECTURE.md` | Components, the code split, Mermaid diagrams |
| `TECHNICAL_SPEC.md` | Channels, HTTP, data model, scan and server constants |
| `IMPLEMENTATION_STATUS.md` | Done / Partial / Not started, feature by feature |
| `KNOWN_ISSUES_AND_TECH_DEBT.md` | Bugs, limits, debt (`KI-nn`) |
| `DECISIONS_AND_RATIONALE.md` | Why things are as they are (`D-NNN`) |
| `ENVIRONMENT_AND_SETUP.md` | Setup, commands, env vars, CI, release |
| `PRODUCT_SPEC.md` | What the product must do, business rules |
| `ROADMAP.md` | Proposed priorities (no plan exists in the repo) |
| `GLOSSARY.md` | Domain terms |
| `OPEN_QUESTIONS.md` | What only the owner can answer, ranked |
| `AI_WORKING_GUIDELINES.md` | Rules for changing this repo |
| `CHANGELOG.md` | One line per release |

Existing documents, linked and not repeated: [README.md](../README.md) (Persian front page), [README.en.md](../README.en.md), [GUIDE.md](../GUIDE.md) (full manual, Persian), [SYNC.md](SYNC.md) (the upstream sync), [readme/](readme/) (banner and screenshots), [superpowers/](superpowers/) (design specs and plans).

`docs/superpowers/` is history, not current truth: several of its numbers and names have since changed (`KNOWN_ISSUES_AND_TECH_DEBT.md` KI-19).
