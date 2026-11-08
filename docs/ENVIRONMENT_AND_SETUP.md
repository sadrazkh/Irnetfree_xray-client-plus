Last verified: 2026-11-08
Scope checked: `package.json`, `package-lock.json`, `.gitignore`, `.github/workflows/*`, `scripts/*`, `src/server/server.js`, `src/main/main.js`. No command below was run for this baseline. Labels: V / A / R, see `MASTER_CONTEXT.md`.

# Environment and setup

User-facing install steps are in [README.en.md](../README.en.md) and [GUIDE.md](../GUIDE.md). This page is for developers.

## Requirements

| Need | Value | Status |
|---|---|---|
| Node for `npm test` | 21 or newer (`node --test` with a glob) | V: `package.json` `test`; `test.yml` comment |
| Node in CI | 22 for tests and dev builds, 20 for tag builds | V: workflows; see KI-02 |
| Electron | `^31.0.0`, locked 31.7.7 | V: `package.json`, `package-lock.json` |
| electron-builder | `^24.13.3`, locked 24.13.3 | V: same |
| Runtime npm dependencies | none | V: `package.json` |
| Headless | Node only, no `npm install` | V: `server.js` header, GUIDE |
| Cores | `bin/` for local checks (git-ignored); the app keeps its own in `<data>/bin` | V: `.gitignore`, `service.js` `userBin` |

## Commands

| Command | Does |
|---|---|
| `npm install`, then `npm run get-xray` | Dev dependencies and a local core in `bin/` |
| `npm start` | The desktop app |
| `npm run server -- --port 6970` | The headless server (flags in `TECHNICAL_SPEC.md` §2) |
| `npm test` | The suite, through `tests/noNetwork.preload.js`. **Always use this form** (D-025) |
| `npm run validate` | Every config shape through `xray run -test` |
| `npm run probe:reverse` | Reverse proxy, real cores, loopback |
| `node scripts/probe-scan.js` | A real scan on loopback, both cores |
| `npm run sync-upstream -- <ref>` | Take upstream files ([SYNC.md](SYNC.md)) |
| `node scripts/sync-upstream.js --check` | Verify hashes only |
| `npm run update-cdn-ranges` | Refresh the shipped CDN lists (reaches the network) |
| `npm run gen-icons` | Icons, used in release builds |
| `npm run dist:win`, `dist:mac`, `dist:linux`, `pack` | Packages |

## Environment variables

| Variable | Used by | Effect |
|---|---|---|
| `IRNF_PLUS_DATA` | `server.js` | Headless data folder when `--data-dir` is absent |
| `IRNF_XRAY_EXE` | `validate-configs.js` | The core binary to test |
| `IRNF_XRAY_FORK` | `validate-configs.js` | `pattn` runs the Xray-PattN-only shapes |
| `IRNF_CORE_VERSION` | `validate-configs.js` | The version a dry run adapts for |
| `IRNF_VALIDATE_DRY`, `IRNF_VALIDATE_OUT` | `validate-configs.js` | Build only, and where to write |
| `IRNF_ENGINES` | probes | Which cores to run |
| `IRNF_DUMP`, `IRNF_VERBOSE` | `probe-reverse.js` | Debug output |

`IRNF_PROBE_BUF` and `IRNF_MODULES` belong to synced files (`configBuilder.js`, `modules.js`).

## Data and ports

| Item | Value | Status |
|---|---|---|
| Desktop data folder | Electron `userData` | V: `main.js` |
| Headless data folder | `~/.irnetfree-plus` by default, kept apart from a desktop install on purpose | V: `server.js` |
| Headless port | 6970, loopback | V: `server.js` `parseArgs` |
| Server tab metrics port | Free port picked at start, loopback only | V: `xserver/core.js`, `buildServerConfig` |
| Default new inbound | wildcard listen, port 443 | V: `xserver/config.js` `inboundDefaults`, `plus/xserver.js` |

## CI and release

| Workflow | Trigger | Does |
|---|---|---|
| `test.yml` | Every push and PR | `npm test` on three OSes. Then on Linux: fetches suggested cores, `validate-configs` on both, both probes |
| `dev-release.yml` | Push to `main` outside docs, or manual | `npm test`, build Windows (all platforms if asked), replace the rolling `dev` pre-release |
| `release.yml` | Tag `v*` or `x.y.z`, or manual | Build three OSes, sync version to the tag, checksums, publish. A tag with `-` is a pre-release. No tests (KI-02) |

Release rules (V): push a tag alone (D-020). `electron-builder` runs with `--publish never`; `softprops/action-gh-release` publishes. Checksum and artifact steps must not block publishing, so they use `continue-on-error`.

`release.yml` sets the build's version from the tag; `package.json` in git matches the latest tag (V: 3.3.3). A release is merged as a `Merge: Plus vX.Y.Z` commit, and the tag points at it (V: git log, `v3.3.3`). `npm run update-cdn-ranges` is manual and not tied to releases (KI-16).

### Publishing a release

**[V]** `.github/workflows/release.yml` runs when a tag `v*` (or `N.N.N`) is pushed, and builds Windows, macOS and Linux (`build` matrix) into the GitHub Release of that tag. Plus has no Android or router build.

1. Set the version in `package.json` and `package-lock.json`. Commit on `main`.
2. From the repository folder, tag and push:

   ```bash
   git tag -a v3.4.0 -m "v3.4.0"
   git push origin main v3.4.0
   ```

3. Follow the build on the repository's Actions tab; the files appear on the Releases page when it ends.

**[A]** A tag made on GitHub (Releases, Draft a new release, a new tag name, target `main`, Publish) should start the same workflow.

