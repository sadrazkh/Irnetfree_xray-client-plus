# IRNetFree Plus — fork identity, Server tab, IP-scan tab — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Spec: `docs/superpowers/specs/2026-09-09-plus-fork-server-scan-design.md` — the spec is authoritative for every interface named here.

**Goal:** Turn the fork at `E:\Cash.Net\source\repos\sadrazkh\Irnetfree_xray-client-plus` into "IRNetFree Plus": installs next to the original, merges upstream cheaply, and adds two tabs — a local Xray **server** panel with reverse proxy (bridge/portal), inbounds, clients, quotas and share links, and an **IP scanner** that tests a config through many IPs on every installed xray-format core and ranks them by measured speed and stability.

**Architecture:** All new behaviour is in new modules (`src/main/xserver/*`, `src/main/scan/*`, `src/renderer/plus/*`) exposing `register(ctx)` to a normalised context that `main.js` and `service.js` both build; upstream files carry only marked hook lines. Renderer additions are classic scripts after `app.js` that share its globals and register initialisers on `window.plusInit`; their strings come from `plus/*.i18n.js` through `window.i18n.extend`.

**Tech Stack:** Node 22 core only (`dependencies` stays empty), Electron 31, `node --test`, Xray 26.3.27 (official) and the PattN fork in `bin/`, `xray run -test` for validation. Branch: `main` of the fork (a separate repository, so no feature branch is needed); version 2.0.0, tag `v2.0.0`.

## Global Constraints

- Runtime code uses only Node core modules; `package.json` `dependencies` stays empty.
- `npm test` green; `npm run validate` green on both cores (`IRNF_XRAY_EXE` for the PattN core).
- `src/server/service.js` mirrors `src/main/main.js`: both build the same `ctx` and call the same `register()`; desktop-only behaviour is decided inside the module from `ctx.isElectron`.
- Upstream files get hook lines only, each marked `// plus` or `<!-- plus -->`; new code goes in new files. No refactoring of upstream code.
- Renderer: every string via `t()`; keys defined exactly once per language (in `plus/*.i18n.js` for the new tabs); logical CSS properties; tokens only (`--panel`, `--line`, `--ink*`, `--accent*`, `--ok`, `--warn`, `--danger`, `--r*`, `--mono`); no inline styles; `[hidden]` hides; element lookups by id must exist in `index.html` (the contract test).
- Owner's machine: never bind `0.0.0.0` in a test, never run `netsh`/`schtasks`, never kill `IRNetFree.exe`, never use ports 10808/10809/10085/10818/10819/10095 in tests; headless checks use `node src/server/server.js --port 39xx --data-dir <temp>`.
- Commits in the owner's name only, no `Co-Authored-By`. Subagents do not commit; the orchestrating session commits after each wave.
- `routing.rules` order is load-bearing everywhere.

Order: P1 (hooks) first, by the orchestrator. Then wave 1 = {P0, S1, C1} in parallel; wave 2 = {S2, R2}; wave 3 = R1; wave 4 = integration, live proof, docs, version, tag.

---

## File map

| File | Responsibility | Task |
|---|---|---|
| `package.json`, `package-lock.json`, `src/main/autostart.js`, `src/main/main.js` (DEFAULT_SETTINGS, APP_REPO), `src/server/service.js` (same), `src/renderer/index.html` (title), `README.md`, `docs/FORK.md`, `tests/autostart.test.js` | Plus identity, side-by-side defaults, sync docs | P0 |
| `src/renderer/i18n.js` (`extend` hook), `src/renderer/app.js` (`plusInit` hook), `src/renderer/index.html` (nav, sections, link/script tags), `tests/renderer.test.js` (plus files), `src/preload/preload.js`, `src/server/web-api.js`, `src/main/main.js`/`src/server/service.js` (ctx + register + teardown), stub `src/main/xserver/index.js`, stub `src/main/scan/index.js`, empty `src/renderer/plus/*` | Hook lines so later tasks touch only their own files | P1 |
| `src/main/xserver/config.js`, `tests/xserver.config.test.js`, `tests/xserver.links.test.js`, `scripts/validate-configs.js` (server shapes) | Model → Xray server JSON, validation, client records/links, other-side snippet | S1 |
| `src/main/xserver/core.js`, `src/main/xserver/index.js`, `tests/xserver.core.test.js` | Process lifecycle, stats/enforcer, channels | S2 |
| `src/main/scan/targets.js`, `substitute.js`, `score.js`, `probes.js`, `scanner.js`, `index.js`, `tests/scan.*.test.js` | IP expansion, address substitution, probes, batch runner, channels | C1 |
| `src/renderer/plus/scan.js`, `scan.css`, `scan.i18n.js`, `#view-scan` in `index.html` | Scan tab UI | R2 |
| `src/renderer/plus/xserver.js`, `xserver.css`, `xserver.i18n.js`, `#view-xserver` in `index.html` | Server tab UI | R1 |
| `README.md`, `docs/FORK.md`, version files | Docs, 2.0.0, tag | W4 |

---

### Task P1: hook lines (orchestrator, before any agent starts)

**Files:** listed in the file map row P1.

**Produces:**
- `window.i18n.extend({ fa: {...}, en: {...} })` — merges keys into both dictionaries; a key defined twice throws in development (`console.error`), so the contract test remains the guard.
- `window.plusInit` — array of `async (data) => {}` initialisers run at the end of `init()` after `renderPendingBanner()`.
- Nav: `<button class="nav-item pro-only" data-view="xserver">` (icon 🖧) after routing; `<button class="nav-item" data-view="scan">` (icon 📡) after it. Sections `#view-xserver` and `#view-scan` exist and are empty apart from their `.view-head` h2.
- Stylesheets `plus/xserver.css`, `plus/scan.css` linked after `skins.css`; scripts `plus/xserver.i18n.js`, `plus/scan.i18n.js` after `i18n.js`; `plus/xserver.js`, `plus/scan.js` after `app.js`.
- `tests/renderer.test.js`: `APP` = `app.js` + `plus/xserver.js` + `plus/scan.js`; `CSS_FILES` gains the two plus stylesheets; `I18N` = `i18n.js` + the two `*.i18n.js` files.
- `ctx` in both mirrors (spec §4) and the calls `createXServer(ctx).register()`, `createScan(ctx).register()`; `xserver.stop()` in `teardownForQuit` / `shutdown` after `xray.stop()`; `xserver.autoStart()` after the auto-connect block.
- `preload.js` / `web-api.js` methods: `xserverGet, xserverSet(model), xserverStart, xserverStop, xserverRestart, xserverStatus, xserverLog, xserverGenKeys, xserverGenId(kind), xserverClientLink({inboundId, clientId}), xserverPreview, xserverOtherSide, xserverFirewall({inboundId, allow}), onXServerStatus(cb), onXServerLog(cb), scanStart(req), scanStop, scanPresets, scanApply(req), scanExport(req), onScanProgress(cb)`.
- Stub modules: `createXServer(ctx)` → `{ register(){}, stop: async()=>{}, autoStart(){} }`; `createScan(ctx)` → `{ register(){} }`.

- [ ] Steps: make the edits above, run `npm test` (593 pass), commit `Plus: hook lines for the server and scan tabs`.

---

### Task P0: Plus identity and sync docs (Opus)

**Files:**
- Modify: `package.json` (name `irnetfree-plus`, version `2.0.0`, description, `build.appId` `com.irnetfree.plus`, `build.productName` `IRNetFree Plus`, `nsis.shortcutName` `IRNetFree Plus`, every `artifactName` `IRNetFree-Plus-…`), `package-lock.json` (name/version at lines 2–3 and 8–9), `src/main/autostart.js` (`TASK = 'IRNetFreePlus'`), `src/main/main.js` and `src/server/service.js` (`DEFAULT_SETTINGS.socksPort 10818`, `httpPort 10819`, `apiPort 10095`; one `APP_REPO = 'sadrazkh/Irnetfree_xray-client-plus'` constant used by the update check and the release asset URL guard), `src/renderer/index.html` (title `IR<b>NETFREE</b> <span class="tb-plus">PLUS</span>`, styled in `styles.css` next to `.tb-title`), `README.md` (a top note: what Plus adds, link to `docs/FORK.md`), `docs/FORK.md` (fa + en: relationship, remotes, sync commands, conflict policy, where new code lives), `tests/autostart.test.js` (task name).
- Do not touch `android/`, `backup.js` (`app: 'IRNetFree'` stays), i18n `app.name`.

**Interfaces:** `APP_REPO` is a module-level `const` in both mirrors; every place that had the literal `sadrazkh/Irnetfree_xray-client` now uses it (`grep -rn "Irnetfree_xray-client" src` must return only the `APP_REPO` lines).

- [ ] **Step 1:** `grep -rn "Irnetfree_xray-client\|IRNetFree-Setup\|IRNetFree-Portable\|com.irnetfree\|10808\|10809\|10085\|TASK = " src package.json tests` and list every hit before editing.
- [ ] **Step 2:** Make the edits. Update the tests that pinned the old values (`tests/autostart.test.js`; any settings test that asserts 10808/10809/10085 as defaults).
- [ ] **Step 3:** `npm test` → all pass. `node -e "console.log(require('./package.json').build.appId)"` → `com.irnetfree.plus`.
- [ ] **Step 4:** Write `docs/FORK.md` and the README note. Report the list of changed files.

---

### Task S1: server config builder (Fable)

**Files:**
- Create: `src/main/xserver/config.js`, `tests/xserver.config.test.js`, `tests/xserver.links.test.js`
- Modify: `scripts/validate-configs.js` (append the server shapes to what it validates)

**Interfaces (Produces — S2, R1 and the validate script rely on these exact names):**

```js
// src/main/xserver/config.js
module.exports = {
  DEFAULT_MODEL,              // spec §2.1 with empty inbounds
  PROTOCOLS: ['vless', 'vmess', 'trojan', 'shadowsocks'],
  NETWORKS: ['tcp', 'ws', 'grpc', 'xhttp'],
  SECURITIES: ['none', 'tls', 'reality'],
  SS_METHODS: ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', 'aes-256-gcm', 'aes-128-gcm', 'chacha20-ietf-poly1305'],
  normalizeModel(raw),        // fills defaults for every missing field, never throws
  newInbound(protocol, overrides = {}),   // fresh id/tag/port defaults per protocol
  newClient(protocol, overrides = {}),    // fresh id + uuid/password
  slugTag(remark, id),        // 'vless-reality-a1b2' — [a-z0-9-] only, unique with the id suffix
  randomShortId(),            // 8 bytes hex
  randomPassword(bytes = 16), // base64 (ss2022 keys use 16 bytes for aes-128, 32 for aes-256 → randomKeyFor(method))
  randomKeyFor(method),
  parseX25519(stdout),        // { privateKey, publicKey } | null — both output forms (spec §2.2)
  validateModel(model, { servers }),      // { ok, errors: [{ path, msg }], warnings: [{ path, msg }] }
  buildServerConfig(model, { apiPort, servers, geoAvailable }),   // Xray JSON (spec §2.2)
  clientServerRecord(inbound, client, model, { address }),        // client-side server record for buildShareLink
  clientLink(inbound, client, model, { address }),                // buildShareLink(clientServerRecord(...))
  otherSideSnippet(model, { servers, address })                   // { snippet: object, link: string|null, role: 'portal'|'bridge'|null }
};
```

Rules the tests must pin (write them first):

- [ ] **Step 1: golden shapes** (`tests/xserver.config.test.js`): for each of `vless+tcp+reality (flow vision)`, `vless+ws+tls`, `vless+grpc+tls`, `vless+xhttp+none`, `vmess+ws+none`, `trojan+tcp+tls`, `shadowsocks (2022) + shadowsocks (aes-256-gcm)` assert the exact inbound object (protocol, `settings.clients` contents incl. `email`, stream settings shape, `sniffing`). Assert `metrics.listen === '127.0.0.1:<apiPort>'`, `stats`, `policy` present; outbounds order `['exit','block']`; `blockPrivate` → first rule `ip: ['geoip:private']` when `geoAvailable`, the literal private list when not; `blockTorrent` rule second; disabled inbound and disabled client omitted; `exit.type === 'server'` → outbound tag `exit` is a clone of the stored server's outbound with `applyCertPin` semantics (use `tests/fixtures.js` records).
- [ ] **Step 2: reverse** — bridge: `reverse.bridges = [{ tag:'bridge', domain }]`, outbounds `['exit','block','interconn']`, rules end with `{ inboundTag:['bridge'], domain:['full:<domain>'], outboundTag:'interconn' }` then `{ inboundTag:['bridge'], outboundTag:'exit' }` in that order; `via:'link'` parses the link with `parseLink`; `via:'server'` uses the stored record. Portal: `reverse.portals = [{ tag:'portal', domain }]`, rules `{ inboundTag:[interconnTag], outboundTag:'portal' }` then `{ inboundTag:[userTags…], outboundTag:'portal' }`; a non-selected inbound has no rule. Validation errors: interconn also a user inbound; no user inbounds; missing domain; bridge with no target.
- [ ] **Step 3: validation** — duplicate tags, duplicate emails across inbounds, port collision on the same listen, TLS without files, Reality without key/serverName/shortId, ws/xhttp without path, inbound with no enabled client → warning not error, `normalizeModel({})` equals `DEFAULT_MODEL` and `normalizeModel` on a full model is idempotent.
- [ ] **Step 4: links** (`tests/xserver.links.test.js`): for every golden inbound, `parseLink(clientLink(...))` yields a server whose `address`/`port` match `{ address }` and whose outbound would reach the inbound: vless `users[0].id === client.uuid`, `flow` matches, `streamSettings.network/security` match, `tlsSettings.serverName`/`realitySettings.publicKey/shortId/serverName` match, ws `path`/`Host`, grpc `serviceName`, xhttp `path/host`, vmess `id`, trojan `password`, ss `method:password` and for ss2022 the `serverKey:userKey` form. `clientLink` with an empty `address` throws `'no public address'`.
- [ ] **Step 5: other side** — bridge here → snippet has `reverse.portals`, `routing.rules` for the interconn and user inbounds it cannot know (use placeholders `"<user-inbound-tag>"`), `link: null`; portal here → snippet has `reverse.bridges`, an `outbounds[0]` built from the interconn inbound's first enabled client (tag `interconn`), the two bridge rules, and `link` = that client's share link.
- [ ] **Step 6: implement** `config.js` to make all of the above pass; `x25519` parsing covers `PrivateKey: … / Password (PublicKey): …` (26.x) and `Private key: … / Public key: …` (older).
- [ ] **Step 7: validate script** — in `scripts/validate-configs.js` add a `serverShapes()` list (the golden models above + bridge + portal) built with `buildServerConfig`, run through the same `xray run -test` loop, counted in the summary. Run `npm run validate` and `IRNF_XRAY_EXE=bin/xray-pattn.exe npm run validate`: every server shape passes on both cores. Paste the summary lines in the report.
- [ ] **Step 8:** `npm test` green. Report: files, test counts, any spec deviation with the reason.

---

### Task C1: scan backend (Fable)

**Files:**
- Create: `src/main/scan/targets.js`, `src/main/scan/substitute.js`, `src/main/scan/score.js`, `src/main/scan/probes.js`, `src/main/scan/scanner.js`, `src/main/scan/index.js` (replace the P1 stub), `tests/scan.targets.test.js`, `tests/scan.substitute.test.js`, `tests/scan.score.test.js`, `tests/scan.scanner.test.js`, `tests/scan.probes.test.js`

**Interfaces (Produces):**

```js
// targets.js
expandTargets(text, { max = 5000 } = {}) → { ips: string[], errors: [{ line, msg }] }   // IPv4 only; CIDR /8–/32; a-b ranges; '#' comments; dedupe
sampleTargets(text, n, rng = Math.random) → string[]                                  // spread across all ranges, not the first n
CF_IPV4_RANGES: string[]                                                             // the 15 published Cloudflare IPv4 blocks

// substitute.js
withAddress(server, ip) → server   // deep copy; spec §3.2; throws 'unsupported protocol' for wireguard/socks/http

// score.js
scoreResult(r) → number            // spec §3.2 formula; 0 when delay.loss === 1 or no delay
delayStats(samplesMs: number[] /* -1 = failed */) → { min, avg, jitter, loss, samples }

// probes.js
delaySeries(socksPort, { n = 3, host = 'cp.cloudflare.com', port = 80, path = '/', timeout = 8000 })
downloadThroughProxy(socksPort, { host, port = 443, path, tls = true, bytes = 10e6, maxMs = 8000, timeout = 8000 })
   → { ok, bytes, ms, ttfb, mbps, error }
uploadThroughProxy(socksPort, { host, port = 443, path, tls = true, bytes = 2e6, timeout = 20000 }) → same shape

// scanner.js
runScan({ server, ips, engines, tests: { tcp, delay, down, up }, opts: { concurrency = 8, batch = 20, delaySamples = 3, downBytes, downMaxMs, downHost, downPath, upHost, upPath }, xray, onResult, onProgress, token: { cancelled: false } })
   → Promise<{ results: Result[], cancelled: boolean }>
// Result = { ip, engine, tcp: { ok, ms }|null, delay: {...}|null, down: {...}|null, up: {...}|null, score, error: string|null }

// index.js
createScan(ctx) → { register(), stop(), busy() }
```

- [ ] **Step 1: targets tests** — `1.1.1.1`, `1.1.1.0/30` → 4 addresses, `10.0.0.1-10.0.0.3`, mixed lines with a comment and a bad line reported in `errors`, dedupe keeps first order, `max` truncates, `/8` is expanded lazily (no 16M array: implement with a generator and stop at `max`); `sampleTargets` on two ranges with `n=4` returns 2 from each with a seeded rng; `CF_IPV4_RANGES` are 15 valid CIDRs.
- [ ] **Step 2: substitute tests** — vless ws tls with hostname address: `address` and `vnext[0].address` become the IP, `tlsSettings.serverName` stays `a.example.com`, `wsSettings.headers.Host` filled from the original address when it was empty; trojan `servers[0].address`; reality `serverName` unchanged; original object untouched (deep copy); `_fragment` kept; wireguard throws.
- [ ] **Step 3: score tests** — more download = higher score; loss 1 → 0; jitter lowers; delay-only mode uses base 1000; `delayStats([50, 70, -1])` → min 50, avg 60, loss 1/3, jitter = mean absolute deviation of the successful samples.
- [ ] **Step 4: probes** — `downloadThroughProxy` over a **local** SOCKS5 stub (write a tiny SOCKS5 server in the test that CONNECTs to a local `http.createServer` streaming N bytes) with `tls:false`: asserts `bytes`, `ttfb ≥ 0`, `mbps > 0`, honours `maxMs`; `uploadThroughProxy` likewise against a local sink; timeout → `{ ok:false, error:'timeout' }`. TLS path: `tls.connect({ socket, servername })` — unit-covered only by a test with a self-signed cert if `tests/fixtures/` has one, otherwise by the live check in W4 (say which in the report).
- [ ] **Step 5: scanner** — inject a fake `xray` (`{ binExists: () => true, startTest: async (cfg, engine) => ({ proc: null, cleanup }) }`) and fake probes through an `opts.probes` override; assert: batches of `batch` size per engine, `onResult` once per ip×engine as each finishes, `onProgress({ done, total })` monotonic, `token.cancelled = true` mid-run stops scheduling and calls `cleanup`, a `startTest` rejection marks that batch's ips `error` and continues with the next batch, `results` sorted by score desc.
- [ ] **Step 6: index.js** — `scan:start` builds the target list, resolves the server (`ctx.resolveTarget(serverId).server` or `parseLink(link)`), refuses `busy`, refuses WireGuard/socks/http with `{ error: 'unsupported protocol' }`, refuses 0 targets, streams `scan-progress` events (`{ runId, done, total, result }` per result, then `{ runId, done, total, finished: true, cancelled }`); `scan:stop`; `scan:presets` → `{ cfRanges: CF_IPV4_RANGES, defaults: {...opts defaults…} }`; `scan:apply` → `ctx.addServer(withAddress(server, ip) with name '<name> [ip]' and a fresh id)` and returns the record; `scan:export` → CSV (header `ip,engine,tcp_ms,delay_min,delay_avg,jitter,loss,down_mbps,up_mbps,score,error`) or JSON. Persist the last request (minus results) in `ctx.store` key `scan`.
- [ ] **Step 7:** `npm test` green. Report: files, tests, the exact result object shape, how `tls` probes were verified.

---

### Task S2: server core and channels (Fable) — after S1

**Files:**
- Create: `src/main/xserver/core.js`, `tests/xserver.core.test.js`
- Modify: `src/main/xserver/index.js` (replace the P1 stub with the real `createXServer(ctx)`)

**Interfaces:** consumes S1 exactly; produces the channels and events of spec §2.4, `createXServer(ctx) → { register(), stop(), autoStart(), status() }`.

`class ServerCore({ dataDir, xray, getModel, setModel, send, log, engineOf })` with `start()`, `stop()`, `restart()`, `status()`, `logLines()`, and injectable `spawn`, `now`, `queryVars` for tests.

- [ ] **Step 1: tests first** — with a fake `spawn` (an `EventEmitter` with `pid`, `kill`, `stdout`/`stderr` streams) and a fake `queryVars`: `start()` writes `<dataDir>/xserver/config.json`, calls `xray.validate` first and returns `{ ok:false, error }` without spawning when it fails; state transitions `stopped → starting → running` once `queryVars` answers; an exit while `running` schedules restarts at 2 s / 5 s / 15 s (fake timers via injected `setTimeout`) then `error`; `stop()` cancels them; a tick adds `/debug/vars` user deltas to `client.used` and marks `online`; quota reached → `enabled:false, disabledBy:'quota'` and one debounced restart; expiry likewise; raising the quota re-enables on the next tick; `parseX25519` wiring; `firewallArgs(tag, port, allow)` returns the exact `netsh` argument arrays; log ring caps at 300.
- [ ] **Step 2: implement** `core.js`. Status payload: `{ state, pid, since, engine, apiPort, error, inbounds: [{ id, tag, port, up, down, clients: [{ id, email, up, down, online }] }] }`. Log lines pushed on `xserver-log` with a level parsed from xray's `[Warning]`/`[Error]` prefixes.
- [ ] **Step 3: channels** in `index.js` per spec §2.4. `xserver:genKeys` runs `<bin> x25519` via `execFile` with the engine's binary from `ctx.xray.resolveEngine(model.engine, { quiet:true })`. `xserver:genId` kinds: `uuid` (`crypto.randomUUID()`), `password`, `shortId`, `ss2022:<method>`. `xserver:firewall`: Windows only, `execFile('netsh', firewallArgs(...))`; elsewhere `{ ok:false, error:'unsupported' }`. `autoStart()`: when `model.autoStart`, `setTimeout(start, 1500)`. Every handler returns `{ ok:false, error }` instead of throwing.
- [ ] **Step 4:** `npm test` green. Then a **local live check** (allowed: 127.0.0.1 only): with `node -e` create a model with one `vless+tcp+reality` inbound on `listen: '127.0.0.1'`, a high port, one client; start the core with `dataDir` under `%TEMP%`; from the generated `clientLink` build a client test config (`configBuilder.buildTestConfig(parseLink(link), port)`), `xray.startTest` it, and `httpThroughProxy` `cp.cloudflare.com` through it — must be `ok`. Then read `status()` and show the client's counters moved. Stop everything, remove the temp dir. Paste the output in the report.

---

### Task R2: scan tab UI (Opus) — after C1 and P1

**Files:**
- Create: `src/renderer/plus/scan.js`, `src/renderer/plus/scan.css`, `src/renderer/plus/scan.i18n.js`
- Modify: `src/renderer/index.html` — only inside `#view-scan`

**Consumes:** `window.api.scanStart/scanStop/scanPresets/scanApply/scanExport/onScanProgress` (P1), result shape from C1, `state.servers`, `renderServers()`, `renderPicker()`, `makeSearchSelect`, `toast`, `escapeHtml`, `fmtBytes`, `copyText`.

- [ ] **Step 1: markup** per spec §3.3 with ids prefixed `scan…` (`#scanSource`, `#scanLink`, `#scanIps`, `#scanCount`, `#btnScanCf`, `#btnScanSample`, `#scanSampleN`, `#scanFile`, `#btnScanFile`, `#scanEngines`, `#scanTests`, `#scanConc`, `#scanBatch`, `#scanSamples`, `#scanDownMb`, `#scanDownHost`, `#scanDownPath`, `#btnScanStart`, `#btnScanStop`, `#scanProgress`, `#scanProgressText`, `#scanTable`, `#scanTbody`, `#scanEmpty`, `#btnScanRetop`, `#btnScanExportCsv`, `#btnScanExportJson`, `#btnScanClear`). Every visible string via `data-i18n` / `t()`; keys `scan.*` in `scan.i18n.js` (fa + en, once each).
- [ ] **Step 2: behaviour** — on `plusInit`: load presets, restore the last request from `state`-independent `window.api.scanPresets().defaults` and the stored last inputs (returned by `scan:presets` as `last`), fill the stored-server picker (xray-format protocols only), disable engines that are not installed (`state.assets`), count targets as the textarea changes (client-side count via a small copy of the CIDR arithmetic is NOT allowed — ask main: add nothing; instead show the count returned by `scan:start` and a plain line count before). Start → `scanStart(req)`; progress rows are inserted/updated by `ip+engine` key (`data-key`), not re-rendered wholesale; sorting by clicking headers; Stop; *use this IP* → `scanApply` → `state.servers.push(record); renderServers(); renderPicker(); toast(t('scan.applied'))`; export via a Blob download; re-test top N reuses the current request with the top N ips.
- [ ] **Step 3: styling** in `scan.css`: table with sticky header, monospace numbers, colour classes `.ping-good/.ping-mid/.ping-bad` reused for delay, a score bar cell; responsive at 900 px (the table scrolls inside its card, the form wraps).
- [ ] **Step 4:** `npm test` green (contract test). Headless check: `node src/server/server.js --port 3993 --data-dir %TEMP%\irnf-plus-r2`, open in the browser pane, switch to the tab, paste `127.0.0.1` and a local link, run a scan with only `tcp` ticked — the row appears; Stop works; export downloads. Report with what was seen.

---

### Task R1: server tab UI (Opus) — after S2 and P1

**Files:**
- Create: `src/renderer/plus/xserver.js`, `src/renderer/plus/xserver.css`, `src/renderer/plus/xserver.i18n.js`
- Modify: `src/renderer/index.html` — only inside `#view-xserver` and two modals appended before `</body>` marked `<!-- plus -->`

**Consumes:** `window.api.xserver*` (P1), the model and status of S1/S2, `state.servers`, `makeSearchSelect`, `renderOptionCards` pattern (copy the option-card markup, do not call the settings function), `vendor/qrcode.js` (see `showServerQr` in app.js for usage), `toast`, `escapeHtml`, `fmtBytes`, `copyText`.

- [ ] **Step 1: markup** per spec §2.5 with ids prefixed `xs…` (`#xsState`, `#xsEngine`, `#xsUptime`, `#btnXsStart`, `#btnXsStop`, `#btnXsRestart`, `#xsAutoStart`, `#xsPublicAddr`, `#btnXsPreview`, `#xsInbounds`, `#xsInboundsEmpty`, `#btnXsAddInbound`, `#xsReverseRole` (select, rendered as option cards into `#xsReverseCards`), `#xsReverseDomain`, `#xsBridgeVia`, `#xsBridgeServerMount`, `#xsBridgeLink`, `#xsPortalInterconn`, `#xsPortalUsers`, `#btnXsOtherSide`, `#xsExitType`, `#xsExitServerMount`, `#xsBlockPrivate`, `#xsBlockTorrent`, `#xsLog`, `#xsErrors`); modals `#xsInboundModal` (fields `#xiRemark`, `#xiProtocol`, `#xiListen`, `#xiPort`, `#xiNetwork`, `#xiPath`, `#xiHost`, `#xiService`, `#xiSecurity`, `#xiCert`, `#xiKey`, `#xiSni`, `#xiRealityDest`, `#xiRealityNames`, `#xiRealityPriv`, `#xiRealityPub`, `#btnXiGenKeys`, `#xiRealityShort`, `#btnXiGenShort`, `#xiSsMethod`, `#xiSsPassword`, `#btnXiGenSsPass`, `#xiSniffing`, `#btnXiSave`, `#btnXiCancel`) and `#xsClientModal` (`#xcEmail`, `#xcSecret`, `#btnXcGen`, `#xcFlow`, `#xcExpiry`, `#xcQuotaGb`, `#xcNote`, `#xcEnabled`, `#btnXcSave`, `#btnXcCancel`), a preview modal `#xsPreviewModal` (`#xsPreviewJson`, `#btnXsPreviewCopy`, `#btnXsPreviewClose`) and a QR/link modal reuse of the existing `#qrModal` if present (check `index.html`; otherwise add `#xsLinkModal`). All strings `xs.*` in `xserver.i18n.js`.
- [ ] **Step 2: behaviour** — one local `xs = { model, status, engines }`; `load()` = `xserverGet` → render; every edit → `xserverSet(model)` → replace `xs.model` from the reply and show `errors` under `#xsErrors` and next to the card whose `path` matches (`inbounds[2].port`); Start/Stop/Restart → status; `onXServerStatus` updates the pill, uptime, per-client counters and online dots in place (`data-xs-client` hooks, no re-render); `onXServerLog` appends to `#xsLog` (cap 300, follow); inbound editor shows/hides fields by protocol/network/security (`[hidden]`); the Reality "generate" button fills both keys; client link/QR from `xserverClientLink`; other-side button copies the snippet and shows the link; firewall button visible only on `state.platform === 'win32'`.
- [ ] **Step 3: styling** `xserver.css`: inbound cards (reuse `.card`, `.proto-badge`, `.switch`, `.usage-bar`), client rows grid, reverse diagram (two nodes and an arrow built from tokens, flips with `dir`), state pill colours by `data-state`.
- [ ] **Step 4:** `npm test` green. Headless check on `--port 3992`: add a `vless+reality` inbound on `127.0.0.1` and a high port, generate keys, add a client, Start → pill `running`, copy link → it parses (`node -e` with `parseLink`), the log shows the core's start lines; switch the reverse role to portal and see the validation message when no user inbound is chosen; Stop. Report with what was seen.

---

### Task W4: integration, live reverse proof, docs, release (orchestrator, Fable)

- [ ] `npm test`, `npm run validate` on both cores, `node scripts/probe-dns-leak.js` (unchanged behaviour), `npm run probe:wg`.
- [ ] Live local reverse proof (spec §5): two `ServerCore` instances in temp data dirs — portal with `interconn` (vless+tcp+none on 127.0.0.1:P1, one client) and `users` (vless+ws+none on 127.0.0.1:P2, one client); bridge with `via:'link'` = the interconn client's link and `exit: direct`; a throwaway client core dialling P2's link; `httpThroughProxy` → `ok`, and the bridge's `exit` outbound counters moved while the portal's `exit` did not.
- [ ] Browser walk-through of both tabs at 900 px and 1400 px in all three skins; no overflow.
- [ ] README (fa/en sections for the two tabs, side-by-side note), `docs/FORK.md` final, version 2.0.0 everywhere (`package.json`, `package-lock.json` ×2), commit `v2.0.0`, annotated tag `v2.0.0` (Persian message), `git push -u origin main --tags` — if the GitHub repository does not exist yet, report the exact two steps for the owner.
