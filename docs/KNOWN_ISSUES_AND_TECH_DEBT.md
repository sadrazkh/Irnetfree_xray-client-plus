Last verified: 2026-11-08
Scope checked: own code, workflows and existing docs, read at v3.3.3. Nothing was run, so these come from reading code, not from seeing them fail. Labels: V / A / R, see `MASTER_CONTEXT.md`.

# Known issues and tech debt

Severity is a judgement (A). Priorities for fixing them are in `ROADMAP.md`.

## Bugs and gaps

| ID | Sev | Issue | Reference (V) |
|---|---|---|---|
| KI-01 | Med | The firewall button only adds a rule. The page always sends `allow: true`, so the delete path is unreachable, and deleting an inbound leaves its rule behind. TCP only | `plus/xserver.js` `xserverFirewall` call; `xserver/core.js` `firewallArgs`; `xserver/index.js` `xserver:firewall` |
| KI-02 | Med | A tag build publishes installers with no test or core gate. It also uses Node 20 where the tests need 21 or newer, so tests could not simply be added as they are | `.github/workflows/release.yml`; compare `dev-release.yml` and `test.yml` |
| KI-03 | Med | The headless panel is plain HTTP. On a non-loopback bind the token and every config cross the network unencrypted, and the token is printed in, and travels in, the URL | `src/server/server.js` `authed`, listen log; `web-api.js` `invoke`, `connect` |
| KI-04 | Med | `--no-auth` on a public bind leaves the whole API open, including server control and core download. Allowed by design, nothing warns | `server.js` `parseArgs`; `guard.js` `hostAllowed` |
| KI-05 | Med | Credentials are plaintext at default file modes: `store.json` holds configs and the model's private keys, and `xserver/config.json` holds the running keys | `xserver/core.js` `_start`; synced `store.js`. The data folder is created with default mode in `service.js` |
| KI-06 | Med | No automated test boots `server.js`: request routing, auth order and static confinement are untested | `tests/` has no `require` or spawn of it |
| KI-07 | Low | `configs:list` returns whole records with keys, to the page and over RPC, though `summary()` says "no keys, no outbound". `summary` is used only for `add`'s reply | `plus/configs.js` `summary`, final `return` comment |
| KI-08 | Low | `speedTop` is silently capped at `batch`: the page allows 50 with batch 20. A test pins the cap, though `speedPhase` already batches, so the reason is unclear | `scanner.js` `makeContext`; `tests/scan.scanner.test.js`; `index.html` `scanSpeedTop` |
| KI-09 | Low | `scan:retest` does not check the `starting` flag. A retest racing a start in its last `await` can launch a second run and overwrite `run`, leaving the first unstoppable | `scan/index.js` `start`, `startRun`, `retest`, `launch` |
| KI-10 | Low | A POST body over 5 MB destroys the request, and the `readBody` promise never settles | `server.js` `readBody` |
| KI-11 | Low | Quota is approximate. Traffic since the last 5 s tick is lost at each stop or restart, and a client can overrun by up to about 15 s (tick plus restart debounce). A membership change restarts the core and drops every connection | `xserver/core.js` `_tick`, `stop`, `_scheduleRestart` |
| KI-12 | Low | If `buildMultiTestConfig` throws in the engine gate, all cores pass ungated with no message | `scan/index.js` `gateEngines` |

## Limitations by design

| ID | Limitation | Reference (V) |
|---|---|---|
| KI-13 | The path check cannot detect a kernel VPN such as plain WireGuard or OpenVPN. README says so | `scan/upstream.js`, README |
| KI-14 | The IRNetFree store path is inferred (`irnetfree` beside the Plus data folder, else the OS app-data folder). A packaged install's real folder names are not verified (A) | `plus/configs.js` `irnetfreeStorePath` |
| KI-15 | `all` mode has no cap, so a very large range plus many ports runs for as long as it takes. Only the summary line warns of the size | `scan/index.js` `PICK_DEFAULTS` |
| KI-16 | Cloudflare's ranges are constants in `targets.js`. `update-cdn-ranges` only reports when they move; the shipped CDN file refreshes only when someone runs it. Not a release step | `scripts/update-cdn-ranges.js` |
| KI-26 | A client's `limitIp` is stored and shown but not enforced: the core cannot do it without its API | `xserver/config.js` `normalizeClient` |
| KI-27 | Builds are unsigned on macOS and Windows, so an OS may refuse or warn at first launch | `package.json` `build` (no signing identity); README first-run section |

## Debt and drift

| ID | Item | Reference (V) |
|---|---|---|
| KI-17 | Stale comments. `release.yml` names `src/main/appUpdate.js`, which does not exist, and an in-app update that verifies checksums (the app only links). `xserver/index.js` header omits `wizard` and `coreInfo` and speaks of mirrors and a client auto-connect. `dev-release.yml` speaks of a private repository's minutes | Those files |
| KI-18 | Leftovers from the client: `.gitattributes` rules for `openwrt/**` and `install.sh`; privileged-script patterns in `tests/noNetwork.preload.js`; the "older callers" paths `withAddress`, `expandTargets`, `buildTargets` and `ips`, now used only by tests or legacy input | Those files; grep of callers |
| KI-19 | `docs/superpowers/` describes past states: a 5000-target cap (now none), `tests/upstreamSync.test.js` (now in `plusShell.test.js`), channel `configs:importIrnetfree` (now `configs:import`), `docs/FORK.md` (gone) | Compare with `scan/index.js`, `tests/`, `apiMap.js` |
| KI-20 | Defaults repeated with different values: tests in `scan/index.js`, `scanner.js`, `plus/scan.js`; delay timeout 4000 and 8000 in `index.js` and `probes.js`. The service's values win at runtime | `DEFAULT_TESTS`, `PRESET_DEFAULTS`, `DELAY_DEFAULTS` |
| KI-21 | `usesFinalmask` copies an unexported upstream rule, and `argOf` is duplicated for the browser. Both can drift | `scan/index.js`; `web-api.js`; `docs/SYNC.md` |
| KI-22 | `docs/SYNC.md` "What is Plus's own" omits `scripts/update-cdn-ranges.js` | `docs/SYNC.md` |
| KI-23 | The English README's FAQ lists what the app contacts but omits the reserved-address check and the ECH resolver. The Persian README links to `GUIDE.md`, which has the full list | `README.en.md` FAQ; `GUIDE.md` privacy table |
| KI-24 | Electron is `^31` (lock 31.7.7), probably past upstream support (A); `sandbox: false` in the window | `package.json`, `package-lock.json`, `main.js` |
| KI-25 | Upstream may have moved past the synced `v1.41.0`. Not checkable without network (A) | `upstream-sync.json` |
