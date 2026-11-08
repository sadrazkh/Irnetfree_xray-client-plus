Last verified: 2026-11-08
Scope checked: `docs/superpowers/`, `docs/SYNC.md`, tag and commit messages, source comments, against the code at v3.3.3. Dates are of the spec or commit that records the decision. Where the reasoning is not recorded anywhere it says `Unknown / reconstructed from code`.

# Decisions and rationale

## D-001: Plus is a tool app, not a fork of the client  (2026-10-15)
- **Context:** until v2.2 Plus was the whole client with two extra tabs. Each sync was a merge with about eleven conflicts, plus identity fixes in upstream's tests and Android, router and macOS-native builds Plus never needed. Scan and Server needed 13 of upstream's 104 `src` files.
- **Decision:** remove the client. Keep Scan, Server, Configs, Settings, Log. The owner chose "only tools, no client" and to keep the Server tab.
- **Alternatives considered:** keep the full fork and merge (rejected for the cost above).
- **Consequences / limitations:** no connect, TUN, routing, subscription fetch by URL, Android or router here; results go to IRNetFree as links.
- **Do not change without reconsidering:** adding any client feature brings back the merge problem.
- **Status:** Verified in code (`docs/superpowers/specs/2026-10-15-plus-v3-tool-app-design.md`, commit `9c80355`, `apiMap.js`)

## D-002: Shared code is synced verbatim with hashes, never merged or edited  (2026-10-15)
- **Context:** the client and Plus must agree on links and config shapes, and merges were too costly (D-001).
- **Decision:** `upstream-sync.json` lists each shared file with a sha256. One script takes a ref. A test fails on any edit. When Plus needs something different, it wraps the file or builds on its exports.
- **Alternatives considered:** a marked-line fork kept mergeable (`docs/FORK.md` in v2.x; rejected, see D-001). Reasons for not using a package or submodule: Unknown / reconstructed from code.
- **Consequences / limitations:** fixes to shared code must happen upstream. Synced files carry code Plus never calls (the `configBuilder` dependency tree).
- **Do not change without reconsidering:** do not "just patch" a synced file, even for a one-line fix.
- **Status:** Verified in code (`scripts/sync-upstream.js`, `tests/plusShell.test.js`, `docs/SYNC.md`)

## D-003: One service and one API map for both front ends  (2026-10-15)
- **Context:** v2 mirrored `main.js` and `service.js`, and the mirrors had to be kept in step.
- **Decision:** `createPlusService` backs both, and `apiMap.js` is plain data that both bridges build `window.api` from.
- **Alternatives considered:** the v2 mirrors (rejected for the duplication).
- **Consequences / limitations:** `argOf` is duplicated for the browser (KI-21).
- **Do not change without reconsidering:** a feature must not exist in only one front end, except window controls.
- **Status:** Verified in code (`src/main/plus/service.js`, `apiMap.js`, `tests/plusShell.test.js`)

## D-004: No administrator rights, one elevated command on demand  (2026-10-15)
- **Context:** nothing Plus does needs admin except the Windows firewall rule.
- **Decision:** Windows builds are `asInvoker`. `elevate.js` tries `netsh` first and goes through UAC only when Windows says elevation is needed.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** an inbound on a privileged port on Linux or macOS is not handled (A: the page's default inbound port is 443).
- **Do not change without reconsidering:** no feature should raise the whole process's privileges.
- **Status:** Verified in code (`package.json` `requestedExecutionLevel`, `plus/elevate.js`)

## D-005: Same app id and data folder across versions, side by side with the client  (2026-10-15)
- **Context:** v2 users have configs, a server model and scan memory.
- **Decision:** keep `com.irnetfree.plus` and the store format. Keep v2 store keys such as `servers` and leave unknown settings untouched.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** compatibility paths stay in code (`migrateModel`, integer `scanTested` entries, `concurrency`).
- **Do not change without reconsidering:** renaming a store key loses user data.
- **Status:** Verified in code (`plus/service.js`, `plus/configs.js`, `tests/plusService.test.js`)

## D-006: Scan in two phases with separate concurrency  (2026-09-17)
- **Context:** one phase with one concurrency made downloads share the link, so per-address speeds were a fraction of the truth, and scans were slow.
- **Decision:** a wide, cheap filter, then a speed test on only the best rows per engine, one transfer at a time by default.
- **Alternatives considered:** the single phase (rejected for the above).
- **Consequences / limitations:** a speed figure exists only for the top rows.
- **Do not change without reconsidering:** raising `speedConcurrency` measures a share of the link, not the target.
- **Status:** Verified in code (`scan/scanner.js`, spec 2026-09-17 §1)

## D-007: Random draws are new every run, with a tested-address history  (2026-09-25)
- **Context:** expansion in order, capped, always tested the same first addresses, and the old random button froze one fixed list.
- **Decision:** draw in main at each start. Keep tested addresses under `scanTested` (cap 50,000) and skip them while a range has others.
- **Alternatives considered:** the fixed list (rejected, same list every time).
- **Consequences / limitations:** the history is per device and not kept for runs over 50,000 rows.
- **Do not change without reconsidering:** results are never stored, only addresses tested.
- **Status:** Verified in code (`scan/index.js`, spec 2026-09-25)

## D-008: Address ranges are lazy spaces, with no address cap  (2026-11-01)
- **Context:** the owner wanted all addresses or N from all ranges together. A list of a `/8` cannot be held in memory.
- **Decision:** a range stays two integers and is walked by index. A sample is N indices. The earlier 5000-target cap is gone.
- **Alternatives considered:** the cap (rejected by the request).
- **Consequences / limitations:** a run can be very long (KI-15). IPv6 blocks stay sampled.
- **Do not change without reconsidering:** never expand a space into an array on the page or in main.
- **Status:** Verified in code (`scan/targets.js`, commit `22215e7`)

## D-009: A pass is the expected answer on most samples; rank by success, then latency  (2026-11-01)
- **Context:** the old probe counted any status below 500, so a block page passed. One lucky answer passed. One dropped packet killed a good target. The old score let a fast, lossy target beat a slower clean one.
- **Decision:** the exact expected status through the tunnel, on `passRatio` of samples (two of three by default). Timeouts retry; definitive failures stop. Score is success %, then median, then jitter. Download Mbps is not in the score.
- **Alternatives considered:** v3.0's formula, base x (1 - loss) / latency / jitter (rejected as above).
- **Consequences / limitations:** a custom probe page must state its expected status, or any 2xx or 3xx counts.
- **Do not change without reconsidering:** the rule is the owner's stated order.
- **Status:** Verified in code (`scan/score.js`, `scan/probes.js`)

## D-010: The parameter matrix reads upstream's presets instead of copying them  (2026-11-01)
- **Context:** the owner wanted a config's parameters tested in every permutation, not only addresses.
- **Decision:** variants are the cartesian product of dimensions. Presets come from synced `serverFields` and PattN gates from `xrayManager`. Each value is written where the app keeps it, so a winning variant is a config IRNetFree runs.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** a sync that renames a preset can break it; tests pin the names.
- **Do not change without reconsidering:** a variant needing Xray-PattN must never run on the official core in its place.
- **Status:** Verified in code (`scan/variants.js`, `docs/SYNC.md`)

## D-011: Past the test limit, an even deterministic sample  (2026-11-01)
- **Context:** variants times targets can be millions.
- **Decision:** `planTests` deals targets in Weyl-sequence order and picks variants so each value appears about equally. The same inputs test the same pairs, so two runs compare.
- **Alternatives considered:** random sampling (rejected: no comparison between runs and a variant could be left out by chance).
- **Consequences / limitations:** only parameters are sampled deterministically; address picks stay random.
- **Do not change without reconsidering:** repeatability is the point.
- **Status:** Verified in code (`scan/variants.js` `planTests`, `spread`, `balancedPick`)

## D-012: Check the way out with an address that cannot exist  (2026-11-02)
- **Context:** a VPN in TUN mode answers for every address, so a scan looks perfect and means nothing.
- **Decision:** before each run, probe RFC 5737 documentation addresses. An answer proves something is lying. It needs no list of VPN adapters.
- **Alternatives considered:** a list of VPN adapters (the source comment only notes that this approach needs none). Others: Unknown / reconstructed from code.
- **Consequences / limitations:** a kernel VPN that really routes is not caught (KI-13). The result warns and does not block.
- **Do not change without reconsidering:** through a SOCKS port only a completed TLS handshake is proof, since Xray's inbound reports success before dialing.
- **Status:** Verified in code (`scan/upstream.js`)

## D-013: An optional SOCKS port as the way out; UDP configs refused  (2026-11-02)
- **Context:** the owner wanted to scan with a VPN on, through a port left open outside it.
- **Decision:** cores, speed test and list update dial through the port. Plain TCP pre-check is dropped and replaced by TLS.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** a config's fragment, finalMask and dialMode act between core and port, not on the real line; `scan:start` says so.
- **Do not change without reconsidering:** do not present such results as equal to a direct scan.
- **Status:** Verified in code (`scan/upstream.js`, `scan/index.js` `proxyTricks`)

## D-014: CDN lists from each CDN's own source, separated by kind  (2026-11-02)
- **Context:** the owner asked for more CDNs and updatable lists. One source mixes CloudFront edges and regional caches.
- **Decision:** IPv4 from the list that separates them, IPv6 from the other source. Regional caches are their own preset, kept so the owner can try them. The origin-facing list is left out. A failed fetch keeps the old list.
- **Alternatives considered:** the mixed list and the origin-facing list (rejected on a recorded measurement in the `cdnRanges.js` header).
- **Consequences / limitations:** Cloudflare's own list is not in the data file (KI-16).
- **Do not change without reconsidering:** only addresses come from these lists, never a host or SNI.
- **Status:** Verified in code (`scan/cdnRanges.js`)

## D-015: The Server tab follows the 3x-ui model  (2026-09-17)
- **Context:** the owner found the first Server tab not good enough and asked for the layout of the new 3x-ui, with tags, so that a reverse tunnel is easy to set up.
- **Decision:** inbounds with tags and clients, tagged outbounds, ordered rules. Reverse proxy is two tags on ordinary objects, and the wizards only write what the user could type.
- **Alternatives considered:** the v1 mode-based model (migrated on read).
- **Consequences / limitations:** no web panel or database of its own, and rule order is load-bearing.
- **Do not change without reconsidering:** the first enabled outbound is the default exit.
- **Status:** Verified in code (`xserver/config.js`, spec 2026-09-17 §2)

## D-016: Only VLESS reverse proxy is generated  (2026-09-09)
- **Context:** the legacy `reverse.bridges` / `portals` block is gone from the 26.9 fork.
- **Decision:** generate the VLESS form on both ends.
- **Alternatives considered:** the legacy block (rejected: the core dropped it).
- **Consequences / limitations:** the bridge's outbound must be flat VLESS settings.
- **Do not change without reconsidering:** each shape was run through `xray run -test`.
- **Status:** Verified in code (`xserver/config.js` header)

## D-017: No runtime npm dependencies  (2026-09-17)
- **Context:** plans state "Node core only; `dependencies` stays empty". The headless server needs no `npm install`.
- **Decision:** Node core only at runtime. Electron and electron-builder are dev only.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** DNS wire format, SOCKS and HTTP over sockets are written by hand (`scan/ech.js`, `upstream.js`, `probes.js`).
- **Do not change without reconsidering:** a dependency would break the clone-and-run headless path and CI's no-install test job.
- **Status:** Verified in code (`package.json`, `test.yml`)

## D-018: A plaintext link the official core refuses runs on Xray-PattN  (2026-11-02)
- **Context:** Xray 26.10.31 refuses a link without TLS to a public address, such as a plaintext bridge link.
- **Decision:** run that config on Xray-PattN when installed, and say so. Otherwise the refusal names the fix.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** depends on the fork keeping that behaviour.
- **Do not change without reconsidering:** the model's engine is not rewritten; only that start moves.
- **Status:** Verified in code (`xserver/core.js` `_start`, commit `6b2df43`)

## D-019: The update check only links to the release  (2026-10-15)
- **Context:** the client has an in-app updater; Plus does not need one.
- **Decision:** `app:checkUpdate` compares with the latest release and offers a link.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** checksums are published but the app does not use them (KI-17).
- **Do not change without reconsidering:** Plus never installs itself.
- **Status:** Verified in code (`plus/service.js`)

## D-020: Push a release tag alone  (2026-09-11)
- **Context:** the v2.0.0 release never built: it was pushed with inherited tags, and GitHub starts tag builds for at most three tags in one push.
- **Decision:** push one tag at a time. A rolling dev release covers the gap.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** the repository holds about 134 inherited upstream tags.
- **Do not change without reconsidering:** never `git push --tags` here.
- **Status:** Verified in code (tag `v2.0.1` message, `dev-release.yml` header)

## D-021: A Windows-only rolling dev pre-release  (2026-09-11)
- **Context:** `release.yml` fires only on tags, so a push could leave nothing to download. The workflow's comment gives build minutes as the reason for one platform.
- **Decision:** every code push to `main` runs tests and replaces the `dev` pre-release. Other platforms build on a manual run. The update check reads `/releases/latest`, which excludes pre-releases.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** macOS and Linux get builds only on a tag or manual run.
- **Do not change without reconsidering:** `make_latest: false` keeps dev builds from being offered as updates.
- **Status:** Verified in code (`.github/workflows/dev-release.yml`)

## D-022: Headless binds to loopback; any other bind needs a token  (2026-10-15)
- **Context:** a loopback panel can still be attacked by any web page through cross-site requests or DNS rebinding.
- **Decision:** default to loopback and `ssh -L`. Generate a token for any other bind. Host and Origin guards always apply.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** no TLS on the panel (KI-03), and `--no-auth` exists (KI-04).
- **Do not change without reconsidering:** `guard.js` is synced, and its comments explain each case.
- **Status:** Verified in code (`src/server/server.js`, `src/server/guard.js`)

## D-023: One upstream rule is copied, because it is not exported  (2026-11-01)
- **Context:** the scan's core gate needs `usesFinalmask`, and synced files cannot be edited to export it.
- **Decision:** keep a local copy in `scan/index.js`.
- **Alternatives considered:** exporting it upstream. Why this was not done: Unknown / reconstructed from code.
- **Consequences / limitations:** it can drift (KI-21).
- **Do not change without reconsidering:** replace it with the export if upstream adds one.
- **Status:** Verified in code (`scan/index.js`, `docs/SYNC.md`)

## D-024: One throw-away core per batch  (2026-09-17)
- **Context:** Unknown / reconstructed from code. Each target needs its own outbound and local SOCKS port in one test config.
- **Decision:** `withCore` starts a core for a batch of up to `batch` items, runs the probes, and kills it.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** a bad value would take down a batch, so the batch is re-run variant by variant.
- **Do not change without reconsidering:** `filterConcurrency` is run-wide on purpose, since a starved machine reads as dead targets.
- **Status:** Verified in code (`scan/scanner.js`)

## D-025: Tests are forbidden to touch the machine  (date unknown)
- **Context:** tests once reached the real system proxy on a machine with a live VPN.
- **Decision:** `npm test` preloads a guard that refuses system commands.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** a new system tool must be added to `BLOCKED`.
- **Do not change without reconsidering:** always run tests through `npm test`.
- **Status:** Verified in code (`tests/noNetwork.preload.js`)
