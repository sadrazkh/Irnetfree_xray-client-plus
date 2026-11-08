Last verified: 2026-11-08
Scope checked: `src/main/plus/*`, `src/main/scan/*`, `src/main/xserver/*`, `src/server/server.js`, `src/main/main.js`, and the exported names used from synced files. Labels: V / A / R, see `MASTER_CONTEXT.md`. Unless a row says otherwise it is V against the file named in its section.

# Technical specification

## 1. The channel contract

Source: `src/main/plus/apiMap.js`. Every handler takes one argument and returns a value. Events go out as `send(channel, payload)`.

| `window.api` group | Channels |
|---|---|
| App | `app:init`, `settings:get`, `settings:set`, `app:checkUpdate`, `log:get`, `log:clear` |
| Configs | `configs:list`, `configs:add`, `configs:remove`, `configs:import` |
| Cores | `assets:status`, `assets:versions`, `assets:download`, `cores:versions`, `cores:install` |
| Server | `xserver:get`, `set`, `start`, `stop`, `restart`, `status`, `log`, `genKeys`, `genId`, `clientLink`, `preview`, `otherSide`, `firewall`, `wizard`, `coreInfo` |
| Scan | `scan:start`, `stop`, `retest`, `presets`, `suggest`, `plan`, `apply`, `links`, `copy`, `export`, `forget`, `sets`, `cdnUpdate`, `pathCheck` |
| Events | `log`, `notify`, `asset-progress`, `xserver-status`, `xserver-log`, `scan-progress` |
| Window (Electron; no-ops headless) | `win:minimize`, `win:maximize`, `win:close`, `app:openExternal`, `app:openDataDir` |

`argOf(kind, args)` turns a call's arguments into the one service argument: `none`, `one`, and the core picker's two-argument `versions` and `install`. The same function is duplicated in `src/server/web-api.js` because it runs in a browser; `tests/plusShell.test.js` covers both.

## 2. Headless HTTP

Source: `src/server/server.js`, `src/server/guard.js` (synced).

| Path | Method | Auth | Result |
|---|---|---|---|
| `/rpc` | POST `{ channel, arg }` | token (if set), Host, Origin | `{ result }` or `{ error }`. Body limit 5 MB. `app:quit` is handled here and is not a service channel |
| `/events` | GET | token (if set), Host, Origin | Server-Sent Events `{ channel, payload }`, ping every 25 s |
| `/`, `/index.html` | GET | token (if set), Host | The page with `__api.js` injected before the first script |
| `/__api.js` | GET | Host | API map plus `web-api.js` |
| `/assets/*`, other static | GET | Host | Files under `assets/` and `src/renderer/`, path-confined |

| Flag | Default | Effect |
|---|---|---|
| `--port`, `-p` | 6970 | |
| `--host`, `-h` | loopback | A non-loopback bind needs a token and gets one generated and printed if none is given |
| `--token`, `-t` | none | Accepted as `?token=` or header `x-irnetfree-token`, compared in constant time (`safeEqual`) |
| `--token-file` | none | Read, or created with mode 0600. The token is then not printed |
| `--data-dir`, `-d` | `IRNF_PLUS_DATA`, else `~/.irnetfree-plus` | |
| `--no-auth` | off | No token even on a public bind. On a loopback bind it does not lift the Host guard (`guard.js` `hostAllowed`) |

## 3. Data on disk

Data folder: Electron `userData`, or the headless `dataDir`. Source: `service.js`, `xserver/core.js`.

| Path | Holds |
|---|---|
| `store.json` | Everything below, plaintext. Atomic write through `.tmp` and rename; an unreadable file is kept as `.corrupt-<timestamp>` (synced `store.js`) |
| `bin/` | Cores and geo files, downloaded at runtime; not packaged (`package.json` `build.files`) |
| `xserver/config.json` | The running server's generated Xray config, plaintext |
| `test-*.json` | A throw-away core's config; removed on cleanup (synced `xrayManager.startTest`) |

| Store key | Owner | Shape |
|---|---|---|
| `servers` | `plus/configs.js` | Upstream's record shape (`parser.js`): `id`, `name`, `protocol`, `address`, `port`, `outbound`, `raw`, plus `importedFrom`, `importedId`, `importedSub`. Name kept from v2 |
| `settings` | `service.js` | `lang` (`fa`/`en`, default `fa`), `theme` (`system`/`dark`/`light`), `skin` (`console`/`cockpit`/`legacy`, default `console`), `openAtLogin`. Other keys from a v2 store stay untouched |
| `xserver` | `xserver/config.js` | Model `schema: 2`, see §6. A v1 model is migrated on read, never rewritten in place (`migrateModel`) |
| `scan` | `scan/index.js` | The last request (`remembered`), never results |
| `scanTested` | `scan/index.js` | Normalised addresses tested, newest last, cap 50,000 (`TESTED_CAP`). v2.2 integer entries are converted on read |
| `scanSets` | `scan/index.js` | Saved parameter sets, at most 50 |
| `scanCdnRanges` | `scan/cdnRanges.js` | `{ id: { ranges, updatedAt } }`, read over the shipped lists |

## 4. Scan request

`scan:start` takes `{ serverId | link, ipsText, portsText, snisText, pick, engines, tests, opts, variants, upstream }`. Returns `{ runId, total, targets, tests, ... }` or `{ error }`. Source: `scan/index.js` `startRun`.

**Address grammar** (`targets.js` header): one per line or comma, space or `;` separated, `#` comments. IPv4, IPv4 CIDR `/8` to `/32`, `a-b` range, IPv6, IPv6 CIDR `/16` to `/128`, host name. Any token may carry a port. An empty box means the config's own address.

**Pick modes** (`sanitizePick`, `pickAddresses`):

| Mode | Meaning | Default |
|---|---|---|
| `all` | Every address, no cap | yes |
| `sample` | `count` uniform over all ranges together | 1000 |
| `random` | `perRange` from each range | 20 |
| `block` | `perBlock` from every aligned `/block` | 5 per `/24`; block sizes `/16` to `/28` (`BLOCK_PREFIXES`) |

`fresh` (default true) skips addresses in `scanTested` for every mode but `all`. Samples are capped at `MAX_SAMPLE` 1,000,000. An IPv6 block is always sampled, 100 per block (`DEFAULT_V6_PER_RANGE`).

**Defaults and presets** (`PRESET_DEFAULTS`, `PRESETS`; bounds in `sanitizeOpts`):

| Option | fast | balanced | accurate | Bounds |
|---|---|---|---|---|
| `delaySamples` | 2 | 3 | 5 | 1-10 |
| `passRatio` | 0.66 | 0.66 | 0.66 | 0.3-1 |
| `tcpTimeout` ms | 1500 | 2000 | 3000 | 500-30000 |
| `delayTimeout` ms | 3000 | 4000 | 4000 | 500-60000 |
| `filterConcurrency` | 24 | 16 | 8 | 1-64 |
| `prefilterConcurrency` | 256 | 128 | 64 | 1-1024 |
| `coresInParallel` | 3 | 2 | 2 | 1-6 |
| `batch` | 20 | 20 | 20 | 1-50 |
| `speedTop` | 5 | 10 | 20 | 0-50, then capped at `batch` (KI-08) |
| `speedRounds` / `speedConcurrency` | 1 / 1 | 1 / 1 | 2 / 1 | 1-3 / 1-4 |

The delay probe host and the speed hosts default to a public connectivity page and a public speed endpoint (`delayHost`, `downHost`, `upHost`) and can all be changed under Advanced. `delayExpect` defaults to `204` for the default page; for another page it is any 2xx or 3xx (`readExpect`).

**Protocols a scan accepts** (`substitute.js` `SUPPORTED`): vless, vmess, trojan, shadowsocks, hysteria2, masque, wireguard. Refused with a reason: sing-box-only configs (`isSingboxOnly`), a JSON config that dials through another proxy (`json-chain`). An SNI list is refused for REALITY, ECH and configs without TLS (`sniSupport`).

**Transport**: Hysteria2, WireGuard, mKCP and MASQUE over HTTP/3 are UDP, so the TCP test is skipped (`transportOf`).

**Variants** (`variants.js` `DIMENSIONS`): `fingerprint`, `alpn`, `cipherSuites`, `fragment`, `finalMask`, `dialMode`, `mux`, `xhttpMode`. At most `MAX_VARIANTS` 5000 (a larger product is refused). The test limit defaults to `DEFAULT_LIMIT` 300, up to `MAX_LIMIT` 1,000,000. Past the limit `planTests` takes an even, deterministic sample. Dropped combinations: cipherSuites without fingerprint `unsafe`, a dialMode beside a fragment, and any that write an identical outbound. A dialMode or the merge mask needs Xray-PattN at least `PATTN_OOB_SINCE`; a finalmask the variant writes needs Xray-PattN (`engineNeed`, `enginesFor`). A share link cannot carry dialMode or mux (`linkLoses`), so such a row is copied as JSON.

**Engine gate** (`gateEngines`): a core too old for the config is left out with the reason, using version floors exported by synced `xrayManager.js` (`MASQUE_SINCE`, `MASQUE_WARP_SINCE`, `ECH_SINCE`, `ECH_OUTBOUND_SINCE`, `FINALMASK_SINCE`, `PATTN_OOB_SINCE`). `usesFinalmask` is a local copy because upstream does not export it (D-023).

**Pass and score** (`score.js`):

- A delay sample is `tunnelGet`: SOCKS CONNECT, one GET, the status must match `expect`. Otherwise `wrong-answer`.
- Pass: at least `ceil(n x passRatio)` of `n` samples answered (`needOf`).
- Score: `100 x success% + round(99 / (1 + median / 200))`. A non-pass, an error, or a failed download scores 0. The page shows score / 100.
- Ranking (`byRank`): success step, then median delay, then jitter, then the rest of the score.
- Failure reasons (`probes.js` `REASONS`): `no-tcp`, `tls`, `core`, `proxy-refused`, `proxy-closed`, `timeout`, `wrong-answer`, `unstable`, `download-failed`.

**`scan-progress` event**: `{ runId, stage, done, total, alive, speedDone, speedTotal, etaMs, reasons, result?, variantStats?, finished?, cancelled?, error? }`. A row arrives twice, phase 1 then phase 2; the page's table is keyed by `target#variant|engine`, and at most `TABLE_MAX` 3000 rows are kept (`plus/scan.js`).

**CSV columns** (`CSV_HEADER`): `addr,port,sni,engine,phase,tcp_ms,delay_min,delay_median,delay_avg,jitter,loss,down_mbps,up_mbps,score,error,variant,reason`.

## 5. Path check and the SOCKS way out

Source: `scan/upstream.js`.

- Direct: TCP connect to RFC 5737 documentation addresses (`CONTROL`). Any accept means `lying`.
- Through a port: a SOCKS CONNECT reply proves nothing, since Xray's inbound says success before dialing, so only a completed TLS handshake with a reserved address counts as `lying`.
- States: `clean`, `lying`, `proxy-down`, `proxy-bad`, `proxy-auth`. A `proxy-*` state refuses the run. `lying` only warns in the log and in the reply's `path`.
- `withUpstream` puts a `socks` outbound in the core config and a `dialerProxy` on every direct dial. A UDP config is refused (`proxy-udp`). Through a port the TLS form of the pre-check is used whenever `sniSupport` allows it (TLS without REALITY or ECH); otherwise there is no pre-check, because a plain TCP connect would mean nothing (`startRun` `tlsCheck`, `scanner.js` `noPrecheck`).

**CDN lists** (`scan/cdnRanges.js`): five providers in `PROVIDERS`, fetched from each CDN's own public list over https only, redirects refused, 8 MB cap, at least `MIN_RANGES` 5 ranges or the list is rejected and the old one stays. Shipped lists: `scan/cdnRanges.data.json` (`fetchedAt` 2026-11-02) and the Cloudflare constants in `targets.js`.

**ECH** (`scan/ech.js`): a config whose `echConfigList` is a DNS query is resolved once per run (HTTPS record, SvcParam key 5) and the list is handed to every core. On failure the query form stays.

## 6. Server model

Source: `xserver/config.js` (`normalizeV2`, `normalizeInbound`, `normalizeClient`, `normalizeOutbound`, `normalizeRule`, `validateModel`, `buildServerConfig`).

| Object | Fields |
|---|---|
| Model | `schema: 2`, `autoStart`, `engine`, `logLevel`, `publicAddress`, `inbounds[]`, `outbounds[]`, `routing { domainStrategy, rules[] }` |
| Inbound | `id`, `tag`, `enabled`, `remark`, `protocol`, `listen`, `port`, `network`, `path`, `host`, `serviceName`, `security`, `tls`, `reality`, `ss`, `sniffing`, `totalBytes`, `expiresAt`, `used`, `disabledBy`, `clients[]` |
| Client | `id`, `enabled`, `email`, `uuid`, `password`, `flow`, `limitIp`, `quotaBytes`, `expiresAt`, `resetDays`, `resetAt`, `comment`, `reverseTag`, `used`, `disabledBy`, `lastSeenAt` |
| Outbound | `id`, `tag`, `kind` (`freedom`, `blackhole`, `server`, `link`), `serverId`, `link`, `reverseTag`, `enabled` |
| Rule | `id`, `enabled`, `comment`, `inboundTags`, `outboundTag`, `domain`, `ip`, `port`, `protocol`, `network`, `preset` |

Rule order is load-bearing and the first enabled outbound is the default exit. Protocols: `vless`, `vmess`, `trojan`, `shadowsocks`. Networks: `tcp`, `ws`, `grpc`, `xhttp`. Security: `none`, `tls`, `reality`. REALITY over `ws` is refused. Shadowsocks is raw TCP only. Reserved tags: `metrics`, `api`.

Reverse proxy: a VLESS client with `reverseTag` makes this machine a portal; a VLESS outbound with `reverseTag` makes it a bridge. The legacy `reverse.bridges` block is not generated. `wizardPortal` and `wizardBridge` write ordinary model objects.

Runtime constants (`xserver/core.js`): metrics poll 300 ms x 20 at start; tick 5 s; restart debounce 10 s; crash back-off 2, 5, 15 s, stable after 60 s; stop wait 3 s; log ring 300 lines. On Windows `_kill` also runs `taskkill /t /f`.

Quota and expiry (`_enforce`): a disabled client carries `disabledBy` (`quota`/`expired`) and comes back when the reason ends; one the user disabled stays off. The reset cycle runs first. Inbounds have their own `totalBytes` and `expiresAt`.

Plaintext fallback: when the official core refuses a link without TLS to a public address (synced `PLAINTEXT_REJECT`), the config runs on Xray-PattN if installed (`ServerCore._start`).

## 7. Cores

Engines come from synced `engines.js`. `xrayEngines()` returns the engines with `format: 'xray'`: `xray` and `xray-pattn`. sing-box is registered there, but no scan or server runs on it and `assets:download` refuses it. Suggested versions are `SUGGESTED` in synced `coreVersions.js`: Xray 26.10.31 and Xray-PattN 26.11.1 at the current sync. Core files are not swapped while something runs on them (`service.js` `coreBusy`).
