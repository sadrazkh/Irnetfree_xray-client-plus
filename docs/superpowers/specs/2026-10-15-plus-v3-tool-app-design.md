# IRNetFree Plus v3 — a tool app (Scan + Server), and the scanner rebuilt for MASQUE, ECH and SNI

Date: 2026-10-15. Supersedes the fork model of `docs/FORK.md` and amends the scan specs of v2.1/v2.2.

## 0. The owner's words and choices

*"ببین شاید بهتر باشه اصلا اون کلاینت رو در بیاریم و فقط تبدیلش کنیم به اسکنر که اضافه کاری نشه"* —
asked, he chose **"فقط ابزار، بدون کلاینت"** and **"تب سرور بماند"**. The scanner request stands:
*"اسکنر رو برای اون هم ماسک هم ech هم sni همه چی بهینه و بهبود بدیم و ساده تر و دقیق تر کامل تر هم باشه"*.

Why it pays: the Scan and Server tabs need 13 of upstream's 104 `src` files. Every sync of the full client
cost a merge with ~11 conflicts, identity fixes in upstream tests, and Android/router/macOS-native builds Plus
never needed. v2.2 → v3 is one last merge (upstream v1.25.0, `e4d71b1`) and then the client goes.

## 1. What Plus v3 is

A desktop app (Windows, macOS, Linux) and a headless server (`npm run server`) with five pages:
**Scan**, **Server**, **Configs**, **Settings**, **Log**. No connect, no TUN, no system proxy, no
subscriptions, no routing, no Android, no router package. It still runs next to IRNetFree: same app id,
same data folder (`irnetfree-plus`), so the configs, the server model and the scan memory of v2 carry over.

- **No administrator rights.** Nothing it does needs them (the cores dial out and listen on high ports), so
  Windows builds are `asInvoker`: no UAC prompt at launch. The one admin action — the Server tab's Windows
  firewall rule — asks for elevation itself (UAC for that one `netsh`).
- **Start with the OS** (for a server that should come up at logon): Electron's login item, `--hidden`.
- **Closing the window** while the server runs hides to the tray; otherwise it quits.

## 2. Upstream code: synced, never edited

`upstream-sync.json` lists every file taken verbatim from upstream, the ref they came from and each file's
sha256. `node scripts/sync-upstream.js <ref>` fetches the ref, checks the files out, rewrites the hashes,
and fails when a synced file now requires a file that is not on the list (it prints the missing ones).
`tests/upstreamSync.test.js` fails when a synced file differs from its recorded hash — Plus never edits
one; it wraps it.

The list (v1.25.0): `src/main/{assets,assetUpdater,certPin,configBuilder,coreCompat,coreVersions,dnsBuilder,
downloader,engineChoice,engines,jsonImport,mux,netutils,parser,routingProfiles,store,xrayManager}.js`,
`src/renderer/{serverFields,corePicker,i18n,theme-boot}.js`, `src/renderer/{styles,skins,settings,lists,home}.css`,
`src/renderer/vendor/qrcode.js`, `src/server/guard.js`, `scripts/download-xray.js`, plus whatever the closure
check adds.

Everything else under `src/` is Plus's own:

| Path | Role |
|---|---|
| `src/main/main.js` | Electron shell: window, tray, IPC → the service |
| `src/main/plus/service.js` | **one** service for both Electron and headless (no mirrors any more) |
| `src/main/plus/configs.js` | the configs list: paste links / JSON, import from IRNetFree, remove |
| `src/main/scan/*`, `src/main/xserver/*` | the two tools |
| `src/preload/preload.js`, `src/server/{server,web-api}.js` | the bridge, and the headless HTTP + SSE server |
| `src/renderer/index.html`, `app.js`, `plus/*` | the shell and the pages |

`i18n.js` (upstream) is loaded first for the core picker's strings; `plus/i18n.js` wraps it — its own
dictionaries first, upstream's `t` as the fallback — and owns `applyI18n`.

## 3. Service channels

`app:init` → `{ version, platform, isElectron, settings, servers, assets, engines, dataDir }`;
`settings:set`; `configs:list|add|remove|importIrnetfree`; `assets:status|download`; `cores:versions|install`
(upstream's `createCoreVersionsApi`, busy while a scan runs or the server runs on that core);
`log:get` + `log` events; `app:checkUpdate` (Plus releases, a link — no self-install); `win:*` (Electron only);
`app:quit`; and the tools' own `scan:*`, `xserver:*`.

## 4. Scanner v3

### 4.1 What a run tests: targets = address × port × SNI

- **Addresses** (one per line or comma-separated, `#` comments): IPv4, IPv4 CIDR, `a-b` ranges, **IPv6** and
  IPv6 CIDR, and **host names**. Any token may carry a port: `1.2.3.4:2053`, `[2606:4700::1]:443`, `host:8443`.
  Empty box: the config's own address.
- **Ports** (optional): `443, 2053, 2083-2087`. Empty: the config's port (a token's own port wins).
- **SNIs** (optional): one name per line. Empty: the config's own SNI.
- Pick: **all** (in order, capped) or **random per range** (v2.2: a fresh draw every run, the tested history
  skipped; IPv6 blocks are always drawn, never walked).
- The product is capped at **5000** targets per run; `truncated` says so.
- Presets under the box: **Cloudflare** (v4 + v6), **WARP MASQUE** (`162.159.198.0/24`), **WARP WireGuard**
  (the seven /24 of engage.cloudflareclient.com, with the WARP ports in the Ports box), and **Suggested** —
  the one that fits the chosen config.

### 4.2 Putting a target into a config (`substitute.js`)

`applyTarget(server, { addr, port, sni })` returns a copy that dials `addr:port`:

| Protocol | Where the address lives |
|---|---|
| vless, vmess | `vnext[0]` (or a flat `settings.address`) |
| trojan, shadowsocks | `servers[0]` (or flat) |
| hysteria2, MASQUE | flat `settings.address/port` |
| WireGuard | `peers[0].endpoint` (`[v6]:port` for IPv6) |
| a JSON config | its one entry outbound (entryOutbounds); a config with more than one entry is refused |

The names stay on the original host: TLS SNI, WS/HTTPUpgrade/XHTTP Host, h2 host, gRPC authority are filled
from it when the link left them empty (HTTPUpgrade is new). **SNI** goes into `tlsSettings.serverName`; a
`verifyPeerCertByName` follows it (a cover domain: the certificate is checked by that name). An SNI is refused,
with a reason the table shows once, for REALITY (the server's serverNames decide), for ECH (the SNI on the wire
is the ECH config's public name; the inner one must stay) and for a config without TLS.

### 4.3 Accuracy

- **ECH fetched once.** A config whose `echConfigList` is a DNS query (`name+udp://1.1.1.1`, `+https://…`)
  has it resolved **once** by the scan (an HTTPS record, ECH SvcParam key 5) over the resolver the link names,
  and every core gets the base64 list: no per-core DNS, no batch lost to one dropped query, no DNS time in a
  latency. The strip shows the public name. If it cannot be fetched, the query form stays (the cores ask
  themselves) and the log says why.
- **The TCP probe only where it means something.** Hysteria2, WireGuard, mKCP and MASQUE over HTTP/3 are UDP:
  no TCP connect for them (the column shows `—`), the delay through the core decides.
- **A core is probed only once it listens.** After a core starts, its first inbound is polled (100 ms steps,
  up to 4 s) instead of a fixed 500 ms — a busy machine starting several cores no longer loses its first rows.
- **The engine gate.** A core too old for the config (MASQUE before 26.9.30, a WARP account before 26.10.10,
  ECH before 25.8.3) is left out before the run with the reason in the reply and on the strip; when none is left
  the run is refused with that reason. Each core gets the config adapted to its version (`coreCompat`).

### 4.4 Results

Rows are keyed `addr:port|sni|engine`. Columns: address, SNI (when it varies), core, TCP, delay (median), avg,
min, jitter, loss, ↓, ↑, score. Row actions: **copy link** (the config with this target — a share link, JSON
for MASQUE), **save to Configs**, re-test speed. **Copy the best N** puts N links on the clipboard, ready to
paste into IRNetFree. CSV/JSON export gains `port`, `sni`.

### 4.5 Simpler

The form is: config · what to test (addresses + presets, ports, SNIs) · how (preset Fast/Balanced/Accurate,
**at once**, cores, speed test on/off). Every other number sits under **Advanced**, closed by default.

## 5. Gates for v3.0.0

`npm test` (Plus's own tests, the sync manifest, a renderer contract, every shipped file parses);
`npm run validate` — the server shapes and the scan's per-protocol shapes (MASQUE included) under `xray -test`;
locally on both installed cores (MASQUE needs ≥ 26.9.30, so locally older cores skip it and CI runs it on the
suggested Xray); `npm run probe:reverse` 2/2; the headless walkthrough of all five pages in fa and en.

## 6. Out of scope

Connecting through a found IP (that is IRNetFree's job — copy the link); fetching subscriptions by URL (import
from IRNetFree or paste the content); Android and the router.
