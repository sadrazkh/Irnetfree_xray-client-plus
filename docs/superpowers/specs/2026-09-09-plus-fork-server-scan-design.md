# IRNetFree Plus — the fork, the Server tab, the IP-scan tab

**Status:** approved by the owner's brief of 2026-09-09 ("make a fork on another repository that
can still move forward with the original; add a 3x-ui-like Xray server tab whose most important
feature is reverse proxy, with practical user management; add a WinCFScan-like test tab that takes
a config and an IP list and tests them on every supported core; plan it, drive it with several
agents, make the best and most stable version"). Decisions the brief left open are marked
**Decision** below and were taken by the implementing session; each is reversible.

خلاصهٔ فارسی: «پلاس» یک فورک از IRNetFree است که کنار نسخهٔ اصلی نصب و اجرا می‌شود، با دو تب تازه:
**سرور** (اجرای xray به‌عنوان سرور روی همین دستگاه، با inbound و کاربر و به‌خصوص ریورس‌پراکسی
bridge/portal) و **اسکن IP** (یک کانفیگ بده، فهرست IP بده، روی هر هستهٔ پشتیبانی‌شده تست کن و
سریع‌ترین و پایدارترین را پیدا کن). همهٔ کد تازه در ماژول‌های جدید است تا ادغام تغییرات مخزن اصلی
ارزان بماند.

---

## 1. The fork

### 1.1 Repositories

| | |
|---|---|
| upstream | `https://github.com/sadrazkh/Irnetfree_xray-client` (remote `upstream`) |
| fork | `https://github.com/sadrazkh/Irnetfree_xray-client-plus` (remote `origin`) |
| local | `E:\Cash.Net\source\repos\sadrazkh\Irnetfree_xray-client-plus` |

Syncing with upstream is one command sequence, documented in `docs/FORK.md`:

```bash
git fetch upstream
git merge upstream/main
npm test && npm run validate
```

**Decision:** a real clone with two remotes rather than a GitHub "fork" object. The `gh` CLI is not
installed on the owner's machine, so the GitHub repository is created by the owner (empty, same
name); the first `git push -u origin main --tags` then publishes everything. Nothing in the
workflow depends on GitHub's fork relationship.

### 1.2 Merge-friendliness rules (binding for every task)

- New behaviour lives in **new files**: `src/main/xserver/*`, `src/main/scan/*`,
  `src/renderer/plus/*`, `tests/xserver*.test.js`, `tests/scan*.test.js`.
- Upstream files receive **hook lines only** — a `require`, one registration call, one nav button,
  one `<section>`, one `<link>`/`<script>`, one line in a teardown. Every hook is marked with a
  trailing `// plus` (JS/CSS) or `<!-- plus -->` (HTML) comment so a merge conflict is recognisable
  at a glance.
- Renderer strings for the new tabs live in `src/renderer/plus/<tab>.i18n.js`, registered through a
  small `window.i18n.extend({ fa, en })` hook added to `i18n.js`; the contract test reads those files
  too. Upstream's `i18n.js` dictionary is not edited.
- The new renderer files are classic scripts loaded after `app.js`; they use its top-level helpers
  (`$`, `$$`, `t`, `state`, `toast`, `escapeHtml`, `fmtBytes`, `makeSearchSelect`, `copyText`,
  `srvById`, `showView`). They initialise through one hook in `init()`:
  `for (const fn of (window.plusInit || [])) await fn(data);` and each file pushes its own
  initialiser onto `window.plusInit`.
- Main-process modules expose `register(ctx)` and are wired identically in `main.js` and
  `service.js` through a normalised context (§4), so the two mirrors stay in step by construction.

### 1.3 Identity (side-by-side install)

The owner runs the original IRNetFree on this machine (ports 10808/10809/10085). Plus must install
and run next to it without touching it.

| Setting | Original | Plus |
|---|---|---|
| `package.json` `name` (→ userData `%APPDATA%\<name>`) | `irnetfree` | `irnetfree-plus` |
| `build.appId` | `com.irnetfree.client` | `com.irnetfree.plus` |
| `build.productName`, shortcut, artifact names | `IRNetFree` | `IRNetFree Plus`, `IRNetFree-Plus-…` |
| Autostart task (`autostart.js` `TASK`) | `IRNetFree` | `IRNetFreePlus` |
| Default `socksPort` / `httpPort` / `apiPort` | 10808 / 10809 / 10085 | **10818 / 10819 / 10095** |
| Release repo for the in-app update check | `sadrazkh/Irnetfree_xray-client` | `sadrazkh/Irnetfree_xray-client-plus` (one `APP_REPO` constant) |
| Title bar | `IR NETFREE` | `IR NETFREE PLUS` |
| Version | 1.5.0 | **2.0.0** (Plus numbers its own releases; upstream's `package.json` bumps are resolved at merge time) |

Backup bundles keep `app: 'IRNetFree'` so a backup moves between the two apps in both directions.
The headless server's default data dir follows the package name as well.

---

## 2. Server tab (`xserver`)

A local **Xray server** managed from the app: inbounds, clients, traffic, and a first-class
**reverse proxy** setup (bridge or portal). It is what running 3x-ui on this Windows machine would
give, reduced to what is practical: no web login, no multi-user panel accounts, no database.

### 2.1 Model (store key `xserver`)

```js
{
  autoStart: false,            // start the server core with the app
  engine: 'xray',              // 'xray' | 'xray-pattn' (xray-format cores only)
  logLevel: 'warning',
  publicAddress: '',           // what clients dial: this machine's public IP / DNS name
  inbounds: [{
    id, tag,                   // tag is unique, derived from remark (slug) + short id
    enabled: true, remark: 'VLESS Reality',
    protocol: 'vless' | 'vmess' | 'trojan' | 'shadowsocks',
    listen: '0.0.0.0', port: 443,
    network: 'tcp' | 'ws' | 'grpc' | 'xhttp',
    path: '/', host: '', serviceName: '',
    security: 'none' | 'tls' | 'reality',
    tls: { certFile: '', keyFile: '', serverName: '', alpn: ['h2','http/1.1'] },
    reality: { dest: 'www.cloudflare.com:443', serverNames: ['www.cloudflare.com'],   // microsoft.com fails the REALITY handshake from here on both cores
               privateKey: '', publicKey: '', shortIds: ['<8-byte hex>'] },
    ss: { method: '2022-blake3-aes-128-gcm' | 'aes-256-gcm' | 'chacha20-ietf-poly1305', password: '' },
    sniffing: true,
    clients: [{
      id, enabled: true, email: 'alice',        // email is xray's user key; unique across the server
      uuid: '', password: '',                   // uuid for vless/vmess; password for trojan/ss
      flow: '' | 'xtls-rprx-vision',
      expiresAt: 0,                             // ms epoch, 0 = never
      quotaBytes: 0,                            // 0 = unlimited (up + down)
      limitIp: 0,                               // informational (xray cannot enforce it without the API); kept for links/compat
      note: '',
      // maintained by the enforcer, never edited by hand:
      used: { up: 0, down: 0 }, disabledBy: '' | 'expired' | 'quota'
    }]
  }],
  exit: { type: 'direct' | 'server', serverId: '' },   // where client traffic leaves: this machine, or through one of the app's own configs
  blockPrivate: true, blockTorrent: false,
  reverse: {
    role: 'off' | 'bridge' | 'portal',
    bridge: { via: 'server' | 'link', serverId: '', link: '' },   // how this bridge reaches the portal's interconn inbound (VLESS)
    portal: { interconnInboundId: '', userInboundIds: [] }        // which VLESS inbound the bridge dials in on; which inbounds' users are forwarded through the bridge
  }
}
```

### 2.2 Config generation (`src/main/xserver/config.js`, pure)

`buildServerConfig(model, { apiPort, servers, geoAvailable })` → Xray JSON:

- `log.loglevel`; `stats: {}`; `policy.levels.0.statsUserUplink/Downlink: true`;
  `policy.system` inbound/outbound stats; `metrics: { tag: 'metrics', listen: '127.0.0.1:<apiPort>' }`
  (same shape `configBuilder.buildConfig` already emits, so `/debug/vars` works unchanged).
- One inbound per enabled model inbound. `settings.clients` carries only enabled clients with
  `email`, and `id`/`password`/`flow` as the protocol needs (`flow` only for vless with
  tcp+reality/tls). `streamSettings` mirrors `parser.buildStreamSettings` shapes from the server's
  side: `wsSettings{path, host}`, `grpcSettings{serviceName}`, `xhttpSettings{path, host}`,
  `tlsSettings{certificates:[{certificateFile, keyFile}], serverName, alpn}`,
  `realitySettings{show:false, dest, xver:0, serverNames, privateKey, shortIds}`.
  `sniffing: { enabled, destOverride: ['http','tls','quic'] }`.
  Shadowsocks: multi-user form — `settings.clients: [{ email, password, method }]` for every
  method (per-client `method` for the legacy AEAD ciphers; for the 2022 ciphers `settings.method`
  plus a server-level `settings.password` key and per-client user keys), `settings.network: 'tcp,udp'`.
- Outbounds, in this order: `exit` (`freedom` when `exit.type === 'direct'`, otherwise a clone of
  the chosen stored server's outbound via `configBuilder.cloneOut` semantics, tag `exit`),
  `block` (blackhole), and for a bridge `interconn` (the outbound to the portal, built from a stored
  server or a parsed link).
- Routing rules, in this order (order is load-bearing):
  1. `blockPrivate` → `{ ip: ['geoip:private'], outboundTag: 'block' }` (only `geoAvailable`; else
     the literal private CIDR list `configBuilder` already keeps).
  2. `blockTorrent` → `{ protocol: ['bittorrent'], outboundTag: 'block' }`.
  3. Reverse rules (below).
  4. Everything else falls to the first outbound (`exit`) — no catch-all rule needed.
- Reverse — the **VLESS reverse proxy**, not the legacy `reverse.bridges/portals` block: the
  patterniha 26.9.1 core already refuses the legacy block ("legacy reverse has been removed and
  migrated to VLESS Reverse Proxy") and the official core carries the same removal, while both
  cores in `bin/` accept the new form. There is no shared domain; the pairing is the VLESS
  interconn credential itself.
  - **bridge**: the `interconn` outbound is a flat VLESS outbound
    `settings: { address, port, id, flow, encryption, reverse: { tag: 'bridge' } }` (the core refuses
    `reverse` inside `vnext`); connections the portal hands back arrive as inbound tag `bridge`, and
    the last rule `{ inboundTag: ['bridge'], outboundTag: 'exit' }` sends them out locally. A
    bridge's `freedom` exit carries `finalRules: [{ action: 'allow' }]`: from 26.9 on the core
    refuses every destination that arrives through a reverse unless a final rule allows it (a
    bridge behind NAT opts in to what the portal may reach); older cores ignore the field.
    `npm run probe:reverse` proves the pair end to end on both cores, on 127.0.0.1 only.
  - **portal**: every enabled client of the interconn inbound carries `reverse: { tag: 'portal' }`;
    the rule `{ inboundTag: [...userTags], outboundTag: 'portal' }` forwards the chosen inbounds'
    users through the bridge; inbounds not selected keep exiting locally. Validation refuses a
    non-VLESS interconn (on either side), a portal whose interconn inbound is also a user inbound
    or has no user inbounds, disabled chosen inbounds, and a bridge with no target.
- `validateModel(model)` → `{ ok, errors: [{ path, msg }] }`: unique tags, unique emails, port
  1–65535 and unique per listen address, TLS needs cert+key files, Reality needs private key and at
  least one serverName and shortId, ws/xhttp need a path, at least one enabled client per enabled
  inbound (an inbound with none is emitted with an empty client list and flagged as a warning, not
  an error), reverse consistency as above, bridge needs a reachable VLESS target.

Helpers (pure, tested): `newInbound(protocol)`, `newClient(protocol)`, `slugTag(remark, id)`,
`randomShortId()`, `parseX25519(stdout)` (accepts the pre-26 `Private key:/Public key:` and the
26.x `PrivateKey:/Password (PublicKey):` forms), `clientServerRecord(inbound, client, model)` →
a **client-side** server record `{ name, protocol, address, port, outbound }` that
`parser.buildShareLink` turns into `vless://…`, `vmess://…`, `trojan://…`, `ss://…`, and
`otherSideSnippet(model)` → the JSON the *other* end of the reverse pair needs (for a 3x-ui
"Xray settings" box or a bare xray): for a bridge here, the portal's `reverse`/`routing` snippet;
for a portal here, the bridge's `reverse`/`outbounds`/`routing` snippet with the interconn client's
share link.

### 2.3 Runtime (`src/main/xserver/core.js`)

`class ServerCore` owns exactly one child process, separate from the client tunnel:

- `start()`: validate model → build config → `xray.validate(config, engine)` (the existing
  `-test` cache) → write `<dataDir>/xserver/config.json` → spawn `bin run -c …` with
  `windowsHide`, cwd of the binary, `spawnEnv()`; wait for the metrics port to answer (up to 5 s)
  → state `running`. Errors are `{ ok: false, error }` and state `error` with the deepest
  `extractXrayError` line; nothing throws to the caller.
- `stop()`, `restart()`; `status()` → `{ state: 'stopped'|'starting'|'running'|'error', pid,
  since, engine, apiPort, error, inbounds: [{ tag, port, up, down }] }`.
- Log ring of the last 300 lines (`log()`), pushed live on `xserver-log`.
- Stats poll every 5 s through `StatsPoller.query()`'s reading of `/debug/vars`: per-inbound
  totals and per-user `stats.user[email]` counters; deltas accumulate into each client's `used`
  (store `setLazy`), and a client whose counter moved since the last tick is `online` in the
  status payload.
- Enforcer, same tick: `expiresAt` passed or `used.up + used.down ≥ quotaBytes` → the client is
  marked `enabled: false, disabledBy`, and a restart is scheduled (debounced 10 s, at most one in
  flight). Re-enabling a client clears `disabledBy`; a bigger quota or later expiry re-enables
  automatically on the next tick when the reason no longer holds.
- Crash policy: an unexpected exit while `running` → up to 3 automatic restarts with 2 s, 5 s,
  15 s back-off, then state `error`. A `stop()` cancels the policy.
- `applyModel(next)` (from the UI): validate, persist, and if running → restart. The UI never
  writes the store directly.
- `autoStart` is honoured after app ready (desktop) / after `createService` (headless), 1.5 s
  after the client auto-connect so the two cores do not race for the same free-port pool.
- Firewall helper (desktop and headless, Windows only): `xserver:firewall` runs
  `netsh advfirewall firewall add rule name="IRNetFree Plus <tag>" dir=in action=allow protocol=TCP
  localport=<port>` (and `delete rule name=…`) **only when the user presses the button**; other
  platforms return `{ ok: false, error: 'unsupported' }`. Tests exercise the argument arrays only.

Both mirrors call `xserver.stop()` in their teardown, after the client core.

### 2.4 Channels (`src/main/xserver/index.js`, `register(ctx)`)

| channel | arg → result |
|---|---|
| `xserver:get` | → `{ model, status, engines: [{ id, label, installed }] }` |
| `xserver:set` | `model` → `{ ok, errors, model, status }` (validate, persist, restart if running) |
| `xserver:start` / `xserver:stop` / `xserver:restart` | → `status` |
| `xserver:status` | → `status` |
| `xserver:log` | → `[line…]` |
| `xserver:genKeys` | → `{ privateKey, publicKey }` from `<engine> x25519` |
| `xserver:genId` | `'uuid' | 'password' | 'shortId' | 'ss2022:<method>'` → string |
| `xserver:clientLink` | `{ inboundId, clientId }` → `{ link, record }` |
| `xserver:preview` | → `{ config }` (the JSON that would run, secrets included — it is the user's own server) |
| `xserver:otherSide` | → `{ snippet, link }` |
| `xserver:firewall` | `{ inboundId, allow }` → `{ ok, error }` |
| events | `xserver-status` (status), `xserver-log` ({ line, level }) |

### 2.5 Renderer (`src/renderer/plus/xserver.js`, `xserver.css`, `xserver.i18n.js`, `#view-xserver`)

- Head: state pill, engine, uptime; Start / Stop / Restart; "start with the app" switch; public
  address input; "show config" (modal with the JSON, copy button).
- **Inbound cards**: badge, remark, `listen:port`, transport/security summary, client count,
  traffic, enable switch, edit, delete, "allow in firewall" (Windows), "add client". Expanded:
  client rows — name, secret (masked, copy), expiry, quota bar (`usage-bar` classes),
  online dot, enable switch, link (copy + QR through `vendor/qrcode.js`), edit, delete.
- **Inbound editor modal** and **client editor modal** with the fields of §2.1; "generate" buttons
  for keys, uuid, password, short id; Reality is the recommended default for a machine without a
  domain (hint text says why).
- **Reverse card**: role option cards (off / bridge / portal) with a two-node diagram; bridge →
  stored VLESS-server picker or link paste; portal → interconn (VLESS) inbound select and user
  inbound checklist; "copy the other side" button (§2.2 `otherSideSnippet`).
- **Exit card**: direct / through a stored config (picker), block private, block torrent.
- Log panel (last lines, follows).
- The nav item is `pro-only` (hidden in simple mode). Every mutation goes through `xserver:set`;
  the renderer re-renders from the returned model, so validation errors show next to the field
  path they name.

---

## 3. IP-scan tab (`scan`)

Give it a config and a list of IPs; it dials the config through each IP (SNI/Host stay on the
original name, which is the Cloudflare-fronting trick WinCFScan relies on), measures, ranks, and
turns the winner into a stored config with one click.

### 3.1 Inputs

- **Config**: a stored server (picker) or a pasted link (`parser.parseLink`). Xray-format
  protocols only (vless/vmess/trojan/ss); WireGuard endpoints are out of scope for this release.
- **IPs**: textarea accepting one item per line or comma-separated — `1.2.3.4`, `1.2.3.0/24`,
  `1.2.3.10-1.2.3.60`, and `#` comments; buttons: *Cloudflare IPv4 ranges* (built-in list),
  *sample N* (random spread across the given ranges, default 100, cap 5000 expanded targets),
  *load file*. Duplicates removed, order preserved.
- **Engines**: checkboxes for the installed xray-format cores (`xray`, `xray-pattn`); sing-box is
  not offered (the translator has no test-config path). Every IP runs on every ticked engine.
- **Tests** (checkboxes): `tcp` (direct TCP connect to ip:port, 3 s), `delay` (HTTP GET through
  the config to `cp.cloudflare.com/`, N samples, default 3 → min/avg/jitter/loss), `down`
  (HTTPS download through the config from `https://speed.cloudflare.com/__down?bytes=<size>`,
  default 10 MB, capped at `maxSeconds` 8; throughput measured from first byte to last, connection
  setup excluded), `up` (off by default; HTTPS POST to `https://speed.cloudflare.com/__up`, 2 MB).
  Download/upload host and path are editable (a custom test URL).
- **Limits**: concurrency (default 8 IPs in flight), targets per core process (default 20 — the
  batch size `ping:realMany` already uses), timeouts.

### 3.2 Engine (`src/main/scan/*`)

- `targets.js` (pure): `expandTargets(text, { max })`, `sampleTargets(text, n, seed?)`,
  `CF_IPV4_RANGES`.
- `substitute.js` (pure): `withAddress(server, ip)` → a deep copy whose `address` and
  `outbound.settings.vnext[0].address` / `servers[0].address` are the IP, with
  `tlsSettings.serverName`, `wsSettings.headers.Host`, `xhttpSettings.host`, `grpc authority`
  and `realitySettings.serverName` filled from the original address when they were empty and the
  original address was a name. `_fragment`/`_noise`/`certPin` are carried over.
- `probes.js`: `downloadThroughProxy(socksPort, { host, port, path, tls, bytes, maxMs })` and
  `uploadThroughProxy` (TLS variant) built on `netutils.socks5Connect` + `tls.connect({ socket,
  servername })`; return `{ ok, bytes, ms, ttfb, mbps, error }`. `delaySeries(port, n)` → `{ min,
  avg, jitter, loss, samples }` using `netutils.httpThroughProxy`.
- `score.js` (pure): documented formula, higher is better:
  `score = base × (1 − loss) / (1 + avg/200) / (1 + jitter/100)` where `base = 100 × downMbps`
  when download was tested, else `1000`. A result with no successful delay sample scores 0.
- `scanner.js`: `runScan({ server, ips, engines, tests, opts, xray, onResult, onProgress, token })`
  — per engine, per batch: `buildMultiTestConfig(targets, ports)` → `xray.startTest(cfg,
  engine)`; within the batch `pLimit(concurrency)`; each IP produces one result object
  `{ ip, engine, tcp, delay, down, up, score, error }` pushed through `onResult` as soon as it is
  done; `token.cancelled` stops scheduling, kills the batch core, and resolves the run with what
  was measured. Fatal batch errors mark the batch's IPs `error` and move on. The core stays
  throwaway: cleanup in `finally`, as `ping:realMany` does.
- `index.js` `register(ctx)`: `scan:start` (`{ serverId | link, ipsText, engines, tests, opts }`
  → `{ runId, total }`; only one run at a time — a second start returns `{ error: 'busy' }`),
  `scan:stop`, `scan:presets` (`{ cfRanges, defaults }`), `scan:apply` (`{ ip, serverId | link,
  name? }` → adds a stored server clone `"<name> [ip]"` through the same path `servers:add` uses
  and returns it), `scan:export` (`{ format: 'csv'|'json', results }` → text). Events:
  `scan-progress` `{ runId, done, total, result? , finished?, cancelled? }`.

### 3.3 Renderer (`src/renderer/plus/scan.js`, `scan.css`, `scan.i18n.js`, `#view-scan`)

- Config row (picker / paste), IP box with the three buttons and a count, engine and test
  checkboxes, limits, Start / Stop, progress bar with done/total and elapsed.
- Results table filled live, sortable by any column, default sort by score; columns: IP, engine,
  TCP, delay avg / min / jitter / loss, download MB/s, upload, score; row actions: *use this IP*
  (→ `scan:apply`, then `renderServers()`/`renderPicker()`), *copy*, *re-test*. Toolbar: *re-test
  the top N*, *export CSV/JSON* (Blob download like the backup export), *clear*.
- Persisted between sessions in store key `scan`: the last inputs, not the results.
- Visible in both UI modes.

---

## 4. Shared wiring

Normalised context, built once in `main.js` and once in `service.js`:

```js
const ctx = {
  handle: (channel, fn) => ipcMain.handle(channel, (e, arg) => fn(arg)),   // service.js: handlers[channel] = fn
  send, notify, store, dataDir, getSettings, xray,
  getServers: () => store.get('servers', []),
  addServer: (record) => { …the exact code path servers:add uses… },
  resolveTarget, log: (line, level) => send('log', { line, level }),
  platform: process.platform, isElectron: true /* false in service.js */
};
const xserver = createXServer(ctx); xserver.register();      // plus
const scan = createScan(ctx); scan.register();               // plus
```

`preload.js` and `web-api.js` gain the same method names (`xserverGet`, …, `scanStart`, …,
`onXServerStatus`, `onXServerLog`, `onScanProgress`). `app:init` is not extended; each tab fetches
its own state in its `plusInit` hook.

---

## 5. Testing and proof

- Unit: `tests/xserver.config.test.js` (golden config shapes for each protocol × transport ×
  security; rule order; reverse bridge/portal; validation errors), `tests/xserver.links.test.js`
  (every generated link parses back with `parseLink` into an outbound that dials the inbound),
  `tests/xserver.core.test.js` (enforcer decisions, back-off, x25519 parsing, firewall args),
  `tests/scan.targets.test.js`, `tests/scan.substitute.test.js`, `tests/scan.score.test.js`,
  `tests/scan.scanner.test.js` (a fake core/probes: batching, cancellation, per-result streaming),
  `tests/renderer.test.js` extended to the `plus/` files and i18n extensions.
- `npm run validate` gains the server shapes (portal, bridge, reality, ws+tls, grpc, xhttp, ss)
  and runs them through `xray run -test` on both cores.
- Live, local-only, in the implementing session: a portal core and a bridge core on 127.0.0.1
  (VLESS reverse proxy), a throwaway client core dialling the portal's user inbound, an HTTP fetch
  that succeeds only if the bridge carried it; the scanner run against a local inbound with a
  local byte server. No
  firewall rule, no 0.0.0.0 bind, no system change on the owner's machine.

## 6. Out of scope (this release)

Per-inbound client IP limits enforced live (needs the gRPC API), a web login for the server tab,
sing-box as a server, WireGuard endpoint scanning, multi-portal/multi-bridge topologies, TLS
certificate issuance (ACME). Each has an obvious home in the model above.
