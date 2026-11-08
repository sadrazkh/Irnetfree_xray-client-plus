Last verified: 2026-11-08
Scope checked: terms as used in `src/`, `docs/SYNC.md` and the README files. Definitions are V against the file named, or general protocol background where no file is named.

# Glossary

**Two words that mean two things here.** *Upstream* is the IRNetFree client repository in the sync, but `scan/upstream.js` uses it for the SOCKS way out of a scan. *Client* is the IRNetFree app, but also a user of an inbound on the Server tab.

## Project

| Term | Meaning |
|---|---|
| Synced file | A file taken verbatim from upstream, listed in `upstream-sync.json`. Never edited here |
| Manifest | `upstream-sync.json`: ref, commit, and each file's sha256 |
| Wrap | Plus's way of changing synced behaviour without editing it (`plus/i18n.js` wraps `i18n.js`) |
| The service | `createPlusService`, behind both front ends |
| Front end | The Electron window or the headless server |
| Headless | The same pages over HTTP, `src/server/server.js` |
| Data folder | Where `store.json` and `bin/` live |
| Store | `store.json`, one JSON file (`store.js`) |
| v2 store | A store written by Plus 2.x; it carries over |
| Dev build | The rolling `dev` pre-release from `dev-release.yml` |

## Scan

| Term | Meaning |
|---|---|
| Target | Address, port and SNI: `{ addr, port, sni }` |
| Space | A lazy indexable set: `{ size, at(i) }`, never a list |
| Pick | How the address box is read: `all`, `sample`, `random`, `block` |
| Block | An aligned stretch such as a `/24`, the unit of the `block` pick |
| Fresh | Skip addresses already in the tested history |
| Dimension | One thing a config can be dialed with, such as fingerprint |
| Variant | One value of each active dimension |
| Item | What the runner tests: a target, optionally with a variant and its cores |
| Engine / core | An Xray binary run as a child process |
| Throw-away core | A core started for one batch and killed after |
| Batch | The items sharing one throw-away core |
| Pre-check | A direct TCP or TLS check with no core |
| Phase 1, filter | Delay series through the tunnel |
| Phase 2, speed | Download and upload on the best rows |
| Delay series | `n` GETs through the tunnel, `delaySeries` |
| Pass, `passRatio` | Enough samples gave the expected answer |
| Way out | How scan traffic leaves: direct or a SOCKS port |
| Path check | Probing a reserved address to see whether something answers falsely |
| `lying` | The path check's verdict when a reserved address answered |
| Preset | A CDN address list, or fast/balanced/accurate settings |

## Server

| Term | Meaning |
|---|---|
| Inbound | A listener on this machine, with clients |
| Client | A credential on an inbound, with quota and expiry |
| Outbound | A tagged exit: freedom, blackhole, a stored config, a link |
| Tag | The name routing rules use |
| Portal | The public side of a reverse proxy |
| Bridge | The side behind NAT that dials out to the portal |
| `reverseTag` | The field that makes a client a portal credential, or an outbound a bridge |
| Metrics port | The core's local `/debug/vars` listener |
| 3x-ui | The panel the tab's layout and model follow |

## Protocols and tricks (general background)

| Term | Meaning |
|---|---|
| Xray-core | The proxy core |
| Xray-PattN | A fork of Xray-core; adds `dialMode` and masks such as `merge`, and allows plaintext to public addresses |
| VLESS, VMess, Trojan, Shadowsocks | Proxy protocols over a stream |
| Hysteria2 | Proxy protocol over QUIC |
| WireGuard | UDP VPN protocol |
| MASQUE | Tunnelling over HTTP/3 or HTTP/2 (CONNECT-IP) |
| WARP | Cloudflare's WireGuard- and MASQUE-based service |
| TLS, SNI | Encryption, and the name sent in the handshake |
| ALPN | Protocol names negotiated in TLS |
| REALITY | TLS camouflage in which the server's `serverNames` decide the SNI |
| ECH | Encrypted Client Hello; the on-wire SNI is the public name |
| uTLS fingerprint | A browser-like TLS ClientHello shape |
| Fronting | Dialing a CDN address while the handshake names another site |
| XHTTP, WebSocket, gRPC | Stream transports |
| Fragment | Splitting early packets to confuse inspection (`_fragment`) |
| finalmask | Xray's packet-mask setting (`streamSettings.finalmask`) |
| dialMode | `sockopt.dialMode`, Xray-PattN's out-of-band byte trick (`oob.<byte>`) |
| mux | Several streams on one connection |
| DPI | Deep packet inspection |
| CIDR | An address range written as `base/prefix` |
| RFC 5737 | IPv4 ranges reserved for documentation, used by the path check |
