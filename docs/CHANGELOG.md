Last verified: 2026-11-08
Scope checked: `git tag`, tag annotations and merge commit messages at `docs/baseline` HEAD. One line per Plus release, newest first.

# Changelog

The repository also holds 134 tags inherited from the upstream client (`v0.x`, `v1.x`, and some bare numbers) and the rolling `dev` tag. Those are not Plus releases and are left out.

- 2026-11-08 (milestone): documentation baseline written (Mode A); consistency review finished; no code changed.
- v3.3.3 (2026-11-04): Server tab, an inbound's Users cell reads in order in Persian, the count first.
- v3.3.2 (2026-11-04): Server tab, the next reset date reads the right way round in Persian.
- v3.3.1 (2026-11-04): Server tab tables line up again; the clients table scrolls in its own box.
- v3.3.0 (2026-11-02): scanning through an optional SOCKS port, and a path check before every run.
- v3.2.0 (2026-11-02): Fastly, CloudFront and Gcore address lists beside Cloudflare's, updatable from each CDN; a new "N from each block" pick.
- v3.1.0 (2026-11-02): synced to upstream v1.41.0; the scanner tests a config's parameters in every combination; no address cap; a pass is a real answer on two of three tries; a pre-check skips dead addresses; the Server tab runs a plaintext link the official core refuses on Xray-PattN.
- v3.0.0 (2026-10-15): Plus becomes a tool app with Scan, Server, Configs, Settings and Log; the client is removed; scanner rebuilt for MASQUE, ECH and SNI; protocol code synced verbatim from upstream v1.25.0; no admin rights.
- v2.2.0 (2026-09-25): fresh random addresses on every run and a tested-address history; synced to upstream v1.14.0.
- v2.1.0 (2026-09-21): two-phase scan; Server tab rebuilt in the 3x-ui style; synced to upstream v1.8.0.
- v2.0.1 (2026-09-11): release pipeline fixed; a failed artifact upload no longer skips publishing.
- v2.0.0 (2026-09-10): the Plus fork with a Server tab and an IP scan tab, installed beside the client (this release never built, see D-020).
