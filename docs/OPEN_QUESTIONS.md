Last verified: 2026-11-08
Scope checked: gaps found while writing this baseline. These are questions only the owner can answer. The repository cannot settle them.

# Open questions

Ranked by how much the answer changes the docs or the risk. The first ten are the most important.

## Top ten

| ID | Question | Why it matters |
|---|---|---|
| OQ-1 | Has the packaged app been launched on real Windows, macOS and Linux, and which versions? | CI builds but never launches it, and tests stub Electron. Those rows stay Partial until you say |
| OQ-2 | Has the Server tab served real clients from a public server, and has the reverse proxy worked across a real NAT? | Only loopback proof exists |
| OQ-3 | Should a tag build be blocked by the tests and core gates? | `release.yml` has neither (KI-02) |
| OQ-4 | How often should Plus sync, and to which upstream version next? | Pinned at `v1.41.0` since 2026-11-01. No stated policy |
| OQ-5 | Is exposing the headless panel to a network supported, or only `ssh -L`? Should `--no-auth` on a public bind exist? | Plain HTTP, token in the URL (KI-03, KI-04) |
| OQ-6 | Which protocols have you actually scanned against real servers? | MASQUE, WARP, Hysteria2, WireGuard and ECH are proven only as configs the core accepts |
| OQ-7 | Should the firewall button be able to remove a rule, or remove it with the inbound? | Rules are left behind now (KI-01) |
| OQ-8 | Keep `limitIp` as a note, enforce it, or remove it? | It looks like a limit and is not one (KI-26) |
| OQ-9 | When should Electron be upgraded, and will the builds ever be signed? | Electron 31 (KI-24); macOS and Windows builds are unsigned (KI-27) |
| OQ-10 | What is the intended use of no-cap scanning of third-party CDN ranges? Should there be a warning, a rate limit, or a stated policy? | `all` mode has no cap (KI-15). Also: should list refresh be part of each release (KI-16)? |

## Others

| ID | Question |
|---|---|
| OQ-11 | Does the IRNetFree import find the store on a real packaged install on each OS? (KI-14) |
| OQ-12 | Should scanning TUIC and AnyTLS configs through sing-box ever be supported? |
| OQ-13 | How long should v1 model and v2 store compatibility code stay? |
| OQ-14 | Is `npm test` green on `main` today, and are the `cores` job's failures treated as blocking? Is branch protection on? |
| OQ-15 | Why is `speedTop` capped at `batch`? (KI-08) |
| OQ-16 | Is scanning through a real direct port in IRNetFree working as intended? |
| OQ-17 | Should the `docs/superpowers/` history stay in a public repo, or be marked or moved? |
| OQ-18 | Does the tested-address history need an off switch, beyond the existing forget button? |
