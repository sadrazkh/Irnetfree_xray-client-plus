Last verified: 2026-11-08
Scope checked: the repository has no roadmap or issue list, so everything here is **R (Recommendation)**, derived from `KNOWN_ISSUES_AND_TECH_DEBT.md` and `OPEN_QUESTIONS.md`. The owner has approved none of it.

# Roadmap (proposed)

Each item points at its issue, which holds the detail and the current state. `Status` is whether the work has started.

## Now: proof and gates

| # | Work | Refs | Status |
|---|---|---|---|
| 1 | Run the packaged app on real Windows, macOS and Linux, then update `IMPLEMENTATION_STATUS.md` | OQ-1 | Not started |
| 2 | Serve a real client from a real public server, including REALITY and the reverse proxy across NAT | OQ-2 | Not started |
| 3 | Add `npm test` to `release.yml`, on Node 22 | KI-02, OQ-3 | Not started |
| 4 | Check how far upstream has moved, then sync | KI-25, OQ-4 | Not started |

## Next: safety and correctness

| # | Work | Refs | Status |
|---|---|---|---|
| 5 | A test that boots `server.js`: auth order, guards, path confinement | KI-06 | Not started |
| 6 | Decide the headless exposure model, then either add TLS or document proxy-only and warn on `--no-auth` | KI-03, KI-04, OQ-5 | Not started |
| 7 | Restrict the data folder's file modes on Linux and macOS | KI-05 | Not started |
| 8 | Add firewall rule removal to the page | KI-01, OQ-7 | Not started |
| 9 | Stop sending whole config records where a summary would do | KI-07 | Not started |
| 10 | Guard `scan:retest` with the `starting` flag | KI-09 | Not started |

## Later: debt

| # | Work | Refs | Status |
|---|---|---|---|
| 11 | Move to a supported Electron, and decide on signing | KI-24, KI-27, OQ-9 | Not started |
| 12 | Make `speedTop` and `batch` consistent | KI-08 | Not started |
| 13 | Fix stale comments and leftovers | KI-17, KI-18 | Not started |
| 14 | Mark `docs/superpowers/` as historical, and update `docs/SYNC.md` and README | KI-19, KI-22, KI-23 | Not started |
| 15 | Make the CDN list refresh a release step | KI-16, OQ-10 | Not started |
| 16 | Ask upstream to export `usesFinalmask`, then delete the copy | KI-21 | Not started |
| 17 | Decide `limitIp`: enforce it or remove it | KI-26, OQ-8 | Not started |
