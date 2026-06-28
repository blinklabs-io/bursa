# Mobile story + lean node — design

**Status:** draft for review · **Date:** 2026-06-27 · **Worktree:** `feat/lean-node`

## Goal
Bring the self-sovereign full-node wallet to mobile **without** abandoning the
node-only identity — i.e. the phone runs its *own* embedded node, not a light
client against someone else's. Feasibility is gated entirely by the node's
on-device footprint, so this design pairs a **lean-node profile** (Phase 0) with
**gomobile packaging** (Phase 1).

## Key findings (research)
- **History expiry exists in dingo** (`internal/historyexpiry`, enabled via
  `dingo.WithHistoryExpiry(HistoryExpiryConfig{Enabled, Frequency})`, confirmed in
  the pinned **v0.58.0**) — our supervisor just never turned it on. It tombstones
  immutable blocks past the stability window, keeping ledger state + UTxOs + a
  recent window.
- **Footprint:** live preview data dir ≈ **61 GB** full (≈12 GB block blobs +
  ≈34 GB ledger/tx metadata + ~1 GB WAL) → estimated **single-digit GB** with
  expiry on.
- **In-process node:** the supervisor runs dingo as a goroutine, not via
  `os/exec` — the iOS subprocess showstopper is already avoided.
- **Pure Go / no CGO:** modernc SQLite + BadgerDB + the crypto libs are all pure
  Go → compiles for `GOOS=android`/`GOOS=ios` via gomobile.
- **WASM can't run the node** (no raw sockets, no real filesystem). It only
  carries offline crypto/tx logic (bursa/bip32, apollo, plutigo) → a *light*
  wallet that breaks self-sovereignty. WASM is a fallback mode, not the story.

## Architecture
```
┌──────────────── mobile app (Android / iOS) ────────────────┐
│  System WebView (WKWebView / Android WebView)               │
│    └─ the existing React SPA  ── loopback HTTP ──┐          │
│  Go core (gomobile AAR / xcframework)            │          │
│    ├─ wallet API (internal/api)  ◄───────────────┘          │
│    ├─ supervisor → dingo node (IN-PROCESS goroutine)        │
│    │     · history expiry ON · Mithril bootstrap            │
│    │     · outbound chainsync to relays · no inbound        │
│    └─ vault/keystore, spend, poolops, … (unchanged)         │
│  data dir = app sandbox (Android /data/data; iOS App Group) │
└─────────────────────────────────────────────────────────────┘
```
Reuses nearly everything already built — the SPA, the API, the supervisor — the
new surface is the gomobile binding + a thin native shell.

## Footprint caveats (be honest)
- "Lean" is still **a few GB** — the UTxO/ledger floor, larger on mainnet than
  preview; expiry drops *blocks/history*, not the live ledger state.
- The one-time **Mithril bootstrap is a multi-GB download** → gate it on wifi.
- Expiry **trades away deep chain history** → fine for a wallet (it indexes its
  own txs + cares about current UTxOs + recent activity), but make it a
  **profile**: default-on for mobile, opt-in on desktop.

## Plan
### Phase 0 — Lean node *(this branch; also a standalone desktop win)*
A user-facing **Settings toggle** ("Lean storage / history expiry", default off)
with tradeoff copy, persisted in the data dir (`BURSA_LEAN` is only the first-run
seed). When on, dingo prunes old immutable **blocks in the live DB** past the
stability window (cheap to recover via chainsync); it applies on **node restart**,
and pruning is **one-way until a re-sync**. The **Mithril snapshot cache is
deliberately RETAINED** — the snapshot is a large, expensive download, so a
re-bootstrap stays cheap. The gate for everything below.

### Phase 1 — Mobile packaging
- `gomobile bind` the Go core → Android **AAR** + iOS **xcframework**, exposing
  start/stop + the loopback API port.
- Thin native shell hosting a system WebView pointed at the loopback API; serve
  the embedded SPA.
- App-sandbox data dir; dingo configured for **outbound-only** chainsync +
  loopback API (no inbound listeners — not needed for a wallet).
- Lean profile defaulted **on** for mobile.

### Phase 2 — Mobile UX & lifecycle
- Foreground-bounded sync (iOS suspends background apps); node **suspend/resume**
  on app lifecycle.
- Bootstrap-over-wifi prompt; battery/data awareness.
- First-run flow tuned for the multi-GB bootstrap.

## Decisions (Phase 1)
- **Platform first:** Android (simpler gomobile + sideload) before iOS.
- **Shell:** native shell + system WebView **reusing the SPA** (recommended) —
  *not* a React Native rewrite (loses all reuse).
- **Lean default:** on for mobile, opt-in (`--lean`/env) for desktop.

## Open risks
- Mainnet lean footprint floor (the live ledger/UTxO state is multi-GB regardless
  of expiry) — validate empirically.
- Mobile background-execution limits vs. keeping the node synced.
- gomobile binding lifecycle (clean node start/stop across app foreground/background).
- Initial bootstrap size/time on mobile networks.

## Validation
- Phase 0: supervisor unit tests (this branch) + an empirical footprint
  before/after measurement (run with expiry on, `du -sh` the data dir).
- Phase 1: a gomobile build target + a minimal Android emulator harness that
  boots the core, loads the SPA, and reaches READY against preview.
