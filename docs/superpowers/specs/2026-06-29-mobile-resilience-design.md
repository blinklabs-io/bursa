# Mobile Resilience — design

**Status:** approved direction (build) · **Date:** 2026-06-29 · **Base:** `feat/mobile` (`0547cb8`, rebased onto current `origin/main`)

## Goal

Make the embedded full-node wallet survive the realities of a phone: the
network interface changing (WiFi↔cellular, loss→regain) and the app being
suspended and resumed (Android doze / backgrounding). Today nothing reacts to
either — the node never re-dials on a network change and nothing re-syncs or
refetches on resume.

## Architecture

Four features, **stacked** (each builds on the previous), so the shared hot
files (`mobile.go`, `boot.go`, `supervisor.go`, `MainActivity.kt`, `hooks.ts`,
`app.tsx`) merge in one direction and the integration branch is just the top of
the stack:

```
feat/mobile (rebased base)
  └─ feat/mobile-net-resilience   (SPA-only; also helps desktop/browser)
       └─ feat/mobile-reconnect    (Go supervisor + gomobile hook + Android NetworkCallback)
            └─ feat/mobile-resume   (gomobile hook + Android onResume + SPA visibility)
                 └─ feat/mobile-foreground  (Android foreground Service)
integration/mobile-opts = feat/mobile-foreground  →  CI builds the test APK
```

## Global constraints (every feature)

- **gomobile boundary:** any new EXPORTED method on `ui/mobile.App` may use only
  gomobile-crossable types (bool, int/int64, float, string, []byte, error,
  exported structs). New hooks take no args (or scalars) and return `error`.
- **Pure Go / `CGO_ENABLED=0`** must hold; `GOOS=android GOARCH=arm64
  CGO_ENABLED=0 go build ./...` must keep passing.
- **Loopback-only**: no new external network surface; the node is the only thing
  that talks to the outside.
- Commits are unsigned WIP (`-c commit.gpgsign=false --no-gpg-sign`); user
  squashes at merge. Do not push from implementers.

## Feature 1 — `feat/mobile-net-resilience` (SPA only)

**What:** the SPA tolerates transient connectivity loss and recovers fast.
- `ui/web/src/api/client.ts`: wrap `fetch` with a small bounded retry +
  backoff for *network* errors (TypeError/`Failed to fetch`), NOT for HTTP 4xx/5xx
  (those are real responses). A couple of retries, capped backoff.
- `ui/web/src/api/hooks.ts` (`useAsync`): when `navigator.onLine` is false or
  `document.hidden`, suspend the poll interval; on the `online` window event,
  fire an immediate refetch. (Keep the existing `pollMs` behavior otherwise.)
- `ui/web/src/app.tsx`: a small, dismissible **offline banner** driven by
  `navigator.onLine` + `online`/`offline` events.
**Tests:** Vitest — retry-then-succeed on a flaky fetch; no retry on a 500;
poll suspends when offline and refetches on `online`; banner shows/hides.
**No Go, no Android.** Independently useful on desktop/browser too.

## Feature 2 — `feat/mobile-reconnect` (Go + gomobile + Android)

**What:** a host network change re-dials the node's peers instead of waiting.
- `ui/internal/supervisor`: add `Reconnect(ctx)` — bounce the running node's
  peer connections (re-dial). Simplest correct implementation: relaunch the node
  run via the existing runID-versioned path (`bootstrapThenLaunch`/run
  versioning) **preserving DataDir** (no re-bootstrap, no data loss); if dingo
  exposes a cheaper connmanager re-dial, prefer that. No-op safely if not running.
- `ui/internal/boot`: `App.OnNetworkChanged()` → `supervisor.Reconnect`.
- `ui/mobile/mobile.go`: exported `(*App) OnNetworkChanged() error` → `boot.App`.
- `mobile/android/.../MainActivity.kt`: register a
  `ConnectivityManager.NetworkCallback`; on `onAvailable`/`onLost` (debounced),
  call the bound `app.onNetworkChanged()` and reload the WebView.
**Tests:** Go — `Reconnect` while running relaunches (new runID, DataDir
unchanged) and is a safe no-op when stopped; `mobile.App.OnNetworkChanged`
delegates. (Android glue verified in the manual APK pass.)

## Feature 3 — `feat/mobile-resume` (gomobile + Android + SPA)

**What:** on resume from background, the node catches up and the UI refetches.
- `ui/mobile/mobile.go`: exported `(*App) OnResume() error` → `boot.App.OnResume()`
  → a supervisor "kick" (status refresh / re-dial if the run died while
  suspended; reuse `Reconnect` if that's the right primitive).
- `mobile/android/.../MainActivity.kt`: `onResume()`/`onPause()` overrides →
  call `app.onResume()` and trigger a WebView refresh.
- `ui/web/src/app.tsx`: `document 'visibilitychange'` → on becoming visible,
  refetch the active views (status/balance/activity).
**Tests:** Go — `OnResume` delegates and is safe before Start; SPA — visibility
→ refetch fires.

## Feature 4 — `feat/mobile-foreground` (Android only)

**What:** keep the node alive while backgrounded so it stays synced, with a
persistent notification, rather than being killed by the OS.
- A `ForegroundService` (Kotlin) that owns the booted wallet (moves the
  `mobile.App` lifecycle into the service), started foreground with a
  low-priority "Bursa is syncing" notification; `MainActivity` binds to it and
  points the WebView at the service's loopback port.
- `AndroidManifest.xml`: `FOREGROUND_SERVICE` (+ `FOREGROUND_SERVICE_DATA_SYNC`)
  and `POST_NOTIFICATIONS` permissions; service declaration.
**No Go change expected** (lifecycle moves Android-side). If a clean
start/stop-from-service needs a Go hook, keep it scalar/error.
**Tests:** none automatable here; covered by the manual APK checklist.

## Integration & test APK

- `integration/mobile-opts` = `feat/mobile-foreground` tip (the stack is linear,
  so the top contains all four). Build the test APK in CI (the NDK is
  x86_64-only; this dev box is aarch64 — CI is the only build path), via the
  existing `mobile.yml` `gomobile bind -target=android/arm64` job.
- Manual checklist (separate doc): install APK → toggle airplane mode / switch
  WiFi↔cellular and confirm the node re-dials and the UI recovers → background
  the app for minutes, confirm it stays synced (foreground service) → resume and
  confirm catch-up + refetch.

## Out of scope / follow-ons

- iOS shell wiring of the same hooks (Android first).
- TPM-sealed vault key — separate independent track (`feat/tpm-vault-key`,
  desktop/server), not part of this stack or the APK.
- Battery/doze tuning beyond keeping the node alive (measure first).
