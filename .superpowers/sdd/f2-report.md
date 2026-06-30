# Feature 2 — mobile-reconnect — implementation report

**Status:** COMPLETE — all tests pass, build clean, android cross-compile clean.

**Commit SHA:** (see below — committed after this file)

**Reconnect mechanism chosen: Stop + relaunch** via the existing runID-versioned
path in `supervisor.Start`. Dingo's public API exposes no connmanager re-dial
short of tearing the node down (only `connmanager.ListenerConfig` as a
construction option, no runtime reconnect surface). Stop+relaunch is therefore
the cleanest correct path and preserves the synced DataDir (Mithril marker
present → `shouldBootstrap` returns false → no re-download, no data loss).

**OnNetworkChanged delegation chain:**
`mobile.App.OnNetworkChanged()` (ui/mobile/mobile.go, nil-guarded under mutex)
→ `boot.App.OnNetworkChanged()` (ui/internal/boot/boot.go, nil-guards `sup`)
→ `supervisor.Supervisor.Reconnect(ctx)` (ui/internal/supervisor/reconnect.go,
no-op when `s.cancel == nil`, otherwise Stop+Start).

**MainActivity glue:** `ConnectivityManager.NetworkCallback` registered in
`registerNetworkCallback()` (called from `onCreate`); `onAvailable`/`onLost`
both schedule a 500 ms debounced `handleNetworkChange()` that calls
`app.onNetworkChanged()` off the main thread, then reloads the WebView on the
UI thread. Callback unregistered in `onDestroy` (before wallet Stop).

**Test results:**
- `go build ./... && go vet ./...` — clean, no errors or warnings.
- `go test ./internal/supervisor/ ./internal/boot/ ./mobile/` — all pass (5
  new tests: 4 supervisor reconnect + 1 boot nil-guard + 2 mobile).
- `GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build ./...` — clean.
- Android glue: manual APK pass (CI only; NDK not available on this aarch64 host).

**Concerns / notes:**
- `NodeFactory` interface added to supervisor to make `dingo.New` injectable for
  tests (same pattern as `Bootstrapper`). This is a minimal, clean addition with
  no production behaviour change; the production path still uses `dingoNodeFactory`.
- `boot.App` stores the parent `ctx` from `Boot` so `OnNetworkChanged` can
  forward it to `Reconnect` without requiring callers to pass a context.
- Stop+relaunch causes a brief re-dial gap (seconds). A future optimisation could
  use a dingo connmanager hook if one is exposed upstream.
