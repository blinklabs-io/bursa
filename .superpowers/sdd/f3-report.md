# Feature 3 — OnResume Report

**Status:** Complete. All tests pass.

**OnResume chain:** `mobile.App.OnResume()` → (mu.Lock, nil-guard) → `boot.App.OnResume()` → (nil-guard, stored ctx) → `supervisor.Reconnect(ctx)` (Stop+relaunch, preserves DataDir, skips re-bootstrap).

**Android threshold:** `onPause` records `System.currentTimeMillis()`. `onResume` always calls `webView.reload()` (cheap, SPA refetch via visibilitychange); only calls `app.onResume()` on a background thread when `elapsed >= 30 000 ms`. Guard: `!app.isInitialized` skips the re-dial entirely before Start.

**SPA visibility refetch:** `useAsync` adds a `document.addEventListener("visibilitychange", () => run(false))` beside the existing `online` listener. The existing `document.hidden` guard in `run()` means a hidden→hidden dispatch is a no-op. Listener removed in the `useEffect` cleanup.

**Reconnect fold (F2-review minor):** `supervisor.Reconnect` now catches the "supervisor already started" sentinel from a concurrent `Start` and returns `nil` — the node is already running, which is the desired post-resume state. Documented in godoc.

**Test results:** `go test ./internal/supervisor/ ./internal/boot/ ./mobile/` — all pass. `npm run type-check && npm run test && npm run build` — 109/109 tests pass, clean build. `GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build ./...` — clean.

**Concerns:** none. Android `onResume` is not unit-testable without a full instrumentation harness; covered by the manual APK checklist per spec.
