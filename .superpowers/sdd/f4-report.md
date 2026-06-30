# Feature 4 — foreground Service (Android) — report

**Status:** complete. Android/Kotlin only; **Go unchanged**. Branch `feat/mobile-foreground`
(stacked on `feat/mobile-resume`). Kotlin compiles only in CI — see gate note.

## What changed (Android only)

- **New `WalletService : Service`** (`mobile/android/app/src/main/java/io/blinklabs/bursa/WalletService.kt`)
  now OWNS the gomobile `App`. Lifecycle:
  - `onCreate`: create the low-importance notification channel (`IMPORTANCE_LOW`,
    `bursa_sync`) — created **before** any `startForeground` (a missing channel
    throws on API 26+).
  - `onStartCommand`: call `startForeground(...)` **first** (before the slow node
    boot, to beat the ~5s `startForegroundService` deadline) with
    `FOREGROUND_SERVICE_TYPE_DATA_SYNC` passed on API 29+ (else the 2-arg form);
    then `startWalletIfNeeded()` → `app.start(filesDir, "preview", true)`.
    Idempotent via a `started` flag (no double-start). Returns `START_STICKY`.
  - `onDestroy`: cancel debounce, **unregister the NetworkCallback**, `app.stop()`.
  - **Binder (`LocalBinder`):** `port()` (returns 0 until booted), pass-throughs
    `onNetworkChanged()` / `onResume()` to the service-held `App`.
  - Notification: ongoing, low-priority "Bursa is syncing", `setOngoing(true)`,
    tap → returns to `MainActivity` (immutable `PendingIntent`).
- **F2 NetworkCallback MOVED into the service** — registered after the node boots,
  500ms debounce, `onNetworkChanged()` on a background `Thread` (node Stop+relaunch
  is blocking); unregistered in `onDestroy`. So re-dial works while backgrounded.
- **`MainActivity`** no longer owns the App. `onCreate`:
  `ContextCompat.startForegroundService(...)` + `bindService(BIND_AUTO_CREATE)`.
  `onServiceConnected` → `loadWebViewWhenReady()` polls the binder's `port()` every
  100ms and loads `http://127.0.0.1:<port>/` only once it is **non-zero**
  (handles the bind-before-boot race). **F3 resume threshold (30s) stays in
  MainActivity**: always cheap `webView.reload()`; route the heavy `onResume()`
  re-dial to the binder off-main-thread only past the threshold. `onDestroy`
  **unbinds but does NOT stop** the service (the node keeps running) and stops the
  port poller.
- **Manifest:** added `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC`,
  `POST_NOTIFICATIONS`; `<service android:name=".WalletService"
  android:exported="false" android:foregroundServiceType="dataSync"/>`. The type is
  on both the `<service>` AND the `startForeground` call (API 34 requirement).
- **Runtime POST_NOTIFICATIONS:** requested on API 33+ via
  `ActivityResultContracts.RequestPermission`; result **ignored** — service runs and
  the notification still posts whether granted or denied (denial only hides it).
- **gradle:** added `androidx.core:core-ktx` (NotificationCompat/ContextCompat) and
  `androidx.activity:activity-ktx` (registerForActivityResult) — both already
  transitive via appcompat, declared explicitly for clarity.
- **strings.xml:** channel + notification title/text strings.

## Verification

- **Go unchanged + cross-compiles:** `cd ui && go build ./...` → exit 0;
  `GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build ./...` → exit 0. `git diff` touches
  only the 5 Android files; reused existing `Start/Stop/Port/OnNetworkChanged/OnResume`
  gomobile methods — no new Go hook needed.
- **Kotlin NOT compiled locally** (no Android SDK/NDK on this aarch64 box; the NDK is
  x86_64-only). The **CI APK job (`mobile.yml`, `gomobile bind -target=android/arm64`)
  is the compile gate.** Self-reviewed against: channel-before-startForeground,
  foregroundServiceType on manifest + startForeground (API 34), 5s
  startForegroundService deadline (startForeground called first), bind lifecycle
  (unbind in onDestroy, no service stop), and the pre-26 startForegroundService
  fallback handled by ContextCompat.

## Lifecycle points I was less than 100% sure about (flagged)

- **START_STICKY restart with a null intent:** `onStartCommand` handles a null intent
  fine (it doesn't read intent extras), so a sticky restart re-boots cleanly. Worth a
  manual-APK confirmation that the OS-restarted (Activity-less) service re-posts the
  notification and re-syncs.
- **Bind-after-process-death:** if the service process is killed and rebinds, `started`
  resets with the process, so a fresh `onStartCommand` re-boots. The Activity's
  `onServiceDisconnected` clears the binder and waits for rebind. Not exercised here.
- **POST_NOTIFICATIONS denied:** API 34 still allows the dataSync foreground service to
  run without the notification visible; confirm on a real API 34 device in the manual
  pass (behaviour is documented but device-dependent).
