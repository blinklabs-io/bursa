# Bursa Mobile (Phase 1)

Native Android and iOS shells for the Bursa full-node wallet. Both shells embed
the **same Go wallet core** — the supervised in-process Dingo node + the loopback
control surface that serves the HTTP API and the embedded React SPA — via a
[gomobile](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile) binding, and
point a system WebView at the loopback URL the wallet serves the SPA on.

This is Phase 1: the binding, the native shells, and the CI/Docker build path.
The apps carry whatever wallet features are on this branch's base (main + the
lean-node history-expiry profile); further features arrive automatically as their
branches merge — the shells just load the embedded SPA, so no shell change is
needed per feature.

## Architecture

```
   ┌──────────────────────────── device ────────────────────────────┐
   │                                                                 │
   │  Native shell (Kotlin / Swift)                                  │
   │  ┌───────────────┐         ┌──────────────────────────────────┐ │
   │  │ System WebView │ ──http──▶│  Go wallet core (gomobile lib)   │ │
   │  │  loads the SPA │ 127.0.0.1│  • boot.Boot()                   │ │
   │  │  + calls /api  │  :<port> │  • supervised embedded Dingo node│ │
   │  └───────────────┘         │  • wallet / spend services       │ │
   │        ▲                    │  • api.Handler + embedded SPA    │ │
   │        │ loadUrl/load       └──────────────────────────────────┘ │
   │        └── app.start(dataDir, "preview", lean=true); app.port()  │
   └─────────────────────────────────────────────────────────────────┘
```

- **Shared core.** The boot logic lives in `ui/internal/boot` (`boot.Boot`),
  shared by the desktop binary (`ui/cmd/bursa-wallet`) and the mobile binding
  (`ui/mobile`) so every front end brings up an identical stack.
- **gomobile binding** (`ui/mobile`): an opaque `App` handle with three methods —
  `Start(dataDir, network string, lean bool) error`, `Port() int`, `Stop() error`.
  Start binds the control surface on `127.0.0.1:0` (an OS-assigned loopback port),
  boots the wallet with the lean (history-expiry) profile, and serves the SPA +
  API there; `Port()` returns the chosen port for the WebView. Only
  gomobile-marshalable types cross the boundary (bool/int/int64/float/string/
  []byte/error + the opaque `App` handle) — no maps, slices-of-structs, or
  channels.
- **In-process lean node.** The embedded Dingo node runs in-process with the
  history-expiry ("lean") profile on by default, pruning immutable block history
  past the stability window for a small on-disk footprint, and Mithril fast-sync
  for a practical first sync.

## Layout

```
mobile/
├── README.md                  ← this file
├── android/
│   ├── Dockerfile             ← canonical Android build env (no host SDK needed)
│   ├── build-in-docker.sh     ← in-container build: gomobile bind → ./gradlew
│   ├── settings.gradle.kts, build.gradle.kts, gradle.properties
│   └── app/
│       ├── build.gradle.kts   ← consumes app/libs/bursa.aar; minSdk 24
│       ├── libs/              ← bursa.aar lands here (built by CI/Docker)
│       └── src/main/
│           ├── AndroidManifest.xml             ← INTERNET + network-security-config
│           ├── java/io/blinklabs/bursa/MainActivity.kt
│           └── res/xml/network_security_config.xml  ← cleartext to 127.0.0.1 only
└── ios/
    ├── project.yml            ← xcodegen spec (embeds Bursa.xcframework)
    └── Bursa/
        ├── AppDelegate.swift
        ├── WalletViewController.swift          ← WKWebView onto the loopback port
        └── Info.plist                          ← ATS localhost exception
```

## Why Docker for Android (and not for iOS)

The Android build is **Dockerized** (`android/Dockerfile`): the image carries the
full toolchain — Go 1.26 + gomobile, the Android SDK cmdline-tools + a platform +
the NDK, and JDK 17 + Gradle — so the AAR and APK build **identically in CI and
locally**, with nothing Android-specific installed on the host. This is the
canonical Android build mechanism; CI uses the same image.

**iOS cannot be Dockerized.** Xcode requires macOS and does not run in a Linux
container, so the iOS xcframework and `.app` are built on a **macOS** machine /
CI runner (`macos-latest`). There is no Docker path for iOS.

> **Host architecture: build Android on an `amd64` host.** The Android NDK ships
> only a `linux-x86_64` toolchain prebuilt, and `gomobile bind -target=android`
> panics (`unsupported GOARCH: arm64`) when run on an `arm64` Linux host because
> it cannot find a matching NDK toolchain. Run the Android Docker build on an
> `amd64` machine (or `docker build/run --platform linux/amd64` under emulation
> on Apple Silicon / arm64 Linux). CI's `ubuntu-latest` runners are `amd64`, so
> this is automatic there.

## Building locally

### Android (via Docker — recommended)

From the **repo root** (the build context is the repo so the image can reach
`ui/`):

```sh
# 1. Build the toolchain image (one time; ~heavy, downloads SDK + NDK)
docker build -f mobile/android/Dockerfile -t bursa-android-build .

# 2. Run the build: mounts the repo + an output dir. Produces the AAR at
#    mobile/android/app/libs/bursa.aar and copies the debug APK to ./out/
mkdir -p out
docker run --rm -v "$PWD":/code -v "$PWD/out":/out bursa-android-build
```

The in-container script (`mobile/android/build-in-docker.sh`) runs, in order:

```sh
cd ui && gomobile bind -target=android -androidapi 24 \
    -javapkg io.blinklabs.bursa -o ../mobile/android/app/libs/bursa.aar ./mobile
cd mobile/android && ./gradlew assembleDebug
```

(The Gradle wrapper jar is not committed; the script materializes it with the
image's Gradle on first run.)

### Android (host toolchain, if you prefer)

Requires Go 1.26, JDK 17, the Android SDK + NDK, and `gomobile` (`go install
golang.org/x/mobile/cmd/gomobile@latest && gomobile init`):

```sh
cd ui/web && npm ci && npm run build          # populate the embedded SPA
cd ../ && gomobile bind -target=android -androidapi 24 \
    -javapkg io.blinklabs.bursa -o ../mobile/android/app/libs/bursa.aar ./mobile
cd ../mobile/android && ./gradlew assembleDebug
```

### iOS (requires macOS + Xcode)

```sh
cd ui/web && npm ci && npm run build          # populate the embedded SPA
cd ../ && gomobile bind -target=ios -o ../mobile/ios/Bursa.xcframework ./mobile
cd ../mobile/ios && xcodegen generate          # brew install xcodegen
xcodebuild -project Bursa.xcodeproj -scheme Bursa \
    -sdk iphonesimulator -configuration Debug build
```

## CI

`.github/workflows/mobile.yml` (triggers: `workflow_dispatch` + tags):

- **`android`** (ubuntu): builds the `mobile/android/Dockerfile` image and runs
  the in-container build (`gomobile bind` → `./gradlew assembleDebug`), then
  uploads the APK artifact. Same image as the local Docker path → reproducible.
- **`ios`** (`macos-latest`): installs gomobile, `gomobile bind -target=ios` →
  `Bursa.xcframework`, `xcodegen generate`, `xcodebuild` (simulator, unsigned),
  then uploads the `.app`. macOS-only — Docker does not apply.

## Artifacts produced only in CI / on a Mac

The Go binding compiles and cross-compiles (android/arm64, ios/arm64, CGO off)
in any environment, but the native artifacts need their platform toolchains:

| Artifact            | Where it is produced                                  |
|---------------------|-------------------------------------------------------|
| `bursa.aar`         | Android Docker image (CI `android` job or local Docker) |
| `bursa-debug.apk`   | same — `./gradlew assembleDebug` in the container     |
| `Bursa.xcframework` | macOS only (CI `ios` job / a Mac with Xcode)          |
| `Bursa.app`         | macOS only — `xcodebuild`                             |
