#!/usr/bin/env bash
# Copyright 2026 Blink Labs Software
# Licensed under the Apache License, Version 2.0.
#
# Builds the Bursa Android app inside the bursa-android-build container:
#   1. gomobile bind  -> mobile/android/app/libs/bursa.aar  (the wallet core)
#   2. ./gradlew assembleDebug -> the debug APK
#   3. copies the APK to /out (a mounted host dir) if one is mounted.
#
# It expects the repo mounted at /code (the image WORKDIR) and, optionally, an
# output dir mounted at /out. See mobile/android/Dockerfile for the run command.
set -euo pipefail

REPO=/code
OUT=/out

echo "==> Building web bundle (populates the //go:embed dist target)"
# The webui package embeds ui/internal/webui/dist; the repo ships an index.html
# placeholder, but build the real SPA when node is available so the AAR carries
# the production bundle. (The Android image has no node; CI builds the web bundle
# in a prior step. Skip gracefully if npm is absent.)
if command -v npm >/dev/null 2>&1; then
    (cd "${REPO}/ui/web" && npm ci && npm run build)
else
    echo "    npm not found in image; using the committed dist placeholder."
fi

echo "==> gomobile bind (android AAR)"
mkdir -p "${REPO}/mobile/android/app/libs"
(cd "${REPO}/ui" && gomobile bind \
    -target=android \
    -androidapi 24 \
    -javapkg io.blinklabs.bursa \
    -o "${REPO}/mobile/android/app/libs/bursa.aar" \
    ./mobile)
echo "    wrote mobile/android/app/libs/bursa.aar"

echo "==> Materializing Gradle wrapper (if missing)"
cd "${REPO}/mobile/android"
if [ ! -f gradle/wrapper/gradle-wrapper.jar ]; then
    # The wrapper .jar is binary and not committed; generate it from the pinned
    # Gradle in the image. gradle-wrapper.properties pins the distribution.
    gradle wrapper --gradle-version "${GRADLE_VERSION:-8.11.1}"
fi

echo "==> ./gradlew assembleDebug"
./gradlew --no-daemon assembleDebug

APK=$(find "${REPO}/mobile/android/app/build/outputs/apk/debug" -name '*.apk' | head -n1 || true)
if [ -n "${APK}" ]; then
    echo "==> Built APK: ${APK}"
    if [ -d "${OUT}" ]; then
        cp "${APK}" "${OUT}/"
        echo "    copied to ${OUT}/$(basename "${APK}")"
    fi
else
    echo "!! No APK produced" >&2
    exit 1
fi
