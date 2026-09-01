#!/usr/bin/env bash
# Copyright 2026 Blink Labs Software
# Licensed under the Apache License, Version 2.0.
#
# Builds the Bursa Android app inside the bursa-android-build container:
#   1. gomobile bind  -> mobile/android/app/libs/bursa.aar  (the wallet core)
#   2. ./gradlew <assembleDebug | assembleRelease bundleRelease>
#   3. copies the resulting APK/AAB to /out (a mounted host dir) if one is mounted.
#
# It expects the repo mounted at /code (the image WORKDIR) and, optionally, an
# output dir mounted at /out. See mobile/android/Dockerfile for the run command.
#
# BURSA_BUILD_TYPE selects the variant:
#   debug   (default) unsigned debug APK, the CI/branch build
#   release           minified release APK + AAB, signed when the keystore
#                     environment (BURSA_KEYSTORE_PATH, BURSA_KEYSTORE_PASSWORD,
#                     BURSA_KEY_ALIAS, BURSA_KEY_PASSWORD) is present
set -euo pipefail

REPO=/code
OUT=/out
BUILD_TYPE="${BURSA_BUILD_TYPE:-debug}"

case "${BUILD_TYPE}" in
    debug | release) ;;
    *)
        echo "!! BURSA_BUILD_TYPE must be 'debug' or 'release', got '${BUILD_TYPE}'" >&2
        exit 2
        ;;
esac

if [ "${BUILD_TYPE}" = release ]; then
    # A release artifact that is not signed cannot be installed or published, so
    # refuse to spend the build rather than emitting one that looks distributable.
    : "${BURSA_KEYSTORE_PATH:?release builds require BURSA_KEYSTORE_PATH}"
    : "${BURSA_KEYSTORE_PASSWORD:?release builds require BURSA_KEYSTORE_PASSWORD}"
    : "${BURSA_KEY_ALIAS:?release builds require BURSA_KEY_ALIAS}"
    : "${BURSA_KEY_PASSWORD:?release builds require BURSA_KEY_PASSWORD}"
    if [ ! -f "${BURSA_KEYSTORE_PATH}" ]; then
        echo "!! keystore not found at ${BURSA_KEYSTORE_PATH}" >&2
        exit 2
    fi
fi

echo "==> Building web bundle (populates the //go:embed dist target)"
# The webui package embeds ui/internal/webui/dist; the repo ships an index.html
# placeholder only so Go builds before the SPA is compiled. The Android image
# includes pinned Node/npm, so the canonical container build must produce the
# production bundle before gomobile embeds it.
(cd "${REPO}/ui/web" && npm ci && npm run build)

echo "==> gomobile bind (android AAR)"
mkdir -p "${REPO}/mobile/android/app/libs"
# arm64 only: the 32-bit Android ABIs (armeabi-v7a/x86) overflow math.MaxUint32
# (int is 32-bit there) in the apollo/dingo deps, so restrict to android/arm64.
(cd "${REPO}/ui" && gomobile bind \
    -target=android/arm64 \
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

copy_out() {
    # $1: description, $2: artifact path
    echo "==> Built $1: $2"
    if [ -d "${OUT}" ]; then
        cp "$2" "${OUT}/"
        echo "    copied to ${OUT}/$(basename "$2")"
    fi
}

if [ "${BUILD_TYPE}" = debug ]; then
    echo "==> ./gradlew assembleDebug"
    ./gradlew --no-daemon assembleDebug

    APK=$(find "${REPO}/mobile/android/app/build/outputs/apk/debug" -name '*.apk' | head -n1 || true)
    if [ -z "${APK}" ]; then
        echo "!! No APK produced" >&2
        exit 1
    fi
    copy_out "debug APK" "${APK}"
else
    echo "==> ./gradlew assembleRelease bundleRelease"
    ./gradlew --no-daemon assembleRelease bundleRelease

    # Gradle writes an unsigned variant to *-unsigned.apk; a signed build must
    # not leave one behind, so select the signed APK explicitly.
    APK=$(find "${REPO}/mobile/android/app/build/outputs/apk/release" \
        -name '*.apk' ! -name '*-unsigned.apk' | head -n1 || true)
    AAB=$(find "${REPO}/mobile/android/app/build/outputs/bundle/release" \
        -name '*.aab' | head -n1 || true)
    if [ -z "${APK}" ]; then
        echo "!! No signed release APK produced" >&2
        exit 1
    fi
    if [ -z "${AAB}" ]; then
        echo "!! No release AAB produced" >&2
        exit 1
    fi

    # Prove the APK really carries a signature before it is published.
    APKSIGNER=$(find "${ANDROID_HOME:-/opt/android-sdk}/build-tools" \
        -name apksigner -type f | sort | tail -n1 || true)
    if [ -z "${APKSIGNER}" ]; then
        echo "!! apksigner not found; cannot verify the release signature" >&2
        exit 1
    fi
    echo "==> apksigner verify"
    "${APKSIGNER}" verify --verbose --print-certs "${APK}"

    copy_out "release APK" "${APK}"
    copy_out "release AAB" "${AAB}"
fi
