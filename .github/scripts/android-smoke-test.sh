#!/usr/bin/env bash
#
# Launch the Bursa Android app on a running emulator and assert the embedded
# wallet actually booted.
#
# "The app started" is not the property under test: the APK can install and the
# Activity can open while the embedded Cardano node fails, leaving a blank
# WebView. MainActivity logs `wallet ready on 127.0.0.1:<port>` once the service
# reports a live loopback port, and `wallet boot failed: ...` when the node
# cannot start; this script waits for the former and fails fast on the latter.
#
# Expects an emulator already attached to adb. Argument: the APK to install.
set -euo pipefail

APK="${1:?usage: android-smoke-test.sh <apk>}"
PACKAGE="${BURSA_PACKAGE:-io.blinklabs.bursa}"
ACTIVITY="${BURSA_ACTIVITY:-.MainActivity}"
TIMEOUT_SECONDS="${BURSA_SMOKE_TIMEOUT:-180}"
BOOT_TIMEOUT_SECONDS="${BURSA_BOOT_TIMEOUT:-300}"

if [ ! -f "${APK}" ]; then
    echo "!! APK not found: ${APK}" >&2
    exit 1
fi

echo "==> Waiting for the emulator to finish booting"
adb wait-for-device
# Bounded: a wedged emulator would otherwise spin here until the job timeout,
# holding a scarce arm64 runner for hours instead of failing in minutes.
boot_deadline=$(( $(date +%s) + BOOT_TIMEOUT_SECONDS ))
until [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; do
    if [ "$(date +%s)" -ge "${boot_deadline}" ]; then
        echo "!! The emulator did not report sys.boot_completed within ${BOOT_TIMEOUT_SECONDS}s" >&2
        exit 1
    fi
    sleep 2
done

echo "==> Installing ${APK}"
adb install -r -g "${APK}"

# Clear logcat so the readiness assertion cannot pass on a previous run's line.
adb logcat -c

echo "==> Launching ${PACKAGE}/${ACTIVITY}"
adb shell am start -W -n "${PACKAGE}/${ACTIVITY}"

echo "==> Waiting up to ${TIMEOUT_SECONDS}s for the embedded wallet to report ready"
deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
ready=""
while [ "$(date +%s)" -lt "${deadline}" ]; do
    log="$(adb logcat -d 2>/dev/null || true)"

    # Match with here-strings, never `... | grep -q`: grep -q exits on the first
    # match and the writer then dies of SIGPIPE, which under `set -o pipefail`
    # makes the whole pipeline non-zero. A match in a large logcat dump would be
    # read as "no match", and the test would time out instead of passing.
    if grep -q 'wallet boot failed:' <<< "${log}"; then
        echo "!! The embedded wallet failed to boot:" >&2
        grep 'wallet boot failed:' <<< "${log}" >&2
        exit 1
    fi
    if grep -qE 'FATAL EXCEPTION|Force finishing activity '"${PACKAGE}" <<< "${log}"; then
        echo "!! The app crashed on launch:" >&2
        grep -A 20 'FATAL EXCEPTION' <<< "${log}" >&2
        exit 1
    fi
    if grep -qE 'wallet ready on 127\.0\.0\.1:[0-9]+' <<< "${log}"; then
        ready="$(grep -oE 'wallet ready on 127\.0\.0\.1:[0-9]+' <<< "${log}" | tail -n1)"
        break
    fi

    # A dead process will never log readiness, so stop waiting for it.
    if [ -z "$(adb shell pidof "${PACKAGE}" 2>/dev/null | tr -d '\r')" ]; then
        echo "!! ${PACKAGE} is no longer running" >&2
        adb logcat -d | tail -n 100 >&2
        exit 1
    fi
    sleep 3
done

if [ -z "${ready}" ]; then
    echo "!! Timed out after ${TIMEOUT_SECONDS}s waiting for the wallet to report ready" >&2
    adb logcat -d | tail -n 200 >&2
    exit 1
fi
echo "==> ${ready}"

# The wallet runs in a foreground service; if it is not there, the node is not
# surviving past the Activity and the app is not in its intended state.
echo "==> Checking the wallet foreground service is running"
services="$(adb shell dumpsys activity services "${PACKAGE}" 2>&1 || true)"
if ! grep -q 'WalletService' <<< "${services}"; then
    echo "!! WalletService is not running" >&2
    printf '%s\n' "${services}" >&2
    exit 1
fi

echo "==> Android smoke test passed"
