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

if [ ! -f "${APK}" ]; then
    echo "!! APK not found: ${APK}" >&2
    exit 1
fi

echo "==> Waiting for the emulator to finish booting"
adb wait-for-device
until [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; do
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

    if printf '%s' "${log}" | grep -q 'wallet boot failed:'; then
        echo "!! The embedded wallet failed to boot:" >&2
        printf '%s\n' "${log}" | grep 'wallet boot failed:' >&2
        exit 1
    fi
    if printf '%s' "${log}" | grep -qE 'FATAL EXCEPTION|Force finishing activity '"${PACKAGE}"; then
        echo "!! The app crashed on launch:" >&2
        printf '%s\n' "${log}" | grep -A 20 'FATAL EXCEPTION' >&2
        exit 1
    fi
    if printf '%s' "${log}" | grep -qE 'wallet ready on 127\.0\.0\.1:[0-9]+'; then
        ready="$(printf '%s' "${log}" | grep -oE 'wallet ready on 127\.0\.0\.1:[0-9]+' | tail -n1)"
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
if ! adb shell dumpsys activity services "${PACKAGE}" | grep -q 'WalletService'; then
    echo "!! WalletService is not running" >&2
    adb shell dumpsys activity services "${PACKAGE}" >&2
    exit 1
fi

echo "==> Android smoke test passed"
