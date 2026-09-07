#!/bin/sh
# Verify native mobile source contracts that can be checked without a native
# device, emulator, Android SDK, or Xcode.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
manifest="$root/mobile/android/app/src/main/AndroidManifest.xml"
gradle="$root/mobile/android/app/build.gradle.kts"
service="$root/mobile/android/app/src/main/java/io/blinklabs/bursa/WalletService.kt"
ios="$root/mobile/ios/Bursa/WalletViewController.swift"

rg -q 'targetSdk = 35' "$gradle"
rg -q 'android:foregroundServiceType="dataSync"' "$manifest"
rg -q 'override fun onTimeout\(startId: Int, fgsType: Int\)' "$service"
rg -q 'stopSelf\(startId\)' "$service"

rg -q '\.applicationSupportDirectory' "$ios"
rg -q 'appendingPathComponent\("Bursa", isDirectory: true\)' "$ios"
if rg -q '\.documentDirectory|NSSearchPathForDirectoriesInDomains' "$ios"; then
	printf '%s\n' 'iOS wallet data must not use the Documents directory' >&2
	exit 1
fi

printf '%s\n' 'mobile source contracts verified'
