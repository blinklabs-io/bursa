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
on_timeout=$(sed -n '/override fun onTimeout(startId: Int, fgsType: Int)/,/^    }/p' "$service")
printf '%s\n' "$on_timeout" | rg -U -q 'override fun onTimeout\(startId: Int, fgsType: Int\)[\s\S]*stopSelf(Result)?\(startId\)'

rg -q '\.applicationSupportDirectory' "$ios"
rg -q 'appendingPathComponent\("Bursa", isDirectory: true\)' "$ios"
printf '%s\n' 'mobile source contracts verified'
