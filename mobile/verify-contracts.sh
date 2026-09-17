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
# A deferred legacy cleanup has to be finished on a later launch, or the old
# Documents tree survives as a second, stale copy of the wallet. Scope the
# check to the marker-present branch so moving the call elsewhere still fails.
marker_branch=$(sed -n '/if fileManager.fileExists(atPath: marker.path)/,/^                }/p' "$ios")
printf '%s\n' "$marker_branch" | rg -U -q 'Self\.removeMigratedLegacyEntries'
printf '%s\n' 'mobile source contracts verified'
