#!/bin/sh
# Verify native mobile source contracts that can be checked without a native
# device, emulator, Android SDK, or Xcode.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
manifest="$root/mobile/android/app/src/main/AndroidManifest.xml"
gradle="$root/mobile/android/app/build.gradle.kts"
service="$root/mobile/android/app/src/main/java/io/blinklabs/bursa/WalletService.kt"
ios="$root/mobile/ios/Bursa/WalletViewController.swift"
extraction_rules="$root/mobile/android/app/src/main/res/xml/data_extraction_rules.xml"

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

# Library/Application Support is in iCloud and iTunes backup by default, so the
# wallet tree (multi-GB chain db plus the encrypted vault) has to opt out. The
# flag is a per-URL resource value, so it is set on every launch rather than at
# first creation.
rg -q 'values\.isExcludedFromBackup = true' "$ios"
create_branch=$(sed -n '/try fileManager.createDirectory(/,/^            if let documentsDir,/p' "$ios")
printf '%s\n' "$create_branch" | rg -U -q 'Self\.excludeFromBackup\(dataDir\)'
# Documents is backed up too, and the legacy tree outlives the copy: it survives
# the copy window, a deferred cleanup, and a name a later launch cannot remove.
# So it is excluded before the copy starts, not only on the fallback path.
pre_copy=$(sed -n '/try fileManager.createDirectory(/,/let entries = try fileManager.contentsOfDirectory(/p' "$ios")
printf '%s\n' "$pre_copy" | rg -U -q 'Self\.excludeFromBackup\(documentsDir\)'
# A setResourceValues failure leaves the tree backup-eligible, which is the
# condition the exclusion exists to remove, so it is reported to the user and
# not only logged.
exclusion_fn=$(sed -n '/private static func excludeFromBackup(/,/^    }/p' "$ios")
printf '%s\n' "$exclusion_fn" | rg -U -q 'return error\.localizedDescription'
appeared=$(sed -n '/override func viewDidAppear(/,/^    }/p' "$ios")
printf '%s\n' "$appeared" | rg -U -q 'if let detail = backupExclusionFailureDetail'
printf '%s\n' "$appeared" | rg -U -q 'presentStartupWarnings\('
presenter=$(sed -n '/private func presentStartupWarnings(/,/^    }/p' "$ios")
printf '%s\n' "$presenter" | rg -U -q 'UIAlertController'
printf '%s\n' "$presenter" | rg -U -q 'present\(alert, animated: true\)'
# Every exclusion call has to route its failure to that report, so a new call
# site cannot reintroduce the log-only path.
exclusion_calls=$(rg -c 'Self\.excludeFromBackup\(' "$ios")
reported_calls=$(rg -c 'noteBackupExclusionFailure\(Self\.excludeFromBackup\(' "$ios")
if [ "$exclusion_calls" != "$reported_calls" ]; then
    printf '%s\n' 'every Self.excludeFromBackup call must report its failure' >&2
    exit 1
fi
# The failed-migration fallback runs from the legacy Documents tree, which is
# backed up too, so it has to carry the exclusion and has to be reported.
migration_catch=$(sed -n '/wallet data migration failed/,/^    }/p' "$ios")
printf '%s\n' "$migration_catch" | rg -U -q 'Self\.excludeFromBackup\('
printf '%s\n' "$migration_catch" | rg -U -q 'migrationFailureDetail = '

# Android's cloud backup is off at the application level; nothing under
# mobile/android may re-enable it.
rg -q 'android:allowBackup="false"' "$manifest"
# allowBackup does not govern the Android 12+ device-to-device transfer path,
# which has its own rules file. An <include> there would re-admit whatever it
# names, so the section must exclude only.
rg -q 'android:dataExtractionRules="@xml/data_extraction_rules"' "$manifest"
device_transfer=$(sed -n '/<device-transfer>/,/<\/device-transfer>/p' "$extraction_rules")
printf '%s\n' "$device_transfer" | rg -U -q '<exclude domain="root" />'
if printf '%s\n' "$device_transfer" | rg -U -q '<include'; then
    printf '%s\n' 'device-transfer must not re-include a domain' >&2
    exit 1
fi

printf '%s\n' 'mobile source contracts verified'
