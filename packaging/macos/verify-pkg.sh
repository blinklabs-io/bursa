#!/bin/bash
# Copyright 2026 Blink Labs Software
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# verify-pkg.sh - prove a built .pkg is actually distributable.
#
# build-pkg.sh signs, notarizes and staples, but a build that merely completed
# is not evidence: productsign can emit a pkg whose chain Gatekeeper rejects,
# a staple can be missing, and an installer can fail on a machine that is not
# the build host. This checks the three properties a user depends on:
#
#   1. signature   - the pkg carries a Developer ID Installer chain
#   2. notarization- Gatekeeper assesses it as a Notarized Developer ID, and
#                    the ticket is stapled so it verifies offline
#   3. installation- it actually installs, and the installed app is itself
#                    signed and accepted by Gatekeeper
#
# Usage: verify-pkg.sh <path-to-pkg>
#
# Set BURSA_VERIFY_INSTALL=0 to check only signature + notarization (for a host
# where installing to /Applications is not acceptable).

set -euo pipefail

PKG="${1:?usage: verify-pkg.sh <path-to-pkg>}"
APP_PATH="/Applications/Bursa.app"
BUNDLE_ID="com.blinklabssoftware.bursa"
BIN_NAME="bursa-wallet"
VERIFY_INSTALL="${BURSA_VERIFY_INSTALL:-1}"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ -f "${PKG}" ] || die "pkg not found: ${PKG}"

# ---------------------------------------------------------------------------
# 1. Installer signature
# ---------------------------------------------------------------------------
log "Checking pkg signature (pkgutil --check-signature)"
sig_out="$(pkgutil --check-signature "${PKG}" 2>&1)" || {
    printf '%s\n' "${sig_out}" >&2
    die "pkgutil could not verify a signature on ${PKG}"
}
printf '%s\n' "${sig_out}"
printf '%s' "${sig_out}" | grep -q 'Developer ID Installer' \
    || die "pkg is not signed by a Developer ID Installer certificate"

# ---------------------------------------------------------------------------
# 2. Notarization: Gatekeeper assessment + a stapled ticket
# ---------------------------------------------------------------------------
log "Assessing the pkg with Gatekeeper (spctl --type install)"
spctl_out="$(spctl -a -vv --type install "${PKG}" 2>&1)" || {
    printf '%s\n' "${spctl_out}" >&2
    die "Gatekeeper rejected ${PKG}"
}
printf '%s\n' "${spctl_out}"
printf '%s' "${spctl_out}" | grep -q 'accepted' \
    || die "Gatekeeper did not accept ${PKG}"
printf '%s' "${spctl_out}" | grep -q 'Notarized Developer ID' \
    || die "${PKG} is not notarized (no 'Notarized Developer ID' source)"

# stapler validate is the offline check: without a stapled ticket a first
# launch on a machine with no network is refused.
log "Validating the stapled notarization ticket"
xcrun stapler validate "${PKG}" \
    || die "no valid notarization ticket is stapled to ${PKG}"

if [ "${VERIFY_INSTALL}" != "1" ]; then
    log "BURSA_VERIFY_INSTALL=0 - skipping the installation check"
    log "Signature and notarization verified: ${PKG}"
    exit 0
fi

# ---------------------------------------------------------------------------
# 3. Installation
# ---------------------------------------------------------------------------
# Start from a clean slate so a pre-existing app cannot make the check pass.
if [ -d "${APP_PATH}" ]; then
    log "Removing a pre-existing ${APP_PATH} so the install is really tested"
    sudo rm -rf "${APP_PATH}"
fi
sudo pkgutil --forget "${BUNDLE_ID}" >/dev/null 2>&1 || true

log "Installing (installer -pkg ... -target /)"
sudo installer -pkg "${PKG}" -target / -verbose

[ -d "${APP_PATH}" ] || die "installer reported success but ${APP_PATH} is missing"
[ -x "${APP_PATH}/Contents/MacOS/${BIN_NAME}" ] \
    || die "${APP_PATH}/Contents/MacOS/${BIN_NAME} is missing or not executable"

log "Confirming the installer receipt was recorded"
pkgutil --pkg-info "${BUNDLE_ID}" \
    || die "no installer receipt for ${BUNDLE_ID}"

log "Verifying the installed app's code signature"
codesign --verify --deep --strict --verbose=2 "${APP_PATH}" \
    || die "the installed app fails code signature verification"

log "Assessing the installed app with Gatekeeper (spctl --type exec)"
app_spctl="$(spctl -a -vv -t exec "${APP_PATH}" 2>&1)" || {
    printf '%s\n' "${app_spctl}" >&2
    die "Gatekeeper rejected the installed app"
}
printf '%s\n' "${app_spctl}"
printf '%s' "${app_spctl}" | grep -q 'accepted' \
    || die "Gatekeeper did not accept the installed app"
printf '%s' "${app_spctl}" | grep -q 'Notarized Developer ID' \
    || die "the installed app is not notarized"

log "Confirming the installed binary's architecture"
lipo -archs "${APP_PATH}/Contents/MacOS/${BIN_NAME}"

# Leave the runner as it was found: a later step attesting or uploading should
# not see an installed copy, and a self-hosted host must not accumulate them.
log "Uninstalling"
sudo rm -rf "${APP_PATH}"
sudo pkgutil --forget "${BUNDLE_ID}" >/dev/null 2>&1 || true

log "Signature, notarization and installation verified: ${PKG}"
