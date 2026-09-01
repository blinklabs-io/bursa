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
#
# The install check refuses to run when a Bursa.app is already present, because
# installing over it and uninstalling afterwards would destroy it. Set
# BURSA_REPLACE_INSTALLED=1 to accept that on a throwaway host such as a CI
# runner.

set -euo pipefail

PKG="${1:?usage: verify-pkg.sh <path-to-pkg>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Same identity build-pkg.sh packages, so a rename cannot leave this checking
# for a bundle nothing produces.
# shellcheck source=packaging/macos/identity.sh
. "${SCRIPT_DIR}/identity.sh"
APP_PATH="${BURSA_APP_PATH:-/Applications/${APP_NAME}.app}"
VERIFY_INSTALL="${BURSA_VERIFY_INSTALL:-1}"
REPLACE_INSTALLED="${BURSA_REPLACE_INSTALLED:-0}"
EXPECTED_ARCH="${BURSA_EXPECTED_ARCH:-}"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARNING:\033[0m %s\n' "$*" >&2; }
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
# A pre-existing app would let the check pass without proving anything, and
# this script cannot put one back after it installs over it. Refuse rather than
# destroy it; a throwaway host can opt in.
# -e misses a dangling symlink, so test for that too: anything at this path is
# about to be removed, whatever its type.
if { [ -e "${APP_PATH}" ] || [ -L "${APP_PATH}" ]; } && [ "${REPLACE_INSTALLED}" != "1" ]; then
    die "${APP_PATH} already exists. Verifying the install would overwrite and then remove it. Set BURSA_REPLACE_INSTALLED=1 to allow that (throwaway hosts only), or BURSA_VERIFY_INSTALL=0 to check signature and notarization only."
fi

# From here on the app is this script's to clean up, however it exits: an early
# failure must not leave a half-verified build installed on the host.
cleanup_install() {
    sudo rm -rf "${APP_PATH}"
    sudo pkgutil --forget "${BUNDLE_ID}" >/dev/null 2>&1 || true
}
trap cleanup_install EXIT

if [ -e "${APP_PATH}" ] || [ -L "${APP_PATH}" ]; then
    log "Removing the pre-existing ${APP_PATH} (BURSA_REPLACE_INSTALLED=1)"
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
archs="$(lipo -archs "${APP_PATH}/Contents/MacOS/${BIN_NAME}")"
printf '%s\n' "${archs}"
if [ -n "${EXPECTED_ARCH}" ]; then
    # Apple and Go spell these differently; accept the Go name the release
    # matrix uses and compare on Apple's.
    case "${EXPECTED_ARCH}" in
        arm64 | aarch64) want=arm64 ;;
        amd64 | x86_64) want=x86_64 ;;
        *) die "unsupported BURSA_EXPECTED_ARCH '${EXPECTED_ARCH}' (use arm64 or amd64)" ;;
    esac
    # A wrong-architecture package installs and passes every signature check;
    # only this comparison catches it.
    if ! grep -qw "${want}" <<< "${archs}"; then
        die "installed binary is '${archs}', expected ${want}"
    fi
    log "Architecture matches the expected ${want}"
else
    warn "BURSA_EXPECTED_ARCH unset - not asserting the binary's architecture"
fi

# Uninstall here rather than leaving it to the trap, so the success message
# below cannot claim a verified, cleaned-up state before cleanup has run, and a
# failure to remove the app is reported instead of happening silently after the
# body returns. The trap stays armed until this point to cover the failure
# paths above, and is cleared once it has nothing left to undo.
log "Uninstalling"
cleanup_install
trap - EXIT

log "Signature, notarization and installation verified: ${PKG}"
