# shellcheck shell=bash
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

# Identity of the macOS artifact, shared by build-pkg.sh and verify-pkg.sh.
#
# These must not drift: verify-pkg.sh looks for the bundle build-pkg.sh
# produces, and a verifier that checks for the wrong name fails open only by
# luck. Sourced rather than duplicated so a rename lands in both at once.
#
# Info.plist and distribution.xml also carry BUNDLE_ID and must be updated with
# it.
# shellcheck disable=SC2034 # consumed by the scripts that source this file
BUNDLE_ID="com.blinklabssoftware.bursa"
# shellcheck disable=SC2034 # consumed by the scripts that source this file
APP_NAME="Bursa"
# The single GUI executable's on-disk name (matches ui/cmd/bursa-wallet output).
# shellcheck disable=SC2034 # consumed by the scripts that source this file
BIN_NAME="bursa-wallet"
