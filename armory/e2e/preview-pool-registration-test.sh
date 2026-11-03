#!/usr/bin/env bash
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

# Runs preview-pool-registration.sh against stub bursa, armory-pool and curl
# (no node, no device) up to its first deliberate failure, and checks how the
# script treats key material:
#   * no signing key appears in the argv of any jq it starts
#   * the device still receives the key (the check is not vacuous)
#   * a user-supplied WORK directory ends up mode 0700
#   * pool-cold.skey and owner.skey are gone after a failed run
#   * a failed cold key import can be rerun in the same directory
#   * the files a rerun needs stay, in a 0700 directory, mode 0600
#
# Usage: bash armory/e2e/preview-pool-registration-test.sh [script]

set -euo pipefail

SCRIPT=$(realpath "${1:-$(dirname "$0")/preview-pool-registration.sh}")
T=$(mktemp -d -t pool-e2e-test-XXXXXX)
trap 'rm -rf "$T"' EXIT
mkdir "$T/bin"
REAL_JQ=$(command -v jq)

COLD_SECRET=5820c01dc01dc01dc01dc01dc01dc01dc01dc01dc01dc01dc01dc01dc01dc01dc01d
OWNER_SECRET=5820beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef
POOL_ID=$(printf 'ab%.0s' $(seq 28))
PUB_HEX=$(printf '11%.0s' $(seq 32))
PUB_B64=$(printf '\x11%.0s' $(seq 32) | base64 -w0)

# jq wrapper: log argv, then run the real jq
cat > "$T/bin/jq" <<STUB
#!/usr/bin/env bash
printf '%s\0' "\$@" >> "$T/jq.argv"
exec "$REAL_JQ" "\$@"
STUB

cat > "$T/bin/bursa" <<STUB
#!/usr/bin/env bash
arg() { local want=\$1; shift; while [ \$# -gt 1 ]; do [ "\$1" = "\$want" ] && { echo "\$2"; return; }; shift; done; }
key() { printf '{"type":"X","description":"","cborHex":"%s"}\n' "\$2" > "\$1"; }
case "\$1 \$2" in
"wallet create") mkdir -p pool; echo "seed words" > pool/seed.txt ;;
"key pool-cold") key "\$(arg --signing-key-file "\$@")" $COLD_SECRET; key "\$(arg --verification-key-file "\$@")" 5820$PUB_HEX ;;
"key pool-owner") key "\$(arg --signing-key-file "\$@")" $OWNER_SECRET; key "\$(arg --verification-key-file "\$@")" 5820$PUB_HEX ;;
"key "*) key "\$(arg --signing-key-file "\$@")" 5820aa; key "\$(arg --verification-key-file "\$@")" 5820bb ;;
"query tip") echo '{"era":"Conway","epoch":1}' ;;
"query utxo") echo '[{"amount":99000000000}]' ;;
"query stake-address") echo '{"registered":true}' ;;
*) echo "unexpected bursa \$*" >&2; exit 99 ;;
esac
STUB

# the device runs the provisioning image and never switches to signing, so the
# script fails at "Device inventory"; STUB_FAIL_COLD=1 fails the cold key import
# first, before pool-cold.skey is removed
cat > "$T/bin/armory-pool" <<STUB
#!/usr/bin/env bash
case "\$*" in
"address "*) echo stake_test1stub ;;
"reward-hex "*) echo e0aa ;;
*" provision cold") [ "\${STUB_FAIL_COLD:-}" = 1 ] && exit 1; cat >> "$T/device.stdin"; printf '{"pool_id":"$POOL_ID","public_key":"$PUB_HEX"}' ;;
*" provision profile") cat >> "$T/device.stdin"; printf '{"owner_key_hash":"$POOL_ID","owner_public_key":"$PUB_B64"}' ;;
*) echo "unexpected armory-pool \$*" >&2; exit 99 ;;
esac
STUB

cat > "$T/bin/curl" <<STUB
#!/usr/bin/env bash
echo "provisioning build"
STUB
chmod +x "$T/bin/"*

problems=0
bad() { echo "FAIL: $*"; problems=$((problems + 1)); }

WORK=$T/work
mkdir -m 755 "$WORK"
run() { # run NAME [ENV...]: run the script in $WORK, leave its exit code in $rc
	local name=$1; shift
	rc=0
	env "$@" PATH="$T/bin:$PATH" WORK="$WORK" SOCKET=/dev/null PAYER_SKEY=/dev/null PAYER_VKEY=/dev/null \
		PAYER_ADDR=addr_test1stub IDENTITY=00 COLD_KEY_ID=551878672 SLOT=0 \
		bash "$SCRIPT" > "$T/$name.out" 2>&1 || rc=$?
}

# a failed cold key import
run import STUB_FAIL_COLD=1
[ "$rc" -ne 0 ] || bad "import failure did not fail the script"
for f in pool-cold.skey owner.skey; do
	[ ! -e "$WORK/$f" ] || bad "$f left behind after the failed import"
done

# a rerun in the same directory reaches the deliberate failure
rm -f "$T/device.stdin"
run rerun
[ "$rc" -eq 1 ] || bad "rerun: expected the deliberate failure (exit 1), got $rc"
grep -q 'device runs the provisioning image' "$T/rerun.out" || bad "rerun did not reach the deliberate failure"

[ -s "$T/jq.argv" ] || bad "jq wrapper saw no calls"
# match the bare 32-byte seed, which also covers the 5820-prefixed cborHex;
# failure messages name the key, never its value
for k in COLD OWNER; do
	s=${k}_SECRET
	s=${!s}
	if grep -qaF "${s:4}" "$T/jq.argv"; then bad "$k signing key seed in jq argv"; fi
	grep -qaF "$s" "$T/device.stdin" 2> /dev/null || bad "device never received the $k signing key"
done

[ "$(stat -c %a "$WORK")" = 700 ] || bad "WORK mode $(stat -c %a "$WORK"), want 700"
for f in pool-cold.skey owner.skey; do
	[ ! -e "$WORK/$f" ] || bad "$f left behind after a failed run"
done
for f in pool/seed.txt vrf.skey kes.skey reward.skey; do
	[ -s "$WORK/$f" ] || { bad "$f missing; a rerun needs it"; continue; }
	[ "$(stat -c %a "$WORK/$f")" = 600 ] || bad "$f mode $(stat -c %a "$WORK/$f"), want 600"
done
[ "$(stat -c %a "$WORK/pool")" = 700 ] || bad "pool dir mode $(stat -c %a "$WORK/pool"), want 700"

if [ "$problems" -ne 0 ]; then
	echo "---- script output"; cat "$T/import.out" "$T/rerun.out"
	exit 1
fi
echo "ok"
