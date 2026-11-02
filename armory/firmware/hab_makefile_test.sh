#!/usr/bin/env bash
# Dry-run checks of the HAB signing support in the Makefile. They need only
# make; no TamaGo toolchain, signing tool or key is used, and nothing is built.
set -u
cd "$(dirname "$0")"

fail=0
check() { # check <description> <condition-status>
	if [ "$2" -eq 0 ]; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi
}
dry() { make -n "$@" 2>&1; }
has() { grep -q -e "$2" <<<"$1"; }

# The default build is unchanged: no signing, no signed image.
out=$(dry imx)
has "$out" habtool; [ $? -ne 0 ]; check "default build does not sign" $?
has "$out" 'armory-signed'; [ $? -ne 0 ]; check "default build makes no signed image" $?
has "$out" 'mkimage'; check "default build still makes the unsigned image" $?

# Every variant signs with the key directory and names its own signed image.
variants=(
	"armory|"
	"armory-provision|PROVISION=1"
	"armory-wipe|WIPE=1"
	"armory-cardano-mainnet|NETWORK=mainnet CHAIN=cardano"
	"armory-prime-mainnet|NETWORK=mainnet CHAIN=prime"
	"armory-provision-cardano-mainnet|PROVISION=1 NETWORK=mainnet CHAIN=cardano"
	"armory-wipe-prime-mainnet|WIPE=1 NETWORK=mainnet CHAIN=prime"
)
for v in "${variants[@]}"; do
	app=${v%%|*}
	# shellcheck disable=SC2086
	out=$(dry imx HAB_KEYS=/keys ${v#*|})
	has "$out" "habtool"; check "$app: habtool runs" $?
	has "$out" "-t /keys/SRK_1_2_3_4_table.bin"; check "$app: SRK table from HAB_KEYS" $?
	has "$out" "-i $app.imx"; check "$app: signs its own image" $?
	has "$out" "$app-signed.imx"; check "$app: writes $app-signed.imx" $?
	has "$out" " -s "; [ $? -ne 0 ]; check "$app: no serial download mode by default" $?
done

# HAB_SDP=1 signs for USB recovery loading into its own file.
out=$(dry imx HAB_KEYS=/keys HAB_SDP=1)
has "$out" " -s "; check "HAB_SDP=1 uses serial download mode" $?
has "$out" "armory-signed-sdp.imx"; check "HAB_SDP=1 writes armory-signed-sdp.imx" $?

# A failed signing run leaves no signed image from an earlier build.
out=$(dry imx HAB_KEYS=/keys)
has "$out" 'rm -f armory-signed.imx'; check "signing removes the old signed image first" $?

# HAB_SRK_INDEX picks the SRK key and the CSF and IMG keys it issued.
out=$(dry imx HAB_KEYS=/keys HAB_SRK_INDEX=2)
has "$out" ' -x 2'; check "HAB_SRK_INDEX=2 signs with SRK key 2" $?
has "$out" '/keys/CSF_2_key.pem'; check "HAB_SRK_INDEX=2 reads CSF_2 keys" $?
has "$out" '/keys/IMG_2_key.pem'; check "HAB_SRK_INDEX=2 reads IMG_2 keys" $?
for i in 0 5 x; do
	out=$(dry imx HAB_KEYS=/keys HAB_SRK_INDEX=$i); rc=$?
	[ $rc -ne 0 ] && has "$out" HAB_SRK_INDEX; check "HAB_SRK_INDEX=$i is refused" $?
done

# A TESTNET image is never signed unless explicitly allowed, and then warns.
out=$(dry imx TESTNET=1 HAB_KEYS=/keys); rc=$?
[ $rc -ne 0 ] && has "$out" HAB_ALLOW_TESTNET && has "$out" '/sign'; check "TESTNET=1 signing is refused" $?
has "$out" 'habtool'; [ $? -ne 0 ]; check "refused TESTNET=1 does not reach habtool" $?
out=$(dry imx TESTNET=1 HAB_KEYS=/keys HAB_ALLOW_TESTNET=1); rc=$?
[ $rc -eq 0 ] && has "$out" habtool; check "TESTNET=1 HAB_ALLOW_TESTNET=1 signs" $?
has "$out" 'WARNING.*unfiltered /sign'; check "allowed TESTNET=1 warns about unfiltered /sign" $?
has "$out" 'armory-testnet-signed.imx'; check "signed TESTNET=1 image is named armory-testnet-signed.imx" $?
has "$out" 'armory-signed.imx'; [ $? -ne 0 ]; check "signed TESTNET=1 image does not take the armory-signed.imx name" $?
out=$(dry imx TESTNET=1 HAB_KEYS=/keys HAB_ALLOW_TESTNET=1 HAB_SDP=1)
has "$out" 'armory-testnet-signed-sdp.imx'; check "signed TESTNET=1 HAB_SDP=1 image is named armory-testnet-signed-sdp.imx" $?
out=$(dry imx TESTNET=1); rc=$?
[ $rc -eq 0 ]; check "unsigned TESTNET=1 build is unaffected" $?

exit $fail
