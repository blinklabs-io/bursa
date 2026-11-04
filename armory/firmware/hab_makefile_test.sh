#!/usr/bin/env bash
# Checks of the HAB signing support in the Makefile. They need only make: the
# dry runs build nothing, and the signing recipe runs in a temporary directory
# against a stub habtool, empty key files and a placeholder unsigned image.
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
	"armory-multi|NETWORK=multi"
	"armory-provision-multi|PROVISION=1 NETWORK=multi"
	"armory-wipe-multi|WIPE=1 NETWORK=multi"
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
for i in 0 5 x "" "5 1" "1 1"; do
	out=$(dry imx HAB_KEYS=/keys "HAB_SRK_INDEX=$i"); rc=$?
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
[ $rc -eq 0 ] && ! has "$out" habtool; check "unsigned TESTNET=1 build is unaffected" $?

# A multi image serves testnet, cardano-mainnet and prime-mainnet from one
# build: its tag, names and refusals. The refusals are matched by their own
# message, so another error (an unknown NETWORK) does not pass for them.
for v in "armory-multi|" "armory-provision-multi|PROVISION=1" "armory-wipe-multi|WIPE=1"; do
	app=${v%%|*}
	# shellcheck disable=SC2086
	out=$(dry all NETWORK=multi ${v#*|}); rc=$?
	[ $rc -eq 0 ]; check "$app: builds" $?
	has "$out" '-tags [a-z,]*multi'; check "$app: builds with the multi tag" $?
	has "$out" "-o $app\$"; check "$app: is named $app" $?
done
out=$(dry all NETWORK=multi TESTNET=1); rc=$?
[ $rc -ne 0 ]; check "NETWORK=multi TESTNET=1 is refused" $?
has "$out" 'a multi image serves mainnet scopes and must not'; check "NETWORK=multi TESTNET=1 is refused for the unfiltered /sign endpoint" $?
out=$(dry all NETWORK=multi TESTNET=1 PROVISION=1); rc=$?
[ $rc -ne 0 ]; check "NETWORK=multi TESTNET=1 PROVISION=1 is refused" $?
has "$out" 'a multi image serves mainnet scopes and must not'; check "NETWORK=multi TESTNET=1 PROVISION=1 names the multi refusal" $?
out=$(dry imx NETWORK=multi TESTNET=1 HAB_KEYS=/keys HAB_ALLOW_TESTNET=1); rc=$?
[ $rc -ne 0 ]; check "HAB_ALLOW_TESTNET does not allow a TESTNET=1 multi image" $?
has "$out" 'a multi image serves mainnet scopes and must not'; check "HAB_ALLOW_TESTNET=1 multi refusal is the multi one" $?
out=$(dry all NETWORK=multi CHAIN=prime); rc=$?
[ $rc -ne 0 ]; check "NETWORK=multi CHAIN=prime is refused" $?
has "$out" 'CHAIN does not apply to NETWORK=multi'; check "NETWORK=multi CHAIN=prime names the CHAIN refusal" $?
out=$(dry all NETWORK=both); rc=$?
[ $rc -ne 0 ]; has "$out" 'testnet, mainnet or multi'; check "an unknown NETWORK is refused" $?
# the existing single-scope images keep their names and tags
out=$(dry all); has "$out" "-o armory\$"; check "NETWORK default still builds armory" $?
has "$out" 'multi'; [ $? -ne 0 ]; check "the default image has no multi tag" $?
out=$(dry all NETWORK=mainnet CHAIN=prime); has "$out" "-o armory-prime-mainnet\$"; check "NETWORK=mainnet CHAIN=prime still builds armory-prime-mainnet" $?
has "$out" 'multi'; [ $? -ne 0 ]; check "a single mainnet image has no multi tag" $?
# clean removes every image name, the multi ones included
out=$(dry clean)
for a in armory-multi armory-provision-multi armory-wipe-multi; do
	has "$out" "$a\.imx"; check "clean removes $a" $?
	has "$out" "$a-signed\.imx"; check "clean removes $a-signed.imx" $?
done

# The signing recipe itself, with the unsigned image taken as built (-o).
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/keys" "$tmp/work"
for f in CSF_1_key.pem CSF_1_crt.pem IMG_1_key.pem IMG_1_crt.pem SRK_1_2_3_4_table.bin; do
	: >"$tmp/keys/$f"
done
cat >"$tmp/habtool" <<'STUB'
#!/bin/sh
# Stub habtool: record the call and write a CSF to the -o file.
echo ran >"${0%/*}/habtool.ran"
while [ $# -gt 0 ]; do
	if [ "$1" = -o ]; then printf CSF >"$2"; fi
	shift
done
STUB
chmod +x "$tmp/habtool"
cp Makefile "$tmp/work/"
printf IMX >"$tmp/work/armory.imx"
sign() { make -s -C "$tmp/work" -o armory.imx armory-signed.imx "$@" 2>&1; }

rm -f "$tmp/habtool.ran"
out=$(sign HAB_KEYS="$tmp/keys" HABTOOL="$tmp/habtool"); rc=$?
[ $rc -eq 0 ] && [ "$(cat "$tmp/work/armory-signed.imx" 2>/dev/null)" = IMXCSF ]
check "signing appends the CSF to the unsigned image" $?

rm -f "$tmp/habtool.ran" "$tmp/work/armory-signed.imx"
mv "$tmp/keys/IMG_1_key.pem" "$tmp/IMG_1_key.pem"
out=$(sign HAB_KEYS="$tmp/keys" HABTOOL="$tmp/habtool"); rc=$?
[ $rc -ne 0 ] && has "$out" "missing $tmp/keys/IMG_1_key.pem" && [ ! -e "$tmp/habtool.ran" ] && [ ! -e "$tmp/work/armory-signed.imx" ]
check "a missing key file stops signing before habtool" $?
mv "$tmp/IMG_1_key.pem" "$tmp/keys/IMG_1_key.pem"

out=$(sign HAB_KEYS="$tmp/keys" HABTOOL="$tmp/no-habtool"); rc=$?
[ $rc -ne 0 ] && has "$out" "no-habtool not found" && [ ! -e "$tmp/work/armory-signed.imx" ]
check "a missing habtool stops signing" $?

exit $fail
