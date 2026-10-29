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

# Registers a new Preview stake pool end to end with Bursa and a USB armory:
# a new pool mnemonic, the cold key and owner key imported into the armory, a
# profile with a pinned reward account, the reward account registered by its own key, the
# owner and pool registered with armory witnesses, and the first opcert issued
# by the armory. Every step is checked against the chain.
#
# Preview and test funds only. Each run creates a new pool and uses a new cold
# key object and profile slot on the device; both are permanent.
#
# Required environment:
#   SOCKET        node-to-client socket of a synced Preview node that answers
#                 the GetPoolState query (cardano-node, or Dingo after v0.89.0)
#   PAYER_SKEY    payment signing key that funds the run (text envelope)
#   PAYER_VKEY    its verification key
#   PAYER_ADDR    its enterprise address
#   IDENTITY      armory identity public key, hex (pinned)
#   COLD_KEY_ID   free cold key object, 551878672..551878687
#   SLOT          free profile slot, 0..31
# Optional:
#   BURSA (bursa; needs key pool-owner and tx build), ARMORY_POOL (armory-pool), SIGNER (http://10.0.0.1),
#   SOURCE (10.0.0.2), PROFILE (e2e<slot>@preview), WORK (new temp dir),
#   PLEDGE (1000000000), COST (170000000), MARGIN (0.02),
#   RETIRE (0; 1 retires the pool at the next epoch),
#   OPCERT_CHECK (path to opcert-check; when set, the opcert is re-verified)

set -euo pipefail

BURSA=${BURSA:-bursa}
ARMORY_POOL=${ARMORY_POOL:-armory-pool}
SIGNER=${SIGNER:-http://10.0.0.1}
SOURCE=${SOURCE:-10.0.0.2}
PROFILE=${PROFILE:-e2e${SLOT}@preview}
WORK=${WORK:-$(mktemp -d -t preview-pool-XXXXXX)}
PLEDGE=${PLEDGE:-1000000000}
COST=${COST:-170000000}
MARGIN=${MARGIN:-0.02}
RETIRE=${RETIRE:-0}
NET=preview

export CARDANO_NETWORK=$NET

: "${SOCKET:?}" "${PAYER_SKEY:?}" "${PAYER_VKEY:?}" "${PAYER_ADDR:?}"
: "${IDENTITY:?}" "${COLD_KEY_ID:?}" "${SLOT:?}"

# the script works inside $WORK, so resolve every path it was given first
abs() { case $1 in */*) realpath "$1" ;; *) command -v "$1" ;; esac; }
SOCKET=$(realpath "$SOCKET")
PAYER_SKEY=$(realpath "$PAYER_SKEY")
PAYER_VKEY=$(realpath "$PAYER_VKEY")
BURSA=$(abs "$BURSA")
ARMORY_POOL=$(abs "$ARMORY_POOL")
if [ -n "${OPCERT_CHECK:-}" ]; then OPCERT_CHECK=$(abs "$OPCERT_CHECK"); fi
mkdir -p "$WORK"
WORK=$(realpath "$WORK")

step() { printf '\n== %s\n' "$*"; }
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }
check() { local what=$1; shift; if "$@" > /dev/null; then pass "$what"; else fail "$what"; fi; }

q() { "$BURSA" query "$@" --socket-path "$SOCKET" --network $NET; }
armory() { "$ARMORY_POOL" -signer "$SIGNER" -source "$SOURCE" -identity "$IDENTITY" -profile "$PROFILE" "$@"; }

# submit builds, witnesses, assembles and submits one transaction.
# Usage: submit NAME "CERT..." "LOCAL_SKEY..." "ARMORY_ROLE..."
submit() {
	local name=$1 certs=$2 skeys=$3 roles=$4 args=() wits=()

	for c in $certs; do args+=(--certificate-file "$c"); done

	if ! "$BURSA" tx build --socket-path "$SOCKET" --network $NET \
		--change-address "$CHANGE_ADDR" "${args[@]}" \
		--out-file "$WORK/$name.tx" 2> "$WORK/$name.witnesses"; then
		cat "$WORK/$name.witnesses" >&2
		fail "tx build $name"
	fi
	cat "$WORK/$name.witnesses"

	for k in $skeys; do
		"$BURSA" tx witness --tx-file "$WORK/$name.tx" --signing-key-file "$k" \
			--out-file "$WORK/$name.$(basename "$k").wit"
		wits+=(--witness-file "$WORK/$name.$(basename "$k").wit")
	done

	for r in $roles; do
		armory witness -role "$r" -tx-file "$WORK/$name.tx" -out "$WORK/$name.armory-$r.wit"
		wits+=(--witness-file "$WORK/$name.armory-$r.wit")
	done

	"$BURSA" tx assemble --tx-file "$WORK/$name.tx" "${wits[@]}" --out-file "$WORK/$name.signed"
	local id
	id=$("$BURSA" tx submit --socket-path "$SOCKET" --network $NET --tx-file "$WORK/$name.signed")
	echo "$name submitted: $id"

	# its change output appears at the change address once it is on chain
	wait_for "$name on chain" "any(.[]; .tx_id == \"$id\")" utxo --address "$CHANGE_ADDR"
}

# wait_for polls a jq predicate over a query until it holds, up to 10 minutes.
wait_for() {
	local what=$1 filter=$2; shift 2

	for _ in $(seq 60); do
		if q "$@" | jq -e "$filter" > /dev/null; then
			pass "$what"
			return
		fi
		sleep 10
	done

	fail "$what (timed out)"
}

echo "work directory: $WORK"
cd "$WORK"

step "Preflight"
q tip | tee tip.json
check "node is in Conway" jq -e '.era | ascii_downcase == "conway"' tip.json
curl -sf -m 5 --interface "$SOURCE" "$SIGNER/" > /dev/null || fail "armory not reachable at $SIGNER"
pass "armory reachable"
need=$((PLEDGE + 600000000))
have=$(q utxo --address "$PAYER_ADDR" | jq '[.[] | .amount // .lovelace // 0] | add // 0')
echo "payer has $have lovelace"
[ "$have" -ge "$need" ] || fail "payer needs at least $need lovelace"
pass "payer funded"
CHANGE_ADDR=$PAYER_ADDR

step "Pool mnemonic and keys"
if [ -s pool/seed.txt ] && [ -s pool-cold.vkey ] && [ -s vrf.skey ] && [ -s kes.skey ] && [ -s reward.skey ]; then
	pass "keys exist from an earlier run"
else
"$BURSA" wallet create --output pool > /dev/null
"$BURSA" key pool-cold --mnemonic-file pool/seed.txt \
	--signing-key-file pool-cold.skey --verification-key-file pool-cold.vkey
"$BURSA" key vrf --mnemonic-file pool/seed.txt \
	--signing-key-file vrf.skey --verification-key-file vrf.vkey
"$BURSA" key kes --mnemonic-file pool/seed.txt --index 0 \
	--signing-key-file kes.skey --verification-key-file kes.vkey
"$BURSA" key stake --mnemonic-file pool/seed.txt --account-index 1 \
	--signing-key-file reward.skey --verification-key-file reward.vkey
pass "keys derived"
fi
# a work directory from before owner key import keeps its device-generated owner
if [ ! -s profile.json ] && [ ! -s owner.vkey ]; then
"$BURSA" key pool-owner --mnemonic-file pool/seed.txt \
	--signing-key-file owner.skey --verification-key-file owner.vkey
pass "owner key derived"
fi

step "Import the cold key into object $COLD_KEY_ID"
if jq -e '.pool_id | length == 56' cold.json > /dev/null 2>&1; then
	pass "cold key imported in an earlier run"
else
jq -n --argjson id "$COLD_KEY_ID" --arg key "$(jq -r .cborHex pool-cold.skey)" \
	'{cold_key_id: $id, signing_key: $key}' |
	curl -sf --interface "$SOURCE" -X POST "$SIGNER/provision/cold" --data-binary @- > cold.json.new
cat cold.json.new
mv cold.json.new cold.json
fi
check "device public key matches pool-cold.vkey" \
	test "5820$(jq -r .public_key cold.json)" = "$(jq -r .cborHex pool-cold.vkey)"
rm -f pool-cold.skey
POOL_HEX=$(jq -r .pool_id cold.json)

step "Reward account"
REWARD_ADDR=$("$ARMORY_POOL" address -stake-vkey reward.vkey -network $NET -type reward)
REWARD_HEX=$("$ARMORY_POOL" reward-hex "$REWARD_ADDR")
echo "reward account $REWARD_ADDR ($REWARD_HEX)"
if q stake-address --address "$REWARD_ADDR" | jq -e '.registered == true' > /dev/null; then
	pass "reward account already registered"
else
"$BURSA" cert stake-registration --stake-vkey reward.vkey --deposit 2000000 -o reward-reg.cert
submit reward-reg "reward-reg.cert" "$PAYER_SKEY reward.skey" ""
fi
wait_for "reward account registered" '.registered == true' stake-address --address "$REWARD_ADDR"

step "Provision profile $PROFILE in slot $SLOT"
if jq -e '.owner_key_hash | length == 56' profile.json > /dev/null 2>&1; then
	pass "profile provisioned in an earlier run"
else
[ -s owner.skey ] || fail "owner.skey missing: derive it again from pool/seed.txt"
jq -n --arg name "$PROFILE" --argjson slot "$SLOT" --argjson id "$COLD_KEY_ID" --arg reward "$REWARD_HEX" \
	--arg owner "$(jq -r .cborHex owner.skey)" \
	'{name: $name, network_id: 0, slot: $slot, cold_key_id: $id, reward_account: $reward, owner_signing_key: $owner}' |
	curl -sf --interface "$SOURCE" -X POST "$SIGNER/provision/profile" --data-binary @- > profile.json.new
cat profile.json.new
mv profile.json.new profile.json
fi
OWNER_HASH=$(jq -r .owner_key_hash profile.json)
if [ -s owner.vkey ]; then
check "device owner key matches owner.vkey" \
	test "5820$(jq -r .owner_public_key profile.json | base64 -d | od -An -tx1 -v | tr -d ' \n')" = "$(jq -r .cborHex owner.vkey)"
rm -f owner.skey
else
echo "owner key generated on the device in an earlier run"
fi

step "Device inventory"
mkdir -p device
armory keys -out-dir device | tee keys.txt
check "inventory pool key matches pool-cold.vkey" \
	test "$(jq -r .cborHex device/pool-cold.vkey)" = "$(jq -r .cborHex pool-cold.vkey)"
POOL_ID=$(awk '/^pool id bech32/ {print $NF}' keys.txt)
echo "pool $POOL_ID ($POOL_HEX), owner $OWNER_HASH"

step "Pledge address: payer payment key, owner stake key"
PLEDGE_ADDR=$("$ARMORY_POOL" address -payment-vkey "$PAYER_VKEY" -stake-vkey device/owner.vkey -network $NET)
echo "pledge address $PLEDGE_ADDR (fund it to meet the pledge; tx build spends only from its change address)"

step "Register owner and pool"
OWNER_ADDR=$(awk '/^owner reward address/ {print $NF}' keys.txt)
"$BURSA" cert pool-registration \
	--cold-vkey pool-cold.vkey --vrf-vkey vrf.vkey \
	--pledge "$PLEDGE" --cost "$COST" --margin "$MARGIN" \
	--reward-account "$REWARD_ADDR" \
	--owner-stake-vkey device/owner.vkey \
	--relay-host "e2e-relay.invalid:3001" \
	-o pool-reg.cert
if q stake-address --address "$OWNER_ADDR" | jq -e '.registered == true' > /dev/null; then
	# a rerun re-registers the pool: no deposit, the owner already delegates
	echo "owner already registered: re-registering the pool"
	submit pool-reg "pool-reg.cert" "$PAYER_SKEY" "pool stake"
else
	"$BURSA" cert stake-registration --stake-vkey device/owner.vkey --deposit 2000000 -o owner-reg.cert
	"$BURSA" cert stake-delegation --stake-vkey device/owner.vkey --pool-id "$POOL_HEX" -o owner-deleg.cert
	submit pool-reg "owner-reg.cert pool-reg.cert owner-deleg.cert" "$PAYER_SKEY" "pool stake"
fi
check "tx build named the pool cold witness" grep -q '^pool cold' pool-reg.witnesses
check "tx build named the owner witness" grep -q " $OWNER_HASH\$" pool-reg.witnesses
wait_for "pool registered" '.registered == true' pool --pool-id "$POOL_HEX"

step "Verify registration"
q pool --pool-id "$POOL_HEX" | tee pool.json
check "owners are exactly the device owner" jq -e --arg o "$OWNER_HASH" '.params.owners == [$o]' pool.json
check "reward account is the pinned one" jq -e --arg r "$REWARD_ADDR" '.params.reward_account == $r' pool.json
check "pledge" jq -e --argjson p "$PLEDGE" '.params.pledge == $p' pool.json
check "pool deposit recorded" jq -e '.deposit > 0' pool.json
q stake-address --address "$OWNER_ADDR" | tee owner.json
check "owner registered" jq -e '.registered == true' owner.json
check "owner delegated to the pool" jq -e --arg p "$POOL_ID" --arg h "$POOL_HEX" '.delegated_pool == $p or .delegated_pool == $h' owner.json

step "Policy refuses a pool registration naming another reward account"
"$BURSA" cert pool-registration \
	--cold-vkey pool-cold.vkey --vrf-vkey vrf.vkey \
	--pledge "$PLEDGE" --cost "$COST" --margin "$MARGIN" \
	--reward-account "$OWNER_ADDR" \
	--owner-stake-vkey device/owner.vkey -o bad-reg.cert
"$BURSA" tx build --socket-path "$SOCKET" --network $NET --change-address "$PAYER_ADDR" \
	--certificate-file bad-reg.cert --out-file bad-reg.tx 2> /dev/null
if armory witness -role pool -tx-file bad-reg.tx -out bad-reg.wit 2> bad-reg.err; then
	fail "device signed a registration with another reward account"
fi
cat bad-reg.err
check "device refused another reward account" grep -q "device refused: policy: .*reward account" bad-reg.err

step "First opcert from the armory"
KES_PERIOD=$(jq -r .kes.current_kes_period pool.json)
CHAIN=$(jq -r '.opcert.on_chain_counter // "none"' pool.json)
# a pool that never forged has no counter; the device treats it as 0
EXPECT=$([ "$CHAIN" = none ] && echo 1 || echo $((CHAIN + 1)))
echo "on-chain counter $CHAIN, expecting issue $EXPECT"
armory opcert -kes-vkey kes.vkey -kes-period "$KES_PERIOD" -chain-counter "$CHAIN" -out node.cert | tee opcert.txt
check "issue counter is the on-chain counter plus one" grep -qx "issue counter $EXPECT" opcert.txt
check "opcert written" test -s node.cert
if [ -n "${OPCERT_CHECK:-}" ]; then
	"$OPCERT_CHECK" -vkey "$(jq -r .cborHex pool-cold.vkey)" -cert "$(jq -r .cborHex node.cert)" \
		-pool "$POOL_HEX" -profile "$PROFILE" -signer "$SIGNER" -source "$SOURCE"
	pass "opcert-check reproduced the certificate"
fi

if [ "$RETIRE" = 1 ]; then
	step "Retire the pool"
	EPOCH=$(q tip | jq -r '.epoch + 1')
	"$BURSA" cert pool-retirement --cold-vkey pool-cold.vkey --epoch "$EPOCH" -o retire.cert
	submit retire "retire.cert" "$PAYER_SKEY" "pool"
	wait_for "retirement recorded for epoch $EPOCH" ".retiring_epoch == $EPOCH" pool --pool-id "$POOL_HEX"
fi

step "Done"
echo "pool $POOL_ID registered; artifacts in $WORK"
