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

# End-to-end opcert issuance without hardware: armory-sim (the device
# service on a virtual SE050 and a file-backed log card) provisioned with
# armory-pool, then the Bursa signer's armory backend issuing opcerts over
# mTLS as a cold-signer client would, and the signing log verified with
# signlog-verify. Every key is generated here and thrown away.
#
# Run from the repository root:
#   armory/e2e/sim-signer-opcert.sh
# Needs go, openssl, curl, jq and xxd.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SIM_ADDR=${SIM_ADDR:-127.0.0.1:18080}
SIGNER_PORT=${SIGNER_PORT:-18443}
PROFILE=sim@preview
CHAIN=7
PERIOD=100

umask 077
W=$(mktemp -d)
pids=()
cleanup() {
	for p in "${pids[@]}"; do kill "$p" 2> /dev/null || true; done
	wait 2> /dev/null || true
	rm -rf "$W"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
pass() { printf 'PASS %s\n' "$*"; }
fail() {
	printf 'FAIL %s\n' "$*" >&2
	exit 1
}

step "Build"
mkdir -p "$W/bin"
(cd "$ROOT/armory" && go build -o "$W/bin/" ./cmd/armory-sim ./cmd/armory-pool ./cmd/signlog-verify)
(cd "$ROOT" && go build -o "$W/bin/bursa" ./cmd/bursa)
PATH="$W/bin:$PATH"
pass "tools built"

# sim starts an image against the shared state and waits until it answers
sim() {
	armory-sim -listen "$SIM_ADDR" -state "$W/device" -image "$1" -card-blocks 16384 > "$W/sim-$1.log" 2>&1 &
	SIM_PID=$!
	pids+=("$SIM_PID")
	# the signing image formats a new card image before it serves
	for _ in $(seq 600); do
		curl -s -o /dev/null "http://$SIM_ADDR/" && return 0
		sleep 0.1
	done
	fail "armory-sim $1 did not start: $(cat "$W/sim-$1.log")"
}
stop_sim() {
	kill "$SIM_PID"
	wait "$SIM_PID" 2> /dev/null || true
}
pool() { armory-pool -signer "http://$SIM_ADDR" -source 127.0.0.1 "$@"; }

step "Provisioning image"
sim provision
armory-pool host-key -out "$W/host.skey" > "$W/host-key.pub"
pool provision host-key < "$W/host-key.pub" > "$W/host-key.json"
jq -e --arg k "$(jq -r .public_key "$W/host-key.pub")" '.host_keys | index($k)' "$W/host-key.json" > /dev/null ||
	fail "host key not registered"
pass "first host key registered unsigned"

# key material goes through files, never through a process's arguments
cold_request() {
	printf '5820%s' "$(openssl rand -hex 32)" > "$W/cold.key"
	jq -n --rawfile k "$W/cold.key" '{cold_key_id: 551878672, signing_key: $k}'
	rm -f "$W/cold.key"
}

if cold_request |
	armory-pool -signer "http://$SIM_ADDR" -source 127.0.0.1 provision cold > /dev/null 2>&1; then
	fail "an unsigned cold import was accepted after a host key was registered"
fi
pass "unsigned request refused once a host key exists"

echo '{}' | pool -host-key "$W/host.skey" provision identity > "$W/identity.json"
IDENTITY=$(jq -r .public_key "$W/identity.json" | base64 -d | od -An -tx1 -v | tr -d ' \n')
[ ${#IDENTITY} -eq 64 ] || fail "no identity key"
pass "identity key $IDENTITY"

cold_request |
	pool -host-key "$W/host.skey" provision cold > "$W/cold.json"
POOL=$(jq -r .pool_id "$W/cold.json")
COLD_VKEY=$(jq -r .public_key "$W/cold.json")
[ ${#POOL} -eq 56 ] || fail "cold import returned no pool id"
pass "cold key imported, pool $POOL"

jq -n --arg name "$PROFILE" --arg reward "e0$(printf 'ee%.0s' $(seq 28))" --argjson chain "$CHAIN" \
	'{name: $name, network_id: 0, slot: 0, cold_key_id: 551878672, chain_counter: $chain, reward_account: $reward}' |
	pool -host-key "$W/host.skey" provision profile > "$W/profile.json"
jq -e '.owner_key_hash | length == 56' "$W/profile.json" > /dev/null || fail "profile not provisioned"
pass "profile $PROFILE provisioned with floor $CHAIN"
stop_sim

step "Signing image"
sim sign
grep -q 'NOT OPEN' "$W/sim-sign.log" && fail "signing log did not open: $(cat "$W/sim-sign.log")"
pass "signing log open on the card image"

step "Bursa signer, armory backend, mTLS"
mkdir -p "$W/pki"
(
	cd "$W/pki"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=sim-ca \
		-keyout ca.key -out ca.crt 2> /dev/null
	issue() {
		openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" -keyout "$1.key" -out "$1.csr" 2> /dev/null
		openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 -out "$1.crt" \
			-extfile <(printf '%s\n' "$2") 2> /dev/null
	}
	issue server "subjectAltName=IP:127.0.0.1
extendedKeyUsage=serverAuth"
	issue operator "subjectAltName=URI:spiffe://sim/operator
extendedKeyUsage=clientAuth"
	issue intruder "subjectAltName=URI:spiffe://sim/intruder
extendedKeyUsage=clientAuth"
)
cat > "$W/signer.yaml" << EOF
signer:
  listen_address: 127.0.0.1
  listen_port: $SIGNER_PORT
  tls_cert_file: $W/pki/server.crt
  tls_key_file: $W/pki/server.key
  client_ca_cert: $W/pki/ca.crt
  require_client_cert: false
  watermark:
    type: file
    path: $W/watermark.sqlite
    mode: enforce
  backends:
    - name: armory
      type: armory
      address: http://$SIM_ADDR
      profile: $PROFILE
      identity_public_key: $IDENTITY
      host_key_file: $W/host.skey
  callers:
    - subject: spiffe://sim/operator
      keys: ["$POOL"]
  keys:
    - hash: "$POOL"
      backend: armory
      allowed_requests: ["opcert"]
EOF
bursa signer --config "$W/signer.yaml" > "$W/signer.log" 2>&1 &
pids+=("$!")
U=https://127.0.0.1:$SIGNER_PORT
for _ in $(seq 100); do
	curl -s -o /dev/null --cacert "$W/pki/ca.crt" "$U/readyz" && break
	sleep 0.1
done
curl -sf -o /dev/null --cacert "$W/pki/ca.crt" "$U/readyz" || fail "signer not ready: $(tail -5 "$W/signer.log")"
pass "signer ready with the armory key"

KES=$(openssl rand -hex 32)
# sign posts an opcert request as client $1 (none, operator or intruder)
# with chain counter $2 and prints the HTTP status, keeping the body
sign() {
	local cert=()
	[ "$1" = none ] || cert=(--cert "$W/pki/$1.crt" --key "$W/pki/$1.key")
	curl -s -o "$W/resp.json" -w '%{http_code}' --cacert "$W/pki/ca.crt" "${cert[@]}" \
		-H 'Content-Type: application/json' \
		-d "{\"type\":\"opcert\",\"key\":\"$POOL\",\"kes_vkey\":\"$KES\",\"chain_counter\":$2,\"kes_period\":$PERIOD}" \
		"$U/v1/sign"
}

[ "$(sign none "$CHAIN")" = 401 ] || fail "request without a client certificate was not refused"
pass "no client certificate: 401"
[ "$(sign intruder "$CHAIN")" = 403 ] || fail "caller outside the ACL was not refused"
pass "caller outside the ACL: 403"

[ "$(sign operator "$CHAIN")" = 200 ] || fail "opcert refused: $(cat "$W/resp.json")"
ISSUE=$(jq -r .issue_counter "$W/resp.json")
[ "$ISSUE" = $((CHAIN + 1)) ] || fail "issue counter $ISSUE, want $((CHAIN + 1))"
[ "$(jq -r .cold_vkey "$W/resp.json")" = "$COLD_VKEY" ] || fail "cold vkey differs from the imported key"
# the signature covers kes_vkey || issue (BE64) || period (BE64)
printf '%s%016x%016x' "$KES" "$ISSUE" "$PERIOD" | xxd -r -p > "$W/signable.bin"
jq -r .signature "$W/resp.json" | xxd -r -p > "$W/sig.bin"
printf '302a300506032b6570032100%s' "$COLD_VKEY" | xxd -r -p > "$W/cold.der"
openssl pkeyutl -verify -pubin -inkey "$W/cold.der" -keyform DER -rawin \
	-in "$W/signable.bin" -sigfile "$W/sig.bin" > /dev/null || fail "opcert signature does not verify"
pass "opcert issued: chain $CHAIN -> issue $ISSUE, signature verifies under the pool cold key"

[ "$(sign operator $((CHAIN - 2)))" = 409 ] || fail "chain counter below the floor was not refused: $(cat "$W/resp.json")"
pass "chain counter below the recorded one: 409"
code=$(sign operator $((ISSUE + 1)))
[ "$code" != 200 ] || fail "chain counter above the last issued counter was accepted"
pass "chain counter above the last issued counter refused ($code: $(jq -r .error "$W/resp.json" 2> /dev/null))"

step "Signing log"
stop_sim
signlog-verify -identity "$IDENTITY" -image "$W/device/card.img" > "$W/signlog.txt" ||
	fail "signing log does not verify: $(cat "$W/signlog.txt")"
grep -q "chain $CHAIN issue $ISSUE period $PERIOD" "$W/signlog.txt" || fail "opcert missing from the signing log: $(cat "$W/signlog.txt")"
pass "signing log verifies and records chain $CHAIN issue $ISSUE period $PERIOD"

printf '\nALL PASSED\n'
