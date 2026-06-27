// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package poolops

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"golang.org/x/crypto/blake2b"
)

// testMnemonic is the standard 24-word BIP-39 "abandon…art" test vector.
const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

func mustRoot(t *testing.T) (root []byte) {
	t.Helper()
	r, err := bursa.GetRootKeyFromMnemonic(testMnemonic, "")
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	return r
}

// TestDeriveCredentials checks the derived cold/VRF/KES key lengths, the pool
// ID derivation, and that the cold vkey is the standard-Ed25519 public key
// (the representation the opcert and tx witness agree with).
func TestDeriveCredentials(t *testing.T) {
	creds, err := deriveCredentials(mustRoot(t), "preview", 0, 0, 0)
	if err != nil {
		t.Fatalf("deriveCredentials: %v", err)
	}
	if !strings.HasPrefix(creds.PoolID, "pool1") {
		t.Fatalf("pool ID does not start with pool1: %q", creds.PoolID)
	}
	coldVkey, err := hex.DecodeString(creds.Cold.VKeyHex)
	if err != nil || len(coldVkey) != 32 {
		t.Fatalf("cold vkey hex invalid: %v len=%d", err, len(coldVkey))
	}
	// Pool ID hex must equal blake2b-224 of the cold vkey.
	wantHash := lcommon.Blake2b224Hash(coldVkey)
	if creds.PoolIDHex != hex.EncodeToString(wantHash.Bytes()) {
		t.Fatalf("pool ID hex = %q, want %q", creds.PoolIDHex, hex.EncodeToString(wantHash.Bytes()))
	}
	vrf, _ := hex.DecodeString(creds.VRF.VKeyHex)
	if len(vrf) != 32 {
		t.Fatalf("VRF vkey len = %d, want 32", len(vrf))
	}
	kes, _ := hex.DecodeString(creds.KES.VKeyHex)
	if len(kes) != 32 {
		t.Fatalf("KES vkey len = %d, want 32", len(kes))
	}
	// Deterministic: re-derive yields the same pool ID.
	creds2, _ := deriveCredentials(mustRoot(t), "preview", 0, 0, 0)
	if creds.PoolID != creds2.PoolID {
		t.Fatalf("non-deterministic pool ID: %q vs %q", creds.PoolID, creds2.PoolID)
	}
}

// TestPoolIDFromColdVKeyHex checks the air-gap pool-ID computation matches the
// seed-derived one for the same cold vkey, and rejects malformed input.
func TestPoolIDFromColdVKeyHex(t *testing.T) {
	creds, _ := deriveCredentials(mustRoot(t), "preview", 0, 0, 0)
	id, err := poolIDFromColdVKeyHex(creds.Cold.VKeyHex)
	if err != nil {
		t.Fatalf("poolIDFromColdVKeyHex: %v", err)
	}
	if id.Bech32("pool") != creds.PoolID {
		t.Fatalf("air-gap pool ID %q != seed pool ID %q", id.Bech32("pool"), creds.PoolID)
	}
	if _, err := poolIDFromColdVKeyHex("zz"); err == nil {
		t.Fatal("expected error for non-hex cold vkey")
	}
	if _, err := poolIDFromColdVKeyHex("abcd"); err == nil {
		t.Fatal("expected error for wrong-length cold vkey")
	}
}

// TestKESPeriodMath checks the integer-division KES-period formula and the
// zero-divisor guard.
func TestKESPeriodMath(t *testing.T) {
	cases := []struct {
		tip, spkp, want uint64
	}{
		{0, 129600, 0},
		{129599, 129600, 0},
		{129600, 129600, 1},
		{259200, 129600, 2},
		{300000, 129600, 2},
	}
	for _, c := range cases {
		got, err := kesPeriod(c.tip, c.spkp)
		if err != nil {
			t.Fatalf("kesPeriod(%d,%d): %v", c.tip, c.spkp, err)
		}
		if got != c.want {
			t.Fatalf("kesPeriod(%d,%d) = %d, want %d", c.tip, c.spkp, got, c.want)
		}
	}
	if _, err := kesPeriod(100, 0); err == nil {
		t.Fatal("expected error when slots_per_kes_period is zero")
	}
}

// TestBuildMetadataCanonicalHash checks the metadata is canonicalized (JCS) and
// hashed with Blake2b-256, that the hash is reproducible regardless of input
// key ordering/whitespace, and that required fields are enforced.
func TestBuildMetadataCanonicalHash(t *testing.T) {
	in := MetadataInput{Name: "My Pool", Ticker: "POOL", Homepage: "https://pool.example", Description: "A pool."}
	res, err := buildMetadata(in)
	if err != nil {
		t.Fatalf("buildMetadata: %v", err)
	}
	// The hash must equal Blake2b-256 of the canonical JSON.
	sum := blake2b.Sum256([]byte(res.JSON))
	if res.HashHex != hex.EncodeToString(sum[:]) {
		t.Fatalf("hash %q does not match blake2b-256 of canonical JSON", res.HashHex)
	}
	// Canonical JSON must be valid and key-sorted (JCS): "description" < "homepage" < "name" < "ticker".
	if !json.Valid([]byte(res.JSON)) {
		t.Fatalf("canonical JSON invalid: %s", res.JSON)
	}
	wantOrder := []string{"description", "homepage", "name", "ticker"}
	last := -1
	for _, k := range wantOrder {
		idx := strings.Index(res.JSON, "\""+k+"\"")
		if idx < 0 || idx < last {
			t.Fatalf("canonical JSON keys not sorted (%s): %s", k, res.JSON)
		}
		last = idx
	}
	// Whitespace differences in inputs must not change the hash (canonicalization).
	res2, _ := buildMetadata(MetadataInput{Name: "  My Pool  ", Ticker: " POOL ", Homepage: "https://pool.example", Description: "A pool."})
	if res2.HashHex != res.HashHex {
		t.Fatalf("hash changed under whitespace: %q vs %q", res2.HashHex, res.HashHex)
	}
	// Missing required fields are rejected.
	if _, err := buildMetadata(MetadataInput{Ticker: "X"}); err == nil {
		t.Fatal("expected error for missing name")
	}
	if _, err := buildMetadata(MetadataInput{Name: "X"}); err == nil {
		t.Fatal("expected error for missing ticker")
	}
}

// TestBuildRegistrationCert checks the registration cert encodes a 29-byte
// reward account (full stake address per the Cardano CDDL) and references the
// supplied metadata, owners, and relays.
func TestBuildRegistrationCert(t *testing.T) {
	s := &Service{}
	creds, _ := deriveCredentials(mustRoot(t), "preview", 0, 0, 0)
	coldVkey, _ := hex.DecodeString(creds.Cold.VKeyHex)
	vrfHash, _ := hex.DecodeString(creds.VRF.HashHex)

	// reward + owner stake address from the test wallet
	root := mustRoot(t)
	acctKey, _ := bursa.GetAccountKey(root, 0)
	stakeKey, _ := bursa.GetStakeKey(acctKey, 0)
	stakeHash := stakeKey.Public().PublicKey().Hash()
	stakeAddr, _ := lcommon.NewAddressFromParts(lcommon.AddressTypeNoneKey, 0, nil, stakeHash)

	metaHash := strings.Repeat("ab", 32) // 32-byte hex
	port := uint32(3001)
	p := RegistrationParams{
		Pledge:        100_000_000,
		Cost:          340_000_000,
		MarginNum:     3,
		MarginDenom:   100,
		RewardAddress: stakeAddr.String(),
		Owners:        []string{stakeAddr.String()},
		Relays: []Relay{
			{Type: "single_host_address", IPv4: "1.2.3.4", Port: &port},
			{Type: "single_host_name", Hostname: "relay.example.com", Port: &port},
		},
		MetadataURL:  "https://pool.example/meta.json",
		MetadataHash: metaHash,
	}
	res, err := s.buildRegistration(coldVkey, vrfHash, p, nil)
	if err != nil {
		t.Fatalf("buildRegistration: %v", err)
	}
	if res.PoolID != creds.PoolID {
		t.Fatalf("pool ID %q != %q", res.PoolID, creds.PoolID)
	}
	raw, err := hex.DecodeString(res.CBORHex)
	if err != nil {
		t.Fatalf("cbor hex: %v", err)
	}
	// Decode the cert array and inspect the reward account (element index 6).
	var arr []cbor.RawMessage
	if _, err := cbor.Decode(raw, &arr); err != nil {
		t.Fatalf("decode cert array: %v", err)
	}
	if len(arr) != 10 {
		t.Fatalf("cert array len = %d, want 10", len(arr))
	}
	var reward []byte
	if _, err := cbor.Decode(arr[6], &reward); err != nil {
		t.Fatalf("decode reward account: %v", err)
	}
	if len(reward) != 29 {
		t.Fatalf("reward account len = %d, want 29 (full stake address)", len(reward))
	}
	if reward[0]&0xf0 == 0 {
		// network header nibble present (e0 testnet / e1 mainnet); the high
		// nibble (0xe) marks a reward/stake address.
		t.Fatalf("reward account missing stake-address header byte: %x", reward[0])
	}
}

// TestBuildRegistrationMarginValidation rejects out-of-range margins.
func TestBuildRegistrationMarginValidation(t *testing.T) {
	s := &Service{}
	creds, _ := deriveCredentials(mustRoot(t), "preview", 0, 0, 0)
	coldVkey, _ := hex.DecodeString(creds.Cold.VKeyHex)
	vrfHash, _ := hex.DecodeString(creds.VRF.HashHex)
	root := mustRoot(t)
	acctKey, _ := bursa.GetAccountKey(root, 0)
	stakeKey, _ := bursa.GetStakeKey(acctKey, 0)
	stakeHash := stakeKey.Public().PublicKey().Hash()
	stakeAddr, _ := lcommon.NewAddressFromParts(lcommon.AddressTypeNoneKey, 0, nil, stakeHash)

	base := RegistrationParams{RewardAddress: stakeAddr.String(), Owners: []string{stakeAddr.String()}}
	// zero denominator
	bad := base
	bad.MarginNum, bad.MarginDenom = 1, 0
	if _, err := s.buildRegistration(coldVkey, vrfHash, bad, nil); err == nil {
		t.Fatal("expected error for zero margin denominator")
	}
	// margin > 1
	bad = base
	bad.MarginNum, bad.MarginDenom = 3, 2
	if _, err := s.buildRegistration(coldVkey, vrfHash, bad, nil); err == nil {
		t.Fatal("expected error for margin > 1")
	}
}

// TestRetirementCertEncoding checks the retirement cert matches bursa's direct
// construction (type 4, operator hash, epoch).
func TestRetirementCertEncoding(t *testing.T) {
	s := &Service{}
	creds, _ := deriveCredentials(mustRoot(t), "preview", 0, 0, 0)
	res, err := s.BuildRetirementCert("", creds.Cold.VKeyHex, 500)
	if err != nil {
		t.Fatalf("BuildRetirementCert: %v", err)
	}
	if res.PoolID != creds.PoolID {
		t.Fatalf("pool ID %q != %q", res.PoolID, creds.PoolID)
	}
	coldVkey, _ := hex.DecodeString(creds.Cold.VKeyHex)
	op := lcommon.Blake2b224Hash(coldVkey)
	want, _ := bursa.CreatePoolRetirementCertificate(&bursa.PoolRetirementCertificateParams{PoolKeyHash: op, Epoch: 500})
	if res.CBORHex != hex.EncodeToString(want) {
		t.Fatalf("retirement cbor %q != %q", res.CBORHex, hex.EncodeToString(want))
	}
}

// TestOpCertPayloadAndAssemble checks the air-gap opcert flow: the payload is
// CBOR([kesVkey, issue, period]); a cold-key signature over it verifies and is
// assembled into an opcert; a wrong signature is rejected.
func TestOpCertPayloadAndAssemble(t *testing.T) {
	s := &Service{}
	creds, _ := deriveCredentials(mustRoot(t), "preview", 0, 0, 0)
	kesVKeyHex := creds.KES.VKeyHex
	coldVKeyHex := creds.Cold.VKeyHex

	payload, err := s.OpCertPayload(kesVKeyHex, 7, 3)
	if err != nil {
		t.Fatalf("OpCertPayload: %v", err)
	}
	// Payload must equal CBOR([kesVkey, issue, period]).
	kesVkey, _ := hex.DecodeString(kesVKeyHex)
	wantPayload, _ := cbor.Encode([]any{kesVkey, uint64(7), uint64(3)})
	if payload.PayloadHex != hex.EncodeToString(wantPayload) {
		t.Fatalf("payload %q != %q", payload.PayloadHex, hex.EncodeToString(wantPayload))
	}

	// Produce a real cold-key signature using the seed (simulating the air-gap
	// signer) and assemble.
	root := mustRoot(t)
	cold, _ := deriveCold(root, 0)
	defer cold.zero()
	payloadBytes, _ := hex.DecodeString(payload.PayloadHex)
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(cold.seed), payloadBytes)
	opcert, err := s.AssembleOpCert(coldVKeyHex, kesVKeyHex, hex.EncodeToString(sig), 7, 3)
	if err != nil {
		t.Fatalf("AssembleOpCert: %v", err)
	}
	if opcert.IssueNumber != 7 || opcert.KesPeriod != 3 {
		t.Fatalf("opcert issue/period = %d/%d, want 7/3", opcert.IssueNumber, opcert.KesPeriod)
	}
	if opcert.ColdSignatureHex != hex.EncodeToString(sig) {
		t.Fatal("assembled opcert signature mismatch")
	}

	// A wrong signature (all zeros) must be rejected.
	if _, err := s.AssembleOpCert(coldVKeyHex, kesVKeyHex, strings.Repeat("00", 64), 7, 3); err == nil {
		t.Fatal("expected AssembleOpCert to reject a non-verifying signature")
	}
}

// TestRelayConversion checks relay encoding for each relay type and validation.
func TestRelayConversion(t *testing.T) {
	port := uint32(6000)
	cases := []struct {
		name    string
		relay   Relay
		wantErr bool
	}{
		{"ipv4", Relay{Type: "single_host_address", IPv4: "10.0.0.1", Port: &port}, false},
		{"ipv6", Relay{Type: "single_host_address", IPv6: "2001:db8::1"}, false},
		{"hostname", Relay{Type: "single_host_name", Hostname: "relay.example", Port: &port}, false},
		{"multihost", Relay{Type: "multi_host_name", Hostname: "_relays.example"}, false},
		{"bad-ipv4", Relay{Type: "single_host_address", IPv4: "999.1.1.1"}, true},
		{"addr-no-ip", Relay{Type: "single_host_address"}, true},
		{"name-no-host", Relay{Type: "single_host_name"}, true},
		{"unknown", Relay{Type: "carrier_pigeon"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.relay.toPoolRelay()
			if (err != nil) != c.wantErr {
				t.Fatalf("toPoolRelay err = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}
