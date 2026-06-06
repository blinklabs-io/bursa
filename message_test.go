// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bursa

import (
	"encoding/hex"
	"testing"

	"github.com/blinklabs-io/bursa/bip32"
	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

func testLoadedKey(entropy []byte) *LoadedKey {
	root := bip32.FromBip39Entropy(entropy, nil)
	return &LoadedKey{SKey: []byte(root), VKey: bip32.XPrv(root).PublicKey()}
}

func testEnterpriseAddress(t *testing.T, vkey []byte) []byte {
	t.Helper()
	keyHash := lcommon.Blake2b224Hash(vkey)
	addr, err := lcommon.NewAddressFromParts(
		lcommon.AddressTypeKeyNone,
		lcommon.AddressNetworkTestnet,
		keyHash[:],
		nil,
	)
	if err != nil {
		t.Fatalf("NewAddressFromParts: %v", err)
	}
	addrBytes, err := addr.Bytes()
	if err != nil {
		t.Fatalf("Address.Bytes: %v", err)
	}
	return addrBytes
}

func testBaseAddress(t *testing.T, paymentVKey, stakeVKey []byte) []byte {
	t.Helper()
	paymentHash := lcommon.Blake2b224Hash(paymentVKey)
	stakeHash := lcommon.Blake2b224Hash(stakeVKey)
	addr, err := lcommon.NewAddressFromParts(
		lcommon.AddressTypeKeyKey,
		lcommon.AddressNetworkTestnet,
		paymentHash[:],
		stakeHash[:],
	)
	if err != nil {
		t.Fatalf("NewAddressFromParts: %v", err)
	}
	addrBytes, err := addr.Bytes()
	if err != nil {
		t.Fatalf("Address.Bytes: %v", err)
	}
	return addrBytes
}

func testScriptPaymentBaseAddress(t *testing.T, stakeVKey []byte) []byte {
	t.Helper()
	scriptHash := lcommon.Blake2b224Hash([]byte("script"))
	stakeHash := lcommon.Blake2b224Hash(stakeVKey)
	addr, err := lcommon.NewAddressFromParts(
		lcommon.AddressTypeScriptKey,
		lcommon.AddressNetworkTestnet,
		scriptHash[:],
		stakeHash[:],
	)
	if err != nil {
		t.Fatalf("NewAddressFromParts: %v", err)
	}
	addrBytes, err := addr.Bytes()
	if err != nil {
		t.Fatalf("Address.Bytes: %v", err)
	}
	return addrBytes
}

func testCoseKeyHex(t *testing.T, vkey []byte, kty, alg, crv int64) string {
	t.Helper()
	coseKey, err := cbor.Encode(map[any]any{
		int64(1):  kty,
		int64(3):  alg,
		int64(-1): crv,
		int64(-2): vkey,
	})
	if err != nil {
		t.Fatalf("encode COSE_Key: %v", err)
	}
	return hex.EncodeToString(coseKey)
}

func testCoseSign1Hex(
	t *testing.T,
	lk *LoadedKey,
	addr, payload []byte,
	cosePayload any,
	hashed bool,
	hashedInProtected bool,
) (string, string) {
	t.Helper()
	vkey, sign, err := signerForKey(lk)
	if err != nil {
		t.Fatalf("signerForKey: %v", err)
	}
	protectedHeaders := map[any]any{
		int64(1):  int64(coseAlgEdDSA),
		"address": addr,
	}
	unprotectedHeaders := map[any]any{}
	if hashedInProtected {
		protectedHeaders["hashed"] = hashed
	} else {
		unprotectedHeaders["hashed"] = hashed
	}
	protected, err := cbor.Encode(protectedHeaders)
	if err != nil {
		t.Fatalf("encode protected headers: %v", err)
	}
	payloadToSign := payload
	if hashed {
		hash := lcommon.Blake2b224Hash(payload)
		payloadToSign = hash[:]
	}
	toBeSigned, err := buildSigStructure(protected, payloadToSign)
	if err != nil {
		t.Fatalf("buildSigStructure: %v", err)
	}
	coseSign1Bytes, err := cbor.Encode([]any{
		protected,
		unprotectedHeaders,
		cosePayload,
		sign(toBeSigned),
	})
	if err != nil {
		t.Fatalf("encode COSE_Sign1: %v", err)
	}
	key := testCoseKeyHex(
		t,
		vkey,
		int64(coseKtyOKP),
		int64(coseAlgEdDSA),
		int64(coseCrvEd25519),
	)
	return hex.EncodeToString(coseSign1Bytes), key
}

func TestSignAndVerifyData(t *testing.T) {
	lk := testLoadedKey(make([]byte, 32))
	addr := testEnterpriseAddress(t, lk.VKey)
	payload := []byte("hello cardano")

	sig, key, err := SignData(addr, payload, lk)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	if len(sig) == 0 || len(key) == 0 {
		t.Fatalf("empty signature or key")
	}
	ok, err := VerifyData(sig, key, payload)
	if err != nil {
		t.Fatalf("VerifyData: %v", err)
	}
	if !ok {
		t.Fatalf("signature failed to verify")
	}
}

func TestSignData_NilLoadedKeyFails(t *testing.T) {
	_, _, err := SignData(nil, []byte("payload"), nil)
	if err == nil {
		t.Fatalf("SignData must reject nil signing key")
	}
}

func TestSignData_RejectsSpoofedAddress(t *testing.T) {
	lk := testLoadedKey(make([]byte, 32))
	other := testLoadedKey(append(make([]byte, 31), 1))
	addr := testEnterpriseAddress(t, other.VKey)

	_, _, err := SignData(addr, []byte("payload"), lk)
	if err == nil {
		t.Fatalf("SignData must reject addresses that do not match the signing key")
	}
}

func TestSignData_RejectsBaseAddressStakeKey(t *testing.T) {
	payment := testLoadedKey(make([]byte, 32))
	stake := testLoadedKey(append(make([]byte, 31), 1))
	addr := testBaseAddress(t, payment.VKey, stake.VKey)

	_, _, err := SignData(addr, []byte("payload"), stake)
	if err == nil {
		t.Fatalf("SignData must reject base addresses signed by stake key")
	}
}

func TestSignData_RejectsScriptPaymentBaseAddressStakeKey(t *testing.T) {
	stake := testLoadedKey(make([]byte, 32))
	addr := testScriptPaymentBaseAddress(t, stake.VKey)

	_, _, err := SignData(addr, []byte("payload"), stake)
	if err == nil {
		t.Fatalf("SignData must reject script-payment base addresses signed by stake key")
	}
}

func TestVerifyData_DetachedPayload(t *testing.T) {
	lk := testLoadedKey(make([]byte, 32))
	addr := testEnterpriseAddress(t, lk.VKey)
	payload := []byte("detached payload")
	sig, key := testCoseSign1Hex(t, lk, addr, payload, nil, false, false)

	ok, err := VerifyData(sig, key, payload)
	if err != nil {
		t.Fatalf("VerifyData: %v", err)
	}
	if !ok {
		t.Fatalf("detached payload signature failed to verify")
	}

	ok, err = VerifyData(sig, key, []byte("tampered"))
	if err != nil {
		t.Fatalf("VerifyData tampered: %v", err)
	}
	if ok {
		t.Fatalf("detached signature must not verify with a different payload")
	}
}

func TestVerifyData_HashedPayload(t *testing.T) {
	lk := testLoadedKey(make([]byte, 32))
	addr := testEnterpriseAddress(t, lk.VKey)
	payload := []byte("payload signed through CIP-8 hashed mode")

	tests := []struct {
		name              string
		cosePayload       any
		hashedInProtected bool
	}{
		{name: "embedded unprotected", cosePayload: payload},
		{name: "detached unprotected", cosePayload: nil},
		{
			name:              "embedded protected",
			cosePayload:       payload,
			hashedInProtected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, key := testCoseSign1Hex(
				t,
				lk,
				addr,
				payload,
				tt.cosePayload,
				true,
				tt.hashedInProtected,
			)

			ok, err := VerifyData(sig, key, payload)
			if err != nil {
				t.Fatalf("VerifyData: %v", err)
			}
			if !ok {
				t.Fatalf("hashed payload signature failed to verify")
			}
		})
	}
}

func TestVerifyData_TamperedPayloadFails(t *testing.T) {
	lk := testLoadedKey(make([]byte, 32))
	addr := testEnterpriseAddress(t, lk.VKey)
	sig, key, err := SignData(addr, []byte("original"), lk)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	ok, err := VerifyData(sig, key, []byte("tampered"))
	if err != nil {
		t.Fatalf("VerifyData: %v", err)
	}
	if ok {
		t.Fatalf("tampered payload must not verify")
	}
}

func TestVerifyData_TamperedSignatureFails(t *testing.T) {
	lk := testLoadedKey(make([]byte, 32))
	addr := testEnterpriseAddress(t, lk.VKey)
	payload := []byte("hello cardano")
	sig, key, err := SignData(addr, payload, lk)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	// Flip the last byte of the hex-encoded COSE_Sign1 (mutates the signature bytes).
	b := []byte(sig)
	if b[len(b)-1] == '0' {
		b[len(b)-1] = '1'
	} else {
		b[len(b)-1] = '0'
	}
	ok, err := VerifyData(string(b), key, payload)
	if err != nil {
		// A single-nibble flip may or may not still decode as valid CBOR; if it
		// does decode, ok must be false. If it fails to decode, that's also an
		// acceptable rejection. Either way it must NOT verify as true.
		return
	}
	if ok {
		t.Fatalf("tampered signature must not verify")
	}
}

func TestVerifyData_WrongKeyFails(t *testing.T) {
	lk1 := testLoadedKey(make([]byte, 32))
	lk2 := testLoadedKey(append(make([]byte, 31), 1))

	payload := []byte("hello cardano")
	sig, _, err := SignData(testEnterpriseAddress(t, lk1.VKey), payload, lk1)
	if err != nil {
		t.Fatalf("SignData lk1: %v", err)
	}
	// Get key2's COSE_Key by signing anything with lk2 and taking its key output.
	_, key2, err := SignData(testEnterpriseAddress(t, lk2.VKey), []byte("x"), lk2)
	if err != nil {
		t.Fatalf("SignData lk2: %v", err)
	}
	ok, err := VerifyData(sig, key2, payload)
	if err == nil {
		t.Fatalf("VerifyData must reject a key that does not match the protected address")
	}
	if ok {
		t.Fatalf("signature must not verify under a different key")
	}
}

func TestVerifyData_RejectsProtectedAddressMismatch(t *testing.T) {
	lk1 := testLoadedKey(make([]byte, 32))
	lk2 := testLoadedKey(append(make([]byte, 31), 1))
	payload := []byte("hello cardano")
	protected, err := buildProtectedHeaders(testEnterpriseAddress(t, lk2.VKey))
	if err != nil {
		t.Fatalf("buildProtectedHeaders: %v", err)
	}
	toBeSigned, err := buildSigStructure(protected, payload)
	if err != nil {
		t.Fatalf("buildSigStructure: %v", err)
	}
	vkey, sign, err := signerForKey(lk1)
	if err != nil {
		t.Fatalf("signerForKey: %v", err)
	}
	coseSign1Bytes, err := cbor.Encode([]any{
		protected,
		map[any]any{"hashed": false},
		payload,
		sign(toBeSigned),
	})
	if err != nil {
		t.Fatalf("encode COSE_Sign1: %v", err)
	}
	key := testCoseKeyHex(
		t,
		vkey,
		int64(coseKtyOKP),
		int64(coseAlgEdDSA),
		int64(coseCrvEd25519),
	)

	ok, err := VerifyData(hex.EncodeToString(coseSign1Bytes), key, payload)
	if err == nil {
		t.Fatalf("VerifyData must reject protected address mismatch")
	}
	if ok {
		t.Fatalf("protected address mismatch must not verify")
	}
}

func TestVerifyData_RejectsInvalidCoseKeyMetadata(t *testing.T) {
	lk := testLoadedKey(make([]byte, 32))
	addr := testEnterpriseAddress(t, lk.VKey)
	payload := []byte("hello cardano")
	sig, _, err := SignData(addr, payload, lk)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}

	tests := []struct {
		name string
		kty  int64
		alg  int64
		crv  int64
	}{
		{name: "wrong key type", kty: 2, alg: coseAlgEdDSA, crv: coseCrvEd25519},
		{name: "wrong algorithm", kty: coseKtyOKP, alg: -7, crv: coseCrvEd25519},
		{name: "wrong curve", kty: coseKtyOKP, alg: coseAlgEdDSA, crv: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := testCoseKeyHex(t, lk.VKey, tt.kty, tt.alg, tt.crv)
			ok, err := VerifyData(sig, key, payload)
			if err == nil {
				t.Fatalf("VerifyData must reject invalid COSE key metadata")
			}
			if ok {
				t.Fatalf("invalid COSE key metadata must not verify")
			}
		})
	}
}

func TestVerifyData_RejectsInvalidProtectedAlgorithm(t *testing.T) {
	lk := testLoadedKey(make([]byte, 32))
	addr := testEnterpriseAddress(t, lk.VKey)
	payload := []byte("hello cardano")
	vkey, sign, err := signerForKey(lk)
	if err != nil {
		t.Fatalf("signerForKey: %v", err)
	}
	protected, err := cbor.Encode(map[any]any{
		int64(1):  int64(-7),
		"address": addr,
	})
	if err != nil {
		t.Fatalf("encode protected headers: %v", err)
	}
	toBeSigned, err := buildSigStructure(protected, payload)
	if err != nil {
		t.Fatalf("buildSigStructure: %v", err)
	}
	coseSign1Bytes, err := cbor.Encode([]any{
		protected,
		map[any]any{"hashed": false},
		payload,
		sign(toBeSigned),
	})
	if err != nil {
		t.Fatalf("encode COSE_Sign1: %v", err)
	}
	key := testCoseKeyHex(
		t,
		vkey,
		int64(coseKtyOKP),
		int64(coseAlgEdDSA),
		int64(coseCrvEd25519),
	)

	ok, err := VerifyData(hex.EncodeToString(coseSign1Bytes), key, payload)
	if err == nil {
		t.Fatalf("VerifyData must reject invalid protected algorithm")
	}
	if ok {
		t.Fatalf("invalid protected algorithm must not verify")
	}
}
