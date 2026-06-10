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
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

const (
	coseAlgEdDSA   = -8 // COSE alg: EdDSA
	coseKtyOKP     = 1  // COSE key type: Octet Key Pair
	coseCrvEd25519 = 6  // COSE curve: Ed25519
)

var errAddressDoesNotMatchSigningKey = errors.New("address does not match signing key")

func decodeHex(s string) ([]byte, error) {
	out, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return out, nil
}

// buildProtectedHeaders serializes the COSE protected header map
// {1: -8, "address": addr} to CBOR bytes.
func buildProtectedHeaders(addr []byte) ([]byte, error) {
	hdr := map[any]any{
		int64(1):  int64(coseAlgEdDSA),
		"address": addr,
	}
	return cbor.Encode(hdr)
}

// buildSigStructure builds the COSE Sig_structure (ToBeSigned) for a COSE_Sign1.
func buildSigStructure(protected, payload []byte) ([]byte, error) {
	return cbor.Encode([]any{"Signature1", protected, []byte{}, payload})
}

func coseInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int8:
		return int64(x), true
	case int16:
		return int64(x), true
	case int32:
		return int64(x), true
	case int64:
		return x, true
	case uint:
		if uint64(x) > math.MaxInt64 {
			return 0, false
		}
		return int64(x), true
	case uint8:
		return int64(x), true
	case uint16:
		return int64(x), true
	case uint32:
		return int64(x), true
	case uint64:
		if x > math.MaxInt64 {
			return 0, false
		}
		return int64(x), true
	default:
		return 0, false
	}
}

func lookupCoseIntLabel(
	m map[any]cbor.RawMessage,
	label int64,
) (cbor.RawMessage, bool) {
	for k, v := range m {
		if got, ok := coseInt(k); ok && got == label {
			return v, true
		}
	}
	return nil, false
}

func lookupCoseStringLabel(
	m map[any]cbor.RawMessage,
	label string,
) (cbor.RawMessage, bool) {
	for k, v := range m {
		if got, ok := k.(string); ok && got == label {
			return v, true
		}
	}
	return nil, false
}

func decodeCoseInt(raw cbor.RawMessage, field string) (int64, error) {
	var value any
	if _, err := cbor.Decode(raw, &value); err != nil {
		return 0, fmt.Errorf("failed to decode COSE %s: %w", field, err)
	}
	got, ok := coseInt(value)
	if !ok {
		return 0, fmt.Errorf("COSE %s must be an integer", field)
	}
	return got, nil
}

func decodeCoseBool(raw cbor.RawMessage, field string) (bool, error) {
	var value bool
	if _, err := cbor.Decode(raw, &value); err != nil {
		return false, fmt.Errorf("failed to decode COSE %s: %w", field, err)
	}
	return value, nil
}

func lookupCoseBoolStringLabel(
	m map[any]cbor.RawMessage,
	label string,
	field string,
) (bool, bool, error) {
	raw, ok := lookupCoseStringLabel(m, label)
	if !ok {
		return false, false, nil
	}
	value, err := decodeCoseBool(raw, field)
	if err != nil {
		return false, false, err
	}
	return value, true, nil
}

func requireCoseInt(
	m map[any]cbor.RawMessage,
	label int64,
	want int64,
	field string,
) error {
	raw, ok := lookupCoseIntLabel(m, label)
	if !ok {
		return fmt.Errorf("COSE %s missing label %d", field, label)
	}
	got, err := decodeCoseInt(raw, field)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("unexpected COSE %s %d (want %d)", field, got, want)
	}
	return nil
}

func validateProtectedHeaders(protected []byte) error {
	var m map[any]cbor.RawMessage
	if _, err := cbor.Decode(protected, &m); err != nil {
		return fmt.Errorf("failed to decode COSE protected headers: %w", err)
	}
	return requireCoseInt(
		m,
		int64(1),
		int64(coseAlgEdDSA),
		"protected algorithm",
	)
}

func extractProtectedAddress(protected []byte) ([]byte, error) {
	var m map[any]cbor.RawMessage
	if _, err := cbor.Decode(protected, &m); err != nil {
		return nil, fmt.Errorf("failed to decode COSE protected headers: %w", err)
	}
	raw, ok := lookupCoseStringLabel(m, "address")
	if !ok {
		return nil, errors.New("COSE protected address missing")
	}
	var addr []byte
	if _, err := cbor.Decode(raw, &addr); err != nil {
		return nil, fmt.Errorf("failed to decode COSE protected address: %w", err)
	}
	return addr, nil
}

func extractProtectedPayloadHashed(protected []byte) (bool, bool, error) {
	var m map[any]cbor.RawMessage
	if _, err := cbor.Decode(protected, &m); err != nil {
		return false, false, fmt.Errorf(
			"failed to decode COSE protected headers: %w",
			err,
		)
	}
	return lookupCoseBoolStringLabel(m, "hashed", "hashed header")
}

func extractUnprotectedPayloadHashed(
	unprotected cbor.RawMessage,
) (bool, bool, error) {
	if len(unprotected) == 0 {
		return false, false, nil
	}
	var m map[any]cbor.RawMessage
	if _, err := cbor.Decode(unprotected, &m); err != nil {
		return false, false, fmt.Errorf(
			"failed to decode COSE unprotected headers: %w",
			err,
		)
	}
	return lookupCoseBoolStringLabel(m, "hashed", "hashed header")
}

func extractPayloadHashed(
	protected []byte,
	unprotected cbor.RawMessage,
) (bool, error) {
	protectedHashed, hasProtectedHashed, err := extractProtectedPayloadHashed(
		protected,
	)
	if err != nil {
		return false, err
	}
	unprotectedHashed, hasUnprotectedHashed, err := extractUnprotectedPayloadHashed(
		unprotected,
	)
	if err != nil {
		return false, err
	}
	if hasProtectedHashed && hasUnprotectedHashed {
		return false, errors.New("COSE hashed header duplicated")
	}
	if hasProtectedHashed {
		return protectedHashed, nil
	}
	if hasUnprotectedHashed {
		return unprotectedHashed, nil
	}
	return false, nil
}

func payloadToVerify(payload []byte, hashed bool) []byte {
	if !hashed {
		return payload
	}
	hash := lcommon.Blake2b224Hash(payload)
	return hash[:]
}

func validateAddressForVKey(addrBytes, vkey []byte) error {
	if len(vkey) != ed25519.PublicKeySize {
		return fmt.Errorf("unexpected public key size %d", len(vkey))
	}
	addr, err := lcommon.NewAddressFromBytes(addrBytes)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}
	keyHash := lcommon.Blake2b224Hash(vkey)
	switch addr.Type() {
	case lcommon.AddressTypeKeyKey,
		lcommon.AddressTypeKeyScript,
		lcommon.AddressTypeKeyPointer,
		lcommon.AddressTypeKeyNone:
		if addr.PaymentKeyHash() == keyHash {
			return nil
		}
	case lcommon.AddressTypeNoneKey:
		if addr.StakeKeyHash() == keyHash {
			return nil
		}
	}
	return errAddressDoesNotMatchSigningKey
}

// SignData signs payload per CIP-8/CIP-30 signData and returns the hex-encoded
// COSE_Sign1 signature and the hex-encoded COSE_Key.
func SignData(addr, payload []byte, lk *LoadedKey) (signatureHex, keyHex string, err error) {
	if lk == nil {
		return "", "", errors.New("signing key cannot be nil")
	}
	vkey, sign, err := signerForKey(lk)
	if err != nil {
		return "", "", err
	}
	if err := validateAddressForVKey(addr, vkey); err != nil {
		return "", "", err
	}
	protected, err := buildProtectedHeaders(addr)
	if err != nil {
		return "", "", err
	}
	toBeSigned, err := buildSigStructure(protected, payload)
	if err != nil {
		return "", "", err
	}
	signature := sign(toBeSigned)
	coseSign1Bytes, err := cbor.Encode([]any{
		protected,
		map[any]any{"hashed": false},
		payload,
		signature,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to encode COSE_Sign1: %w", err)
	}
	coseKey, err := cbor.Encode(map[any]any{
		int64(1):  int64(coseKtyOKP),
		int64(3):  int64(coseAlgEdDSA),
		int64(-1): int64(coseCrvEd25519),
		int64(-2): vkey,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to encode COSE_Key: %w", err)
	}
	return hex.EncodeToString(coseSign1Bytes), hex.EncodeToString(coseKey), nil
}

// coseSign1 is the decoded COSE_Sign1 array.
type coseSign1 struct {
	cbor.StructAsArray
	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

// extractCoseKeyPub extracts the public key (label -2) from a COSE_Key.
func extractCoseKeyPub(keyBytes []byte) ([]byte, error) {
	var m map[any]cbor.RawMessage
	if _, err := cbor.Decode(keyBytes, &m); err != nil {
		return nil, fmt.Errorf("failed to decode COSE_Key: %w", err)
	}
	if err := requireCoseInt(m, int64(1), int64(coseKtyOKP), "key type"); err != nil {
		return nil, err
	}
	if err := requireCoseInt(m, int64(3), int64(coseAlgEdDSA), "key algorithm"); err != nil {
		return nil, err
	}
	if err := requireCoseInt(m, int64(-1), int64(coseCrvEd25519), "key curve"); err != nil {
		return nil, err
	}
	raw, ok := lookupCoseIntLabel(m, int64(-2))
	if !ok {
		return nil, errors.New("COSE_Key missing public key (label -2)")
	}
	var pub []byte
	if _, err := cbor.Decode(raw, &pub); err != nil {
		return nil, fmt.Errorf("failed to decode COSE_Key public key: %w", err)
	}
	return pub, nil
}

// VerifyData verifies a CIP-8/CIP-30 signData signature (hex COSE_Sign1) using
// the public key from the supplied COSE_Key (hex), over the expected payload.
func VerifyData(signatureHex, keyHex string, expectedPayload []byte) (bool, error) {
	sigBytes, err := decodeHex(signatureHex)
	if err != nil {
		return false, err
	}
	keyBytes, err := decodeHex(keyHex)
	if err != nil {
		return false, err
	}
	var c coseSign1
	if _, err := cbor.Decode(sigBytes, &c); err != nil {
		return false, fmt.Errorf("failed to decode COSE_Sign1: %w", err)
	}
	if err := validateProtectedHeaders(c.Protected); err != nil {
		return false, err
	}
	payload := c.Payload
	if payload == nil && expectedPayload != nil {
		payload = expectedPayload
	}
	if expectedPayload != nil &&
		c.Payload != nil &&
		!bytes.Equal(c.Payload, expectedPayload) {
		return false, nil
	}
	hashed, err := extractPayloadHashed(c.Protected, c.Unprotected)
	if err != nil {
		return false, err
	}
	pub, err := extractCoseKeyPub(keyBytes)
	if err != nil {
		return false, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return false, fmt.Errorf("unexpected public key size %d", len(pub))
	}
	addr, err := extractProtectedAddress(c.Protected)
	if err != nil {
		return false, err
	}
	if err := validateAddressForVKey(addr, pub); err != nil {
		if errors.Is(err, errAddressDoesNotMatchSigningKey) {
			return false, errors.New("protected address does not match public key")
		}
		return false, err
	}
	toBeSigned, err := buildSigStructure(c.Protected, payloadToVerify(payload, hashed))
	if err != nil {
		return false, err
	}
	return ed25519.Verify(ed25519.PublicKey(pub), toBeSigned, c.Signature), nil
}
