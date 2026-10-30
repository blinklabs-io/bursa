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

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/blinklabs-io/bursa/armory/device"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"
)

// Text envelope types and descriptions. Witness and opcert match what
// `bursa tx witness` (internal/cli/tx.go RunTxWitness: "Detached vkey
// witness", type "TxWitness ConwayEra") and `bursa cert op-cert --out`
// (internal/cli/cli.go: "NodeOperationalCertificate", "Operational
// Certificate") write. Key descriptions match bursa.go GetPoolColdVKey and
// GetStakeVKey.
const (
	poolVkeyType         = "StakePoolVerificationKey_ed25519"
	poolVkeyDesc         = "Stake Pool Cold Verification Key"
	stakeVkeyType        = "StakeVerificationKeyShelley_ed25519"
	stakeVkeyDesc        = "Stake Verification Key"
	paymentVkeyType      = "PaymentVerificationKeyShelley_ed25519"
	witnessType          = "TxWitness ConwayEra"
	witnessDesc          = "Detached vkey witness"
	opCertType           = "NodeOperationalCertificate"
	opCertDesc           = "Operational Certificate"
	conwayEra       uint = 6
)

// envelope is the cardano-cli JSON text envelope.
type envelope struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	CborHex     string `json:"cborHex"`
}

func readEnvelope(data []byte) (envelope, []byte, error) {
	var env envelope

	if err := json.Unmarshal(bytes.TrimSpace(data), &env); err != nil {
		return env, nil, fmt.Errorf("not a text envelope: %w", err)
	}

	raw, err := hex.DecodeString(strings.TrimSpace(env.CborHex))
	if err != nil {
		return env, nil, fmt.Errorf("bad cborHex: %w", err)
	}

	return env, raw, nil
}

// marshalEnvelope matches bursa.WriteCborEnvelope: four-space indent and a
// trailing newline.
func marshalEnvelope(typ, desc string, raw []byte) []byte {
	return fmt.Appendf(nil, "{\n    \"type\": %q,\n    \"description\": %q,\n    \"cborHex\": \"%x\"\n}\n", typ, desc, raw)
}

// marshalOpCertEnvelope matches the fixed template `bursa cert op-cert --out`
// writes, which has no trailing newline.
func marshalOpCertEnvelope(raw []byte) []byte {
	return fmt.Appendf(nil, "{\n    \"type\": %q,\n    \"description\": %q,\n    \"cborHex\": \"%x\"\n}", opCertType, opCertDesc, raw)
}

// vkeyCBOR is a verification key as a CBOR byte string: 5820 + key.
func vkeyCBOR(pub []byte) []byte {
	return append([]byte{0x58, 0x20}, pub...)
}

// readVkey returns the 32-byte key of a verification key envelope of the
// wanted type.
func readVkey(data []byte, wantType string) (ed25519.PublicKey, error) {
	env, raw, err := readEnvelope(data)
	if err != nil {
		return nil, err
	}

	if env.Type != wantType {
		return nil, fmt.Errorf("envelope type %q, want %q", env.Type, wantType)
	}

	if len(raw) != 34 || raw[0] != 0x58 || raw[1] != 0x20 {
		return nil, errors.New("cborHex is not a 32-byte key")
	}

	return ed25519.PublicKey(raw[2:]), nil
}

func hash224(b []byte) [28]byte {
	h, _ := blake2b.New(28, nil)
	h.Write(b)

	var out [28]byte
	copy(out[:], h.Sum(nil))

	return out
}

func toBech32(hrp string, data []byte) (string, error) {
	c, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}

	return bech32.Encode(hrp, c)
}

func fromBech32(s string) (hrp string, data []byte, err error) {
	hrp, c, err := bech32.Decode(s)
	if err != nil {
		return "", nil, err
	}

	data, err = bech32.ConvertBits(c, 5, 8, false)

	return hrp, data, err
}

// network is the address network: testnet 0, mainnet 1.
func networkID(name string) (byte, error) {
	switch name {
	case "mainnet":
		return 1, nil
	case "preview", "preprod", "testnet":
		return 0, nil
	}

	return 0, fmt.Errorf("unknown network %q (mainnet, preview, preprod, testnet)", name)
}

// rewardAddress is header 0xe0|network followed by the stake key hash.
func rewardAddress(net byte, stake ed25519.PublicKey) (string, error) {
	h := hash224(stake)
	raw := append([]byte{0xe0 | net}, h[:]...)

	hrp := "stake_test"
	if net == 1 {
		hrp = "stake"
	}

	return toBech32(hrp, raw)
}

// baseAddress is header 0x00|network, the payment key hash and the stake key
// hash.
func baseAddress(net byte, payment, stake ed25519.PublicKey) (string, error) {
	p, s := hash224(payment), hash224(stake)
	raw := append([]byte{net}, p[:]...)
	raw = append(raw, s[:]...)

	hrp := "addr_test"
	if net == 1 {
		hrp = "addr"
	}

	return toBech32(hrp, raw)
}

// rewardHex decodes a reward address to hex.
func rewardHex(addr string) (string, error) {
	_, data, err := fromBech32(addr)
	if err != nil {
		return "", err
	}

	if len(data) != 29 || data[0]>>4 != 0xe && data[0]>>4 != 0xf {
		return "", errors.New("not a reward address")
	}

	return hex.EncodeToString(data), nil
}

// txBody returns the exact bytes of element 0 of an unsigned transaction's
// CBOR array, without re-encoding.
func txBody(raw []byte) ([]byte, error) {
	var tx []cbor.RawMessage

	if err := cbor.Unmarshal(raw, &tx); err != nil {
		return nil, fmt.Errorf("transaction is not a CBOR array: %w", err)
	}

	if len(tx) != 4 {
		return nil, fmt.Errorf("transaction has %d elements, want 4", len(tx))
	}

	return tx[0], nil
}

// readTx returns the transaction CBOR of a Conway text envelope.
func readTx(data []byte) ([]byte, error) {
	env, raw, err := readEnvelope(data)
	if err != nil {
		return nil, err
	}

	if env.Type != "Unwitnessed Tx ConwayEra" && env.Type != "Tx ConwayEra" {
		return nil, fmt.Errorf("envelope type %q is not a Conway transaction", env.Type)
	}

	return raw, nil
}

// witnessCBOR is [vkey, signature], what bursa.EncodeWitness writes.
func witnessCBOR(vkey, sig []byte) ([]byte, error) {
	return cbor.Marshal([]any{vkey, sig})
}

// opCertCBOR is [[kes_vkey, issue, period, cold_sig], cold_vkey].
func opCertCBOR(kes []byte, issue, period uint64, sig, cold []byte) ([]byte, error) {
	return cbor.Marshal([]any{[]any{kes, issue, period, sig}, cold})
}

// opCertPayload is kes_vkey || chain counter || KES period, big endian.
func opCertPayload(kes []byte, chain, period uint64) []byte {
	out := bytes.Clone(kes)
	out = binary.BigEndian.AppendUint64(out, chain)

	return binary.BigEndian.AppendUint64(out, period)
}

// verifyInventory checks the inventory's version and the identity key's
// attestation over the nonce and keys, and returns the keys by role.
func verifyInventory(identity ed25519.PublicKey, nonce []byte, inv device.Inventory) (map[string]ed25519.PublicKey, error) {
	if inv.Version != device.Protocol {
		return nil, fmt.Errorf("inventory version %q, want %q", inv.Version, device.Protocol)
	}

	if !ed25519.Verify(identity, device.InventoryBinding(nonce, inv.Keys), inv.Attestation) {
		return nil, errors.New("inventory attestation does not verify under the pinned identity key")
	}

	keys := map[string]ed25519.PublicKey{}

	for _, k := range inv.Keys {
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("role %q key is not 32 bytes", k.Role)
		}

		if _, dup := keys[k.Role]; dup {
			return nil, fmt.Errorf("duplicate role %q", k.Role)
		}

		keys[k.Role] = k.PublicKey
	}

	for _, r := range []string{"pool", "stake"} {
		if keys[r] == nil {
			return nil, fmt.Errorf("inventory has no %s key", r)
		}
	}

	return keys, nil
}

// verifySignResponse checks the protocol version, nonce echo, refusal and the
// key's binding signature over the request. The caller verifies the signature
// over the message it expects.
func verifySignResponse(req device.SignRequest, resp device.SignResponse, pub ed25519.PublicKey) error {
	if resp.Version != device.Protocol {
		return fmt.Errorf("response version %q, want %q", resp.Version, device.Protocol)
	}

	if !bytes.Equal(resp.Nonce, req.Nonce) {
		return errors.New("response does not echo the request nonce")
	}

	if resp.Error != "" {
		return fmt.Errorf("device refused: %s", resp.Error)
	}

	if len(resp.Signature) != ed25519.SignatureSize {
		return errors.New("response has no signature")
	}

	if !ed25519.Verify(pub, device.ResponseBinding(req, resp.Signature, resp.Summary), resp.BindingSignature) {
		return errors.New("binding signature does not verify under the device key")
	}

	return nil
}

func hexHash(pub []byte) string {
	h := hash224(pub)
	return hex.EncodeToString(h[:])
}

// txBodyRequest builds the tx-body request for body signed by role's key.
func txBodyRequest(profile, role string, pub ed25519.PublicKey, nonce, body []byte) device.SignRequest {
	era := conwayEra

	return device.SignRequest{
		Version: device.Protocol, Purpose: "tx-body", KeyHash: hexHash(pub), Role: role,
		Nonce: nonce, Payload: body, Profile: profile, Era: &era,
	}
}

// checkTxBody verifies a tx-body response and returns the witness CBOR.
func checkTxBody(req device.SignRequest, resp device.SignResponse, pub ed25519.PublicKey) ([]byte, error) {
	if err := verifySignResponse(req, resp, pub); err != nil {
		return nil, err
	}

	hash := blake2b.Sum256(req.Payload)

	if !ed25519.Verify(pub, hash[:], resp.Signature) {
		return nil, errors.New("signature does not verify over blake2b-256 of the body")
	}

	return witnessCBOR(pub, resp.Signature)
}

// opCertRequest builds the opcert-next request for the pool key.
func opCertRequest(profile string, pub ed25519.PublicKey, nonce, kes []byte, chain, period uint64) device.SignRequest {
	return device.SignRequest{
		Version: device.Protocol, Purpose: "opcert-next", KeyHash: hexHash(pub), Role: "pool",
		Nonce: nonce, Payload: opCertPayload(kes, chain, period), Profile: profile,
	}
}

// checkOpCert verifies an opcert-next response and returns the certificate
// CBOR and issue counter.
func checkOpCert(req device.SignRequest, resp device.SignResponse, pub ed25519.PublicKey, chain, period uint64) ([]byte, uint64, error) {
	if err := verifySignResponse(req, resp, pub); err != nil {
		return nil, 0, err
	}

	if chain == math.MaxUint64 {
		return nil, 0, errors.New("chain counter out of range")
	}

	if resp.IssueCounter == nil {
		return nil, 0, errors.New("response has no issue counter")
	}

	issue := *resp.IssueCounter

	if issue != chain+1 {
		return nil, 0, fmt.Errorf("device issued counter %d, want %d", issue, chain+1)
	}

	kes := req.Payload[:32]

	if !ed25519.Verify(pub, opCertPayload(kes, issue, period), resp.Signature) {
		return nil, 0, errors.New("signature does not verify over kes vkey, issue counter and period")
	}

	raw, err := opCertCBOR(kes, issue, period, resp.Signature, pub)

	return raw, issue, err
}
