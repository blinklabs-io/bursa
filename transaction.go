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
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa/bip32"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// decodeVkeyWitnessField decodes the value of witness-set key 0 (vkey
// witnesses), handling both the plain-array form (pre-Conway) and the CBOR
// tag-258 set form (Conway+). Returns the witnesses, whether the value was
// tag-258 wrapped, and any error. A nil/empty input yields an empty slice.
func decodeVkeyWitnessField(raw []byte) ([]lcommon.VkeyWitness, bool, error) {
	if len(raw) == 0 {
		return nil, false, nil
	}
	var tag cbor.RawTag
	if _, err := cbor.Decode(raw, &tag); err == nil {
		if tag.Number != cbor.CborTagSet {
			return nil, false, fmt.Errorf("unexpected CBOR tag %d on vkey witnesses", tag.Number)
		}
		var items []lcommon.VkeyWitness
		if _, err := cbor.Decode([]byte(tag.Content), &items); err != nil {
			return nil, false, fmt.Errorf("failed to decode tagged vkey witnesses: %w", err)
		}
		return items, true, nil
	}
	var items []lcommon.VkeyWitness
	if _, err := cbor.Decode(raw, &items); err != nil {
		return nil, false, fmt.Errorf("failed to decode vkey witnesses: %w", err)
	}
	return items, false, nil
}

// encodeVkeyWitnessField encodes vkey witnesses as witness-set key 0, using the
// tag-258 set form when useTag is true (required for Conway+).
func encodeVkeyWitnessField(items []lcommon.VkeyWitness, useTag bool) ([]byte, error) {
	st := cbor.NewSetType[lcommon.VkeyWitness](items, useTag)
	out, err := st.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to encode vkey witnesses: %w", err)
	}
	return out, nil
}

func dedupeVkeyWitnesses(items []lcommon.VkeyWitness) []lcommon.VkeyWitness {
	if len(items) < 2 {
		return items
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]lcommon.VkeyWitness, 0, len(items))
	for _, item := range items {
		key := hex.EncodeToString(item.Vkey) + ":" + hex.EncodeToString(item.Signature)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

// injectVkeyWitnesses adds vkey witnesses to a transaction's witness set
// without re-encoding the transaction body. Only the witness_set element of the
// [body, witness_set, is_valid, aux_data] array is rewritten.
func injectVkeyWitnesses(txCbor []byte, newWits []lcommon.VkeyWitness, useTag bool) ([]byte, error) {
	var arr []cbor.RawMessage
	if _, err := cbor.Decode(txCbor, &arr); err != nil {
		return nil, fmt.Errorf("failed to decode transaction array: %w", err)
	}
	if len(arr) < 2 {
		return nil, fmt.Errorf("unexpected transaction shape: %d elements", len(arr))
	}
	ws := map[uint64]cbor.RawMessage{}
	if len(arr[1]) > 0 {
		if _, err := cbor.Decode(arr[1], &ws); err != nil {
			return nil, fmt.Errorf("failed to decode witness set: %w", err)
		}
	}
	existing, hadTag, err := decodeVkeyWitnessField(ws[0])
	if err != nil {
		return nil, err
	}
	merged := append(existing, newWits...)
	merged = dedupeVkeyWitnesses(merged)
	field0, err := encodeVkeyWitnessField(merged, useTag || hadTag)
	if err != nil {
		return nil, err
	}
	ws[0] = cbor.RawMessage(field0)
	wsBytes, err := cbor.Encode(ws)
	if err != nil {
		return nil, fmt.Errorf("failed to encode witness set: %w", err)
	}
	arr[1] = cbor.RawMessage(wsBytes)
	out, err := cbor.Encode(arr)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signed transaction: %w", err)
	}
	return out, nil
}

// useTagForTxType reports whether the vkey-witness field should be tag-258
// wrapped for the given transaction type. Conway and later require set tags.
func useTagForTxType(txType uint) bool {
	return txType >= ledger.TxTypeConway
}

// ErrSignatureVerification indicates a freshly produced signature failed to
// verify against its own public key. With correct key material and an intact
// signing routine this can never happen, so it signals memory corruption, a
// fault-injection ("glitch") attack on the deterministic EdDSA signer — the
// standard defense against which is to verify before releasing the signature,
// since a faulted second signing of the same message would otherwise leak the
// private scalar — or a signing-math bug. The signature is discarded, never
// returned.
var ErrSignatureVerification = errors.New("produced signature failed self-verification")

// verifyingSigner wraps a raw signing function with a verify-after-sign
// self-check: it signs, then confirms the result verifies against pub before
// returning it, yielding ErrSignatureVerification otherwise. crypto/ed25519
// verification is valid for both standard and Cardano extended
// (BIP32-Ed25519) signatures because both verify against the 32-byte public
// key, and Go's verifier additionally rejects non-canonical S (malleable)
// signatures. This is defense-in-depth applied at the lowest signing layer so
// every caller — offline tx signing, CIP-8 data signing, and the remote
// signer's custody backends — inherits the same guarantee.
func verifyingSigner(pub []byte, raw func(msg []byte) []byte) func(msg []byte) ([]byte, error) {
	return func(msg []byte) ([]byte, error) {
		sig := raw(msg)
		if len(pub) != ed25519.PublicKeySize ||
			!ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
			return nil, ErrSignatureVerification
		}
		return sig, nil
	}
}

// signerForKey returns the 32-byte public (vkey) bytes and a signing closure
// for a loaded signing key. Extended BIP32 keys (96-byte SKey) use Cardano
// BIP32-Ed25519 signing; standard keys (64-byte ed25519 private key) use
// crypto/ed25519. The returned closure verifies every signature it produces
// against vkey before returning it (see verifyingSigner / ErrSignatureVerification).
func signerForKey(lk *LoadedKey) (vkey []byte, sign func(msg []byte) ([]byte, error), err error) {
	if lk == nil {
		return nil, nil, errors.New("signing key cannot be nil")
	}
	switch len(lk.SKey) {
	case 96:
		x := bip32.XPrv(lk.SKey)
		pub := x.PublicKey()
		return pub, verifyingSigner(pub, x.Sign), nil
	case 64:
		priv := ed25519.PrivateKey(lk.SKey)
		pub := priv.Public().(ed25519.PublicKey)
		return pub, verifyingSigner(pub, func(msg []byte) []byte { return ed25519.Sign(priv, msg) }), nil
	default:
		return nil, nil, fmt.Errorf("unsupported signing key length %d (want 64 or 96)", len(lk.SKey))
	}
}

// CreateWitness signs the given 32-byte transaction id with the loaded key and
// returns a vkey witness.
func CreateWitness(txID []byte, lk *LoadedKey) (lcommon.VkeyWitness, error) {
	if len(txID) != 32 {
		return lcommon.VkeyWitness{}, fmt.Errorf("transaction id must be 32 bytes, got %d", len(txID))
	}
	vkey, sign, err := signerForKey(lk)
	if err != nil {
		return lcommon.VkeyWitness{}, err
	}
	sig, err := sign(txID)
	if err != nil {
		return lcommon.VkeyWitness{}, err
	}
	return lcommon.VkeyWitness{Vkey: vkey, Signature: sig}, nil
}

// SignTransaction adds a vkey witness for each provided signing key and returns
// the signed transaction CBOR. The body (and thus the txid) is never modified.
func SignTransaction(txCbor []byte, signers []*LoadedKey) ([]byte, error) {
	if len(signers) == 0 {
		return nil, errors.New("no signing keys provided")
	}
	txType, err := ledger.DetermineTransactionType(txCbor)
	if err != nil {
		return nil, fmt.Errorf("failed to determine transaction era: %w", err)
	}
	tx, err := ledger.NewTransactionFromCbor(txType, txCbor)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transaction: %w", err)
	}
	txID := tx.Hash().Bytes()
	wits := make([]lcommon.VkeyWitness, 0, len(signers))
	for _, lk := range signers {
		w, err := CreateWitness(txID, lk)
		if err != nil {
			return nil, err
		}
		wits = append(wits, w)
	}
	return injectVkeyWitnesses(txCbor, wits, useTagForTxType(txType))
}

// WitnessTransaction produces a single detached vkey witness for the
// transaction using the given key (for multi-party / multisig assembly).
func WitnessTransaction(txCbor []byte, lk *LoadedKey) (lcommon.VkeyWitness, error) {
	txType, err := ledger.DetermineTransactionType(txCbor)
	if err != nil {
		return lcommon.VkeyWitness{}, fmt.Errorf("failed to determine transaction era: %w", err)
	}
	tx, err := ledger.NewTransactionFromCbor(txType, txCbor)
	if err != nil {
		return lcommon.VkeyWitness{}, fmt.Errorf("failed to decode transaction: %w", err)
	}
	return CreateWitness(tx.Hash().Bytes(), lk)
}

// AssembleTransaction merges the provided detached witnesses into the
// transaction and returns the assembled signed transaction CBOR.
func AssembleTransaction(txCbor []byte, wits []lcommon.VkeyWitness) ([]byte, error) {
	if len(wits) == 0 {
		return nil, errors.New("no witnesses provided")
	}
	txType, err := ledger.DetermineTransactionType(txCbor)
	if err != nil {
		return nil, fmt.Errorf("failed to determine transaction era: %w", err)
	}
	return injectVkeyWitnesses(txCbor, wits, useTagForTxType(txType))
}

// EncodeWitness serializes a single vkey witness to CBOR.
func EncodeWitness(w lcommon.VkeyWitness) ([]byte, error) {
	out, err := cbor.Encode(w)
	if err != nil {
		return nil, fmt.Errorf("failed to encode witness: %w", err)
	}
	return out, nil
}

// DecodeWitness deserializes a single vkey witness from CBOR.
func DecodeWitness(data []byte) (lcommon.VkeyWitness, error) {
	var w lcommon.VkeyWitness
	if _, err := cbor.Decode(data, &w); err != nil {
		return lcommon.VkeyWitness{}, fmt.Errorf("failed to decode witness: %w", err)
	}
	return w, nil
}

// TransactionID returns the hex-encoded transaction id (blake2b-256 of the body).
func TransactionID(txCbor []byte) (string, error) {
	txType, err := ledger.DetermineTransactionType(txCbor)
	if err != nil {
		return "", fmt.Errorf("failed to determine transaction era: %w", err)
	}
	tx, err := ledger.NewTransactionFromCbor(txType, txCbor)
	if err != nil {
		return "", fmt.Errorf("failed to decode transaction: %w", err)
	}
	return hex.EncodeToString(tx.Hash().Bytes()), nil
}

// TxInput is a decoded transaction input.
type TxInput struct {
	TxId  string `json:"tx_id"`
	Index uint32 `json:"index"`
}

// TxOutput is a decoded transaction output.
type TxOutput struct {
	Address  string `json:"address"`
	Lovelace string `json:"lovelace"`
	// HasAssets is true when the output carries native (multi-)assets in
	// addition to lovelace. The policy engine treats native-asset movement as
	// a distinct, deny-by-default operation because lovelace limits do not
	// bound token quantities.
	HasAssets bool `json:"has_assets,omitempty"`
}

// TxInspection is the decoded, human-readable view of a transaction.
type TxInspection struct {
	TxId             string     `json:"tx_id"`
	Era              string     `json:"era"`
	SizeBytes        int        `json:"size_bytes"`
	IsValid          bool       `json:"is_valid"`
	Fee              string     `json:"fee,omitempty"`
	TTL              uint64     `json:"ttl,omitempty"`
	ValidityStart    uint64     `json:"validity_interval_start,omitempty"`
	Inputs           []TxInput  `json:"inputs"`
	Outputs          []TxOutput `json:"outputs"`
	CertificateCount int        `json:"certificate_count"`
	WithdrawalCount  int        `json:"withdrawal_count"`
	HasMint          bool       `json:"has_mint"`
	HasMetadata      bool       `json:"has_metadata"`
	RequiredSigners  int        `json:"required_signers"`
	VkeyWitnesses    int        `json:"vkey_witnesses"`
	NativeScripts    int        `json:"native_scripts"`
	// Conway governance and treasury components. These authorize
	// high-impact actions (casting DRep/committee votes, submitting
	// governance proposals, donating to the treasury) that are independent
	// of outputs/certificates/withdrawals, so the policy engine must inspect
	// and gate them explicitly.
	VotingProcedureCount   int  `json:"voting_procedure_count,omitempty"`
	ProposalProcedureCount int  `json:"proposal_procedure_count,omitempty"`
	HasTreasuryDonation    bool `json:"has_treasury_donation,omitempty"`
}

func eraName(txType uint) string {
	switch txType {
	case ledger.TxTypeByron:
		return "Byron"
	case ledger.TxTypeShelley:
		return "Shelley"
	case ledger.TxTypeAllegra:
		return "Allegra"
	case ledger.TxTypeMary:
		return "Mary"
	case ledger.TxTypeAlonzo:
		return "Alonzo"
	case ledger.TxTypeBabbage:
		return "Babbage"
	case ledger.TxTypeConway:
		return "Conway"
	case ledger.TxTypeDijkstra:
		return "Dijkstra"
	default:
		return fmt.Sprintf("Unknown(%d)", txType)
	}
}

// InspectTransaction decodes a transaction into a human-readable summary.
func InspectTransaction(txCbor []byte) (*TxInspection, error) {
	txType, err := ledger.DetermineTransactionType(txCbor)
	if err != nil {
		return nil, fmt.Errorf("failed to determine transaction era: %w", err)
	}
	tx, err := ledger.NewTransactionFromCbor(txType, txCbor)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transaction: %w", err)
	}
	insp := &TxInspection{
		TxId:          hex.EncodeToString(tx.Hash().Bytes()),
		Era:           eraName(txType),
		SizeBytes:     len(txCbor),
		IsValid:       tx.IsValid(),
		TTL:           tx.TTL(),
		ValidityStart: tx.ValidityIntervalStart(),
	}
	if fee := tx.Fee(); fee != nil {
		insp.Fee = fee.String()
	}
	for _, in := range tx.Inputs() {
		insp.Inputs = append(insp.Inputs, TxInput{
			TxId:  hex.EncodeToString(in.Id().Bytes()),
			Index: in.Index(),
		})
	}
	for _, out := range tx.Outputs() {
		lovelace := "0"
		if amt := out.Amount(); amt != nil {
			lovelace = amt.String()
		}
		hasAssets := false
		if assets := out.Assets(); assets != nil && len(assets.Policies()) > 0 {
			hasAssets = true
		}
		insp.Outputs = append(insp.Outputs, TxOutput{
			Address:   out.Address().String(),
			Lovelace:  lovelace,
			HasAssets: hasAssets,
		})
	}
	insp.CertificateCount = len(tx.Certificates())
	insp.WithdrawalCount = len(tx.Withdrawals())
	insp.HasMint = tx.AssetMint() != nil
	insp.HasMetadata = tx.Metadata() != nil
	insp.RequiredSigners = len(tx.RequiredSigners())
	insp.VotingProcedureCount = len(tx.VotingProcedures())
	insp.ProposalProcedureCount = len(tx.ProposalProcedures())
	if d := tx.Donation(); d != nil && d.Sign() > 0 {
		insp.HasTreasuryDonation = true
	}
	if ws := tx.Witnesses(); ws != nil {
		insp.VkeyWitnesses = len(ws.Vkey())
		insp.NativeScripts = len(ws.NativeScripts())
	}
	return insp, nil
}

// ProtocolParams holds the fee-relevant subset of cardano protocol parameters,
// using the cardano-cli protocol-parameters.json field names.
type ProtocolParams struct {
	TxFeePerByte uint64 `json:"txFeePerByte"`
	TxFeeFixed   uint64 `json:"txFeeFixed"`
}

// ParseProtocolParams parses a cardano-cli protocol-parameters JSON document,
// extracting the fee-relevant fields.
func ParseProtocolParams(data []byte) (ProtocolParams, error) {
	var raw struct {
		TxFeePerByte *uint64 `json:"txFeePerByte"`
		TxFeeFixed   *uint64 `json:"txFeeFixed"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return ProtocolParams{}, fmt.Errorf("failed to parse protocol params: %w", err)
	}
	if raw.TxFeePerByte == nil || raw.TxFeeFixed == nil {
		return ProtocolParams{}, errors.New("protocol params missing txFeePerByte/txFeeFixed")
	}
	return ProtocolParams{TxFeePerByte: *raw.TxFeePerByte, TxFeeFixed: *raw.TxFeeFixed}, nil
}

// MinFee returns the minimum fee in lovelace for a transaction of the given
// serialized size: fee = txFeePerByte * sizeBytes + txFeeFixed. This base
// linear formula does not include Plutus execution units or reference-script
// tiers; for script transactions the result is a lower bound.
func MinFee(sizeBytes int, params ProtocolParams) uint64 {
	if sizeBytes < 0 {
		return params.TxFeeFixed
	}
	return params.TxFeePerByte*uint64(sizeBytes) + params.TxFeeFixed
}

// SignDigest signs an arbitrary message with the loaded key and returns the raw
// 64-byte signature. Standard ed25519 keys use crypto/ed25519; extended
// BIP32-Ed25519 keys use the Cardano signing routine. This is the low-level
// signing primitive used by the remote signer's custody backends. The produced
// signature is verified against the key's own public key before return; a
// failure yields ErrSignatureVerification.
//
// SECURITY: SignDigest signs whatever bytes it is handed — it performs no
// transaction decoding and no policy evaluation. Callers MUST only pass a
// digest derived from a fully decoded, policy-checked request (e.g. the
// blake2b-256 tx id from TransactionID after InspectTransaction, or a CIP-8
// Sig_structure). Never wire this primitive to a caller-supplied, un-inspected
// digest: doing so would let an attacker obtain a valid witness over an
// arbitrary transaction body (a drain). The remote signer upholds this by
// computing the digest itself from decoded CBOR and signing only after policy
// passes; any new signing entry point must do the same.
func SignDigest(lk *LoadedKey, msg []byte) ([]byte, error) {
	_, sign, err := signerForKey(lk)
	if err != nil {
		return nil, err
	}
	return sign(msg)
}

// PublicKeyOf returns the canonical 32-byte Ed25519 verification key for the
// loaded key (the value placed in a vkey witness and hashed for the key hash).
func PublicKeyOf(lk *LoadedKey) ([]byte, error) {
	vkey, _, err := signerForKey(lk)
	if err != nil {
		return nil, err
	}
	return vkey, nil
}
