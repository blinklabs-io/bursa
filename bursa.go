// Copyright 2025 Blink Labs Software
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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/blinklabs-io/bursa/bip32"
	ouroboros "github.com/blinklabs-io/gouroboros"
	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/btcsuite/btcd/btcutil/bech32"
	bip39 "github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/blake2b"
)

var (
	// ErrInvalidMnemonic indicates the provided mnemonic is not valid BIP39
	ErrInvalidMnemonic = errors.New("invalid mnemonic")
	// ErrInvalidDerivationIndex indicates a derivation index exceeds the maximum allowed value
	ErrInvalidDerivationIndex = errors.New(
		"derivation indices must be less than 2^31",
	)
	// ErrInvalidNetwork indicates the provided network name is not recognized
	ErrInvalidNetwork = errors.New("invalid network name")
)

type KeyFile struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	CborHex     string `json:"cborHex"`
	// Embedded CBOR storage for automatic caching
	cbor.DecodeStoreCbor `                          swaggerignore:"true"`
}

type LoadedKey struct {
	File        string
	Type        string
	Description string
	RawCBOR     []byte
	VKey        []byte
	SKey        []byte
}

// Script represents a native script for multi-signature wallets
// This is an alias for gouroboros ledger common Script for compatibility
type Script = lcommon.Script

// Native script type aliases for gouroboros types
type (
	NativeScript                 = lcommon.NativeScript
	NativeScriptPubkey           = lcommon.NativeScriptPubkey
	NativeScriptAll              = lcommon.NativeScriptAll
	NativeScriptAny              = lcommon.NativeScriptAny
	NativeScriptNofK             = lcommon.NativeScriptNofK
	NativeScriptInvalidBefore    = lcommon.NativeScriptInvalidBefore
	NativeScriptInvalidHereafter = lcommon.NativeScriptInvalidHereafter
)

// GetScriptType returns the script type identifier for a native script.
// Only accepts *NativeScript types; returns an error for other script types.
func GetScriptType(script Script) (int, error) {
	nativeScript, ok := script.(*NativeScript)
	if !ok {
		return 0, errors.New("script is not a native script")
	}
	// We need to determine the type from the CBOR data
	// Since NativeScript stores the CBOR, we can decode the first byte to get the type
	cborData := nativeScript.Cbor()
	if len(cborData) == 0 {
		return 0, errors.New("script CBOR data is empty")
	}
	id, err := cbor.DecodeIdFromList(cborData)
	if err != nil {
		return 0, fmt.Errorf("failed to decode script type from CBOR: %w", err)
	}
	return id, nil
}

// String returns the Bech32-encoded representation of the key according to CIP-0005
func (kf KeyFile) String() string {
	var prefix string
	switch kf.Type {
	case "PaymentVerificationKeyShelley_ed25519":
		prefix = "addr_vk"
	case "PaymentSigningKeyShelley_ed25519":
		prefix = "addr_sk"
	case "PaymentExtendedSigningKeyShelley_ed25519_bip32":
		prefix = "addr_xsk"
	case "StakeVerificationKeyShelley_ed25519":
		prefix = "stake_vk"
	case "StakeSigningKeyShelley_ed25519":
		prefix = "stake_sk"
	case "StakeExtendedSigningKeyShelley_ed25519_bip32":
		prefix = "stake_xsk"
	case "DRepVerificationKeyShelley_ed25519":
		prefix = "drep_vk"
	case "DRepSigningKeyShelley_ed25519":
		prefix = "drep_sk"
	case "DRepExtendedSigningKeyShelley_ed25519_bip32":
		prefix = "drep_xsk"
	case "CommitteeColdVerificationKeyShelley_ed25519":
		prefix = "cc_cold_vk"
	case "CommitteeColdSigningKeyShelley_ed25519":
		prefix = "cc_cold_sk"
	case "CommitteeColdExtendedSigningKeyShelley_ed25519_bip32":
		prefix = "cc_cold_xsk"
	case "CommitteeHotVerificationKeyShelley_ed25519":
		prefix = "cc_hot_vk"
	case "CommitteeHotSigningKeyShelley_ed25519":
		prefix = "cc_hot_sk"
	case "CommitteeHotExtendedSigningKeyShelley_ed25519_bip32":
		prefix = "cc_hot_xsk"
	case "StakePoolVerificationKeyShelley_ed25519":
		prefix = "pool_vk"
	case "StakePoolSigningKeyShelley_ed25519":
		prefix = "pool_sk"
	case "StakePoolExtendedSigningKeyShelley_ed25519_bip32":
		prefix = "pool_xsk"
	default:
		// Fallback to CBOR hex if type not recognized
		return kf.CborHex
	}

	cborData, err := hex.DecodeString(kf.CborHex)
	if err != nil {
		return kf.CborHex
	}
	var decoded []any
	_, err = cbor.Decode(cborData, &decoded)
	if err != nil {
		return kf.CborHex
	}
	if len(decoded) < 2 {
		return kf.CborHex
	}

	var data []byte
	if strings.Contains(kf.Type, "_bip32") {
		if len(decoded) < 3 {
			return kf.CborHex
		}
		priv, ok1 := decoded[1].([]byte)
		chain, ok2 := decoded[2].([]byte)
		if !ok1 || !ok2 {
			return kf.CborHex
		}
		data = append(priv, chain...)
	} else {
		key, ok := decoded[1].([]byte)
		if !ok {
			return kf.CborHex
		}
		data = key
	}

	converted, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		return kf.CborHex
	}
	encoded, err := bech32.Encode(prefix, converted)
	if err != nil {
		return kf.CborHex
	}
	return encoded
}

// Buffer pool for JSON marshaling
var jsonBufferPool = sync.Pool{
	New: func() any {
		return &bytes.Buffer{}
	},
}

// Wallet represents a complete HD wallet with all key types
type Wallet struct {
	Mnemonic                  string  `json:"mnemonic"                     example:"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"`
	PaymentAddress            string  `json:"payment_address"              example:"addr1qxqs59lphg8g6qndelq8xwqn60ag3aeyfcp33c2kdp46a429mg32v29q3cg4sdj5c9ts5vxknc0yutnj8x8r8qy2l2q9sgds2"`
	StakeAddress              string  `json:"stake_address"                example:"stake1uy9ggsc9qls4pu9qvyyacwnmr9tt0gzcdt5s0zj4au8qkqc65ge8t"`
	PaymentVKey               KeyFile `json:"payment_vkey"`
	PaymentSKey               KeyFile `json:"payment_skey"`
	PaymentExtendedSKey       KeyFile `json:"payment_extended_skey"`
	StakeVKey                 KeyFile `json:"stake_vkey"`
	StakeSKey                 KeyFile `json:"stake_skey"`
	StakeExtendedSKey         KeyFile `json:"stake_extended_skey"`
	DRepVKey                  KeyFile `json:"drep_vkey"`
	DRepSKey                  KeyFile `json:"drep_skey"`
	DRepExtendedSKey          KeyFile `json:"drep_extended_skey"`
	CommitteeColdVKey         KeyFile `json:"committee_cold_vkey"`
	CommitteeColdSKey         KeyFile `json:"committee_cold_skey"`
	CommitteeColdExtendedSKey KeyFile `json:"committee_cold_extended_skey"`
	CommitteeHotVKey          KeyFile `json:"committee_hot_vkey"`
	CommitteeHotSKey          KeyFile `json:"committee_hot_skey"`
	CommitteeHotExtendedSKey  KeyFile `json:"committee_hot_extended_skey"`
	PoolColdVKey              KeyFile `json:"pool_cold_vkey"`
	PoolColdSKey              KeyFile `json:"pool_cold_skey"`
	PoolColdExtendedSKey      KeyFile `json:"pool_cold_extended_skey"`
}

// GenerateMnemonic generates a new BIP39 mnemonic phrase
func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", fmt.Errorf("failed to generate entropy: %w", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate mnemonic: %w", err)
	}
	return mnemonic, nil
}

// NewWallet creates a new wallet from a BIP39 mnemonic phrase.
// All derivation indices (accountId, paymentId, stakeId, drepId, committeeColdId, committeeHotId, poolColdId, addressId) must be less than 2^31 (0x80000000).
// This constraint ensures compatibility with BIP32/BIP44 derivation standards.
func NewWallet(
	mnemonic, network, password string,
	accountId uint32,
	paymentId, stakeId, drepId, committeeColdId, committeeHotId, poolColdId, addressId uint32,
) (*Wallet, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, ErrInvalidMnemonic
	}
	if accountId >= 0x80000000 || paymentId >= 0x80000000 ||
		stakeId >= 0x80000000 || drepId >= 0x80000000 ||
		committeeColdId >= 0x80000000 || committeeHotId >= 0x80000000 ||
		poolColdId >= 0x80000000 || addressId >= 0x80000000 {
		return nil, ErrInvalidDerivationIndex
	}
	rootKey, err := GetRootKeyFromMnemonic(mnemonic, password)
	if err != nil {
		return nil, fmt.Errorf("failed to get root key from mnemonic: %w", err)
	}
	accountKey, err := GetAccountKey(rootKey, accountId)
	if err != nil {
		return nil, fmt.Errorf("failed to get account key: %w", err)
	}
	paymentKey, err := GetPaymentKey(accountKey, paymentId)
	if err != nil {
		return nil, fmt.Errorf("failed to get payment key: %w", err)
	}
	stakeKey, err := GetStakeKey(accountKey, stakeId)
	if err != nil {
		return nil, fmt.Errorf("failed to get stake key: %w", err)
	}
	drepKey, err := GetDRepKey(accountKey, drepId)
	if err != nil {
		return nil, fmt.Errorf("failed to get DRep key: %w", err)
	}
	committeeColdKey, err := GetCommitteeColdKey(accountKey, committeeColdId)
	if err != nil {
		return nil, fmt.Errorf("failed to get committee cold key: %w", err)
	}
	committeeHotKey, err := GetCommitteeHotKey(accountKey, committeeHotId)
	if err != nil {
		return nil, fmt.Errorf("failed to get committee hot key: %w", err)
	}
	// CIP-1853: Derive pool cold key using m/1853'/1815'/0'/index'
	// usecase is fixed to 0 as per CIP-1853 specification
	poolColdKey, err := GetPoolColdKey(rootKey, 0, poolColdId)
	if err != nil {
		return nil, fmt.Errorf("failed to get pool cold key: %w", err)
	}
	addr, err := GetAddress(accountKey, network, addressId)
	if err != nil {
		return nil, fmt.Errorf("unable to get address: %w", err)
	}
	if addr == nil {
		return nil, errors.New("unable to get address")
	}
	stakeAddr := addr.StakeAddress()
	if stakeAddr == nil {
		return nil, errors.New("unable to get stake address")
	}
	paymentVKey, err := GetPaymentVKey(paymentKey)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get payment verification key: %w",
			err,
		)
	}
	paymentSKey, err := GetPaymentSKey(paymentKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get payment signing key: %w", err)
	}
	paymentExtendedSKey, err := GetPaymentExtendedSKey(paymentKey)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get payment extended signing key: %w",
			err,
		)
	}
	stakeVKey, err := GetStakeVKey(stakeKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get stake verification key: %w", err)
	}
	stakeSKey, err := GetStakeSKey(stakeKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get stake signing key: %w", err)
	}
	stakeExtendedSKey, err := GetStakeExtendedSKey(stakeKey)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get stake extended signing key: %w",
			err,
		)
	}
	drepVKey, err := GetDRepVKey(drepKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get DRep verification key: %w", err)
	}
	drepSKey, err := GetDRepSKey(drepKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get DRep signing key: %w", err)
	}
	drepExtendedSKey, err := GetDRepExtendedSKey(drepKey)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get DRep extended signing key: %w",
			err,
		)
	}
	committeeColdVKey, err := GetCommitteeColdVKey(committeeColdKey)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get committee cold verification key: %w",
			err,
		)
	}
	committeeColdSKey, err := GetCommitteeColdSKey(committeeColdKey)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get committee cold signing key: %w",
			err,
		)
	}
	committeeColdExtendedSKey, err := GetCommitteeColdExtendedSKey(
		committeeColdKey,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get committee cold extended signing key: %w",
			err,
		)
	}
	committeeHotVKey, err := GetCommitteeHotVKey(committeeHotKey)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get committee hot verification key: %w",
			err,
		)
	}
	committeeHotSKey, err := GetCommitteeHotSKey(committeeHotKey)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get committee hot signing key: %w",
			err,
		)
	}
	committeeHotExtendedSKey, err := GetCommitteeHotExtendedSKey(
		committeeHotKey,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get committee hot extended signing key: %w",
			err,
		)
	}
	poolColdVKey, err := GetPoolColdVKey(poolColdKey)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get pool cold verification key: %w",
			err,
		)
	}
	poolColdSKey, err := GetPoolColdSKey(poolColdKey)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get pool cold signing key: %w",
			err,
		)
	}
	poolColdExtendedSKey, err := GetPoolColdExtendedSKey(poolColdKey)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get pool cold extended signing key: %w",
			err,
		)
	}
	w := &Wallet{
		Mnemonic:                  mnemonic,
		PaymentAddress:            addr.String(),
		StakeAddress:              stakeAddr.String(),
		PaymentVKey:               paymentVKey,
		PaymentSKey:               paymentSKey,
		PaymentExtendedSKey:       paymentExtendedSKey,
		StakeVKey:                 stakeVKey,
		StakeSKey:                 stakeSKey,
		StakeExtendedSKey:         stakeExtendedSKey,
		DRepVKey:                  drepVKey,
		DRepSKey:                  drepSKey,
		DRepExtendedSKey:          drepExtendedSKey,
		CommitteeColdVKey:         committeeColdVKey,
		CommitteeColdSKey:         committeeColdSKey,
		CommitteeColdExtendedSKey: committeeColdExtendedSKey,
		CommitteeHotVKey:          committeeHotVKey,
		CommitteeHotSKey:          committeeHotSKey,
		CommitteeHotExtendedSKey:  committeeHotExtendedSKey,
		PoolColdVKey:              poolColdVKey,
		PoolColdSKey:              poolColdSKey,
		PoolColdExtendedSKey:      poolColdExtendedSKey,
	}
	return w, nil
}

func ExtractKeyFiles(wallet *Wallet) (map[string]string, error) {
	if wallet == nil {
		return nil, errors.New("wallet cannot be nil")
	}
	keyMap := map[string]KeyFile{
		"payment.vkey":                 wallet.PaymentVKey,
		"payment.skey":                 wallet.PaymentSKey,
		"paymentExtended.skey":         wallet.PaymentExtendedSKey,
		"stake.vkey":                   wallet.StakeVKey,
		"stake.skey":                   wallet.StakeSKey,
		"stakeExtended.skey":           wallet.StakeExtendedSKey,
		"drep.vkey":                    wallet.DRepVKey,
		"drep.skey":                    wallet.DRepSKey,
		"drepExtended.skey":            wallet.DRepExtendedSKey,
		"committee-cold.vkey":          wallet.CommitteeColdVKey,
		"committee-cold.skey":          wallet.CommitteeColdSKey,
		"committee-cold-extended.skey": wallet.CommitteeColdExtendedSKey,
		"committee-hot.vkey":           wallet.CommitteeHotVKey,
		"committee-hot.skey":           wallet.CommitteeHotSKey,
		"committee-hot-extended.skey":  wallet.CommitteeHotExtendedSKey,
		"pool-cold.vkey":               wallet.PoolColdVKey,
		"pool-cold.skey":               wallet.PoolColdSKey,
		"pool-cold-extended.skey":      wallet.PoolColdExtendedSKey,
	}

	result := make(map[string]string)
	for name, kf := range keyMap {
		keyStr, err := GetKeyFile(kf)
		if err != nil {
			return nil, fmt.Errorf("unable to get %s: %w", name, err)
		}
		result[name] = keyStr
	}
	return result, nil
}

func GetRootKeyFromMnemonic(mnemonic, password string) (bip32.XPrv, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, ErrInvalidMnemonic
	}
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	pwBytes := []byte{}
	if password != "" {
		pwBytes = []byte(password)
	}
	rootKey := GetRootKey(entropy, pwBytes)
	return rootKey, nil
}

func GetRootKey(entropy []byte, password []byte) bip32.XPrv {
	return bip32.FromBip39Entropy(entropy, password)
}

func GetAccountKey(rootKey bip32.XPrv, num uint32) (bip32.XPrv, error) {
	const harden = 0x80000000
	if num > 0x7FFFFFFF {
		return nil, ErrInvalidDerivationIndex
	}
	hardNum := harden + num
	return rootKey.
		Derive(uint32(harden + 1852)).
		Derive(uint32(harden + 1815)).
		Derive(uint32(hardNum)), nil
}

func GetPaymentKey(accountKey bip32.XPrv, num uint32) (bip32.XPrv, error) {
	if num >= 0x80000000 {
		return nil, ErrInvalidDerivationIndex
	}
	return accountKey.Derive(0).Derive(num), nil
}

func GetPaymentVKey(paymentKey bip32.XPrv) (KeyFile, error) {
	keyCbor, err := cbor.Encode(
		[]any{0, paymentKey.Public().PublicKey()},
	)
	if err != nil {
		return KeyFile{}, fmt.Errorf(
			"failed to encode payment verification key CBOR: %w",
			err,
		)
	}
	kf := KeyFile{
		Type:        "PaymentVerificationKeyShelley_ed25519",
		Description: "Payment Verification Key",
		CborHex:     hex.EncodeToString(keyCbor),
	}
	kf.SetCbor(keyCbor)
	return kf, nil
}

func getSigningKeyFile(
	key bip32.XPrv,
	keyType, description string,
) (KeyFile, error) {
	keyCbor, err := cbor.Encode([]any{0, key.PrivateKey()[:32]})
	if err != nil {
		return KeyFile{}, fmt.Errorf(
			"failed to encode %s CBOR: %w",
			description,
			err,
		)
	}
	kf := KeyFile{
		Type:        keyType,
		Description: description,
		CborHex:     hex.EncodeToString(keyCbor),
	}
	kf.SetCbor(keyCbor)
	return kf, nil
}

func GetPaymentSKey(paymentKey bip32.XPrv) (KeyFile, error) {
	return getSigningKeyFile(
		paymentKey,
		"PaymentSigningKeyShelley_ed25519",
		"Payment Signing Key",
	)
}

func GetPaymentExtendedSKey(paymentKey bip32.XPrv) (KeyFile, error) {
	keyCbor, err := cbor.Encode([]any{
		0,
		paymentKey.PrivateKey(),
		paymentKey.ChainCode(),
	})
	if err != nil {
		return KeyFile{}, fmt.Errorf(
			"failed to encode payment extended signing key CBOR: %w",
			err,
		)
	}
	kf := KeyFile{
		Type:        "PaymentExtendedSigningKeyShelley_ed25519_bip32",
		Description: "Payment Extended Signing Key (BIP32)",
		CborHex:     hex.EncodeToString(keyCbor),
	}
	kf.SetCbor(keyCbor)
	return kf, nil
}

func GetStakeKey(accountKey bip32.XPrv, num uint32) (bip32.XPrv, error) {
	if num >= 0x80000000 {
		return nil, ErrInvalidDerivationIndex
	}
	return accountKey.Derive(2).Derive(num), nil
}

func GetStakeVKey(stakeKey bip32.XPrv) (KeyFile, error) {
	keyCbor, err := cbor.Encode(
		[]any{0, stakeKey.Public().PublicKey()},
	)
	if err != nil {
		return KeyFile{}, fmt.Errorf(
			"failed to encode stake verification key CBOR: %w",
			err,
		)
	}
	kf := KeyFile{
		Type:        "StakeVerificationKeyShelley_ed25519",
		Description: "Stake Verification Key",
		CborHex:     hex.EncodeToString(keyCbor),
	}
	kf.SetCbor(keyCbor)
	return kf, nil
}

func GetStakeSKey(stakeKey bip32.XPrv) (KeyFile, error) {
	return getSigningKeyFile(
		stakeKey,
		"StakeSigningKeyShelley_ed25519",
		"Stake Signing Key",
	)
}

func GetStakeExtendedSKey(stakeKey bip32.XPrv) (KeyFile, error) {
	keyCbor, err := cbor.Encode([]any{
		0,
		stakeKey.PrivateKey(),
		stakeKey.ChainCode(),
	})
	if err != nil {
		return KeyFile{}, fmt.Errorf(
			"failed to encode stake extended signing key CBOR: %w",
			err,
		)
	}
	kf := KeyFile{
		Type:        "StakeExtendedSigningKeyShelley_ed25519_bip32",
		Description: "Stake Extended Signing Key (BIP32)",
		CborHex:     hex.EncodeToString(keyCbor),
	}
	kf.SetCbor(keyCbor)
	return kf, nil
}

func GetDRepKey(accountKey bip32.XPrv, num uint32) (bip32.XPrv, error) {
	if num >= 0x80000000 {
		return nil, ErrInvalidDerivationIndex
	}
	return accountKey.Derive(3).Derive(num), nil
}

func GetDRepVKey(drepKey bip32.XPrv) (KeyFile, error) {
	keyCbor, err := cbor.Encode(
		[]any{0, drepKey.Public().PublicKey()},
	)
	if err != nil {
		return KeyFile{}, fmt.Errorf(
			"failed to encode DRep verification key CBOR: %w",
			err,
		)
	}
	kf := KeyFile{
		Type:        "DRepVerificationKeyShelley_ed25519",
		Description: "DRep Verification Key",
		CborHex:     hex.EncodeToString(keyCbor),
	}
	kf.SetCbor(keyCbor)
	return kf, nil
}

func GetDRepSKey(drepKey bip32.XPrv) (KeyFile, error) {
	return getSigningKeyFile(
		drepKey,
		"DRepSigningKeyShelley_ed25519",
		"DRep Signing Key",
	)
}

func GetDRepExtendedSKey(drepKey bip32.XPrv) (KeyFile, error) {
	keyCbor, err := cbor.Encode([]any{
		0,
		drepKey.PrivateKey(),
		drepKey.ChainCode(),
	})
	if err != nil {
		return KeyFile{}, fmt.Errorf(
			"failed to encode DRep extended signing key CBOR: %w",
			err,
		)
	}
	kf := KeyFile{
		Type:        "DRepExtendedSigningKeyShelley_ed25519_bip32",
		Description: "DRep Extended Signing Key (BIP32)",
		CborHex:     hex.EncodeToString(keyCbor),
	}
	kf.SetCbor(keyCbor)
	return kf, nil
}

func GetCommitteeColdKey(
	accountKey bip32.XPrv,
	num uint32,
) (bip32.XPrv, error) {
	if num >= 0x80000000 {
		return nil, ErrInvalidDerivationIndex
	}
	return accountKey.Derive(4).Derive(num), nil
}

func GetCommitteeColdVKey(committeeKey bip32.XPrv) (KeyFile, error) {
	keyCbor, err := cbor.Encode(
		[]any{0, committeeKey.Public().PublicKey()},
	)
	if err != nil {
		return KeyFile{}, fmt.Errorf(
			"failed to encode Committee Cold verification key CBOR: %w",
			err,
		)
	}
	kf := KeyFile{
		Type:        "CommitteeColdVerificationKeyShelley_ed25519",
		Description: "Committee Cold Verification Key",
		CborHex:     hex.EncodeToString(keyCbor),
	}
	kf.SetCbor(keyCbor)
	return kf, nil
}

func GetCommitteeColdSKey(committeeKey bip32.XPrv) (KeyFile, error) {
	return getSigningKeyFile(
		committeeKey,
		"CommitteeColdSigningKeyShelley_ed25519",
		"Committee Cold Signing Key",
	)
}

func GetCommitteeColdExtendedSKey(committeeKey bip32.XPrv) (KeyFile, error) {
	keyCbor, err := cbor.Encode([]any{
		0,
		committeeKey.PrivateKey(),
		committeeKey.ChainCode(),
	})
	if err != nil {
		return KeyFile{}, fmt.Errorf(
			"failed to encode Committee Cold extended signing key CBOR: %w",
			err,
		)
	}
	kf := KeyFile{
		Type:        "CommitteeColdExtendedSigningKeyShelley_ed25519_bip32",
		Description: "Committee Cold Extended Signing Key (BIP32)",
		CborHex:     hex.EncodeToString(keyCbor),
	}
	kf.SetCbor(keyCbor)
	return kf, nil
}

func GetCommitteeHotKey(accountKey bip32.XPrv, num uint32) (bip32.XPrv, error) {
	if num >= 0x80000000 {
		return nil, ErrInvalidDerivationIndex
	}
	return accountKey.Derive(5).Derive(num), nil
}

func GetCommitteeHotVKey(committeeKey bip32.XPrv) (KeyFile, error) {
	keyCbor, err := cbor.Encode(
		[]any{0, committeeKey.Public().PublicKey()},
	)
	if err != nil {
		return KeyFile{}, fmt.Errorf(
			"failed to encode Committee Hot verification key CBOR: %w",
			err,
		)
	}
	kf := KeyFile{
		Type:        "CommitteeHotVerificationKeyShelley_ed25519",
		Description: "Committee Hot Verification Key",
		CborHex:     hex.EncodeToString(keyCbor),
	}
	kf.SetCbor(keyCbor)
	return kf, nil
}

func GetCommitteeHotSKey(committeeKey bip32.XPrv) (KeyFile, error) {
	return getSigningKeyFile(
		committeeKey,
		"CommitteeHotSigningKeyShelley_ed25519",
		"Committee Hot Signing Key",
	)
}

func GetCommitteeHotExtendedSKey(committeeKey bip32.XPrv) (KeyFile, error) {
	keyCbor, err := cbor.Encode([]any{
		0,
		committeeKey.PrivateKey(),
		committeeKey.ChainCode(),
	})
	if err != nil {
		return KeyFile{}, fmt.Errorf(
			"failed to encode Committee Hot extended signing key CBOR: %w",
			err,
		)
	}
	kf := KeyFile{
		Type:        "CommitteeHotExtendedSigningKeyShelley_ed25519_bip32",
		Description: "Committee Hot Extended Signing Key (BIP32)",
		CborHex:     hex.EncodeToString(keyCbor),
	}
	kf.SetCbor(keyCbor)
	return kf, nil
}

// GetPoolColdKey derives a stake pool cold key using CIP-1853 path: m/1853'/1815'/usecase'/index'
// The usecase parameter is currently fixed to 0 as per CIP-1853 specification.
// This function implements HD (Hierarchical Deterministic) derivation for stake pool cold keys.
func GetPoolColdKey(
	rootKey bip32.XPrv,
	usecase uint32,
	index uint32,
) (bip32.XPrv, error) {
	const harden = 0x80000000
	// CIP-1853: All indices in the path must be hardened
	if usecase >= 0x80000000 || index >= 0x80000000 {
		return nil, ErrInvalidDerivationIndex
	}
	// m/1853'/1815'/usecase'/index'
	return rootKey.
		Derive(harden + 1853).
		Derive(harden + 1815).
		Derive(harden + usecase).
		Derive(harden + index), nil
}

// GetPoolColdVKey creates a stake pool cold verification key file
func GetPoolColdVKey(poolColdKey bip32.XPrv) (KeyFile, error) {
	keyCbor, err := cbor.Encode(
		[]any{0, poolColdKey.Public().PublicKey()},
	)
	if err != nil {
		return KeyFile{}, fmt.Errorf(
			"failed to encode pool cold verification key CBOR: %w",
			err,
		)
	}
	kf := KeyFile{
		Type:        "StakePoolVerificationKeyShelley_ed25519",
		Description: "Stake Pool Cold Verification Key",
		CborHex:     hex.EncodeToString(keyCbor),
	}
	kf.SetCbor(keyCbor)
	return kf, nil
}

// GetPoolColdSKey creates a stake pool cold signing key file
func GetPoolColdSKey(poolColdKey bip32.XPrv) (KeyFile, error) {
	return getSigningKeyFile(
		poolColdKey,
		"StakePoolSigningKeyShelley_ed25519",
		"Stake Pool Cold Signing Key",
	)
}

// GetPoolColdExtendedSKey creates a stake pool cold extended signing key file (BIP32)
func GetPoolColdExtendedSKey(poolColdKey bip32.XPrv) (KeyFile, error) {
	keyCbor, err := cbor.Encode([]any{
		0,
		poolColdKey.PrivateKey(),
		poolColdKey.ChainCode(),
	})
	if err != nil {
		return KeyFile{}, fmt.Errorf(
			"failed to encode pool cold extended signing key CBOR: %w",
			err,
		)
	}
	kf := KeyFile{
		Type:        "StakePoolExtendedSigningKeyShelley_ed25519_bip32",
		Description: "Stake Pool Cold Extended Signing Key (BIP32)",
		CborHex:     hex.EncodeToString(keyCbor),
	}
	kf.SetCbor(keyCbor)
	return kf, nil
}

// GetMultiSigAccountKey derives a multi-signature account key using CIP-1854 path
func GetMultiSigAccountKey(rootKey bip32.XPrv, num uint32) (bip32.XPrv, error) {
	const harden = 0x80000000
	if num > 0x7FFFFFFF {
		return nil, ErrInvalidDerivationIndex
	}
	hardNum := harden + num
	return rootKey.
		Derive(uint32(harden + 1854)).
		Derive(uint32(harden + 1815)).
		Derive(uint32(hardNum)), nil
}

// GetMultiSigPaymentKey derives a multi-signature payment key
func GetMultiSigPaymentKey(
	accountKey bip32.XPrv,
	num uint32,
) (bip32.XPrv, error) {
	if num >= 0x80000000 {
		return nil, ErrInvalidDerivationIndex
	}
	return accountKey.Derive(0).Derive(num), nil
}

// createVerificationKeyFile creates a verification key file for the given key and type
func createVerificationKeyFile(
	key bip32.XPrv,
	keyType, description string,
) (KeyFile, error) {
	keyCbor, err := cbor.Encode(
		[]any{0, key.Public().PublicKey()},
	)
	if err != nil {
		return KeyFile{}, fmt.Errorf(
			"failed to encode %s CBOR: %w",
			strings.ToLower(description),
			err,
		)
	}
	kf := KeyFile{
		Type:        keyType,
		Description: description,
		CborHex:     hex.EncodeToString(keyCbor),
	}
	kf.SetCbor(keyCbor)
	return kf, nil
}

// GetMultiSigPaymentVKey creates a verification key file for multi-sig payment key
func GetMultiSigPaymentVKey(paymentKey bip32.XPrv) (KeyFile, error) {
	return createVerificationKeyFile(
		paymentKey,
		"PaymentVerificationKeyShelley_ed25519",
		"Multi-Sig Payment Verification Key",
	)
}

// GetMultiSigPaymentSKey creates a signing key file for multi-sig payment key
func GetMultiSigPaymentSKey(paymentKey bip32.XPrv) (KeyFile, error) {
	return getSigningKeyFile(
		paymentKey,
		"PaymentSigningKeyShelley_ed25519",
		"Multi-Sig Payment Signing Key",
	)
}

// GetMultiSigStakeKey derives a multi-signature stake key
func GetMultiSigStakeKey(
	accountKey bip32.XPrv,
	num uint32,
) (bip32.XPrv, error) {
	if num >= 0x80000000 {
		return nil, ErrInvalidDerivationIndex
	}
	return accountKey.Derive(2).Derive(num), nil
}

// GetMultiSigStakeVKey creates a verification key file for multi-sig stake key
func GetMultiSigStakeVKey(stakeKey bip32.XPrv) (KeyFile, error) {
	return createVerificationKeyFile(
		stakeKey,
		"StakeVerificationKeyShelley_ed25519",
		"Multi-Sig Stake Verification Key",
	)
}

// GetMultiSigStakeSKey creates a signing key file for multi-sig stake key
func GetMultiSigStakeSKey(stakeKey bip32.XPrv) (KeyFile, error) {
	return getSigningKeyFile(
		stakeKey,
		"StakeSigningKeyShelley_ed25519",
		"Multi-Sig Stake Signing Key",
	)
}

// NewScriptSig creates a signature script requiring the given key hash
// keyHash must be 28 bytes (Blake2b-224 hash of public key per CIP-1854)
func NewScriptSig(keyHash []byte) (*NativeScript, error) {
	if len(keyHash) != 28 {
		return nil, fmt.Errorf(
			"invalid key hash length: got %d bytes, expected 28 bytes (Blake2b-224)",
			len(keyHash),
		)
	}
	concrete := &NativeScriptPubkey{
		Type: 0,
		Hash: keyHash,
	}
	cborData, err := cbor.Encode(concrete)
	if err != nil {
		return nil, err
	}
	var script NativeScript
	if _, err := cbor.Decode(cborData, &script); err != nil {
		return nil, err
	}
	return &script, nil
}

// NewScriptAll creates an "all" script requiring all sub-scripts to be satisfied
func NewScriptAll(scripts ...Script) (*NativeScript, error) {
	if len(scripts) == 0 {
		return nil, errors.New("at least one script required for all script")
	}
	nativeScripts := make([]NativeScript, len(scripts))
	for i, script := range scripts {
		nativeScript, ok := script.(*NativeScript)
		if !ok {
			return nil, errors.New("script must be a *NativeScript")
		}
		nativeScripts[i] = *nativeScript
	}
	concrete := &NativeScriptAll{
		Type:    1,
		Scripts: nativeScripts,
	}
	cborData, err := cbor.Encode(concrete)
	if err != nil {
		return nil, err
	}
	var script NativeScript
	if _, err := cbor.Decode(cborData, &script); err != nil {
		return nil, err
	}
	return &script, nil
}

// NewScriptAny creates an "any" script requiring any sub-script to be satisfied
func NewScriptAny(scripts ...Script) (*NativeScript, error) {
	if len(scripts) == 0 {
		return nil, errors.New("at least one script required for any script")
	}
	nativeScripts := make([]NativeScript, len(scripts))
	for i, script := range scripts {
		nativeScript, ok := script.(*NativeScript)
		if !ok {
			return nil, errors.New("script must be a *NativeScript")
		}
		nativeScripts[i] = *nativeScript
	}
	concrete := &NativeScriptAny{
		Type:    2,
		Scripts: nativeScripts,
	}
	cborData, err := cbor.Encode(concrete)
	if err != nil {
		return nil, err
	}
	var script NativeScript
	if _, err := cbor.Decode(cborData, &script); err != nil {
		return nil, err
	}
	return &script, nil
}

// NewScriptNOf creates an "N-of-K" script requiring N out of K sub-scripts to be satisfied
func NewScriptNOf(n int, scripts ...Script) (*NativeScript, error) {
	if n < 1 || n > len(scripts) {
		return nil, fmt.Errorf(
			"invalid n value %d: must be between 1 and %d",
			n,
			len(scripts),
		)
	}
	nativeScripts := make([]NativeScript, len(scripts))
	for i, script := range scripts {
		nativeScript, ok := script.(*NativeScript)
		if !ok {
			return nil, errors.New("script must be a *NativeScript")
		}
		nativeScripts[i] = *nativeScript
	}
	concrete := &NativeScriptNofK{
		Type:    3,
		N:       uint(n),
		Scripts: nativeScripts,
	}
	cborData, err := cbor.Encode(concrete)
	if err != nil {
		return nil, err
	}
	var script NativeScript
	if _, err := cbor.Decode(cborData, &script); err != nil {
		return nil, err
	}
	return &script, nil
}

// NewScriptBefore creates a "before" script valid before the given slot
// Per CIP-1854: InvalidHereafter means the script is invalid from this slot onwards (valid before)
func NewScriptBefore(slot uint64) (*NativeScript, error) {
	concrete := &NativeScriptInvalidHereafter{
		Type: 5,
		Slot: slot,
	}
	cborData, err := cbor.Encode(concrete)
	if err != nil {
		return nil, err
	}
	var script NativeScript
	if _, err := cbor.Decode(cborData, &script); err != nil {
		return nil, err
	}
	return &script, nil
}

// NewScriptAfter creates an "after" script valid after the given slot
// Per CIP-1854: InvalidBefore means the script is invalid before this slot (valid after/at)
func NewScriptAfter(slot uint64) (*NativeScript, error) {
	concrete := &NativeScriptInvalidBefore{
		Type: 4,
		Slot: slot,
	}
	cborData, err := cbor.Encode(concrete)
	if err != nil {
		return nil, err
	}
	var script NativeScript
	if _, err := cbor.Decode(cborData, &script); err != nil {
		return nil, err
	}
	return &script, nil
}

// NewMultiSigScript creates an N-of-M multi-signature script
// For example, NewMultiSigScript(2, keyHash1, keyHash2, keyHash3) creates a 2-of-3 script
func NewMultiSigScript(
	required int,
	keyHashes ...[]byte,
) (*NativeScript, error) {
	if len(keyHashes) == 0 {
		return nil, errors.New("at least one key hash required")
	}
	if required < 1 || required > len(keyHashes) {
		return nil, fmt.Errorf(
			"invalid required signatures count: %d (must be 1-%d)",
			required,
			len(keyHashes),
		)
	}

	scripts := make([]Script, len(keyHashes))
	for i, keyHash := range keyHashes {
		script, err := NewScriptSig(keyHash)
		if err != nil {
			return nil, err
		}
		scripts[i] = script
	}

	return NewScriptNOf(required, scripts...)
}

// NewAllMultiSigScript creates an all-of multi-signature script (all keys must sign)
func NewAllMultiSigScript(keyHashes ...[]byte) (*NativeScript, error) {
	if len(keyHashes) == 0 {
		return nil, errors.New("at least one key hash required")
	}

	scripts := make([]Script, len(keyHashes))
	for i, keyHash := range keyHashes {
		script, err := NewScriptSig(keyHash)
		if err != nil {
			return nil, err
		}
		scripts[i] = script
	}

	return NewScriptAll(scripts...)
}

// NewAnyMultiSigScript creates an any-of multi-signature script (any key can sign)
func NewAnyMultiSigScript(keyHashes ...[]byte) (*NativeScript, error) {
	if len(keyHashes) == 0 {
		return nil, errors.New("at least one key hash required")
	}

	scripts := make([]Script, len(keyHashes))
	for i, keyHash := range keyHashes {
		script, err := NewScriptSig(keyHash)
		if err != nil {
			return nil, err
		}
		scripts[i] = script
	}

	return NewScriptAny(scripts...)
}

// NewTimelockedScript wraps a script with a timelock condition
func NewTimelockedScript(
	slot uint64,
	before bool,
	script Script,
) (Script, error) {
	// Validate that the script is a native script
	nativeScript, ok := script.(*NativeScript)
	if !ok {
		return nil, errors.New("timelock wrapper only supports native scripts")
	}

	var timelockScript *NativeScript
	var err error
	if before {
		timelockScript, err = NewScriptBefore(slot)
	} else {
		timelockScript, err = NewScriptAfter(slot)
	}
	if err != nil {
		return nil, err
	}
	return NewScriptAll(timelockScript, nativeScript)
}

// NewMultiSigScriptFromKeys creates an N-of-M script from public key hashes
// This is a convenience function that extracts key hashes from Ed25519 public keys
func NewMultiSigScriptFromKeys(
	required int,
	pubKeys ...ed25519.PublicKey,
) (*NativeScript, error) {
	keyHashes := make([][]byte, len(pubKeys))
	for i, pubKey := range pubKeys {
		// For Ed25519, the key hash is typically the Blake2b-224 hash of the public key
		hasher, err := blake2b.New(28, nil)
		if err != nil {
			// This should never happen with valid parameters
			return nil, fmt.Errorf("failed to create blake2b hasher: %w", err)
		}
		hasher.Write(pubKey)
		keyHashes[i] = hasher.Sum(nil)
	}
	return NewMultiSigScript(required, keyHashes...)
}

// GetScriptHash computes the hash of a script for use in addresses
func GetScriptHash(script Script) ([]byte, error) {
	if script == nil {
		return nil, errors.New("script cannot be nil")
	}
	scriptCBOR := script.RawScriptBytes()
	hasher, err := blake2b.New(28, nil)
	if err != nil {
		// This should never happen with valid parameters
		return nil, fmt.Errorf("failed to create blake2b hasher: %w", err)
	}
	hasher.Write(scriptCBOR)
	return hasher.Sum(nil), nil
}

// GetScriptAddress creates an address from a script
func GetScriptAddress(script Script, networkName string) (string, error) {
	if networkName == "" {
		return "", ErrInvalidNetwork
	}
	network, ok := ouroboros.NetworkByName(networkName)
	if !ok {
		return "", ErrInvalidNetwork
	}
	scriptHash, err := GetScriptHash(script)
	if err != nil {
		return "", fmt.Errorf("failed to get script hash: %w", err)
	}
	addr, err := lcommon.NewAddressFromParts(
		lcommon.AddressTypeScriptNone,
		network.Id,
		scriptHash,
		nil, // no stake part for script addresses
	)
	if err != nil {
		return "", fmt.Errorf("error creating script address: %w", err)
	}
	return addr.String(), nil
}

// Maximum recursion depth for script validation to prevent stack overflow
const maxScriptDepth = 20

// ValidateScript checks if a script is satisfied given signatures and current slot
// If requireSignatures is true, requires signatures for ScriptSig scripts and validates format.
// If false, allows empty signatures for structural validation only.
func ValidateScript(
	script Script,
	signatures [][]byte,
	slot uint64,
	requireSignatures bool,
) bool {
	return validateScriptWithDepth(
		script,
		signatures,
		slot,
		requireSignatures,
		0,
	)
}

// minSignaturesRequired returns the minimum number of signatures required to satisfy the script
func minSignaturesRequired(script *NativeScript) int {
	switch s := script.Item().(type) {
	case *NativeScriptPubkey:
		return 1
	case *NativeScriptAll:
		total := 0
		for _, subScript := range s.Scripts {
			total += minSignaturesRequired(&subScript)
		}
		return total
	case *NativeScriptAny:
		min := 0
		for _, subScript := range s.Scripts {
			subMin := minSignaturesRequired(&subScript)
			if min == 0 || subMin < min {
				min = subMin
			}
		}
		return min
	case *NativeScriptNofK:
		// For NofK, we need to satisfy N out of K sub-scripts
		// To minimize signatures, we choose the N sub-scripts with the smallest min sigs
		// But since it's complex, for now, assume we need at least N signatures if any sub needs sigs
		// Actually, properly: sort the min sigs of sub-scripts, sum the smallest N
		subMins := make([]int, len(s.Scripts))
		for i, subScript := range s.Scripts {
			subMins[i] = minSignaturesRequired(&subScript)
		}
		// Sort ascending
		sort.Ints(subMins)
		total := 0
		for i := range subMins {
			if uint(i) >= s.N { //nolint:gosec
				break
			}
			total += subMins[i]
		}
		return total
	case *NativeScriptInvalidBefore, *NativeScriptInvalidHereafter:
		return 0
	default:
		return 0
	}
}

// validateScriptWithDepth is the internal recursive validator with depth tracking
func validateScriptWithDepth(
	script Script,
	signatures [][]byte,
	slot uint64,
	requireSignatures bool,
	depth int,
) bool {
	// Prevent stack overflow from deeply nested scripts
	if depth > maxScriptDepth {
		return false
	}

	nativeScript, ok := script.(*NativeScript)
	if !ok {
		return false
	}

	switch s := nativeScript.Item().(type) {
	case *NativeScriptPubkey:
		return validateScriptSig(s, signatures, requireSignatures)
	case *NativeScriptAll:
		return validateScriptAllWithDepth(s, signatures, slot, requireSignatures, depth+1)
	case *NativeScriptAny:
		return validateScriptAnyWithDepth(s, signatures, slot, requireSignatures, depth+1)
	case *NativeScriptNofK:
		return validateScriptNOfWithDepth(s, signatures, slot, requireSignatures, depth+1)
	case *NativeScriptInvalidBefore:
		return validateScriptInvalidBefore(s, slot)
	case *NativeScriptInvalidHereafter:
		return validateScriptInvalidHereafter(s, slot)
	default:
		return false
	}
}

// validateScriptSig checks if a signature script is satisfied
//
// SECURITY WARNING: This function currently allows empty signatures for structural validation.
// In production spending validation, signatures MUST be provided and cryptographically verified.
// This implementation is a placeholder for testing script logic and should not be used
// for actual transaction validation without proper Ed25519 signature verification.
//
// TODO: Implement full Ed25519 signature verification against transaction hash and script.Hash
func validateScriptSig(
	_ *NativeScriptPubkey,
	signatures [][]byte,
	requireSignatures bool,
) bool {
	if requireSignatures {
		// Require signatures for format validation
		if len(signatures) == 0 {
			return false
		}
		// TODO: Implement proper Ed25519 signature verification against script.Hash
		// For now, check basic signature format (64 bytes for Ed25519)
		for _, sig := range signatures {
			if len(sig) != 64 {
				return false // Invalid Ed25519 signature length
			}
		}
		return len(signatures) >= 1
	} else {
		// For structural validation, ignore all signature checks
		// Only validate the script structure itself
		return true
	}
}

// validateScriptAllWithDepth checks if all sub-scripts are satisfied
func validateScriptAllWithDepth(
	script *NativeScriptAll,
	signatures [][]byte,
	slot uint64,
	requireSignatures bool,
	depth int,
) bool {
	if requireSignatures {
		total := 0
		for _, subScript := range script.Scripts {
			total += minSignaturesRequired(&subScript)
		}
		if len(signatures) < total {
			return false
		}
	}
	for _, subScript := range script.Scripts {
		if !validateScriptWithDepth(
			&subScript,
			signatures,
			slot,
			requireSignatures,
			depth,
		) {
			return false
		}
	}
	return true
}

// validateScriptAnyWithDepth checks if any sub-script is satisfied
func validateScriptAnyWithDepth(
	script *NativeScriptAny,
	signatures [][]byte,
	slot uint64,
	requireSignatures bool,
	depth int,
) bool {
	for _, subScript := range script.Scripts {
		if validateScriptWithDepth(
			&subScript,
			signatures,
			slot,
			requireSignatures,
			depth,
		) {
			return true
		}
	}
	return false
}

// validateScriptNOfWithDepth checks if at least N sub-scripts are satisfied
func validateScriptNOfWithDepth(
	script *NativeScriptNofK,
	signatures [][]byte,
	slot uint64,
	requireSignatures bool,
	depth int,
) bool {
	// Safety check: N should be reasonable for cryptographic purposes
	if script.N > 255 {
		return false
	}
	if requireSignatures {
		// Lower bound on signatures needed for this node (accounts for 0-sig leaves like timelocks)
		// Create a temporary NativeScript to call minSignaturesRequired
		cborData, err := cbor.Encode(script)
		if err != nil {
			return false
		}
		var tempScript NativeScript
		if _, err := cbor.Decode(cborData, &tempScript); err != nil {
			return false
		}
		minReq := minSignaturesRequired(&tempScript)
		if len(signatures) < minReq {
			return false
		}
	}
	satisfied := 0
	for _, subScript := range script.Scripts {
		if validateScriptWithDepth(
			&subScript,
			signatures,
			slot,
			requireSignatures,
			depth,
		) {
			satisfied++
		}
	}
	return satisfied >= int(script.N)
}

// validateScriptBefore checks if current slot is before the specified slot
// Per CIP-1854: InvalidHereafter means script is invalid from this slot onwards (valid before)
// validateScriptInvalidHereafter checks if current slot is before the specified slot
// Per CIP-1854: InvalidHereafter means script is invalid at/after this slot (valid before)
func validateScriptInvalidHereafter(
	script *NativeScriptInvalidHereafter,
	slot uint64,
) bool {
	return slot < script.Slot
}

// validateScriptInvalidBefore checks if current slot is at/after the specified slot
// Per CIP-1854: InvalidBefore means script is invalid before this slot (valid at/after)
func validateScriptInvalidBefore(
	script *NativeScriptInvalidBefore,
	slot uint64,
) bool {
	return slot >= script.Slot
}

func GetAddress(
	accountKey bip32.XPrv,
	networkName string,
	num uint32,
) (*lcommon.Address, error) {
	if networkName == "" {
		return nil, ErrInvalidNetwork
	}
	network, ok := ouroboros.NetworkByName(networkName)
	if !ok {
		return nil, ErrInvalidNetwork
	}
	if num >= 0x80000000 {
		return nil, ErrInvalidDerivationIndex
	}
	paymentKey, err := GetPaymentKey(accountKey, num)
	if err != nil {
		return nil, fmt.Errorf("failed to get payment key: %w", err)
	}
	paymentKeyPublicHash := paymentKey.Public().PublicKey().Hash()
	stakeKey, err := GetStakeKey(accountKey, num)
	if err != nil {
		return nil, fmt.Errorf("failed to get stake key: %w", err)
	}
	stakeKeyPublicHash := stakeKey.Public().PublicKey().Hash()
	addr, err := lcommon.NewAddressFromParts(
		lcommon.AddressTypeKeyKey,
		network.Id,
		paymentKeyPublicHash[:],
		stakeKeyPublicHash[:],
	)
	if err != nil {
		return nil, fmt.Errorf("error creating address: %w", err)
	}
	return &addr, nil
}

func GetRewardAddress(
	stakeVKey KeyFile,
	networkName string,
) (*lcommon.Address, error) {
	if networkName == "" {
		return nil, ErrInvalidNetwork
	}
	network, ok := ouroboros.NetworkByName(networkName)
	if !ok {
		return nil, ErrInvalidNetwork
	}

	// Decode the stake verification key CBOR to get the public key
	cborData, err := hex.DecodeString(stakeVKey.CborHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode stake vkey CBOR: %w", err)
	}
	var decoded []any
	_, err = cbor.Decode(cborData, &decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode stake vkey: %w", err)
	}
	if len(decoded) < 2 {
		return nil, errors.New("invalid stake vkey CBOR structure")
	}
	stakePubKeyBytes, ok := decoded[1].([]byte)
	if !ok || len(stakePubKeyBytes) != 32 {
		return nil, errors.New("invalid stake public key")
	}

	// Create stake public key and hash it
	stakePubKey := bip32.PublicKey(stakePubKeyBytes)
	stakeKeyPublicHash := stakePubKey.Hash()

	// Create reward address (AddressTypeNoneKey with only stake key hash)
	addr, err := lcommon.NewAddressFromParts(
		lcommon.AddressTypeNoneKey,
		network.Id,
		nil, // no payment part for reward addresses
		stakeKeyPublicHash[:],
	)
	if err != nil {
		return nil, fmt.Errorf("error creating reward address: %w", err)
	}
	return &addr, nil
}

func GetExtendedPrivateKey(privateKey bip32.XPrv) bip32.XPrv {
	// Create a defensive copy to prevent accidental mutation of the input key
	xprv := make([]byte, 96)
	// Copy the 64-byte private key (k_L || k_R) and the 32-byte chain code
	copy(xprv[:64], privateKey.PrivateKey())
	copy(xprv[64:], privateKey.ChainCode())
	return xprv
}

func GetKeyFile(keyFile KeyFile) (string, error) {
	// Use buffer pool to avoid allocations
	buf := jsonBufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		jsonBufferPool.Put(buf)
	}()

	// Use 4 spaces for indent
	encoder := json.NewEncoder(buf)
	encoder.SetIndent("", "    ")
	if err := encoder.Encode(keyFile); err != nil {
		return "", fmt.Errorf("failed to marshal key file: %w", err)
	}

	// Return the string with trailing newline for backward compatibility
	result := buf.String()
	return result, nil
}

func decodeNonExtendedCborKey(skeyBytes []byte) ([]byte, []byte, error) {
	var data []any
	if _, err := cbor.Decode(skeyBytes, &data); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal skey CBOR: %w", err)
	}
	if len(data) != 2 || data[0] != uint64(0) {
		return nil, nil, errors.New("invalid skey CBOR structure")
	}
	keyBytes, ok := data[1].([]byte)
	if !ok || len(keyBytes) != 32 {
		return nil, nil, errors.New("invalid skey bytes")
	}
	key := ed25519.NewKeyFromSeed(keyBytes)
	return key[:], key[32:], nil
}

func decodeExtendedCborKey(skeyBytes []byte) ([]byte, []byte, error) {
	var data []any
	if _, err := cbor.Decode(skeyBytes, &data); err != nil {
		return nil, nil, fmt.Errorf(
			"failed to unmarshal extended skey CBOR: %w",
			err,
		)
	}
	if len(data) != 3 || data[0] != uint64(0) {
		return nil, nil, errors.New("invalid extended skey CBOR structure")
	}
	privBytes, ok1 := data[1].([]byte)
	chainBytes, ok2 := data[2].([]byte)
	if !ok1 || !ok2 || len(privBytes) != 64 || len(chainBytes) != 32 {
		return nil, nil, errors.New("invalid extended skey bytes")
	}
	xprv := append(privBytes, chainBytes...)
	x := bip32.XPrv(xprv)
	pub := x.Public().PublicKey()
	return xprv, pub, nil
}

func decodeVerificationKey(vkeyBytes []byte) ([]byte, error) {
	var data []any
	if _, err := cbor.Decode(vkeyBytes, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vkey CBOR: %w", err)
	}
	if len(data) != 2 || data[0] != uint64(0) {
		return nil, errors.New("invalid vkey CBOR structure")
	}
	keyBytes, ok := data[1].([]byte)
	if !ok || len(keyBytes) != 32 {
		return nil, errors.New("invalid vkey bytes")
	}
	return keyBytes, nil
}

func parseKeyEnvelope(fileBytes []byte) (*LoadedKey, error) {
	var env KeyFile
	if err := json.Unmarshal(fileBytes, &env); err != nil {
		return nil, errors.New("could not parse key file envelope")
	}

	// Use cached CBOR data if available, otherwise decode from hex
	var cborData []byte
	if cached := env.Cbor(); len(cached) > 0 {
		cborData = cached
	} else {
		var err error
		cborData, err = hex.DecodeString(env.CborHex)
		if err != nil {
			return nil, fmt.Errorf("could not decode key from hex: %w", err)
		}
		// Cache the decoded CBOR data
		env.SetCbor(cborData)
	}

	lk := &LoadedKey{
		Type:        env.Type,
		Description: env.Description,
		RawCBOR:     cborData,
	}
	// Decode cbor encoded key bytes
	switch env.Type {
	case "PaymentVerificationKeyShelley_ed25519",
		"StakeVerificationKeyShelley_ed25519",
		"DRepVerificationKeyShelley_ed25519",
		"CommitteeColdVerificationKeyShelley_ed25519",
		"CommitteeHotVerificationKeyShelley_ed25519",
		"StakePoolVerificationKeyShelley_ed25519":
		vk, err := decodeVerificationKey(cborData)
		if err != nil {
			return nil, err
		}
		lk.VKey = vk
		return lk, nil
	case "PaymentSigningKeyShelley_ed25519",
		"StakeSigningKeyShelley_ed25519",
		"DRepSigningKeyShelley_ed25519",
		"CommitteeColdSigningKeyShelley_ed25519",
		"CommitteeHotSigningKeyShelley_ed25519",
		"StakePoolSigningKeyShelley_ed25519":
		sk, vk, err := decodeNonExtendedCborKey(cborData)
		if err != nil {
			return nil, err
		}
		lk.SKey, lk.VKey = sk, vk
		return lk, nil
	case "PaymentExtendedSigningKeyShelley_ed25519_bip32",
		"StakeExtendedSigningKeyShelley_ed25519_bip32",
		"DRepExtendedSigningKeyShelley_ed25519_bip32",
		"CommitteeColdExtendedSigningKeyShelley_ed25519_bip32",
		"CommitteeHotExtendedSigningKeyShelley_ed25519_bip32",
		"StakePoolExtendedSigningKeyShelley_ed25519_bip32":
		sk, vk, err := decodeExtendedCborKey(cborData)
		if err != nil {
			return nil, err
		}
		lk.SKey, lk.VKey = sk, vk
		return lk, nil
	default:
		return nil, fmt.Errorf("unknown key type: %s", env.Type)
	}
}

func LoadWalletDir(dir string, showSecrets bool) ([]*LoadedKey, error) {
	if dir == "" {
		return nil, errors.New("directory path cannot be empty")
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %q: %w", dir, err)
	}

	// Pre-allocate slice with estimated capacity to reduce allocations
	// Most wallets have around 6 key files
	out := make([]*LoadedKey, 0, 8)

	for _, e := range files {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !(strings.HasSuffix(n, ".vkey")) &&
			!(strings.HasSuffix(n, ".skey")) {
			continue
		}
		p := filepath.Join(dir, n)
		b, err := os.ReadFile(p)
		if err != nil {
			// Skip files that can't be read
			continue
		}
		loadedKeyFile, err := parseKeyEnvelope(b)
		if err != nil {
			// Skip files that can't be parsed
			continue
		}
		loadedKeyFile.File = n
		out = append(out, loadedKeyFile)
	}
	if len(out) == 0 {
		return nil, fs.ErrNotExist
	}

	return out, nil
}

func PrintLoadedKeys(keys []*LoadedKey, showSecrets bool) {
	// Pre-allocate buffer for output to reduce allocations
	var buf bytes.Buffer
	buf.Grow(4096) // Pre-allocate reasonable size

	for _, k := range keys {
		switch {
		case len(k.SKey) > 0 && len(k.VKey) > 0:
			if showSecrets {
				fmt.Fprintf(
					&buf,
					"%s | %s | Private Key (skey): %dB %s | Public Key (vkey): 32B %s\n",
					k.File,
					k.Type,
					len(k.SKey),
					hex.EncodeToString(k.SKey),
					hex.EncodeToString(k.VKey),
				)
			} else {
				fmt.Fprintf(&buf, "%s | %s | skey=%dB | vkey=32B %s\n",
					k.File, k.Type, len(k.SKey), hex.EncodeToString(k.VKey))
			}
		case len(k.VKey) == 32:
			fmt.Fprintf(&buf,
				"%s | %s | Public Key (vkey): 32B %s\n",
				k.File, k.Type, hex.EncodeToString(k.VKey))
		default:
			fmt.Fprintf(&buf, "%s | %s | unsupported\n", k.File, k.Type)
		}
	}

	fmt.Print(buf.String())
}

// ScriptData represents a script with metadata for serialization
type ScriptData struct {
	Type    string         `json:"type"`
	Script  map[string]any `json:"script"`
	Address string         `json:"address,omitempty"`
	Hash    string         `json:"hash,omitempty"`
}

// MarshalScript serializes a script to JSON with metadata
func MarshalScript(script Script, network string) (*ScriptData, error) {
	scriptMap, err := scriptToMap(script)
	if err != nil {
		return nil, fmt.Errorf("failed to convert script to map: %w", err)
	}

	data := &ScriptData{
		Type:   "NativeScript",
		Script: scriptMap,
	}

	// Generate address if network is provided
	if network != "" {
		address, err := GetScriptAddress(script, network)
		if err != nil {
			return nil, fmt.Errorf("failed to generate script address: %w", err)
		}
		data.Address = address
	}

	// Generate script hash
	hash, err := GetScriptHash(script)
	if err != nil {
		return nil, fmt.Errorf("failed to generate script hash: %w", err)
	}
	data.Hash = hex.EncodeToString(hash)

	return data, nil
}

// UnmarshalScript deserializes a script from JSON
func UnmarshalScript(data *ScriptData) (Script, error) {
	if data.Type != "NativeScript" {
		return nil, fmt.Errorf("unsupported script type: %s", data.Type)
	}
	return mapToScript(data.Script)
}

// scriptToMap converts a Script to a map for JSON serialization
func scriptToMap(script Script) (map[string]any, error) {
	if script == nil {
		return nil, errors.New("script cannot be nil")
	}
	nativeScript, ok := script.(*NativeScript)
	if !ok {
		return nil, errors.New("unsupported script type")
	}

	switch s := nativeScript.Item().(type) {
	case *NativeScriptPubkey:
		return map[string]any{
			"type":    "sig",
			"keyHash": hex.EncodeToString(s.Hash),
		}, nil
	case *NativeScriptAll:
		scripts := make([]any, len(s.Scripts))
		for i, subScript := range s.Scripts {
			subMap, err := scriptToMap(&subScript)
			if err != nil {
				return nil, err
			}
			scripts[i] = subMap
		}
		return map[string]any{
			"type":    "all",
			"scripts": scripts,
		}, nil
	case *NativeScriptAny:
		scripts := make([]any, len(s.Scripts))
		for i, subScript := range s.Scripts {
			subMap, err := scriptToMap(&subScript)
			if err != nil {
				return nil, err
			}
			scripts[i] = subMap
		}
		return map[string]any{
			"type":    "any",
			"scripts": scripts,
		}, nil
	case *NativeScriptNofK:
		scripts := make([]any, len(s.Scripts))
		for i, subScript := range s.Scripts {
			subMap, err := scriptToMap(&subScript)
			if err != nil {
				return nil, err
			}
			scripts[i] = subMap
		}
		return map[string]any{
			"type":    "nOf",
			"n":       s.N,
			"scripts": scripts,
		}, nil
	case *NativeScriptInvalidBefore:
		return map[string]any{
			"type": "after",
			"slot": s.Slot,
		}, nil
	case *NativeScriptInvalidHereafter:
		return map[string]any{
			"type": "before",
			"slot": s.Slot,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported script type: %T", script)
	}
}

// mapToScript converts a map back to a Script
func mapToScript(m map[string]any) (Script, error) {
	scriptType, ok := m["type"].(string)
	if !ok {
		return nil, errors.New("missing or invalid script type")
	}

	switch scriptType {
	case "sig":
		keyHashStr, ok := m["keyHash"].(string)
		if !ok {
			return nil, errors.New("missing or invalid keyHash for sig script")
		}
		keyHash, err := hex.DecodeString(keyHashStr)
		if err != nil {
			return nil, fmt.Errorf("invalid keyHash hex: %w", err)
		}
		script, err := NewScriptSig(keyHash)
		if err != nil {
			return nil, err
		}
		return script, nil
	case "all":
		scriptsInterface, ok := m["scripts"].([]any)
		if !ok {
			return nil, errors.New("missing or invalid scripts for all script")
		}
		scripts := make([]Script, len(scriptsInterface))
		for i, scriptInterface := range scriptsInterface {
			scriptMap, ok := scriptInterface.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid script at index %d", i)
			}
			script, err := mapToScript(scriptMap)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to parse script at index %d: %w",
					i,
					err,
				)
			}
			scripts[i] = script
		}
		return NewScriptAll(scripts...)
	case "any":
		scriptsInterface, ok := m["scripts"].([]any)
		if !ok {
			return nil, errors.New("missing or invalid scripts for any script")
		}
		scripts := make([]Script, len(scriptsInterface))
		for i, scriptInterface := range scriptsInterface {
			scriptMap, ok := scriptInterface.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid script at index %d", i)
			}
			script, err := mapToScript(scriptMap)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to parse script at index %d: %w",
					i,
					err,
				)
			}
			scripts[i] = script
		}
		return NewScriptAny(scripts...)
	case "nOf":
		nFloat, ok := m["n"].(float64)
		if !ok {
			return nil, errors.New("missing or invalid n for nOf script")
		}
		// Validate integer precision and reasonable range
		if nFloat < 1 || nFloat > 255 || nFloat != float64(int(nFloat)) {
			return nil, errors.New(
				"n must be an integer between 1 and 255 for nOf script",
			)
		}
		n := int(nFloat)
		scriptsInterface, ok := m["scripts"].([]any)
		if !ok {
			return nil, errors.New("missing or invalid scripts for nOf script")
		}
		if n < 1 || n > len(scriptsInterface) {
			return nil, fmt.Errorf(
				"invalid n value %d: must be between 1 and %d",
				n,
				len(scriptsInterface),
			)
		}
		scripts := make([]Script, len(scriptsInterface))
		for i, scriptInterface := range scriptsInterface {
			scriptMap, ok := scriptInterface.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid script at index %d", i)
			}
			script, err := mapToScript(scriptMap)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to parse script at index %d: %w",
					i,
					err,
				)
			}
			scripts[i] = script
		}
		return NewScriptNOf(n, scripts...)
	case "before":
		slotFloat, ok := m["slot"].(float64)
		if !ok {
			return nil, errors.New("missing or invalid slot for before script")
		}
		// Check for overflow: float64 loses precision above 2^53-1
		const maxExactInt = 9007199254740991.0 // (1<<53) - 1
		if slotFloat < 0 || slotFloat > maxExactInt {
			return nil, errors.New(
				"invalid slot: must be a non-negative integer <= 9007199254740991 (within float64 exact integer range)",
			)
		}
		// Verify integer precision
		if slotFloat != float64(uint64(slotFloat)) {
			return nil, errors.New(
				"invalid slot: must be an integer value",
			)
		}
		slot := uint64(slotFloat)
		return NewScriptBefore(slot)
	case "after":
		slotFloat, ok := m["slot"].(float64)
		if !ok {
			return nil, errors.New("missing or invalid slot for after script")
		}
		// Check for overflow: float64 loses precision above 2^53-1
		const maxExactInt = 9007199254740991.0 // (1<<53) - 1
		if slotFloat < 0 || slotFloat > maxExactInt {
			return nil, errors.New(
				"invalid slot: must be a non-negative integer <= 9007199254740991 (within float64 exact integer range)",
			)
		}
		// Verify integer precision
		if slotFloat != float64(uint64(slotFloat)) {
			return nil, errors.New(
				"invalid slot: must be an integer value",
			)
		}
		slot := uint64(slotFloat)
		return NewScriptAfter(slot)
	default:
		return nil, fmt.Errorf("unsupported script type: %s", scriptType)
	}
}
