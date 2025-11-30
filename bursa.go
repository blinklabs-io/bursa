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
	"strings"
	"sync"

	"github.com/blinklabs-io/bursa/bip32"
	ouroboros "github.com/blinklabs-io/gouroboros"
	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/btcsuite/btcd/btcutil/bech32"
	bip39 "github.com/tyler-smith/go-bip39"
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
	Type        string `json:"type"        example:"PaymentVerificationKeyShelley_ed25519"`
	Description string `json:"description" example:"Payment Verification Key"`
	CborHex     string `json:"cborHex"     example:"5820a9ebe2e435c03608fbdec443686d23661a796ab6d4dea71734c69b6dde310880"`
	// Embedded CBOR storage for automatic caching
	cbor.DecodeStoreCbor `                                                                                                         swaggerignore:"true"`
}

type LoadedKey struct {
	File        string
	Type        string
	Description string
	RawCBOR     []byte
	VKey        []byte
	SKey        []byte
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
// All derivation indices (accountId, paymentId, stakeId, drepId, committeeColdId, committeeHotId, addressId) must be less than 2^31 (0x80000000).
// This constraint ensures compatibility with BIP32/BIP44 derivation standards.
func NewWallet(
	mnemonic, network, password string,
	accountId uint32,
	paymentId, stakeId, drepId, committeeColdId, committeeHotId, addressId uint32,
) (*Wallet, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, ErrInvalidMnemonic
	}
	if accountId >= 0x80000000 || paymentId >= 0x80000000 ||
		stakeId >= 0x80000000 || drepId >= 0x80000000 ||
		committeeColdId >= 0x80000000 || committeeHotId >= 0x80000000 ||
		addressId >= 0x80000000 {
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

func GetExtendedPrivateKey(privateKey bip32.XPrv) bip32.XPrv {
	// Create a defensive copy to prevent accidental mutation of the input key
	xprv := make([]byte, 96)
	copy(xprv[:32], privateKey[:32])
	copy(xprv[32:64], privateKey[32:64]) // preserve k_R
	copy(xprv[64:], privateKey[64:])
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
		"CommitteeHotVerificationKeyShelley_ed25519":
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
		"CommitteeHotSigningKeyShelley_ed25519":
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
		"CommitteeHotExtendedSigningKeyShelley_ed25519_bip32":
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
