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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	ouroboros "github.com/blinklabs-io/gouroboros"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	// TODO: create our own bip32 implementation, see #132
	"github.com/fivebinaries/go-cardano-serialization/bip32"
	"github.com/fxamacker/cbor/v2"
	bip39 "github.com/tyler-smith/go-bip39"

	"github.com/blinklabs-io/bursa/internal/config"
)

type KeyFile struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	CborHex     string `json:"cborHex"`
}

type Wallet struct {
	Mnemonic            string  `json:"mnemonic"`
	PaymentAddress      string  `json:"payment_address"`
	StakeAddress        string  `json:"stake_address"`
	PaymentVKey         KeyFile `json:"payment_vkey"`
	PaymentSKey         KeyFile `json:"payment_skey"`
	PaymentExtendedSKey KeyFile `json:"payment_extended_skey"`
	StakeVKey           KeyFile `json:"stake_vkey"`
	StakeSKey           KeyFile `json:"stake_skey"`
	StakeExtendedSKey   KeyFile `json:"stake_extended_skey"`
}

func NewWallet(
	mnemonic, network, password string,
	accountId uint,
	paymentId, stakeId, addressId uint32,
) (*Wallet, error) {
	rootKey, err := GetRootKeyFromMnemonic(mnemonic, password)
	if err != nil {
		return nil, fmt.Errorf("failed to get root key from mnemonic: %s", err)
	}
	accountKey := GetAccountKey(rootKey, accountId)
	paymentKey := GetPaymentKey(accountKey, paymentId)
	stakeKey := GetStakeKey(accountKey, stakeId)
	addr := GetAddress(accountKey, network, addressId)
	if addr == nil {
		return nil, errors.New("unable to get address")
	}
	stakeAddr := addr.StakeAddress()
	if stakeAddr == nil {
		return nil, errors.New("unable to get stake address")
	}
	w := &Wallet{
		Mnemonic:            mnemonic,
		PaymentAddress:      addr.String(),
		StakeAddress:        stakeAddr.String(),
		PaymentVKey:         GetPaymentVKey(paymentKey),
		PaymentSKey:         GetPaymentSKey(paymentKey),
		PaymentExtendedSKey: GetPaymentExtendedSKey(paymentKey),
		StakeVKey:           GetStakeVKey(stakeKey),
		StakeSKey:           GetStakeSKey(stakeKey),
		StakeExtendedSKey:   GetStakeExtendedSKey(stakeKey),
	}
	return w, nil
}

func NewDefaultWallet(mnemonic string) (*Wallet, error) {
	cfg := config.GetConfig()
	w, err := NewWallet(mnemonic, cfg.Network, "", 0, 0, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create default wallet: %s", err)
	}
	return w, nil
}

func NewMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}
	return mnemonic, nil
}

func GetRootKeyFromMnemonic(mnemonic, password string) (bip32.XPrv, error) {
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

func GetAccountKey(rootKey bip32.XPrv, num uint) bip32.XPrv {
	const harden = 0x80000000
	hardNum := harden + num
	if hardNum > math.MaxUint32 {
		panic("num out of bounds")
	}
	return rootKey.
		Derive(uint32(harden + 1852)).
		Derive(uint32(harden + 1815)).
		Derive(uint32(hardNum))
}

func GetPaymentKey(accountKey bip32.XPrv, num uint32) bip32.XPrv {
	return accountKey.Derive(0).Derive(num)
}

func GetPaymentVKey(paymentKey bip32.XPrv) KeyFile {
	keyCbor, err := cbor.Marshal(paymentKey.Public().PublicKey())
	if err != nil {
		panic(err)
	}
	return KeyFile{
		Type:        "PaymentVerificationKeyShelley_ed25519",
		Description: "Payment Verification Key",
		CborHex:     hex.EncodeToString(keyCbor),
	}
}

func GetPaymentSKey(paymentKey bip32.XPrv) KeyFile {
	keyCbor, err := cbor.Marshal(paymentKey)
	if err != nil {
		panic(err)
	}
	return KeyFile{
		Type:        "PaymentSigningKeyShelley_ed25519",
		Description: "Payment Signing Key",
		CborHex:     hex.EncodeToString(keyCbor),
	}
}

func GetPaymentExtendedSKey(paymentKey bip32.XPrv) KeyFile {
	keyCbor, err := cbor.Marshal(
		GetExtendedPrivateKey(paymentKey, paymentKey.Public().PublicKey()),
	)
	if err != nil {
		panic(err)
	}
	return KeyFile{
		Type:        "PaymentExtendedSigningKeyShelley_ed25519_bip32",
		Description: "Payment Extended Signing Key (BIP32)",
		CborHex:     hex.EncodeToString(keyCbor),
	}
}
func GetStakeKey(accountKey bip32.XPrv, num uint32) bip32.XPrv {
	return accountKey.Derive(2).Derive(num)
}

func GetStakeVKey(stakeKey bip32.XPrv) KeyFile {
	keyCbor, err := cbor.Marshal(stakeKey.Public().PublicKey())
	if err != nil {
		panic(err)
	}
	return KeyFile{
		Type:        "StakeVerificationKeyShelley_ed25519",
		Description: "Stake Verification Key",
		CborHex:     hex.EncodeToString(keyCbor),
	}
}

func GetStakeSKey(stakeKey bip32.XPrv) KeyFile {
	keyCbor, err := cbor.Marshal(stakeKey)
	if err != nil {
		panic(err)
	}
	return KeyFile{
		Type:        "StakeSigningKeyShelley_ed25519",
		Description: "Stake Signing Key",
		CborHex:     hex.EncodeToString(keyCbor),
	}
}

func GetStakeExtendedSKey(stakeKey bip32.XPrv) KeyFile {
	keyCbor, err := cbor.Marshal(
		GetExtendedPrivateKey(stakeKey, stakeKey.Public().PublicKey()),
	)
	if err != nil {
		panic(err)
	}
	return KeyFile{
		Type:        "StakeExtendedSigningKeyShelley_ed25519_bip32",
		Description: "Stake Extended Signing Key (BIP32)",
		CborHex:     hex.EncodeToString(keyCbor),
	}
}

func GetAddress(
	accountKey bip32.XPrv,
	networkName string,
	num uint32,
) *lcommon.Address {
	network, ok := ouroboros.NetworkByName(networkName)
	if !ok {
		fmt.Println("couldn't get network")
		return nil
	}
	paymentKeyPublicHash := GetPaymentKey(
		accountKey,
		num,
	).Public().
		PublicKey().
		Hash()
	stakeKeyPublicHash := GetStakeKey(
		accountKey,
		num,
	).Public().
		PublicKey().
		Hash()
	addr, err := lcommon.NewAddressFromParts(
		lcommon.AddressTypeKeyKey,
		network.Id,
		paymentKeyPublicHash[:],
		stakeKeyPublicHash[:],
	)
	if err != nil {
		fmt.Println("error creating address", err)
		return nil
	}
	return &addr
}

func GetExtendedPrivateKey(privateKey []byte, publicKey []byte) bip32.XPrv {
	xprv := bip32.XPrv{}
	xprv = append(xprv, privateKey[:64]...)
	xprv = append(xprv, publicKey...)
	xprv = append(xprv, privateKey[64:]...)
	return xprv
}

func GetKeyFile(keyFile KeyFile) string {
	// Use 4 spaces for indent
	ret, err := json.MarshalIndent(keyFile, "", "    ")
	if err != nil {
		return ""
	}
	// Append newline
	return fmt.Sprintf("%s\n", ret)
}
