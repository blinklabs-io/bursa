// Copyright 2023 Blink Labs, LLC.
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
	"encoding/json"
	"fmt"

	"github.com/blinklabs-io/bursa/internal/config"
	// TODO: replace these w/ gOuroboros (blinklabs-io/gouroboros#364)
	"github.com/fivebinaries/go-cardano-serialization/address"
	"github.com/fivebinaries/go-cardano-serialization/bip32"
	"github.com/fivebinaries/go-cardano-serialization/network"
	"github.com/fxamacker/cbor/v2"
	bip39 "github.com/tyler-smith/go-bip39"
)

type KeyFile struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	CborHex     string `json:"cborHex"`
}

type Wallet struct {
	Mnemonic       string  `json:"mnemonic"`
	PaymentAddress string  `json:"payment_address"`
	StakeAddress   string  `json:"stake_address"`
	PaymentVKey    KeyFile `json:"-"`
	PaymentSKey    KeyFile `json:"-"`
	StakeVKey      KeyFile `json:"-"`
	StakeSKey      KeyFile `json:"-"`
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

func GetRootKeyFromMnemonic(mnemonic string) (bip32.XPrv, error) {
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	rootKey := GetRootKey(entropy, []byte{}) // TODO: support password
	return rootKey, nil
}

func GetRootKey(entropy []byte, password []byte) bip32.XPrv {
	return bip32.FromBip39Entropy(entropy, password)
}

func GetAccountKey(rootKey bip32.XPrv, num uint) bip32.XPrv {
	const harden = 0x80000000
	return rootKey.
		Derive(uint32(harden + 1852)).
		Derive(uint32(harden + 1815)).
		Derive(uint32(harden + num))
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
		Type: "PaymentVerificationKeyShelley_ed25519",
		Description: "Payment Verification Key",
		CborHex: fmt.Sprintf("%x", keyCbor),
	}
}

func GetPaymentSKey(paymentKey bip32.XPrv) KeyFile {
	keyCbor, err := cbor.Marshal(GetExtendedPrivateKey(paymentKey, paymentKey.Public().PublicKey()))
	if err != nil {
		panic(err)
	}
	return KeyFile{
		Type: "PaymentExtendedSigningKeyShelley_ed25519_bip32",
		Description: "Payment Signing Key",
		CborHex: fmt.Sprintf("%x", keyCbor),
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
		Type: "StakeVerificationKeyShelley_ed25519",
		Description: "Stake Verification Key",
		CborHex: fmt.Sprintf("%x", keyCbor),
	}
}

func GetStakeSKey(stakeKey bip32.XPrv) KeyFile {
	keyCbor, err := cbor.Marshal(GetExtendedPrivateKey(stakeKey, stakeKey.Public().PublicKey()))
	if err != nil {
		panic(err)
	}
	return KeyFile{
		Type: "StakeExtendedSigningKeyShelley_ed25519_bip32",
		Description: "Stake Signing Key",
		CborHex: fmt.Sprintf("%x", keyCbor),
	}
}

func GetAddress(accountKey bip32.XPrv, net string, num uint32) *address.BaseAddress {
	nw := network.TestNet()
	if net == "mainnet" {
		nw = network.MainNet()
	}
	paymentKeyPublicHash := GetPaymentKey(accountKey, num).Public().PublicKey().Hash()
	stakeKeyPublicHash := GetStakeKey(accountKey, num).Public().PublicKey().Hash()
	addr := address.NewBaseAddress(
		nw,
		&address.StakeCredential{
			Kind:    address.KeyStakeCredentialType,
			Payload: paymentKeyPublicHash[:],
		},
		&address.StakeCredential{
			Kind:    address.KeyStakeCredentialType,
			Payload: stakeKeyPublicHash[:],
		},
	)
	return addr
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

func Run() {
	// Load Config
	cfg, err := config.LoadConfig()
	if err != nil {
		panic(err)
	}

	mnemonic := cfg.Mnemonic
	if mnemonic == "" {
		mnemonic, err = NewMnemonic()
		if err != nil {
			panic(err)
		}
	}
	rootKey, err := GetRootKeyFromMnemonic(mnemonic)
	if err != nil {
		panic(err)
	}
	accountKey := GetAccountKey(rootKey, 0) // TODO: more accounts
	addr := GetAddress(accountKey, cfg.Network, 0) // TODO: more addresses

	fmt.Println("Loaded mnemonic and generated address...")
	fmt.Printf("MNEMONIC=%s\n", mnemonic)
	fmt.Printf("PAYMENT_ADDRESS=%s\n", addr.String())
	fmt.Printf("STAKE_ADDRESS=%s\n", addr.ToReward().String())

	fmt.Printf("payment.vkey=%s", GetKeyFile(GetPaymentVKey(GetPaymentKey(accountKey, 0))))
	fmt.Printf("payment.skey=%s", GetKeyFile(GetPaymentSKey(GetPaymentKey(accountKey, 0))))
	fmt.Printf("stake.vkey=%s", GetKeyFile(GetStakeVKey(GetStakeKey(accountKey, 0))))
	fmt.Printf("stake.vkey=%s", GetKeyFile(GetStakeSKey(GetStakeKey(accountKey, 0))))
}
