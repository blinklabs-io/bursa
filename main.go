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

package main

import (
	"fmt"

	// TODO: replace these w/ gOuroboros (blinklabs-io/gouroboros#364)
	"github.com/fivebinaries/go-cardano-serialization/address"
	"github.com/fivebinaries/go-cardano-serialization/bip32"
	"github.com/fivebinaries/go-cardano-serialization/network"
	"github.com/kelseyhightower/envconfig"
	bip39 "github.com/tyler-smith/go-bip39"
)

type Config struct {
	Mnemonic string `envconfig:"MNEMONIC"`
	Network  string `envconfig:"NETWORK"`
}

// We use a singleton for the config for convenience
var globalConfig = Config{
	Mnemonic: "",
	Network:  "mainnet",
}

func GetConfig() *Config {
	return &globalConfig
}

func LoadConfig() (*Config, error) {
	if err := envconfig.Process("bursa", &globalConfig); err != nil {
		return nil, fmt.Errorf("failed loading config from environment: %s", err)
	}
	return &globalConfig, nil
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

func GetPaymentKey(accountKey bip32.XPrv) bip32.XPrv {
	return accountKey.Derive(0).Derive(0)
}

func GetStakeKey(accountKey bip32.XPrv) bip32.XPrv {
	return accountKey.Derive(2).Derive(0)
}

func GetAddress(accountKey bip32.XPrv) *address.BaseAddress {
	cfg := GetConfig()
	net := network.TestNet()
	if cfg.Network == "mainnet" {
		net = network.MainNet()
	}
	paymentKeyPublicHash := GetPaymentKey(accountKey).Public().PublicKey().Hash()
	stakeKeyPublicHash := GetStakeKey(accountKey).Public().PublicKey().Hash()
	addr := address.NewBaseAddress(
		net,
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

func main() {
	// Load Config
	cfg, err := LoadConfig()
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
	addr := GetAddress(accountKey)
	fmt.Println("Loaded mnemonic and generated address...")
	fmt.Println(fmt.Sprintf("MNEMONIC=%s", mnemonic))
	fmt.Println(fmt.Sprintf("PAYMENT_ADDRESS=%s", addr.String()))
	fmt.Println(fmt.Sprintf("STAKE_ADDRESS=%s", addr.ToReward().String()))
}
