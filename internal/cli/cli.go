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

package cli

import (
	"fmt"
	"os"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/logging"
)

func NewDefaultWallet(mnemonic string) (*bursa.Wallet, error) {
	cfg := config.GetConfig()
	logger := logging.GetLogger()

	rootKey, err := bursa.GetRootKeyFromMnemonic(mnemonic)
	if err != nil {
		logger.Errorf("failed to get root key from mnemonic")
		return nil, fmt.Errorf("failed to get root key from mnemonic: %s", err)
	}
	accountKey := bursa.GetAccountKey(rootKey, 0)
	paymentKey := bursa.GetPaymentKey(accountKey, 0)
	stakeKey := bursa.GetStakeKey(accountKey, 0)
	addr := bursa.GetAddress(accountKey, cfg.Network, 0)
	w := &bursa.Wallet{
		Mnemonic:       mnemonic,
		PaymentAddress: addr.String(),
		StakeAddress:   addr.ToReward().String(),
		PaymentVKey:    bursa.GetPaymentVKey(paymentKey),
		PaymentSKey:    bursa.GetPaymentSKey(paymentKey),
		StakeVKey:      bursa.GetStakeVKey(stakeKey),
		StakeSKey:      bursa.GetStakeSKey(stakeKey),
	}
	return w, nil
}

func Run() {
	// Load Config
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Printf("Failed to load config: %s\n", err)
		os.Exit(1)
	}
	// Configure logging
	logging.Setup()
	logger := logging.GetLogger()
	// Sync logger on exit
	defer func() {
		if err := logger.Sync(); err != nil {
			// ignore error
			return
		}
	}()

	// Load mnemonic
	mnemonic := cfg.Mnemonic
	if mnemonic == "" {
		mnemonic, err = bursa.NewMnemonic()
		if err != nil {
			logger.Fatalf("failed to load mnemonic: %s", err)
		}
	}
	w, err := NewDefaultWallet(mnemonic)
	if err != nil {
		logger.Fatalf("failed to initialize wallet: %s", err)
	}

	logger.Infof("Loaded mnemonic and generated address...")
	fmt.Printf("MNEMONIC=%s\n", w.Mnemonic)
	fmt.Printf("PAYMENT_ADDRESS=%s\n", w.PaymentAddress)
	fmt.Printf("STAKE_ADDRESS=%s\n", w.StakeAddress)

	fmt.Printf("payment.vkey=%s\n", w.PaymentVKey)
	fmt.Printf("payment.skey=%s\n", w.PaymentSKey)
	fmt.Printf("stake.vkey=%s\n", w.StakeVKey)
	fmt.Printf("stake.skey=%s\n", w.StakeSKey)
}
