// Copyright 2023 Blink Labs Software
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
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sync/errgroup"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/logging"
)

func Run() {
	fs := flag.NewFlagSet("cli", flag.ExitOnError)
	flagOutput := fs.String(
		"output",
		"",
		"output directory for files, otherwise uses STDOUT",
	)
	if len(os.Args) >= 2 {
		_ = fs.Parse(os.Args[2:]) // ignore parse errors
	}

	cfg := config.GetConfig()
	logger := logging.GetLogger()
	// Load mnemonic
	var err error
	mnemonic := cfg.Mnemonic
	if mnemonic == "" {
		mnemonic, err = bursa.NewMnemonic()
		if err != nil {
			logger.Fatalf("failed to load mnemonic: %s", err)
		}
	}
	w, err := bursa.NewDefaultWallet(mnemonic)
	if err != nil {
		logger.Fatalf("failed to initialize wallet: %s", err)
	}

	logger.Infof("Loaded mnemonic and generated address...")

	if *flagOutput == "" {
		fmt.Printf("MNEMONIC=%s\n", w.Mnemonic)
		fmt.Printf("PAYMENT_ADDRESS=%s\n", w.PaymentAddress)
		fmt.Printf("STAKE_ADDRESS=%s\n", w.StakeAddress)

		fmt.Printf("payment.vkey=%s\n", bursa.GetKeyFile(w.PaymentVKey))
		fmt.Printf("payment.skey=%s\n", bursa.GetKeyFile(w.PaymentSKey))
		fmt.Printf("paymentExtended.skey=%s\n", bursa.GetKeyFile(w.PaymentExtendedSKey))
		fmt.Printf("stake.vkey=%s\n", bursa.GetKeyFile(w.StakeVKey))
		fmt.Printf("stake.skey=%s\n", bursa.GetKeyFile(w.StakeSKey))
		fmt.Printf("stakeExtended.skey=%s\n", bursa.GetKeyFile(w.StakeExtendedSKey))
	} else {
		fmt.Printf("Output dir: %v\n", *flagOutput)
		_, err := os.Stat(*flagOutput)
		if os.IsNotExist(err) {
			err = os.MkdirAll(*flagOutput, 0755)
			if err != nil {
				panic(err)
			}
		}
		var fileMap = []map[string]string{
			{"seed.txt": w.Mnemonic},
			{"payment.addr": w.PaymentAddress},
			{"stake.addr": w.StakeAddress},
			{"payment.vkey": bursa.GetKeyFile(w.PaymentVKey)},
			{"payment.skey": bursa.GetKeyFile(w.PaymentSKey)},
			{"paymentExtended.skey": bursa.GetKeyFile(w.PaymentExtendedSKey)},
			{"stake.vkey": bursa.GetKeyFile(w.StakeVKey)},
			{"stake.skey": bursa.GetKeyFile(w.StakeSKey)},
			{"stakeExtended.skey": bursa.GetKeyFile(w.StakeExtendedSKey)},
		}
		var g errgroup.Group
		for _, m := range fileMap {
			for k, v := range m {
				k := k
				v := v
				g.Go(func() error {
					path := filepath.Join(*flagOutput, k)
					err = os.WriteFile(path, []byte(v), 0666)
					if err != nil {
						return err
					}
					return err
				})
			}
		}
		err = g.Wait()
		if err != nil {
			logger.Fatalf("error occurred: %s", err)
			os.Exit(1)
		}
		logger.Infof("wrote output files to %s", *flagOutput)

	}
}
