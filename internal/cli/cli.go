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

package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/logging"
	"golang.org/x/sync/errgroup"
)

// It remains a default entrypoint for creation
func Run(cfg *config.Config, output string) {
	RunCreate(cfg, output)
}

func RunCreate(cfg *config.Config, output string) {
	logger := logging.GetLogger()
	// Load mnemonic
	var err error
	mnemonic := cfg.Mnemonic
	if mnemonic == "" {
		mnemonic, err = bursa.GenerateMnemonic()
		if err != nil {
			logger.Error("failed to generate mnemonic", "error", err)
			os.Exit(1)
		}
	}
	w, err := bursa.NewWallet(mnemonic, cfg.Network, "", 0, 0, 0, 0)
	if err != nil {
		logger.Error("failed to initialize wallet", "error", err)
		os.Exit(1)
	}
	if w == nil {
		logger.Error("wallet empty after init... this shouldn't happen")
		os.Exit(1)
	}

	logger.Info("Loaded mnemonic and generated address")

	keyFiles, err := bursa.ExtractKeyFiles(w)
	if err != nil {
		logger.Error("failed to extract key files", "error", err)
		os.Exit(1)
	}

	if output == "" {
		logger.Info("MNEMONIC", "mnemonic", w.Mnemonic)
		logger.Info("PAYMENT_ADDRESS", "payment_address", w.PaymentAddress)
		logger.Info("STAKE_ADDRESS", "stake_address", w.StakeAddress)
		for key, value := range keyFiles {
			logger.Info(key, key, value)
		}
	} else {
		fmt.Printf("Output dir: %v\n", output)
		_, err := os.Stat(output)
		if os.IsNotExist(err) {
			err = os.MkdirAll(output, 0o755)
			if err != nil {
				panic(err)
			}
		}
		fileMap := []map[string]string{
			{"seed.txt": w.Mnemonic},
			{"payment.addr": w.PaymentAddress},
			{"stake.addr": w.StakeAddress},
		}
		for key, value := range keyFiles {
			fileMap = append(fileMap, map[string]string{key: value})
		}
		var g errgroup.Group
		for _, m := range fileMap {
			for k, v := range m {
				g.Go(func() error {
					path := filepath.Join(output, k)
					err = os.WriteFile(path, []byte(v), 0o600)
					if err != nil {
						return err
					}
					return err
				})
			}
		}
		err = g.Wait()
		if err != nil {
			logger.Error("error occurred", "error", err)
			os.Exit(1)
		}
		logger.Info("wrote output files", "directory", output)
	}
}

func RunLoad(dir string, showSecrets bool) {
	logger := logging.GetLogger()
	if dir == "" {
		dir = "."
	}
	keys, err := bursa.LoadWalletDir(dir, showSecrets)
	if err != nil {
		logger.Error("failed to load wallet keys", "dir", dir, "error", err)
		os.Exit(1)
	}
	bursa.PrintLoadedKeys(keys, showSecrets)
}
