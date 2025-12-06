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
	"encoding/hex"
	"encoding/json"
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
	w, err := bursa.NewWallet(mnemonic, cfg.Network, "", 0, 0, 0, 0, 0, 0, 0)
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
		logger.Error("directory path cannot be empty")
		os.Exit(1)
	}
	keys, err := bursa.LoadWalletDir(dir, showSecrets)
	if err != nil {
		logger.Error("failed to load wallet keys", "dir", dir, "error", err)
		os.Exit(1)
	}
	bursa.PrintLoadedKeys(keys, showSecrets)
}

func RunScriptCreate(
	required int,
	keyHashes []string,
	output, network string,
	all, any bool,
	timelockBefore, timelockAfter uint64,
) {
	logger := logging.GetLogger()

	// Validate parameters
	if all && any {
		logger.Error("cannot specify both --all and --any")
		os.Exit(1)
	}
	if all && required > 0 {
		logger.Error("cannot specify --required with --all")
		os.Exit(1)
	}
	if any && required > 0 {
		logger.Error("cannot specify --required with --any")
		os.Exit(1)
	}
	if !all && !any && required == 0 {
		logger.Error("must specify --required, --all, or --any")
		os.Exit(1)
	}
	if len(keyHashes) == 0 {
		logger.Error("must provide at least one key hash")
		os.Exit(1)
	}
	if timelockBefore > 0 && timelockAfter > 0 {
		logger.Error(
			"cannot specify both --timelock-before and --timelock-after",
		)
		os.Exit(1)
	}

	// Parse key hashes
	hashes := make([][]byte, len(keyHashes))
	for i, hashStr := range keyHashes {
		hash, err := hex.DecodeString(hashStr)
		if err != nil {
			logger.Error(
				"invalid key hash format",
				"hash",
				hashStr,
				"error",
				err,
			)
			os.Exit(1)
		}
		hashes[i] = hash
	}

	// Create the script
	var script bursa.Script
	if all {
		script = bursa.NewAllMultiSigScript(hashes...)
	} else if any {
		script = bursa.NewAnyMultiSigScript(hashes...)
	} else {
		script = bursa.NewMultiSigScript(required, hashes...)
	}

	// Apply timelock if specified
	if timelockBefore > 0 {
		script = bursa.NewTimelockedScript(timelockBefore, true, script)
	} else if timelockAfter > 0 {
		script = bursa.NewTimelockedScript(timelockAfter, false, script)
	}

	// Marshal script data
	scriptData, err := bursa.MarshalScript(script, network)
	if err != nil {
		logger.Error("failed to marshal script", "error", err)
		os.Exit(1)
	}

	// Output the script
	if output != "" {
		// Write to file
		file, err := os.Create(output)
		if err != nil {
			logger.Error(
				"failed to create output file",
				"file",
				output,
				"error",
				err,
			)
			os.Exit(1)
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(scriptData); err != nil {
			logger.Error("failed to write script to file", "error", err)
			os.Exit(1)
		}
		logger.Info("script written to file", "file", output)
	} else {
		// Print to stdout
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(scriptData); err != nil {
			logger.Error("failed to encode script", "error", err)
			os.Exit(1)
		}
	}
}

func RunScriptValidate(scriptFile string, signatures []string, slot uint64) {
	logger := logging.GetLogger()

	// Read script file
	file, err := os.Open(scriptFile)
	if err != nil {
		logger.Error(
			"failed to open script file",
			"file",
			scriptFile,
			"error",
			err,
		)
		os.Exit(1)
	}
	defer file.Close()

	var scriptData bursa.ScriptData
	if err := json.NewDecoder(file).Decode(&scriptData); err != nil {
		logger.Error("failed to parse script file", "error", err)
		os.Exit(1)
	}

	// Unmarshal script
	script, err := bursa.UnmarshalScript(&scriptData)
	if err != nil {
		logger.Error("failed to unmarshal script", "error", err)
		os.Exit(1)
	}

	// Parse signatures
	sigBytes := make([][]byte, 0, len(signatures))
	for _, sigStr := range signatures {
		sig, err := hex.DecodeString(sigStr)
		if err != nil {
			logger.Error(
				"invalid signature format",
				"signature",
				sigStr,
				"error",
				err,
			)
			os.Exit(1)
		}
		sigBytes = append(sigBytes, sig)
	}

	// Validate script
	valid := bursa.ValidateScript(script, sigBytes, slot)

	// Output result
	result := map[string]any{
		"valid":      valid,
		"slot":       slot,
		"signatures": len(signatures),
		"scriptHash": scriptData.Hash,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		logger.Error("failed to encode result", "error", err)
		os.Exit(1)
	}
}

func RunScriptAddress(scriptFile, network string) {
	logger := logging.GetLogger()

	// Read script file
	file, err := os.Open(scriptFile)
	if err != nil {
		logger.Error(
			"failed to open script file",
			"file",
			scriptFile,
			"error",
			err,
		)
		os.Exit(1)
	}
	defer file.Close()

	var scriptData bursa.ScriptData
	if err := json.NewDecoder(file).Decode(&scriptData); err != nil {
		logger.Error("failed to parse script file", "error", err)
		os.Exit(1)
	}

	// Unmarshal script
	script, err := bursa.UnmarshalScript(&scriptData)
	if err != nil {
		logger.Error("failed to unmarshal script", "error", err)
		os.Exit(1)
	}

	// Generate address
	address, err := bursa.GetScriptAddress(script, network)
	if err != nil {
		logger.Error("failed to generate script address", "error", err)
		os.Exit(1)
	}

	// Output result
	result := map[string]any{
		"address":    address,
		"network":    network,
		"scriptHash": scriptData.Hash,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		logger.Error("failed to encode result", "error", err)
		os.Exit(1)
	}
}
