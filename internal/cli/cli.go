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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/logging"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
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
	all, useAny bool,
	timelockBefore, timelockAfter uint64,
) error {
	logger := logging.GetLogger()

	// Validate parameters
	if all && useAny {
		return errors.New("cannot specify both --all and --any")
	}
	if all && required > 0 {
		return errors.New("cannot specify --required with --all")
	}
	if useAny && required > 0 {
		return errors.New("cannot specify --required with --any")
	}
	if !all && !useAny && required == 0 {
		return errors.New("must specify --required, --all, or --any")
	}
	if len(keyHashes) == 0 {
		return errors.New("must provide at least one key hash")
	}
	if timelockBefore > 0 && timelockAfter > 0 {
		return errors.New(
			"cannot specify both --timelock-before and --timelock-after",
		)
	}

	// Parse key hashes
	hashes := make([][]byte, len(keyHashes))
	for i, hashStr := range keyHashes {
		hash, err := hex.DecodeString(hashStr)
		if err != nil {
			return fmt.Errorf(
				"invalid key hash format %q: %w",
				hashStr,
				err,
			)
		}
		if len(hash) != 28 {
			return fmt.Errorf(
				"invalid key hash length for %q: expected 28 bytes, got %d",
				hashStr,
				len(hash),
			)
		}
		hashes[i] = hash
	}

	// Validate required count
	if required > len(hashes) {
		return fmt.Errorf(
			"required (%d) cannot exceed number of key hashes (%d)",
			required,
			len(hashes),
		)
	}

	// Create the script
	var script bursa.Script
	var err error
	if all {
		script, err = bursa.NewAllMultiSigScript(hashes...)
	} else if useAny {
		script, err = bursa.NewAnyMultiSigScript(hashes...)
	} else {
		script, err = bursa.NewMultiSigScript(required, hashes...)
	}
	if err != nil {
		return fmt.Errorf("failed to create script: %w", err)
	}

	// Apply timelock if specified
	if timelockBefore > 0 {
		script, err = bursa.NewTimelockedScript(timelockBefore, true, script)
		if err != nil {
			return fmt.Errorf("failed to create timelocked script: %w", err)
		}
	} else if timelockAfter > 0 {
		script, err = bursa.NewTimelockedScript(timelockAfter, false, script)
		if err != nil {
			return fmt.Errorf("failed to create timelocked script: %w", err)
		}
	}

	// Marshal script data
	scriptData, err := bursa.MarshalScript(script, network)
	if err != nil {
		return fmt.Errorf("failed to marshal script: %w", err)
	}

	// Output the script
	if output != "" {
		// Write to file
		file, err := os.Create(output)
		if err != nil {
			return fmt.Errorf(
				"failed to create output file %q: %w",
				output,
				err,
			)
		}
		defer func() {
			if err := file.Close(); err != nil {
				logger.Warn("failed to close output file", "error", err)
			}
		}()

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(scriptData); err != nil {
			return fmt.Errorf("failed to write script to file: %w", err)
		}

		logger.Info("script written to file", "file", output)
	} else {
		// Print to stdout
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(scriptData); err != nil {
			return fmt.Errorf("failed to encode script: %w", err)
		}
	}

	return nil
}

func scriptRequiresSignatures(script bursa.Script) bool {
	nativeScript, ok := script.(*bursa.NativeScript)
	if !ok {
		return false
	}
	switch s := nativeScript.Item().(type) {
	case *bursa.NativeScriptPubkey:
		return true
	case *bursa.NativeScriptAll:
		return anyScriptRequiresSignatures(convertScripts(s.Scripts))
	case *bursa.NativeScriptAny:
		return anyScriptRequiresSignatures(convertScripts(s.Scripts))
	case *bursa.NativeScriptNofK:
		return anyScriptRequiresSignatures(convertScripts(s.Scripts))
	case *bursa.NativeScriptInvalidBefore, *bursa.NativeScriptInvalidHereafter:
		return false
	}
	return false
}

// convertScripts converts []lcommon.NativeScript to []bursa.Script
func convertScripts(scripts []lcommon.NativeScript) []bursa.Script {
	result := make([]bursa.Script, len(scripts))
	for i, scr := range scripts {
		result[i] = scr
	}
	return result
}

// anyScriptRequiresSignatures checks if any script in the slice requires signatures
func anyScriptRequiresSignatures(scripts []bursa.Script) bool {
	return slices.ContainsFunc(scripts, scriptRequiresSignatures)
}

func RunScriptValidate(
	scriptFile string,
	signatures []string,
	slot uint64,
	structuralOnly bool,
) {
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

	// Compute script hash
	hash, err := bursa.GetScriptHash(script)
	if err != nil {
		logger.Error("failed to compute script hash", "error", err)
		os.Exit(1)
	}
	hashHex := hex.EncodeToString(hash)

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
		if len(sig) == 0 {
			logger.Error("decoded signature is empty", "signature", sigStr)
			os.Exit(1)
		}
		sigBytes = append(sigBytes, sig)
	}

	// Check if signatures are required
	if !structuralOnly && len(sigBytes) == 0 &&
		scriptRequiresSignatures(script) {
		logger.Error(
			"signatures required for format validation of scripts with signature requirements (use --structural-only for basic structure checks)",
		)
		os.Exit(1)
	}

	// Validate script
	valid := bursa.ValidateScript(script, sigBytes, slot, !structuralOnly)

	// Output result
	result := map[string]any{
		"valid":          valid,
		"slot":           slot,
		"signatures":     len(signatures),
		"scriptHash":     hashHex,
		"structuralOnly": structuralOnly,
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

	// Compute script hash
	hash, err := bursa.GetScriptHash(script)
	if err != nil {
		logger.Error("failed to compute script hash", "error", err)
		os.Exit(1)
	}
	hashHex := hex.EncodeToString(hash)

	// Generate address
	address, err := bursa.GetScriptAddress(script, network)
	if err != nil {
		logger.Error(
			"failed to generate script address",
			"network",
			network,
			"error",
			err,
		)
		os.Exit(1)
	}

	// Output result
	result := map[string]any{
		"address":    address,
		"network":    network,
		"scriptHash": hashHex,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		logger.Error("failed to encode result", "error", err)
		os.Exit(1)
	}
}
