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
	"strings"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/logging"
	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/btcsuite/btcd/btcutil/bech32"
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
	w, err := bursa.NewWallet(mnemonic, bursa.WithNetwork(cfg.Network))
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
		fileMap := make([]map[string]string, 0, 3+len(keyFiles))
		fileMap = append(fileMap,
			map[string]string{"seed.txt": w.Mnemonic},
			map[string]string{"payment.addr": w.PaymentAddress},
			map[string]string{"stake.addr": w.StakeAddress},
		)
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

// resolveMnemonic loads a mnemonic from various sources in order of precedence:
// 1. Direct mnemonic string (--mnemonic flag)
// 2. MNEMONIC environment variable
// 3. File specified by mnemonicFile (--mnemonic-file flag)
// 4. Default file "seed.txt" in current directory
func resolveMnemonic(mnemonic, mnemonicFile string) (string, error) {
	// 1. Direct mnemonic string takes highest precedence
	if mnemonic != "" {
		return strings.TrimSpace(mnemonic), nil
	}

	// 2. Check MNEMONIC environment variable
	if envMnemonic := os.Getenv("MNEMONIC"); envMnemonic != "" {
		return strings.TrimSpace(envMnemonic), nil
	}

	// 3. Read from specified file or default to seed.txt
	filePath := mnemonicFile
	if filePath == "" {
		filePath = "seed.txt"
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if mnemonicFile != "" {
			// User explicitly specified a file that doesn't exist
			return "", fmt.Errorf(
				"failed to read mnemonic file %q: %w",
				mnemonicFile,
				err,
			)
		}
		// Default seed.txt not found and no other source available
		return "", errors.New(
			"no mnemonic provided: use --mnemonic, --mnemonic-file, " +
				"set MNEMONIC env var, or create seed.txt",
		)
	}

	return strings.TrimSpace(string(data)), nil
}

func RunRestore(
	cfg *config.Config,
	mnemonic, mnemonicFile, password, output string,
) {
	logger := logging.GetLogger()

	// Load mnemonic from various sources (in order of precedence)
	resolvedMnemonic, err := resolveMnemonic(mnemonic, mnemonicFile)
	if err != nil {
		logger.Error("failed to load mnemonic", "error", err)
		os.Exit(1)
	}

	w, err := bursa.NewWallet(
		resolvedMnemonic,
		bursa.WithNetwork(cfg.Network),
		bursa.WithPassword(password),
	)
	if err != nil {
		logger.Error("failed to restore wallet", "error", err)
		os.Exit(1)
	}
	if w == nil {
		logger.Error("wallet empty after restore... this shouldn't happen")
		os.Exit(1)
	}

	logger.Info("Restored wallet from mnemonic")

	keyFiles, err := bursa.ExtractKeyFiles(w)
	if err != nil {
		logger.Error("failed to extract key files", "error", err)
		os.Exit(1)
	}

	if output == "" {
		// Don't output the mnemonic since the user already has it
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
				logger.Error("failed to create output directory", "error", err)
				os.Exit(1)
			}
		}
		fileMap := make([]map[string]string, 0, 2+len(keyFiles))
		fileMap = append(fileMap,
			map[string]string{"payment.addr": w.PaymentAddress},
			map[string]string{"stake.addr": w.StakeAddress},
		)
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

// RunKeyRoot derives and outputs the root extended private key from a mnemonic
func RunKeyRoot(mnemonic, mnemonicFile, password string) error {
	resolvedMnemonic, err := resolveMnemonic(mnemonic, mnemonicFile)
	if err != nil {
		return err
	}

	rootKey, err := bursa.GetRootKeyFromMnemonic(resolvedMnemonic, password)
	if err != nil {
		return fmt.Errorf("failed to derive root key: %w", err)
	}

	// Output in bech32 format
	fmt.Println(rootKey.String())
	return nil
}

// RunKeyAccount derives and outputs an account extended private key
func RunKeyAccount(
	mnemonic, mnemonicFile, password string,
	accountIndex uint32,
) error {
	resolvedMnemonic, err := resolveMnemonic(mnemonic, mnemonicFile)
	if err != nil {
		return err
	}

	rootKey, err := bursa.GetRootKeyFromMnemonic(resolvedMnemonic, password)
	if err != nil {
		return fmt.Errorf("failed to derive root key: %w", err)
	}

	accountKey, err := bursa.GetAccountKey(rootKey, accountIndex)
	if err != nil {
		return fmt.Errorf("failed to derive account key: %w", err)
	}

	// Output in bech32 format with acct_xsk prefix
	encoded, err := encodeAccountKey(accountKey)
	if err != nil {
		return fmt.Errorf("failed to encode account key: %w", err)
	}
	fmt.Println(encoded)
	return nil
}

// RunKeyPayment derives and outputs a payment extended private key
func RunKeyPayment(
	mnemonic, mnemonicFile, password string,
	accountIndex, paymentIndex uint32,
) error {
	resolvedMnemonic, err := resolveMnemonic(mnemonic, mnemonicFile)
	if err != nil {
		return err
	}

	rootKey, err := bursa.GetRootKeyFromMnemonic(resolvedMnemonic, password)
	if err != nil {
		return fmt.Errorf("failed to derive root key: %w", err)
	}

	accountKey, err := bursa.GetAccountKey(rootKey, accountIndex)
	if err != nil {
		return fmt.Errorf("failed to derive account key: %w", err)
	}

	paymentKey, err := bursa.GetPaymentKey(accountKey, paymentIndex)
	if err != nil {
		return fmt.Errorf("failed to derive payment key: %w", err)
	}

	// Output in bech32 format with addr_xsk prefix
	encoded, err := encodePaymentKey(paymentKey)
	if err != nil {
		return fmt.Errorf("failed to encode payment key: %w", err)
	}
	fmt.Println(encoded)
	return nil
}

// RunKeyStake derives and outputs a stake extended private key
func RunKeyStake(
	mnemonic, mnemonicFile, password string,
	accountIndex, stakeIndex uint32,
) error {
	resolvedMnemonic, err := resolveMnemonic(mnemonic, mnemonicFile)
	if err != nil {
		return err
	}

	rootKey, err := bursa.GetRootKeyFromMnemonic(resolvedMnemonic, password)
	if err != nil {
		return fmt.Errorf("failed to derive root key: %w", err)
	}

	accountKey, err := bursa.GetAccountKey(rootKey, accountIndex)
	if err != nil {
		return fmt.Errorf("failed to derive account key: %w", err)
	}

	stakeKey, err := bursa.GetStakeKey(accountKey, stakeIndex)
	if err != nil {
		return fmt.Errorf("failed to derive stake key: %w", err)
	}

	// Output in bech32 format with stake_xsk prefix
	encoded, err := encodeStakeKey(stakeKey)
	if err != nil {
		return fmt.Errorf("failed to encode stake key: %w", err)
	}
	fmt.Println(encoded)
	return nil
}

// RunKeyPolicy derives a policy key from a mnemonic and outputs it in bech32
func RunKeyPolicy(
	mnemonic, mnemonicFile, password string,
	index uint32,
) error {
	resolvedMnemonic, err := resolveMnemonic(mnemonic, mnemonicFile)
	if err != nil {
		return err
	}

	rootKey, err := bursa.GetRootKeyFromMnemonic(resolvedMnemonic, password)
	if err != nil {
		return fmt.Errorf("failed to derive root key: %w", err)
	}

	policyKey, err := bursa.GetPolicyKey(rootKey, index)
	if err != nil {
		return fmt.Errorf("failed to derive policy key: %w", err)
	}

	// Output in bech32 format with policy_xsk prefix
	encoded, err := encodePolicyKey(policyKey)
	if err != nil {
		return fmt.Errorf("failed to encode policy key: %w", err)
	}
	fmt.Println(encoded)
	return nil
}

// encodeExtendedPrivateKey encodes an extended private key in bech32 format
// with the specified human-readable prefix (hrp).
func encodeExtendedPrivateKey(key []byte, hrp string) (string, error) {
	converted, err := bech32.ConvertBits(key, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %w", err)
	}
	encoded, err := bech32.Encode(hrp, converted)
	if err != nil {
		return "", fmt.Errorf("failed to bech32 encode: %w", err)
	}
	return encoded, nil
}

// encodeAccountKey encodes an account extended private key in bech32 format
func encodeAccountKey(key []byte) (string, error) {
	return encodeExtendedPrivateKey(key, "acct_xsk")
}

// encodePaymentKey encodes a payment extended private key in bech32 format
func encodePaymentKey(key []byte) (string, error) {
	return encodeExtendedPrivateKey(key, "addr_xsk")
}

// encodeStakeKey encodes a stake extended private key in bech32 format
func encodeStakeKey(key []byte) (string, error) {
	return encodeExtendedPrivateKey(key, "stake_xsk")
}

// encodePolicyKey encodes a policy extended private key in bech32 format
func encodePolicyKey(key []byte) (string, error) {
	return encodeExtendedPrivateKey(key, "policy_xsk")
}

// RunKeyPoolCold derives a pool cold key from a mnemonic and outputs in bech32
func RunKeyPoolCold(
	mnemonic, mnemonicFile, password string,
	index uint32,
) error {
	resolvedMnemonic, err := resolveMnemonic(mnemonic, mnemonicFile)
	if err != nil {
		return err
	}

	rootKey, err := bursa.GetRootKeyFromMnemonic(resolvedMnemonic, password)
	if err != nil {
		return fmt.Errorf("failed to derive root key: %w", err)
	}

	// CIP-1853: usecase is fixed to 0 as per specification
	poolColdKey, err := bursa.GetPoolColdKey(rootKey, 0, index)
	if err != nil {
		return fmt.Errorf("failed to derive pool cold key: %w", err)
	}

	// Output in bech32 format with pool_xsk prefix
	encoded, err := encodePoolColdKey(poolColdKey)
	if err != nil {
		return fmt.Errorf("failed to encode pool cold key: %w", err)
	}
	fmt.Println(encoded)
	return nil
}

// encodePoolColdKey encodes a pool cold extended private key in bech32 format
func encodePoolColdKey(key []byte) (string, error) {
	return encodeExtendedPrivateKey(key, "pool_xsk")
}

// encodeDRepKey encodes a DRep extended private key in bech32 format
func encodeDRepKey(key []byte) (string, error) {
	return encodeExtendedPrivateKey(key, "drep_xsk")
}

// encodeCommitteeColdKey encodes a committee cold extended private key
func encodeCommitteeColdKey(key []byte) (string, error) {
	return encodeExtendedPrivateKey(key, "cc_cold_xsk")
}

// encodeCommitteeHotKey encodes a committee hot extended private key
func encodeCommitteeHotKey(key []byte) (string, error) {
	return encodeExtendedPrivateKey(key, "cc_hot_xsk")
}

// RunKeyDRep derives a DRep key from a mnemonic and outputs it in bech32
func RunKeyDRep(
	mnemonic, mnemonicFile, password string,
	accountIndex, index uint32,
) error {
	resolvedMnemonic, err := resolveMnemonic(mnemonic, mnemonicFile)
	if err != nil {
		return err
	}

	rootKey, err := bursa.GetRootKeyFromMnemonic(resolvedMnemonic, password)
	if err != nil {
		return fmt.Errorf("failed to derive root key: %w", err)
	}

	accountKey, err := bursa.GetAccountKey(rootKey, accountIndex)
	if err != nil {
		return fmt.Errorf("failed to derive account key: %w", err)
	}

	// CIP-0105: DRep key derivation from account key
	drepKey, err := bursa.GetDRepKey(accountKey, index)
	if err != nil {
		return fmt.Errorf("failed to derive DRep key: %w", err)
	}

	// Output in bech32 format with drep_xsk prefix
	encoded, err := encodeDRepKey(drepKey)
	if err != nil {
		return fmt.Errorf("failed to encode DRep key: %w", err)
	}
	fmt.Println(encoded)
	return nil
}

// RunKeyCommitteeCold derives a committee cold key and outputs it in bech32
func RunKeyCommitteeCold(
	mnemonic, mnemonicFile, password string,
	accountIndex, index uint32,
) error {
	resolvedMnemonic, err := resolveMnemonic(mnemonic, mnemonicFile)
	if err != nil {
		return err
	}

	rootKey, err := bursa.GetRootKeyFromMnemonic(resolvedMnemonic, password)
	if err != nil {
		return fmt.Errorf("failed to derive root key: %w", err)
	}

	accountKey, err := bursa.GetAccountKey(rootKey, accountIndex)
	if err != nil {
		return fmt.Errorf("failed to derive account key: %w", err)
	}

	// CIP-0105: Committee cold key derivation from account key (role 4)
	committeeColdKey, err := bursa.GetCommitteeColdKey(accountKey, index)
	if err != nil {
		return fmt.Errorf("failed to derive committee cold key: %w", err)
	}

	// Output in bech32 format with cc_cold_xsk prefix
	encoded, err := encodeCommitteeColdKey(committeeColdKey)
	if err != nil {
		return fmt.Errorf("failed to encode committee cold key: %w", err)
	}
	fmt.Println(encoded)
	return nil
}

// RunKeyCommitteeHot derives a committee hot key and outputs it in bech32
func RunKeyCommitteeHot(
	mnemonic, mnemonicFile, password string,
	accountIndex, index uint32,
) error {
	resolvedMnemonic, err := resolveMnemonic(mnemonic, mnemonicFile)
	if err != nil {
		return err
	}

	rootKey, err := bursa.GetRootKeyFromMnemonic(resolvedMnemonic, password)
	if err != nil {
		return fmt.Errorf("failed to derive root key: %w", err)
	}

	accountKey, err := bursa.GetAccountKey(rootKey, accountIndex)
	if err != nil {
		return fmt.Errorf("failed to derive account key: %w", err)
	}

	// CIP-0105: Committee hot key derivation from account key (role 5)
	committeeHotKey, err := bursa.GetCommitteeHotKey(accountKey, index)
	if err != nil {
		return fmt.Errorf("failed to derive committee hot key: %w", err)
	}

	// Output in bech32 format with cc_hot_xsk prefix
	encoded, err := encodeCommitteeHotKey(committeeHotKey)
	if err != nil {
		return fmt.Errorf("failed to encode committee hot key: %w", err)
	}
	fmt.Println(encoded)
	return nil
}

// RunKeyVRF derives a VRF key pair from a mnemonic and outputs it
func RunKeyVRF(
	mnemonic, mnemonicFile, password string,
	index uint32,
) error {
	resolvedMnemonic, err := resolveMnemonic(mnemonic, mnemonicFile)
	if err != nil {
		return err
	}

	rootKey, err := bursa.GetRootKeyFromMnemonic(resolvedMnemonic, password)
	if err != nil {
		return fmt.Errorf("failed to derive root key: %w", err)
	}

	// Derive VRF seed from root key
	vrfSeed, err := bursa.GetVRFSeed(rootKey, index)
	if err != nil {
		return fmt.Errorf("failed to derive VRF seed: %w", err)
	}

	// Generate VRF key pair
	vrfPubKey, vrfSecKey, err := bursa.GetVRFKeyPair(vrfSeed)
	if err != nil {
		return fmt.Errorf("failed to generate VRF key pair: %w", err)
	}

	// Output VRF keys in bech32 format
	// VRF signing key (secret key / seed)
	vrfSkEncoded, err := encodeVRFSigningKey(vrfSecKey)
	if err != nil {
		return fmt.Errorf("failed to encode VRF signing key: %w", err)
	}

	// VRF verification key (public key)
	vrfVkEncoded, err := encodeVRFVerificationKey(vrfPubKey)
	if err != nil {
		return fmt.Errorf("failed to encode VRF verification key: %w", err)
	}

	fmt.Printf("vrf_skey: %s\n", vrfSkEncoded)
	fmt.Printf("vrf_vkey: %s\n", vrfVkEncoded)
	return nil
}

// encodeVRFSigningKey encodes a VRF signing key in bech32 format
func encodeVRFSigningKey(key []byte) (string, error) {
	converted, err := bech32.ConvertBits(key, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %w", err)
	}
	encoded, err := bech32.Encode("vrf_sk", converted)
	if err != nil {
		return "", fmt.Errorf("failed to bech32 encode: %w", err)
	}
	return encoded, nil
}

// encodeVRFVerificationKey encodes a VRF verification key in bech32 format
func encodeVRFVerificationKey(key []byte) (string, error) {
	converted, err := bech32.ConvertBits(key, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %w", err)
	}
	encoded, err := bech32.Encode("vrf_vk", converted)
	if err != nil {
		return "", fmt.Errorf("failed to bech32 encode: %w", err)
	}
	return encoded, nil
}

// RunKeyKES derives a KES key pair from a mnemonic and outputs it
func RunKeyKES(
	mnemonic, mnemonicFile, password string,
	index uint32,
) error {
	resolvedMnemonic, err := resolveMnemonic(mnemonic, mnemonicFile)
	if err != nil {
		return err
	}

	rootKey, err := bursa.GetRootKeyFromMnemonic(resolvedMnemonic, password)
	if err != nil {
		return fmt.Errorf("failed to derive root key: %w", err)
	}

	// Derive KES seed from root key
	kesSeed, err := bursa.GetKESSeed(rootKey, index)
	if err != nil {
		return fmt.Errorf("failed to derive KES seed: %w", err)
	}

	// Generate KES key pair
	kesSecKey, kesPubKey, err := bursa.GetKESKeyPair(kesSeed)
	if err != nil {
		return fmt.Errorf("failed to generate KES key pair: %w", err)
	}

	// Output KES keys in bech32 format
	// KES signing key (secret key)
	kesSkEncoded, err := encodeKESSigningKey(kesSecKey.Data)
	if err != nil {
		return fmt.Errorf("failed to encode KES signing key: %w", err)
	}

	// KES verification key (public key)
	kesVkEncoded, err := encodeKESVerificationKey(kesPubKey)
	if err != nil {
		return fmt.Errorf("failed to encode KES verification key: %w", err)
	}

	fmt.Printf("kes_skey: %s\n", kesSkEncoded)
	fmt.Printf("kes_vkey: %s\n", kesVkEncoded)
	return nil
}

// encodeKESSigningKey encodes a KES signing key in bech32 format
func encodeKESSigningKey(key []byte) (string, error) {
	converted, err := bech32.ConvertBits(key, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %w", err)
	}
	encoded, err := bech32.Encode("kes_sk", converted)
	if err != nil {
		return "", fmt.Errorf("failed to bech32 encode: %w", err)
	}
	return encoded, nil
}

// encodeKESVerificationKey encodes a KES verification key in bech32 format
func encodeKESVerificationKey(key []byte) (string, error) {
	converted, err := bech32.ConvertBits(key, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %w", err)
	}
	encoded, err := bech32.Encode("kes_vk", converted)
	if err != nil {
		return "", fmt.Errorf("failed to bech32 encode: %w", err)
	}
	return encoded, nil
}

// RunCertOpCert creates an operational certificate linking a KES key to a pool cold key
func RunCertOpCert(
	kesVkeyFile, coldSkeyFile, outputFile string,
	counter, kesPeriod uint64,
) error {
	// Read KES verification key
	kesVkeyData, err := os.ReadFile(kesVkeyFile)
	if err != nil {
		return fmt.Errorf("failed to read KES vkey file: %w", err)
	}

	// Parse KES vkey - expect 32 bytes hex or bech32
	kesVkey, err := parseVerificationKey(kesVkeyData)
	if err != nil {
		return fmt.Errorf("failed to parse KES vkey: %w", err)
	}

	// Read pool cold signing key
	coldSkeyData, err := os.ReadFile(coldSkeyFile)
	if err != nil {
		return fmt.Errorf("failed to read cold skey file: %w", err)
	}

	// Parse cold signing key - expect 32 or 64 bytes hex or bech32
	coldSkey, err := parseSigningKey(coldSkeyData)
	if err != nil {
		return fmt.Errorf("failed to parse cold skey: %w", err)
	}

	// Create operational certificate
	opCert, err := bursa.CreateOperationalCertificate(
		kesVkey,
		counter,
		kesPeriod,
		coldSkey,
	)
	if err != nil {
		return fmt.Errorf("failed to create operational certificate: %w", err)
	}

	// Output the certificate
	if outputFile != "" {
		// Encode certificate to CBOR
		cborHex, err := encodeOpCertCBOR(opCert)
		if err != nil {
			return err
		}
		// Write to file in JSON format (similar to cardano-cli)
		certJSON := fmt.Sprintf(`{
    "type": "NodeOperationalCertificate",
    "description": "Operational Certificate",
    "cborHex": "%s"
}`, cborHex)
		if err := os.WriteFile(outputFile, []byte(certJSON), 0o600); err != nil {
			return fmt.Errorf("failed to write certificate file: %w", err)
		}
		fmt.Printf("Operational certificate written to %s\n", outputFile)
	} else {
		// Output to stdout
		fmt.Printf("KES vkey:    %x\n", opCert.KesVkey)
		fmt.Printf("Counter:     %d\n", opCert.IssueNumber)
		fmt.Printf("KES period:  %d\n", opCert.KesPeriod)
		fmt.Printf("Signature:   %x\n", opCert.ColdSignature)
	}

	return nil
}

// keyEnvelope represents a JSON key file envelope
type keyEnvelope struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	CborHex     string `json:"cborHex"`
}

// parseVerificationKey parses a verification key from various formats
func parseVerificationKey(data []byte) ([]byte, error) {
	str := strings.TrimSpace(string(data))

	// Try JSON envelope first
	var env keyEnvelope
	if err := json.Unmarshal(data, &env); err == nil && env.CborHex != "" {
		cborData, err := hex.DecodeString(env.CborHex)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to decode cborHex from envelope: %w",
				err,
			)
		}
		// Decode CBOR to extract raw key bytes
		// cardano-cli uses simple CBOR byte string encoding
		var keyBytes []byte
		if _, err := cbor.Decode(cborData, &keyBytes); err == nil {
			if len(keyBytes) == 32 {
				return keyBytes, nil
			}
			return nil, fmt.Errorf(
				"invalid key length in envelope: got %d, expected 32",
				len(keyBytes),
			)
		}
		// Try array structure: [0, key_bytes] for some key types
		var decoded []any
		if _, err := cbor.Decode(cborData, &decoded); err == nil {
			if len(decoded) == 2 {
				if keyBytes, ok := decoded[1].([]byte); ok {
					if len(keyBytes) == 32 {
						return keyBytes, nil
					}
				}
			}
		}
		// If CBOR structure doesn't match, try using raw bytes
		if len(cborData) == 32 {
			return cborData, nil
		}
		return nil, errors.New(
			"invalid CBOR structure in key envelope",
		)
	}

	// Try bech32 - only accept KES verification keys for operational certificates
	if strings.HasPrefix(str, "kes_vk") {
		_, decoded, err := bech32.Decode(str)
		if err != nil {
			return nil, fmt.Errorf("failed to decode bech32: %w", err)
		}
		key, err := bech32.ConvertBits(decoded, 5, 8, false)
		if err != nil {
			return nil, fmt.Errorf("failed to convert bits: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf(
				"invalid bech32 key length: got %d bytes, expected 32",
				len(key),
			)
		}
		return key, nil
	}

	// Try hex
	key, err := hex.DecodeString(str)
	if err == nil && len(key) == 32 {
		return key, nil
	}

	return nil, errors.New(
		"invalid verification key format (expected JSON envelope, bech32, " +
			"or 32-byte hex)",
	)
}

// parseSigningKey parses a signing key from various formats
func parseSigningKey(data []byte) ([]byte, error) {
	str := strings.TrimSpace(string(data))

	// Try JSON envelope first
	var env keyEnvelope
	if err := json.Unmarshal(data, &env); err == nil && env.CborHex != "" {
		cborData, err := hex.DecodeString(env.CborHex)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to decode cborHex from envelope: %w",
				err,
			)
		}
		// Decode CBOR to extract raw key bytes
		// Extended signing keys are CBOR-encoded as raw bytes
		var keyBytes []byte
		if _, err := cbor.Decode(cborData, &keyBytes); err == nil {
			// Extended key: 64 bytes (32 seed + 32 chain code)
			// Non-extended key: 32 bytes
			if len(keyBytes) == 64 {
				return keyBytes[:32], nil
			}
			if len(keyBytes) == 32 {
				return keyBytes, nil
			}
			return nil, fmt.Errorf(
				"invalid key length in envelope: got %d, expected 32 or 64",
				len(keyBytes),
			)
		}
		// If direct CBOR decode fails, try using raw bytes
		if len(cborData) == 64 {
			return cborData[:32], nil
		}
		if len(cborData) == 32 {
			return cborData, nil
		}
		return nil, errors.New(
			"invalid CBOR structure in signing key envelope",
		)
	}

	// Try bech32
	if strings.HasPrefix(str, "pool_xsk") || strings.HasPrefix(str, "pool_sk") {
		_, decoded, err := bech32.Decode(str)
		if err != nil {
			return nil, fmt.Errorf("failed to decode bech32: %w", err)
		}
		key, err := bech32.ConvertBits(decoded, 5, 8, false)
		if err != nil {
			return nil, fmt.Errorf("failed to convert bits: %w", err)
		}
		// Validate and extract the 32-byte seed from extended keys
		if len(key) == 64 {
			return key[:32], nil
		}
		if len(key) == 32 {
			return key, nil
		}
		return nil, fmt.Errorf(
			"invalid bech32 key length: got %d bytes, expected 32 or 64",
			len(key),
		)
	}

	// Try hex
	key, err := hex.DecodeString(str)
	if err == nil && (len(key) == 32 || len(key) == 64) {
		if len(key) == 64 {
			return key[:32], nil
		}
		return key, nil
	}

	return nil, errors.New(
		"invalid signing key format (expected JSON envelope, bech32, " +
			"or 32/64-byte hex)",
	)
}

// encodeOpCertCBOR encodes an operational certificate to CBOR hex
func encodeOpCertCBOR(
	opCert *bursa.OperationalCertificate,
) (string, error) {
	// OpCert CBOR: [kes_vkey, counter, kes_period, signature]
	certData := []any{
		opCert.KesVkey,
		opCert.IssueNumber,
		opCert.KesPeriod,
		opCert.ColdSignature,
	}
	cborBytes, err := cbor.Encode(certData)
	if err != nil {
		return "", fmt.Errorf("failed to encode certificate to CBOR: %w", err)
	}
	return hex.EncodeToString(cborBytes), nil
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
