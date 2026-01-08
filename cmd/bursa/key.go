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

package main

import (
	"os"

	"github.com/blinklabs-io/bursa/internal/cli"
	"github.com/blinklabs-io/bursa/internal/logging"
	"github.com/spf13/cobra"
)

func keyCommand() *cobra.Command {
	keyCommand := cobra.Command{
		Use:   "key",
		Short: "Key derivation commands",
		Long: `Commands for deriving individual keys from a mnemonic.

These commands follow CIP-1852 key derivation paths and output keys
in bech32 format suitable for use with cardano-cli and other tools.

Key derivation hierarchy:
  mnemonic -> root -> account -> payment/stake

Examples:
  bursa key root --mnemonic "word1 word2 ..."
  bursa key account --mnemonic "word1 word2 ..." --index 0
  bursa key payment --mnemonic "word1 word2 ..."
  bursa key stake --mnemonic "word1 word2 ..."`,
	}

	keyCommand.AddCommand(
		keyRootCommand(),
		keyAccountCommand(),
		keyPaymentCommand(),
		keyStakeCommand(),
	)
	return &keyCommand
}

func keyRootCommand() *cobra.Command {
	var mnemonic string
	var mnemonicFile string
	var password string

	cmd := cobra.Command{
		Use:   "root",
		Short: "Derive root key from mnemonic",
		Long: `Derives the root extended private key from a BIP-39 mnemonic.

The root key is the master key from which all other keys are derived.
Output is in bech32 format (root_xsk prefix).

The mnemonic can be provided via:
  1. --mnemonic flag
  2. MNEMONIC environment variable
  3. --mnemonic-file flag
  4. Default file "seed.txt"

Examples:
  bursa key root --mnemonic "word1 word2 ... word24"
  bursa key root --mnemonic-file seed.txt
  bursa key root --password "optional"`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunKeyRoot(
				mnemonic,
				mnemonicFile,
				password,
			); err != nil {
				logging.GetLogger().
					Error("failed to derive root key", "error", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVar(&mnemonic, "mnemonic", "", "BIP-39 mnemonic phrase")
	cmd.Flags().StringVar(
		&mnemonicFile,
		"mnemonic-file",
		"",
		"Path to file containing mnemonic (default: seed.txt)",
	)
	cmd.Flags().StringVar(
		&password,
		"password",
		"",
		"Optional password for key derivation",
	)

	return &cmd
}

func keyAccountCommand() *cobra.Command {
	var mnemonic string
	var mnemonicFile string
	var password string
	var index uint32

	cmd := cobra.Command{
		Use:   "account",
		Short: "Derive account key from mnemonic",
		Long: `Derives an account extended private key from a BIP-39 mnemonic.

The account key follows CIP-1852 path: m/1852'/1815'/account'
Output is in bech32 format (acct_xsk prefix).

Examples:
  bursa key account --mnemonic "word1 word2 ... word24"
  bursa key account --mnemonic "word1 word2 ..." --index 1
  bursa key account --mnemonic-file seed.txt --index 0`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunKeyAccount(
				mnemonic,
				mnemonicFile,
				password,
				index,
			); err != nil {
				logging.GetLogger().Error(
					"failed to derive account key",
					"error",
					err,
				)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVar(&mnemonic, "mnemonic", "", "BIP-39 mnemonic phrase")
	cmd.Flags().StringVar(
		&mnemonicFile,
		"mnemonic-file",
		"",
		"Path to file containing mnemonic (default: seed.txt)",
	)
	cmd.Flags().StringVar(
		&password,
		"password",
		"",
		"Optional password for key derivation",
	)
	cmd.Flags().Uint32Var(&index, "index", 0, "Account index (default: 0)")

	return &cmd
}

func keyPaymentCommand() *cobra.Command {
	var mnemonic string
	var mnemonicFile string
	var password string
	var accountIndex uint32
	var paymentIndex uint32

	cmd := cobra.Command{
		Use:   "payment",
		Short: "Derive payment key from mnemonic",
		Long: `Derives a payment extended private key from a BIP-39 mnemonic.

The payment key follows CIP-1852 path: m/1852'/1815'/account'/0/index
Output is in bech32 format (addr_xsk prefix).

Examples:
  bursa key payment --mnemonic "word1 word2 ... word24"
  bursa key payment --mnemonic "word1 word2 ..." --account-index 0 --index 0
  bursa key payment --mnemonic-file seed.txt`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunKeyPayment(
				mnemonic,
				mnemonicFile,
				password,
				accountIndex,
				paymentIndex,
			); err != nil {
				logging.GetLogger().Error(
					"failed to derive payment key",
					"error",
					err,
				)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVar(&mnemonic, "mnemonic", "", "BIP-39 mnemonic phrase")
	cmd.Flags().StringVar(
		&mnemonicFile,
		"mnemonic-file",
		"",
		"Path to file containing mnemonic (default: seed.txt)",
	)
	cmd.Flags().StringVar(
		&password,
		"password",
		"",
		"Optional password for key derivation",
	)
	cmd.Flags().Uint32Var(
		&accountIndex,
		"account-index",
		0,
		"Account index (default: 0)",
	)
	cmd.Flags().
		Uint32Var(&paymentIndex, "index", 0, "Payment key index (default: 0)")

	return &cmd
}

func keyStakeCommand() *cobra.Command {
	var mnemonic string
	var mnemonicFile string
	var password string
	var accountIndex uint32
	var stakeIndex uint32

	cmd := cobra.Command{
		Use:   "stake",
		Short: "Derive stake key from mnemonic",
		Long: `Derives a stake extended private key from a BIP-39 mnemonic.

The stake key follows CIP-1852 path: m/1852'/1815'/account'/2/index
Output is in bech32 format (stake_xsk prefix).

Examples:
  bursa key stake --mnemonic "word1 word2 ... word24"
  bursa key stake --mnemonic "word1 word2 ..." --account-index 0 --index 0
  bursa key stake --mnemonic-file seed.txt`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunKeyStake(
				mnemonic,
				mnemonicFile,
				password,
				accountIndex,
				stakeIndex,
			); err != nil {
				logging.GetLogger().Error(
					"failed to derive stake key",
					"error",
					err,
				)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVar(&mnemonic, "mnemonic", "", "BIP-39 mnemonic phrase")
	cmd.Flags().StringVar(
		&mnemonicFile,
		"mnemonic-file",
		"",
		"Path to file containing mnemonic (default: seed.txt)",
	)
	cmd.Flags().StringVar(
		&password,
		"password",
		"",
		"Optional password for key derivation",
	)
	cmd.Flags().Uint32Var(
		&accountIndex,
		"account-index",
		0,
		"Account index (default: 0)",
	)
	cmd.Flags().
		Uint32Var(&stakeIndex, "index", 0, "Stake key index (default: 0)")

	return &cmd
}
