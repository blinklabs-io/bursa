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

Keys are derived following Cardano CIP standards and output in bech32 format
suitable for use with cardano-cli and other tools.

Derivation paths by key type:
  CIP-1852: root, account, payment, stake (m/1852'/1815'/...)
  CIP-1853: pool-cold (m/1853'/1815'/...)
  CIP-1855: policy (m/1855'/1815'/...)
  CIP-0105: drep, committee-cold, committee-hot (m/1852'/1815'/account'/role/...)

Examples:
  bursa key root --mnemonic "word1 word2 ..."
  bursa key account --mnemonic "word1 word2 ..." --index 0
  bursa key payment --mnemonic "word1 word2 ..."
  bursa key stake --mnemonic "word1 word2 ..."
  bursa key pool-cold --mnemonic "word1 word2 ..."
  bursa key policy --mnemonic "word1 word2 ..."
  bursa key drep --mnemonic "word1 word2 ..."
  bursa key committee-cold --mnemonic "word1 word2 ..."
  bursa key committee-hot --mnemonic "word1 word2 ..."`,
	}

	keyCommand.AddCommand(
		keyRootCommand(),
		keyAccountCommand(),
		keyPaymentCommand(),
		keyStakeCommand(),
		keyPolicyCommand(),
		keyPoolColdCommand(),
		keyVRFCommand(),
		keyKESCommand(),
		keyDRepCommand(),
		keyCommitteeColdCommand(),
		keyCommitteeHotCommand(),
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

func keyPolicyCommand() *cobra.Command {
	var mnemonic string
	var mnemonicFile string
	var password string
	var index uint32

	cmd := cobra.Command{
		Use:   "policy",
		Short: "Derive forging policy key from mnemonic",
		Long: `Derives a forging policy extended private key from a BIP-39 mnemonic.

The policy key follows CIP-1855 path: m/1855'/1815'/policy_ix'
These keys are used for native asset minting/burning policies.
Output is in bech32 format (policy_xsk prefix).

Examples:
  bursa key policy --mnemonic "word1 word2 ... word24"
  bursa key policy --mnemonic "word1 word2 ..." --index 0
  bursa key policy --mnemonic-file seed.txt --index 1`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunKeyPolicy(
				mnemonic,
				mnemonicFile,
				password,
				index,
			); err != nil {
				logging.GetLogger().Error(
					"failed to derive policy key",
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
	cmd.Flags().Uint32Var(&index, "index", 0, "Policy key index (default: 0)")

	return &cmd
}

func keyPoolColdCommand() *cobra.Command {
	var mnemonic string
	var mnemonicFile string
	var password string
	var index uint32

	cmd := cobra.Command{
		Use:   "pool-cold",
		Short: "Derive stake pool cold key from mnemonic",
		Long: `Derives a stake pool cold extended private key from a BIP-39 mnemonic.

The pool cold key follows CIP-1853 path: m/1853'/1815'/0'/index'
These keys are used as the long-term identity keys for stake pool operators.
Output is in bech32 format (pool_xsk prefix).

Examples:
  bursa key pool-cold --mnemonic "word1 word2 ... word24"
  bursa key pool-cold --mnemonic "word1 word2 ..." --index 0
  bursa key pool-cold --mnemonic-file seed.txt --index 1`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunKeyPoolCold(
				mnemonic,
				mnemonicFile,
				password,
				index,
			); err != nil {
				logging.GetLogger().Error(
					"failed to derive pool cold key",
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
	cmd.Flags().
		Uint32Var(&index, "index", 0, "Pool cold key index (default: 0)")

	return &cmd
}

func keyVRFCommand() *cobra.Command {
	var mnemonic string
	var mnemonicFile string
	var password string
	var index uint32

	cmd := cobra.Command{
		Use:   "vrf",
		Short: "Derive VRF key pair from mnemonic",
		Long: `Derives a VRF (Verifiable Random Function) key pair from a BIP-39 mnemonic.

VRF keys are used by stake pool operators for leader election in the Praos
consensus protocol. The seed is derived deterministically from the mnemonic,
allowing for key recovery.

Output includes both signing key (vrf_sk) and verification key (vrf_vk)
in bech32 format.

Examples:
  bursa key vrf --mnemonic "word1 word2 ... word24"
  bursa key vrf --mnemonic "word1 word2 ..." --index 0
  bursa key vrf --mnemonic-file seed.txt --index 1`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunKeyVRF(
				mnemonic,
				mnemonicFile,
				password,
				index,
			); err != nil {
				logging.GetLogger().Error(
					"failed to derive VRF key",
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
	cmd.Flags().Uint32Var(&index, "index", 0, "VRF key index (default: 0)")

	return &cmd
}

func keyKESCommand() *cobra.Command {
	var mnemonic string
	var mnemonicFile string
	var password string
	var index uint32

	cmd := cobra.Command{
		Use:   "kes",
		Short: "Derive KES key pair from mnemonic",
		Long: `Derives a KES (Key Evolving Signature) key pair from a BIP-39 mnemonic.

KES keys are used by stake pool operators for block signing in the Praos
consensus protocol. KES provides forward-secure signatures where compromising
the current key does not compromise past signatures.

This implementation uses Cardano's depth 6, providing 64 time periods.
The seed is derived deterministically from the mnemonic, allowing for key recovery.

Output includes both signing key (kes_sk, 608 bytes) and verification key
(kes_vk, 32 bytes) in bech32 format.

Examples:
  bursa key kes --mnemonic "word1 word2 ... word24"
  bursa key kes --mnemonic "word1 word2 ..." --index 0
  bursa key kes --mnemonic-file seed.txt --index 1`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunKeyKES(
				mnemonic,
				mnemonicFile,
				password,
				index,
			); err != nil {
				logging.GetLogger().Error(
					"failed to derive KES key",
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
	cmd.Flags().Uint32Var(&index, "index", 0, "KES key index (default: 0)")

	return &cmd
}

func keyDRepCommand() *cobra.Command {
	var mnemonic string
	var mnemonicFile string
	var password string
	var accountIndex uint32
	var index uint32

	cmd := cobra.Command{
		Use:   "drep",
		Short: "Derive DRep key from mnemonic",
		Long: `Derives a DRep (Delegated Representative) extended private key from a mnemonic.

The DRep key follows CIP-0105 path: m/1852'/1815'/account'/3/index
These keys are used for governance participation as a Delegated Representative.
Output is in bech32 format (drep_xsk prefix).

Examples:
  bursa key drep --mnemonic "word1 word2 ... word24"
  bursa key drep --mnemonic "word1 word2 ..." --account-index 0 --index 0
  bursa key drep --mnemonic-file seed.txt --index 1`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunKeyDRep(
				mnemonic,
				mnemonicFile,
				password,
				accountIndex,
				index,
			); err != nil {
				logging.GetLogger().Error(
					"failed to derive DRep key",
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
	cmd.Flags().Uint32Var(&index, "index", 0, "DRep key index (default: 0)")

	return &cmd
}

func keyCommitteeColdCommand() *cobra.Command {
	var mnemonic string
	var mnemonicFile string
	var password string
	var accountIndex uint32
	var index uint32

	cmd := cobra.Command{
		Use:   "committee-cold",
		Short: "Derive committee cold key from mnemonic",
		Long: `Derives a Constitutional Committee cold extended private key from a mnemonic.

The committee cold key follows CIP-0105 path: m/1852'/1815'/account'/4/index
These keys are used for Constitutional Committee membership (long-term identity).
Output is in bech32 format (cc_cold_xsk prefix).

Examples:
  bursa key committee-cold --mnemonic "word1 word2 ... word24"
  bursa key committee-cold --mnemonic "word1 word2 ..." --account-index 0 --index 0
  bursa key committee-cold --mnemonic-file seed.txt --index 1`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunKeyCommitteeCold(
				mnemonic,
				mnemonicFile,
				password,
				accountIndex,
				index,
			); err != nil {
				logging.GetLogger().Error(
					"failed to derive committee cold key",
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
		Uint32Var(&index, "index", 0, "Committee cold key index (default: 0)")

	return &cmd
}

func keyCommitteeHotCommand() *cobra.Command {
	var mnemonic string
	var mnemonicFile string
	var password string
	var accountIndex uint32
	var index uint32

	cmd := cobra.Command{
		Use:   "committee-hot",
		Short: "Derive committee hot key from mnemonic",
		Long: `Derives a Constitutional Committee hot extended private key from a mnemonic.

The committee hot key follows CIP-0105 path: m/1852'/1815'/account'/5/index
These keys are used for Constitutional Committee voting (operational key).
Output is in bech32 format (cc_hot_xsk prefix).

Examples:
  bursa key committee-hot --mnemonic "word1 word2 ... word24"
  bursa key committee-hot --mnemonic "word1 word2 ..." --account-index 0 --index 0
  bursa key committee-hot --mnemonic-file seed.txt --index 1`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunKeyCommitteeHot(
				mnemonic,
				mnemonicFile,
				password,
				accountIndex,
				index,
			); err != nil {
				logging.GetLogger().Error(
					"failed to derive committee hot key",
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
		Uint32Var(&index, "index", 0, "Committee hot key index (default: 0)")

	return &cmd
}
