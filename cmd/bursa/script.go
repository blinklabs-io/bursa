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
	"github.com/blinklabs-io/bursa/internal/cli"
	"github.com/spf13/cobra"
)

func scriptCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "script",
		Short: "Script commands for multi-signature operations",
	}

	cmd.AddCommand(
		scriptCreateCommand(),
		scriptValidateCommand(),
		scriptAddressCommand(),
	)
	return cmd
}

func scriptCreateCommand() *cobra.Command {
	var (
		required       int
		keyHashes      []string
		output         string
		network        string
		all            bool
		any            bool
		timelockBefore uint64
		timelockAfter  uint64
	)

	scriptCreateCommand := &cobra.Command{
		Use:   "create",
		Short: "Creates a new multi-signature script",
		Long: `Creates a new multi-signature script with the specified parameters.

Examples:
  # Create a 2-of-3 multi-sig script
  bursa script create --required 2 --key-hashes abcdef1234567890abcdef1234567890abcdef12,abcdef1234567890abcdef1234567890abcdef13,abcdef1234567890abcdef1234567890abcdef14

  # Create an all-signers-required script
  bursa script create --all --key-hashes abcdef1234567890abcdef1234567890abcdef12,abcdef1234567890abcdef1234567890abcdef13

  # Create an any-signer script
  bursa script create --any --key-hashes abcdef1234567890abcdef1234567890abcdef12,abcdef1234567890abcdef1234567890abcdef13,abcdef1234567890abcdef1234567890abcdef14

  # Create a timelocked script (valid after slot 1000000)
  bursa script create --required 2 --key-hashes abcdef1234567890abcdef1234567890abcdef12,abcdef1234567890abcdef1234567890abcdef13 --timelock-after 1000000`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunScriptCreate(
				required,
				keyHashes,
				output,
				network,
				all,
				any,
				timelockBefore,
				timelockAfter,
			)
		},
	}

	scriptCreateCommand.Flags().
		IntVar(&required, "required", 0, "Number of required signatures (for N-of-M scripts)")
	scriptCreateCommand.Flags().
		StringSliceVar(&keyHashes, "key-hashes", nil, "Comma-separated list of key hashes (hex encoded)")
	scriptCreateCommand.Flags().
		StringVar(&output, "output", "", "Output file path (optional)")
	scriptCreateCommand.Flags().
		StringVar(&network, "network", "mainnet", "Network name (mainnet, testnet, etc.)")
	scriptCreateCommand.Flags().
		BoolVar(&all, "all", false, "Create all-signers-required script")
	scriptCreateCommand.Flags().
		BoolVar(&any, "any", false, "Create any-signer script")
	scriptCreateCommand.Flags().
		Uint64Var(&timelockBefore, "timelock-before", 0, "Make script valid only before this slot")
	scriptCreateCommand.Flags().
		Uint64Var(&timelockAfter, "timelock-after", 0, "Make script valid only after this slot")

	if err := scriptCreateCommand.MarkFlagRequired("key-hashes"); err != nil {
		panic(err)
	}
	scriptCreateCommand.MarkFlagsOneRequired("required", "all", "any")
	scriptCreateCommand.MarkFlagsMutuallyExclusive("required", "all", "any")
	scriptCreateCommand.Args = cobra.NoArgs

	return scriptCreateCommand
}

func scriptValidateCommand() *cobra.Command {
	var (
		scriptFile     string
		signatures     []string
		slot           uint64
		structuralOnly bool
	)

	scriptValidateCommand := &cobra.Command{
		Use:   "validate",
		Short: "Validates a script against signatures and slot",
		Long: `Validates whether a script is satisfied given a set of signatures and current slot.

By default, performs format validation requiring signatures for signature scripts.
Use --structural-only for basic structure validation without signatures.

Examples:
  # Validate a script with signatures (hex-encoded signatures)
  bursa script validate --script script.json --signatures 0123ab...,4567cd... --slot 123456789

  # Validate a timelocked script
  bursa script validate --script script.json --slot 123456789 --structural-only

  # Perform structural validation only
  bursa script validate --script script.json --structural-only`,
		Run: func(cmd *cobra.Command, args []string) {
			cli.RunScriptValidate(scriptFile, signatures, slot, structuralOnly)
		},
	}

	scriptValidateCommand.Flags().
		StringVar(&scriptFile, "script", "", "Path to script file (required)")
	scriptValidateCommand.Flags().
		StringSliceVar(&signatures, "signatures", nil, "Comma-separated list of signatures (hex encoded)")
	scriptValidateCommand.Flags().
		Uint64Var(&slot, "slot", 0, "Current slot number for timelock validation")
	scriptValidateCommand.Flags().
		BoolVar(&structuralOnly, "structural-only", false, "Perform structural validation only (no signature format checking)")

	if err := scriptValidateCommand.MarkFlagRequired("script"); err != nil {
		panic(err)
	}
	scriptValidateCommand.Args = cobra.NoArgs

	return scriptValidateCommand
}

func scriptAddressCommand() *cobra.Command {
	var (
		scriptFile string
		network    string
	)

	scriptAddressCommand := &cobra.Command{
		Use:   "address",
		Short: "Generates an address from a script",
		Long: `Generates a Cardano address from a multi-signature script.

Examples:
  # Generate mainnet address from script
  bursa script address --script script.json --network mainnet

  # Generate testnet address from script
  bursa script address --script script.json --network testnet`,
		Run: func(cmd *cobra.Command, args []string) {
			cli.RunScriptAddress(scriptFile, network)
		},
	}

	scriptAddressCommand.Flags().
		StringVar(&scriptFile, "script", "", "Path to script file (required)")
	scriptAddressCommand.Flags().
		StringVar(&network, "network", "mainnet", "Network name (mainnet, testnet, etc.)")

	if err := scriptAddressCommand.MarkFlagRequired("script"); err != nil {
		panic(err)
	}
	scriptAddressCommand.Args = cobra.NoArgs

	return scriptAddressCommand
}
