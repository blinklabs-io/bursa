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

func addressCommand() *cobra.Command {
	addressCmd := cobra.Command{
		Use:   "address",
		Short: "Address utility commands",
		Long: `Commands for working with Cardano addresses.

Supports all CIP-0019 address types including base, enterprise, pointer,
reward, and legacy Byron addresses.

Examples:
  bursa address info addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer...
  bursa address info stake1uy9ggsc9qls4pu46g9...`,
	}

	addressCmd.AddCommand(
		addressInfoCommand(),
		addressBuildCommand(),
		addressEnterpriseCommand(),
	)
	return &addressCmd
}

func addressInfoCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "info <address>",
		Short: "Display information about a Cardano address",
		Long: `Parses a Cardano address and displays its components.

Supports all CIP-0019 address types:
  - Base addresses (payment + stake credentials)
  - Enterprise addresses (payment only)
  - Pointer addresses (payment + stake pointer)
  - Reward addresses (stake only)
  - Byron/Bootstrap addresses (legacy)

Credentials are displayed in both bech32 and hex formats.

Examples:
  bursa address info addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer...
  bursa address info addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jh...
  bursa address info stake1uy9ggsc9qls4pu46g9...`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunAddressInfo(args[0]); err != nil {
				logging.GetLogger().
					Error("failed to parse address", "error", err)
				os.Exit(1)
			}
		},
	}

	return &cmd
}

func addressBuildCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "build",
		Short: "Build a Cardano address from verification keys",
		Long: `Builds a Cardano address from verification keys.

Supports building base, enterprise, and reward addresses.

Examples:
  bursa address build --payment-key addr_vk1... --stake-key stake_vk1... --network mainnet
  bursa address build --payment-key addr_vk1... --network mainnet --type enterprise
  bursa address build --stake-key stake_vk1... --network mainnet --type reward`,
		Run: func(cmd *cobra.Command, args []string) {
			paymentKey, _ := cmd.Flags().GetString("payment-key")
			stakeKey, _ := cmd.Flags().GetString("stake-key")
			network, _ := cmd.Flags().GetString("network")
			addrType, _ := cmd.Flags().GetString("type")

			if err := cli.RunAddressBuild(paymentKey, stakeKey, network, addrType); err != nil {
				logging.GetLogger().
					Error("failed to build address", "error", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().
		String("payment-key", "", "Bech32-encoded payment verification key")
	cmd.Flags().String("stake-key", "", "Bech32-encoded stake verification key")
	cmd.Flags().String("network", "mainnet", "Network (mainnet or testnet)")
	cmd.Flags().
		String("type", "base", "Address type (base, enterprise, reward)")

	if err := cmd.MarkFlagRequired("network"); err != nil {
		panic(err)
	}

	return &cmd
}

func addressEnterpriseCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "enterprise",
		Short: "Generate enterprise (payment-only) address",
		Long: `Generate an enterprise address from a payment verification key.

Enterprise addresses contain only a payment credential and no stake credential.
They are useful for simple payments without staking delegation.

Examples:
  bursa address enterprise --payment-key addr_vk1... --network mainnet
  bursa address enterprise --payment-key-file payment.vkey --network testnet`,
		Run: func(cmd *cobra.Command, args []string) {
			paymentKey, _ := cmd.Flags().GetString("payment-key")
			paymentKeyFile, _ := cmd.Flags().GetString("payment-key-file")
			network, _ := cmd.Flags().GetString("network")

			if err := cli.RunAddressEnterprise(paymentKey, paymentKeyFile, network); err != nil {
				logging.GetLogger().
					Error("failed to generate enterprise address", "error", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().
		String("payment-key", "", "Bech32-encoded payment verification key")
	cmd.Flags().
		String("payment-key-file", "", "Path to payment verification key file")
	cmd.Flags().String("network", "mainnet", "Network (mainnet or testnet)")

	if err := cmd.MarkFlagRequired("network"); err != nil {
		panic(err)
	}
	cmd.MarkFlagsMutuallyExclusive("payment-key", "payment-key-file")

	return &cmd
}
