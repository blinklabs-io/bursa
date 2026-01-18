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
