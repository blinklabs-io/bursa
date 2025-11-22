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
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/logging"
	"github.com/spf13/cobra"
)

var output string

func walletCommand() *cobra.Command {
	walletCommand := cobra.Command{
		Use:   "wallet",
		Short: "Wallet commands",
	}

	walletCommand.AddCommand(
		walletCreateCommand(),
		walletLoadCommand(),
	)
	return &walletCommand
}

func walletCreateCommand() *cobra.Command {
	walletCreateCommand := cobra.Command{
		Use:   "create",
		Short: "Creates a new wallet",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.LoadConfig()
			if err != nil {
				logging.GetLogger().Error("failed to load config", "error", err)
				os.Exit(1)
			}
			cli.RunCreate(cfg, output)
		},
	}

	walletCreateCommand.PersistentFlags().
		StringVar(&output, "output", "", "optional path to write files")

	return &walletCreateCommand
}

func walletLoadCommand() *cobra.Command {
	var dir string
	var showSecrets bool

	walletLoadCommand := cobra.Command{
		Use:   "load",
		Short: "Loads and decodes wallet key files from a directory",
		Run: func(cmd *cobra.Command, args []string) {
			cli.RunLoad(dir, showSecrets)
		},
	}
	walletLoadCommand.Flags().StringVar(&dir, "dir", ".", "Directory containing wallet key files (Ex: *.vkey, *.skey)")
	walletLoadCommand.Flags().BoolVar(&showSecrets, "show-secrets", false, "Display private key hex values (use with caution)")

	return &walletLoadCommand
}
