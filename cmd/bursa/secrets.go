// Copyright 2026 Blink Labs Software
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
	"errors"

	"github.com/blinklabs-io/bursa/internal/cli"
	"github.com/spf13/cobra"
)

// addSecretFlags registers the mnemonic and password inputs shared by every
// derivation command. --mnemonic and --password stay for compatibility but are
// deprecated because process arguments are visible to other local users; the
// file flags accept "-" to read standard input.
func addSecretFlags(
	cmd *cobra.Command,
	mnemonic, mnemonicFile, password *string,
) {
	var passwordFile string
	flags := cmd.Flags()
	flags.StringVar(mnemonic, "mnemonic", "", "BIP-39 mnemonic phrase")
	flags.StringVar(
		mnemonicFile,
		"mnemonic-file",
		"",
		`Path to file containing mnemonic, or "-" for standard input (default: seed.txt)`,
	)
	flags.StringVar(password, "password", "", "Optional password for key derivation")
	flags.StringVar(
		&passwordFile,
		"password-file",
		"",
		`Path to file containing the derivation password, or "-" for standard input`,
	)
	_ = flags.MarkDeprecated("mnemonic", "process arguments are visible to other users; use --mnemonic-file")
	_ = flags.MarkDeprecated("password", "process arguments are visible to other users; use --password-file")
	cmd.MarkFlagsMutuallyExclusive("password", "password-file")

	cmd.PreRunE = func(*cobra.Command, []string) error {
		if passwordFile == "" {
			return nil
		}
		if passwordFile == "-" && *mnemonicFile == "-" {
			return errors.New(`--mnemonic-file and --password-file cannot both read standard input`)
		}
		value, err := cli.ReadSecretFile(passwordFile)
		if err != nil {
			return err
		}
		*password = value
		return nil
	}
}
