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

func certCommand() *cobra.Command {
	certCommand := cobra.Command{
		Use:   "cert",
		Short: "Certificate generation commands",
		Long: `Commands for generating various Cardano certificates.

These commands create certificates for stake pool operations,
stake delegation, and Conway era governance.

Certificate types:
  op-cert    - Operational certificate for block production

Examples:
  bursa cert op-cert --kes-vkey kes.vkey --cold-skey cold.skey \
    --counter 0 --kes-period 200 --out node.cert`,
	}

	certCommand.AddCommand(
		certOpCertCommand(),
	)
	return &certCommand
}

func certOpCertCommand() *cobra.Command {
	var kesVkeyFile string
	var coldSkeyFile string
	var outputFile string
	var counter uint64
	var kesPeriod uint64

	cmd := cobra.Command{
		Use:   "op-cert",
		Short: "Generate an operational certificate",
		Long: `Generates an operational certificate linking a KES key to a pool cold key.

The operational certificate is required for stake pool block production.
It binds the hot (KES) key to the cold key identity of the pool.

Required inputs:
  --kes-vkey    KES verification key file (bech32 or hex format)
  --cold-skey   Pool cold signing key file (bech32 or hex format)
  --counter     Certificate sequence number (must increment with each new cert)
  --kes-period  KES period at certificate creation time

The counter value must be incremented each time a new operational certificate
is created. The KES period is the current slot divided by the slots per KES
period (typically 129600 slots = ~36 hours on mainnet).

Output format is compatible with cardano-cli operational certificates.

Examples:
  # Generate op-cert with explicit KES period
  bursa cert op-cert --kes-vkey kes.vkey --cold-skey cold.skey \
    --counter 0 --kes-period 200 --out node.cert

  # Generate op-cert output to stdout
  bursa cert op-cert --kes-vkey kes.vkey --cold-skey cold.skey \
    --counter 1 --kes-period 201`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunCertOpCert(
				kesVkeyFile,
				coldSkeyFile,
				outputFile,
				counter,
				kesPeriod,
			); err != nil {
				logging.GetLogger().Error(
					"failed to create operational certificate",
					"error",
					err,
				)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVar(
		&kesVkeyFile,
		"kes-vkey",
		"",
		"Path to KES verification key file",
	)
	cmd.Flags().StringVar(
		&coldSkeyFile,
		"cold-skey",
		"",
		"Path to pool cold signing key file",
	)
	cmd.Flags().StringVarP(
		&outputFile,
		"out",
		"o",
		"",
		"Output file for certificate (stdout if not specified)",
	)
	cmd.Flags().Uint64Var(
		&counter,
		"counter",
		0,
		"Operational certificate sequence number",
	)
	cmd.Flags().Uint64Var(
		&kesPeriod,
		"kes-period",
		0,
		"KES period at certificate creation",
	)

	// Mark required flags
	_ = cmd.MarkFlagRequired("kes-vkey")
	_ = cmd.MarkFlagRequired("cold-skey")
	_ = cmd.MarkFlagRequired("counter")
	_ = cmd.MarkFlagRequired("kes-period")

	return &cmd
}
