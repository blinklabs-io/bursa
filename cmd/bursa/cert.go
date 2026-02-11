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
  op-cert            - Operational certificate for block production
  pool-registration  - Pool registration certificate
  pool-retirement    - Pool retirement certificate

Examples:
  bursa cert op-cert --kes-vkey kes.vkey --cold-skey cold.skey \
    --counter 0 --kes-period 200 --out node.cert
  bursa cert pool-registration --cold-vkey cold.vkey --vrf-vkey vrf.vkey \
    --pledge 500000000 --cost 340000000 --margin 0.05 \
    --reward-account stake1... --out pool-reg.cert
  bursa cert pool-retirement --cold-vkey cold.vkey --epoch 300 \
    --out pool-retire.cert`,
	}

	certCommand.AddCommand(
		certOpCertCommand(),
		certPoolRegistrationCommand(),
		certPoolRetirementCommand(),
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

func certPoolRegistrationCommand() *cobra.Command {
	var coldVkeyFile string
	var vrfVkeyFile string
	var pledge uint64
	var cost uint64
	var margin float64
	var rewardAccount string
	var metadataURL string
	var metadataHash string
	var outputFile string

	cmd := cobra.Command{
		Use:   "pool-registration",
		Short: "Generate a pool registration certificate",
		Long: `Generates a stake pool registration certificate.

The pool registration certificate registers a new stake pool or
updates an existing registration on the Cardano blockchain.

Required inputs:
  --cold-vkey       Pool cold verification key file
  --vrf-vkey        VRF verification key file
  --pledge          Pledge amount in lovelace
  --cost            Fixed cost per epoch in lovelace
  --margin          Pool margin (0.0 to 1.0)
  --reward-account  Reward account address (bech32 stake address)

Optional inputs:
  --metadata-url    Pool metadata URL
  --metadata-hash   Pool metadata hash (hex)

Output format is compatible with cardano-cli certificates.

Examples:
  bursa cert pool-registration \
    --cold-vkey cold.vkey --vrf-vkey vrf.vkey \
    --pledge 500000000 --cost 340000000 --margin 0.05 \
    --reward-account stake1... --out pool-reg.cert

  bursa cert pool-registration \
    --cold-vkey cold.vkey --vrf-vkey vrf.vkey \
    --pledge 1000000000 --cost 340000000 --margin 0.01 \
    --reward-account stake1... \
    --metadata-url "https://example.com/pool.json" \
    --metadata-hash "abc123..." --out pool-reg.cert`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunCertPoolRegistration(
				coldVkeyFile,
				vrfVkeyFile,
				rewardAccount,
				outputFile,
				pledge,
				cost,
				margin,
				metadataURL,
				metadataHash,
			); err != nil {
				logging.GetLogger().Error(
					"failed to create pool registration certificate",
					"error",
					err,
				)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVar(
		&coldVkeyFile,
		"cold-vkey",
		"",
		"Path to pool cold verification key file",
	)
	cmd.Flags().StringVar(
		&vrfVkeyFile,
		"vrf-vkey",
		"",
		"Path to VRF verification key file",
	)
	cmd.Flags().Uint64Var(
		&pledge,
		"pledge",
		0,
		"Pledge amount in lovelace",
	)
	cmd.Flags().Uint64Var(
		&cost,
		"cost",
		0,
		"Fixed cost per epoch in lovelace",
	)
	cmd.Flags().Float64Var(
		&margin,
		"margin",
		0,
		"Pool margin (0.0 to 1.0)",
	)
	cmd.Flags().StringVar(
		&rewardAccount,
		"reward-account",
		"",
		"Reward account address (bech32 stake address)",
	)
	cmd.Flags().StringVar(
		&metadataURL,
		"metadata-url",
		"",
		"Pool metadata URL (optional)",
	)
	cmd.Flags().StringVar(
		&metadataHash,
		"metadata-hash",
		"",
		"Pool metadata hash in hex (optional)",
	)
	cmd.Flags().StringVarP(
		&outputFile,
		"out",
		"o",
		"",
		"Output file for certificate (stdout if not specified)",
	)

	_ = cmd.MarkFlagRequired("cold-vkey")
	_ = cmd.MarkFlagRequired("vrf-vkey")
	_ = cmd.MarkFlagRequired("pledge")
	_ = cmd.MarkFlagRequired("cost")
	_ = cmd.MarkFlagRequired("margin")
	_ = cmd.MarkFlagRequired("reward-account")

	return &cmd
}

func certPoolRetirementCommand() *cobra.Command {
	var coldVkeyFile string
	var epoch uint64
	var outputFile string

	cmd := cobra.Command{
		Use:   "pool-retirement",
		Short: "Generate a pool retirement certificate",
		Long: `Generates a stake pool retirement certificate.

The pool retirement certificate signals that a stake pool will
retire at the specified epoch boundary.

Required inputs:
  --cold-vkey  Pool cold verification key file
  --epoch      Retirement epoch

Output format is compatible with cardano-cli certificates.

Examples:
  bursa cert pool-retirement --cold-vkey cold.vkey \
    --epoch 300 --out pool-retire.cert

  bursa cert pool-retirement --cold-vkey cold.vkey \
    --epoch 350`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunCertPoolRetirement(
				coldVkeyFile,
				outputFile,
				epoch,
			); err != nil {
				logging.GetLogger().Error(
					"failed to create pool retirement certificate",
					"error",
					err,
				)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVar(
		&coldVkeyFile,
		"cold-vkey",
		"",
		"Path to pool cold verification key file",
	)
	cmd.Flags().Uint64Var(
		&epoch,
		"epoch",
		0,
		"Retirement epoch",
	)
	cmd.Flags().StringVarP(
		&outputFile,
		"out",
		"o",
		"",
		"Output file for certificate (stdout if not specified)",
	)

	_ = cmd.MarkFlagRequired("cold-vkey")
	_ = cmd.MarkFlagRequired("epoch")

	return &cmd
}
