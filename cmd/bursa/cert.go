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
  op-cert               - Operational certificate for block production
  pool-registration     - Pool registration certificate
  pool-retirement       - Pool retirement certificate
  stake-registration    - Stake address registration
  stake-deregistration  - Stake address deregistration
  stake-delegation      - Stake delegation to a pool
  drep-registration     - DRep registration (Conway)
  drep-deregistration   - DRep deregistration (Conway)
  vote-delegation       - Vote delegation (Conway)
  committee-hot-auth    - Committee hot key auth (Conway)
  committee-cold-resign - Committee cold key resign (Conway)

Examples:
  bursa cert op-cert --kes-vkey kes.vkey --cold-skey cold.skey \
    --counter 0 --kes-period 200 --out node.cert
  bursa cert pool-registration --cold-vkey cold.vkey --vrf-vkey vrf.vkey \
    --pledge 500000000 --cost 340000000 --margin 0.05 \
    --reward-account stake1... --out pool-reg.cert
  bursa cert stake-registration --stake-vkey stake.vkey \
    --out stake-reg.cert
  bursa cert drep-registration --drep-vkey drep.vkey \
    --deposit 500000000 --out drep-reg.cert`,
	}

	certCommand.AddCommand(
		certOpCertCommand(),
		certPoolRegistrationCommand(),
		certPoolRetirementCommand(),
		certStakeRegistrationCommand(),
		certStakeDeregistrationCommand(),
		certStakeDelegationCommand(),
		certDRepRegistrationCommand(),
		certDRepDeregistrationCommand(),
		certVoteDelegationCommand(),
		certCommitteeHotAuthCommand(),
		certCommitteeColdResignCommand(),
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

func certStakeRegistrationCommand() *cobra.Command {
	var stakeVkeyFile string
	var outputFile string

	cmd := cobra.Command{
		Use:   "stake-registration",
		Short: "Create a stake address registration certificate",
		Long: `Creates a stake address registration certificate.

This certificate registers a stake address on-chain, which is
required before the stake key can be used for delegation or
reward withdrawal.

Output format is a cardano-cli compatible JSON text envelope.

Examples:
  bursa cert stake-registration \
    --stake-vkey stake.vkey --out stake-reg.cert`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunCertStakeRegistration(
				stakeVkeyFile,
				outputFile,
			); err != nil {
				logging.GetLogger().Error(
					"failed to create stake registration certificate",
					"error",
					err,
				)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVar(
		&stakeVkeyFile,
		"stake-vkey",
		"",
		"Path to stake verification key file",
	)
	cmd.Flags().StringVarP(
		&outputFile,
		"out",
		"o",
		"",
		"Output file for certificate (stdout if not specified)",
	)

	_ = cmd.MarkFlagRequired("stake-vkey")

	return &cmd
}

func certStakeDeregistrationCommand() *cobra.Command {
	var stakeVkeyFile string
	var outputFile string

	cmd := cobra.Command{
		Use:   "stake-deregistration",
		Short: "Create a stake address deregistration certificate",
		Long: `Creates a stake address deregistration certificate.

This certificate deregisters a stake address, returning the
deposit and removing the stake key from on-chain registration.

Output format is a cardano-cli compatible JSON text envelope.

Examples:
  bursa cert stake-deregistration \
    --stake-vkey stake.vkey --out stake-dereg.cert`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunCertStakeDeregistration(
				stakeVkeyFile,
				outputFile,
			); err != nil {
				logging.GetLogger().Error(
					"failed to create stake deregistration certificate",
					"error",
					err,
				)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVar(
		&stakeVkeyFile,
		"stake-vkey",
		"",
		"Path to stake verification key file",
	)
	cmd.Flags().StringVarP(
		&outputFile,
		"out",
		"o",
		"",
		"Output file for certificate (stdout if not specified)",
	)

	_ = cmd.MarkFlagRequired("stake-vkey")

	return &cmd
}

func certStakeDelegationCommand() *cobra.Command {
	var stakeVkeyFile string
	var poolID string
	var outputFile string

	cmd := cobra.Command{
		Use:   "stake-delegation",
		Short: "Create a stake delegation certificate",
		Long: `Creates a stake delegation certificate.

This certificate delegates stake from a stake key to a specific
stake pool identified by its pool ID (bech32 or hex format).

Output format is a cardano-cli compatible JSON text envelope.

Examples:
  bursa cert stake-delegation \
    --stake-vkey stake.vkey \
    --pool-id pool1... \
    --out stake-deleg.cert`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunCertStakeDelegation(
				stakeVkeyFile,
				poolID,
				outputFile,
			); err != nil {
				logging.GetLogger().Error(
					"failed to create stake delegation certificate",
					"error",
					err,
				)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVar(
		&stakeVkeyFile,
		"stake-vkey",
		"",
		"Path to stake verification key file",
	)
	cmd.Flags().StringVar(
		&poolID,
		"pool-id",
		"",
		"Pool ID (bech32 pool1... or hex)",
	)
	cmd.Flags().StringVarP(
		&outputFile,
		"out",
		"o",
		"",
		"Output file for certificate (stdout if not specified)",
	)

	_ = cmd.MarkFlagRequired("stake-vkey")
	_ = cmd.MarkFlagRequired("pool-id")

	return &cmd
}

func certDRepRegistrationCommand() *cobra.Command {
	var drepVkeyFile string
	var deposit uint64
	var anchorURL string
	var anchorHash string
	var outputFile string

	cmd := cobra.Command{
		Use:   "drep-registration",
		Short: "Create a DRep registration certificate (Conway)",
		Long: `Creates a DRep registration certificate for Conway era governance.

This certificate registers a Delegated Representative (DRep)
on-chain, which allows the DRep to receive vote delegations
and participate in governance actions.

A deposit amount in lovelace is required. An optional anchor
URL and hash can be provided for DRep metadata.

Output format is a cardano-cli compatible JSON text envelope.

Examples:
  # Register DRep without anchor
  bursa cert drep-registration \
    --drep-vkey drep.vkey \
    --deposit 500000000 \
    --out drep-reg.cert

  # Register DRep with anchor metadata
  bursa cert drep-registration \
    --drep-vkey drep.vkey \
    --deposit 500000000 \
    --anchor-url https://example.com/drep.json \
    --anchor-hash abc123... \
    --out drep-reg.cert`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunCertDRepRegistration(
				drepVkeyFile,
				outputFile,
				deposit,
				anchorURL,
				anchorHash,
			); err != nil {
				logging.GetLogger().Error(
					"failed to create DRep registration certificate",
					"error",
					err,
				)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVar(
		&drepVkeyFile,
		"drep-vkey",
		"",
		"Path to DRep verification key file",
	)
	cmd.Flags().Uint64Var(
		&deposit,
		"deposit",
		0,
		"Deposit amount in lovelace",
	)
	cmd.Flags().StringVar(
		&anchorURL,
		"anchor-url",
		"",
		"Optional anchor URL for DRep metadata",
	)
	cmd.Flags().StringVar(
		&anchorHash,
		"anchor-hash",
		"",
		"Optional anchor hash (required if anchor-url is set)",
	)
	cmd.Flags().StringVarP(
		&outputFile,
		"out",
		"o",
		"",
		"Output file for certificate (stdout if not specified)",
	)

	_ = cmd.MarkFlagRequired("drep-vkey")
	_ = cmd.MarkFlagRequired("deposit")

	return &cmd
}

func certDRepDeregistrationCommand() *cobra.Command {
	var drepVkeyFile string
	var depositRefund uint64
	var outputFile string

	cmd := cobra.Command{
		Use:   "drep-deregistration",
		Short: "Create a DRep deregistration certificate (Conway)",
		Long: `Creates a DRep deregistration (retirement) certificate.

This certificate deregisters a DRep from on-chain governance,
returning the deposit refund amount.

Output format is a cardano-cli compatible JSON text envelope.

Examples:
  bursa cert drep-deregistration \
    --drep-vkey drep.vkey \
    --deposit-refund 500000000 \
    --out drep-dereg.cert`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunCertDRepDeregistration(
				drepVkeyFile,
				outputFile,
				depositRefund,
			); err != nil {
				logging.GetLogger().Error(
					"failed to create DRep deregistration certificate",
					"error",
					err,
				)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVar(
		&drepVkeyFile,
		"drep-vkey",
		"",
		"Path to DRep verification key file",
	)
	cmd.Flags().Uint64Var(
		&depositRefund,
		"deposit-refund",
		0,
		"Deposit refund amount in lovelace",
	)
	cmd.Flags().StringVarP(
		&outputFile,
		"out",
		"o",
		"",
		"Output file for certificate (stdout if not specified)",
	)

	_ = cmd.MarkFlagRequired("drep-vkey")
	_ = cmd.MarkFlagRequired("deposit-refund")

	return &cmd
}

func certVoteDelegationCommand() *cobra.Command {
	var stakeVkeyFile string
	var drepVkeyHash string
	var drepID string
	var alwaysAbstain bool
	var alwaysNoConfidence bool
	var outputFile string

	cmd := cobra.Command{
		Use:   "vote-delegation",
		Short: "Create a vote delegation certificate (Conway)",
		Long: `Creates a vote delegation certificate for Conway era governance.

This certificate delegates voting power from a stake key to a
DRep, or to special voting options (always-abstain or
always-no-confidence).

Exactly one delegation target must be specified:
  --drep-vkey-hash       Delegate to a DRep by key hash (hex)
  --drep-id              Delegate to a DRep by ID (bech32 or hex)
  --always-abstain       Always abstain from voting
  --always-no-confidence Always vote no confidence

Output format is a cardano-cli compatible JSON text envelope.

Examples:
  # Delegate to a specific DRep
  bursa cert vote-delegation \
    --stake-vkey stake.vkey \
    --drep-id drep1... \
    --out vote-deleg.cert

  # Always abstain
  bursa cert vote-delegation \
    --stake-vkey stake.vkey \
    --always-abstain \
    --out vote-deleg.cert`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunCertVoteDelegation(
				stakeVkeyFile,
				drepVkeyHash,
				drepID,
				outputFile,
				alwaysAbstain,
				alwaysNoConfidence,
			); err != nil {
				logging.GetLogger().Error(
					"failed to create vote delegation certificate",
					"error",
					err,
				)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVar(
		&stakeVkeyFile,
		"stake-vkey",
		"",
		"Path to stake verification key file",
	)
	cmd.Flags().StringVar(
		&drepVkeyHash,
		"drep-vkey-hash",
		"",
		"DRep verification key hash (hex, 28 bytes)",
	)
	cmd.Flags().StringVar(
		&drepID,
		"drep-id",
		"",
		"DRep ID (bech32 drep1... or hex)",
	)
	cmd.Flags().BoolVar(
		&alwaysAbstain,
		"always-abstain",
		false,
		"Delegate to always-abstain",
	)
	cmd.Flags().BoolVar(
		&alwaysNoConfidence,
		"always-no-confidence",
		false,
		"Delegate to always-no-confidence",
	)
	cmd.Flags().StringVarP(
		&outputFile,
		"out",
		"o",
		"",
		"Output file for certificate (stdout if not specified)",
	)

	_ = cmd.MarkFlagRequired("stake-vkey")

	return &cmd
}

func certCommitteeHotAuthCommand() *cobra.Command {
	var coldVkeyFile string
	var hotVkeyFile string
	var outputFile string

	cmd := cobra.Command{
		Use:   "committee-hot-auth",
		Short: "Create a committee hot key authorization certificate (Conway)",
		Long: `Creates a constitutional committee hot key authorization certificate.

This certificate authorizes a hot key to act on behalf of a
committee cold key for governance voting. The cold key remains
offline while the hot key participates in governance.

Output format is a cardano-cli compatible JSON text envelope.

Examples:
  bursa cert committee-hot-auth \
    --cold-vkey cc-cold.vkey \
    --hot-vkey cc-hot.vkey \
    --out cc-hot-auth.cert`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunCertCommitteeHotAuth(
				coldVkeyFile,
				hotVkeyFile,
				outputFile,
			); err != nil {
				logging.GetLogger().Error(
					"failed to create committee hot auth certificate",
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
		"Path to committee cold verification key file",
	)
	cmd.Flags().StringVar(
		&hotVkeyFile,
		"hot-vkey",
		"",
		"Path to committee hot verification key file",
	)
	cmd.Flags().StringVarP(
		&outputFile,
		"out",
		"o",
		"",
		"Output file for certificate (stdout if not specified)",
	)

	_ = cmd.MarkFlagRequired("cold-vkey")
	_ = cmd.MarkFlagRequired("hot-vkey")

	return &cmd
}

func certCommitteeColdResignCommand() *cobra.Command {
	var coldVkeyFile string
	var anchorURL string
	var anchorHash string
	var outputFile string

	cmd := cobra.Command{
		Use:   "committee-cold-resign",
		Short: "Create a committee cold key resignation certificate (Conway)",
		Long: `Creates a constitutional committee cold key resignation certificate.

This certificate resigns a committee member by their cold key.
An optional anchor URL and hash can be provided to reference
a rationale document.

Output format is a cardano-cli compatible JSON text envelope.

Examples:
  # Resign without anchor
  bursa cert committee-cold-resign \
    --cold-vkey cc-cold.vkey \
    --out cc-resign.cert

  # Resign with anchor rationale
  bursa cert committee-cold-resign \
    --cold-vkey cc-cold.vkey \
    --anchor-url https://example.com/resign.json \
    --anchor-hash abc123... \
    --out cc-resign.cert`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunCertCommitteeColdResign(
				coldVkeyFile,
				outputFile,
				anchorURL,
				anchorHash,
			); err != nil {
				logging.GetLogger().Error(
					"failed to create committee cold resign certificate",
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
		"Path to committee cold verification key file",
	)
	cmd.Flags().StringVar(
		&anchorURL,
		"anchor-url",
		"",
		"Optional anchor URL for resignation rationale",
	)
	cmd.Flags().StringVar(
		&anchorHash,
		"anchor-hash",
		"",
		"Optional anchor hash (required if anchor-url is set)",
	)
	cmd.Flags().StringVarP(
		&outputFile,
		"out",
		"o",
		"",
		"Output file for certificate (stdout if not specified)",
	)

	_ = cmd.MarkFlagRequired("cold-vkey")

	return &cmd
}
