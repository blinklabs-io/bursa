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
	"github.com/blinklabs-io/bursa/internal/txbuilder"
	"github.com/spf13/cobra"
)

func txCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tx",
		Short: "Offline transaction operations (sign, witness, assemble)",
	}
	cmd.AddCommand(txSignCommand(), txWitnessCommand(), txAssembleCommand(), txIdCommand(), txDecodeCommand(), txBuildCommand(), txSubmitCommand())
	return cmd
}

func txSignCommand() *cobra.Command {
	var txFile, era string
	var signingKeyFiles []string
	var outFile string
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a transaction with one or more signing keys",
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunTxSign(txFile, signingKeyFiles, outFile, era); err != nil {
				logging.GetLogger().Error("failed to sign transaction", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&txFile, "tx-file", "", "Path to the transaction (hex CBOR or JSON envelope)")
	cmd.Flags().StringArrayVar(&signingKeyFiles, "signing-key-file", nil, "Signing key file (repeatable)")
	cmd.Flags().StringVar(&era, "era", "", "Transaction era (e.g. babbage, conway); required when the input does not name its era and its CBOR is valid in more than one")
	cmd.Flags().StringVar(&outFile, "out-file", "", "Output file (default: stdout)")
	_ = cmd.MarkFlagRequired("tx-file")
	_ = cmd.MarkFlagRequired("signing-key-file")
	return cmd
}

func txWitnessCommand() *cobra.Command {
	var txFile, signingKeyFile, outFile, era string
	cmd := &cobra.Command{
		Use:   "witness",
		Short: "Produce a detached vkey witness for a transaction",
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunTxWitness(txFile, signingKeyFile, outFile, era); err != nil {
				logging.GetLogger().Error("failed to create witness", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&txFile, "tx-file", "", "Path to the transaction (hex CBOR or JSON envelope)")
	cmd.Flags().StringVar(&signingKeyFile, "signing-key-file", "", "Signing key file")
	cmd.Flags().StringVar(&era, "era", "", "Transaction era (e.g. babbage, conway); required when the input does not name its era and its CBOR is valid in more than one")
	cmd.Flags().StringVar(&outFile, "out-file", "", "Output file (default: stdout)")
	_ = cmd.MarkFlagRequired("tx-file")
	_ = cmd.MarkFlagRequired("signing-key-file")
	return cmd
}

func txAssembleCommand() *cobra.Command {
	var txFile, era string
	var witnessFiles []string
	var outFile string
	cmd := &cobra.Command{
		Use:   "assemble",
		Short: "Merge detached witnesses into a transaction",
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunTxAssemble(txFile, witnessFiles, outFile, era); err != nil {
				logging.GetLogger().Error("failed to assemble transaction", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&txFile, "tx-file", "", "Path to the transaction (hex CBOR or JSON envelope)")
	cmd.Flags().StringArrayVar(&witnessFiles, "witness-file", nil, "Witness file (repeatable)")
	cmd.Flags().StringVar(&era, "era", "", "Transaction era (e.g. babbage, conway); required when the input does not name its era and its CBOR is valid in more than one")
	cmd.Flags().StringVar(&outFile, "out-file", "", "Output file (default: stdout)")
	_ = cmd.MarkFlagRequired("tx-file")
	_ = cmd.MarkFlagRequired("witness-file")
	return cmd
}

func txIdCommand() *cobra.Command {
	var txFile string
	cmd := &cobra.Command{
		Use:   "id",
		Short: "Print the transaction id (hex) of a transaction",
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunTxId(txFile); err != nil {
				logging.GetLogger().Error("failed to compute transaction id", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&txFile, "tx-file", "", "Path to the transaction (hex CBOR or JSON envelope)")
	_ = cmd.MarkFlagRequired("tx-file")
	return cmd
}

func txDecodeCommand() *cobra.Command {
	var txFile, protocolParamsFile string
	var witnessCount, byronWitnessCount uint
	cmd := &cobra.Command{
		Use:   "decode",
		Short: "Decode and inspect a transaction (optionally estimate min fee)",
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunTxDecode(txFile, protocolParamsFile, witnessCount, byronWitnessCount); err != nil {
				logging.GetLogger().Error("failed to decode transaction", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&txFile, "tx-file", "", "Path to the transaction (hex CBOR or JSON envelope)")
	cmd.Flags().StringVar(&protocolParamsFile, "protocol-params", "", "cardano-cli protocol-parameters.json for min-fee estimate")
	cmd.Flags().UintVar(&witnessCount, "witness-count", 0, "Vkey witnesses still to be added; the min-fee estimate includes their encoded size")
	cmd.Flags().UintVar(&byronWitnessCount, "byron-witness-count", 0, "Bootstrap witnesses still to be added; the min-fee estimate includes their encoded size")
	_ = cmd.MarkFlagRequired("tx-file")
	return cmd
}

func txBuildCommand() *cobra.Command {
	var socketPath, network, changeAddress, outFile string
	var certificateFiles []string
	var witnessCount uint
	var ttlMargin uint64
	var timeout int64
	var vote cli.PoolVoteFlags
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build a pool operation transaction",
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunTxBuild(socketPath, network, changeAddress, certificateFiles, witnessCount, outFile, ttlMargin, timeout, vote); err != nil {
				logging.GetLogger().Error("failed to build transaction", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket-path", "", "Path to node socket")
	cmd.Flags().StringVar(&network, "network", "", "Network name or magic")
	cmd.Flags().StringVar(&changeAddress, "change-address", "", "Change address")
	cmd.Flags().StringArrayVar(&certificateFiles, "certificate-file", nil, "Certificate file (repeatable)")
	cmd.Flags().UintVar(&witnessCount, "witness-count", 0, "Number of keys that will sign; computed from the inputs, certificates and votes when omitted or 0")
	cmd.Flags().StringVar(&outFile, "out-file", "", "Output file (default: stdout)")
	cmd.Flags().Uint64Var(&ttlMargin, "ttl-margin", txbuilder.DefaultTTLMargin, "Slots the transaction stays valid for")
	cmd.Flags().Int64Var(&timeout, "timeout", 60, "Timeout in seconds")
	cmd.Flags().StringVar(&vote.PoolID, "vote-pool-id", "", "Stake pool ID (bech32 pool1... or 56-hex key hash)")
	cmd.Flags().StringVar(&vote.GovAction, "vote-gov-action", "", "Governance action as <txid>#<index>")
	cmd.Flags().StringVar(&vote.Vote, "vote", "", "Vote (yes|no|abstain)")
	cmd.Flags().StringVar(&vote.AnchorURL, "vote-anchor-url", "", "Vote anchor URL")
	cmd.Flags().StringVar(&vote.AnchorHash, "vote-anchor-hash", "", "Vote anchor hash (32 bytes hex)")
	_ = cmd.MarkFlagRequired("socket-path")
	_ = cmd.MarkFlagRequired("network")
	_ = cmd.MarkFlagRequired("change-address")
	return cmd
}

func txSubmitCommand() *cobra.Command {
	var socketPath, network, txFile string
	var timeout int64
	cmd := &cobra.Command{
		Use:   "submit",
		Short: "Submit a transaction",
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunTxSubmit(socketPath, network, txFile, timeout); err != nil {
				logging.GetLogger().Error("failed to submit transaction", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket-path", "", "Path to node socket")
	cmd.Flags().StringVar(&network, "network", "", "Network name or magic")
	cmd.Flags().StringVar(&txFile, "tx-file", "", "Transaction file")
	cmd.Flags().Int64Var(&timeout, "timeout", 60, "Timeout in seconds")
	_ = cmd.MarkFlagRequired("socket-path")
	_ = cmd.MarkFlagRequired("network")
	_ = cmd.MarkFlagRequired("tx-file")
	return cmd
}
