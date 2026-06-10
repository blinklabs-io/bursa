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

func txCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tx",
		Short: "Offline transaction operations (sign, witness, assemble)",
	}
	cmd.AddCommand(txSignCommand(), txWitnessCommand(), txAssembleCommand(), txIdCommand(), txDecodeCommand())
	return cmd
}

func txSignCommand() *cobra.Command {
	var txFile string
	var signingKeyFiles []string
	var outFile string
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a transaction with one or more signing keys",
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunTxSign(txFile, signingKeyFiles, outFile); err != nil {
				logging.GetLogger().Error("failed to sign transaction", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&txFile, "tx-file", "", "Path to the transaction (hex CBOR or JSON envelope)")
	cmd.Flags().StringArrayVar(&signingKeyFiles, "signing-key-file", nil, "Signing key file (repeatable)")
	cmd.Flags().StringVar(&outFile, "out-file", "", "Output file (default: stdout)")
	_ = cmd.MarkFlagRequired("tx-file")
	_ = cmd.MarkFlagRequired("signing-key-file")
	return cmd
}

func txWitnessCommand() *cobra.Command {
	var txFile, signingKeyFile, outFile string
	cmd := &cobra.Command{
		Use:   "witness",
		Short: "Produce a detached vkey witness for a transaction",
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunTxWitness(txFile, signingKeyFile, outFile); err != nil {
				logging.GetLogger().Error("failed to create witness", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&txFile, "tx-file", "", "Path to the transaction (hex CBOR or JSON envelope)")
	cmd.Flags().StringVar(&signingKeyFile, "signing-key-file", "", "Signing key file")
	cmd.Flags().StringVar(&outFile, "out-file", "", "Output file (default: stdout)")
	_ = cmd.MarkFlagRequired("tx-file")
	_ = cmd.MarkFlagRequired("signing-key-file")
	return cmd
}

func txAssembleCommand() *cobra.Command {
	var txFile string
	var witnessFiles []string
	var outFile string
	cmd := &cobra.Command{
		Use:   "assemble",
		Short: "Merge detached witnesses into a transaction",
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunTxAssemble(txFile, witnessFiles, outFile); err != nil {
				logging.GetLogger().Error("failed to assemble transaction", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&txFile, "tx-file", "", "Path to the transaction (hex CBOR or JSON envelope)")
	cmd.Flags().StringArrayVar(&witnessFiles, "witness-file", nil, "Witness file (repeatable)")
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
	cmd := &cobra.Command{
		Use:   "decode",
		Short: "Decode and inspect a transaction (optionally estimate min fee)",
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunTxDecode(txFile, protocolParamsFile); err != nil {
				logging.GetLogger().Error("failed to decode transaction", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&txFile, "tx-file", "", "Path to the transaction (hex CBOR or JSON envelope)")
	cmd.Flags().StringVar(&protocolParamsFile, "protocol-params", "", "cardano-cli protocol-parameters.json for min-fee estimate")
	_ = cmd.MarkFlagRequired("tx-file")
	return cmd
}
