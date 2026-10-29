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

func queryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query the ledger state",
	}
	cmd.AddCommand(queryPoolCommand(), queryStakeAddressCommand(), queryUtxoCommand(), queryTipCommand())
	return cmd
}

func queryPoolCommand() *cobra.Command {
	var socketPath, network, poolID, outFile string
	var timeout int64
	cmd := &cobra.Command{
		Use:   "pool",
		Short: "Query stake pool information",
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunQueryPool(socketPath, network, poolID, outFile, timeout); err != nil {
				logging.GetLogger().Error("failed to query pool", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket-path", "", "Path to node socket")
	cmd.Flags().StringVar(&network, "network", "", "Network name or magic")
	cmd.Flags().StringVar(&poolID, "pool-id", "", "Pool ID (bech32 pool1... or 56 hex)")
	cmd.Flags().StringVar(&outFile, "out-file", "", "Output file (default: stdout)")
	cmd.Flags().Int64Var(&timeout, "timeout", 60, "Timeout in seconds")
	_ = cmd.MarkFlagRequired("socket-path")
	_ = cmd.MarkFlagRequired("network")
	_ = cmd.MarkFlagRequired("pool-id")
	return cmd
}

func queryStakeAddressCommand() *cobra.Command {
	var socketPath, network, address, outFile string
	var timeout int64
	cmd := &cobra.Command{
		Use:   "stake-address",
		Short: "Query stake address information",
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunQueryStakeAddress(socketPath, network, address, outFile, timeout); err != nil {
				logging.GetLogger().Error("failed to query stake address", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket-path", "", "Path to node socket")
	cmd.Flags().StringVar(&network, "network", "", "Network name or magic")
	cmd.Flags().StringVar(&address, "address", "", "Stake address (stake1... or stake_test1...)")
	cmd.Flags().StringVar(&outFile, "out-file", "", "Output file (default: stdout)")
	cmd.Flags().Int64Var(&timeout, "timeout", 60, "Timeout in seconds")
	_ = cmd.MarkFlagRequired("socket-path")
	_ = cmd.MarkFlagRequired("network")
	_ = cmd.MarkFlagRequired("address")
	return cmd
}

func queryUtxoCommand() *cobra.Command {
	var socketPath, network, address, outFile string
	var timeout int64
	cmd := &cobra.Command{
		Use:   "utxo",
		Short: "Query UTxOs for an address",
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunQueryUtxo(socketPath, network, address, outFile, timeout); err != nil {
				logging.GetLogger().Error("failed to query utxo", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket-path", "", "Path to node socket")
	cmd.Flags().StringVar(&network, "network", "", "Network name or magic")
	cmd.Flags().StringVar(&address, "address", "", "Address")
	cmd.Flags().StringVar(&outFile, "out-file", "", "Output file (default: stdout)")
	cmd.Flags().Int64Var(&timeout, "timeout", 60, "Timeout in seconds")
	_ = cmd.MarkFlagRequired("socket-path")
	_ = cmd.MarkFlagRequired("network")
	_ = cmd.MarkFlagRequired("address")
	return cmd
}

func queryTipCommand() *cobra.Command {
	var socketPath, network, outFile string
	var timeout int64
	cmd := &cobra.Command{
		Use:   "tip",
		Short: "Query chain tip information",
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunQueryTip(socketPath, network, outFile, timeout); err != nil {
				logging.GetLogger().Error("failed to query tip", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket-path", "", "Path to node socket")
	cmd.Flags().StringVar(&network, "network", "", "Network name or magic")
	cmd.Flags().StringVar(&outFile, "out-file", "", "Output file (default: stdout)")
	cmd.Flags().Int64Var(&timeout, "timeout", 60, "Timeout in seconds")
	_ = cmd.MarkFlagRequired("socket-path")
	_ = cmd.MarkFlagRequired("network")
	return cmd
}
