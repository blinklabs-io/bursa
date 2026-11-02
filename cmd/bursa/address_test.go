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
	"io"
	"testing"

	"github.com/spf13/cobra"
)

func TestAddressListRejectsPositionalArgs(t *testing.T) {
	cmd := addressListCommand()
	cmd.SetArgs([]string{"mnemonic.txt"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected address list to reject positional args")
	}
}

func TestNetworkFlagHelpConsistent(t *testing.T) {
	const want = "Network name or numeric magic (mainnet, testnet, preprod, preview, sanchonet, dijkstra, musashi, prime-mainnet, prime-testnet, devnet)"
	commands := map[string]*cobra.Command{
		"address build":      addressBuildCommand(),
		"address enterprise": addressEnterpriseCommand(),
		"address list":       addressListCommand(),
		"script create":      scriptCreateCommand(),
		"script address":     scriptAddressCommand(),
	}
	for name, cmd := range commands {
		t.Run(name, func(t *testing.T) {
			flag := cmd.Flags().Lookup("network")
			if flag == nil {
				t.Fatal("network flag is missing")
			}
			if flag.Usage != want {
				t.Fatalf("network help = %q, want %q", flag.Usage, want)
			}
		})
	}
}
