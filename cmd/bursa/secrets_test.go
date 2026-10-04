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
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func newSecretFlagsCommand() (cmd *cobra.Command, mnemonic, mnemonicFile, password *string) {
	mnemonic, mnemonicFile, password = new(string), new(string), new(string)
	cmd = &cobra.Command{Use: "x", Run: func(*cobra.Command, []string) {}}
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	addSecretFlags(cmd, mnemonic, mnemonicFile, password)
	return cmd, mnemonic, mnemonicFile, password
}

func TestSecretFlagsReadPasswordFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(path, []byte("s3 cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd, _, _, password := newSecretFlagsCommand()
	cmd.SetArgs([]string{"--password-file", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if *password != "s3 cret" {
		t.Fatalf("password %q, want %q", *password, "s3 cret")
	}
}

func TestSecretFlagsRejectConflictingInputs(t *testing.T) {
	t.Parallel()
	for name, args := range map[string][]string{
		"password and password-file": {"--password", "a", "--password-file", "b"},
		"both read stdin":            {"--mnemonic-file", "-", "--password-file", "-"},
	} {
		cmd, _, _, _ := newSecretFlagsCommand()
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// TestDerivationCommandsOfferSecretFiles checks every command that accepts a
// password or mnemonic argument also offers the file form and flags the
// argument as deprecated.
func TestDerivationCommandsOfferSecretFiles(t *testing.T) {
	t.Parallel()
	seen := 0
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, name := range []string{"mnemonic", "password"} {
			f := c.Flags().Lookup(name)
			if f == nil {
				continue
			}
			seen++
			if f.Deprecated == "" {
				t.Errorf("%s --%s is not deprecated", c.CommandPath(), name)
			}
		}
		if c.Flags().Lookup("password") != nil &&
			c.Flags().Lookup("password-file") == nil {
			t.Errorf("%s has --password but no --password-file", c.CommandPath())
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	for _, c := range []*cobra.Command{
		keyCommand(), addressCommand(), walletCommand(),
	} {
		walk(c)
	}
	if seen == 0 {
		t.Fatal("found no commands with secret flags; walk is broken")
	}
}
