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
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

const certTestStakeVkey = `{
  "type": "StakeVerificationKeyShelley_ed25519",
  "description": "Stake Verification Key",
  "cborHex": "5820839350412a3ec4d9aad93039bec2899562184b5ea9babb8595a6f127d48afb29"
}`

// runStakeCertCommand executes a stake certificate command with
// the given extra flags and returns the CBOR hex it wrote.
func runStakeCertCommand(
	t *testing.T,
	newCmd func() *cobra.Command,
	extra ...string,
) string {
	t.Helper()
	dir := t.TempDir()
	vkey := filepath.Join(dir, "stake.vkey")
	if err := os.WriteFile(vkey, []byte(certTestStakeVkey), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.cert")
	cmd := newCmd()
	cmd.SetArgs(append(
		[]string{"--stake-vkey", vkey, "--out", out}, extra...,
	))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]string
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope["cborHex"]
}

// certTestStakeCred is the CBOR stake credential [0, keyhash] for
// certTestStakeVkey. The Conway certificates below match
// cardano-cli 11.0 for the same key and deposit.
const certTestStakeCred = "8200581cd88b9f136cc94612ed33dd8774c6f43db347ae5814d8efd725d39313"

func TestCertStakeRegistrationDepositFlag(t *testing.T) {
	tests := []struct {
		name  string
		extra []string
		want  string
	}{
		{"absent", nil, "8200" + certTestStakeCred},
		{"zero", []string{"--deposit", "0"}, "8307" + certTestStakeCred + "00"},
		{"set", []string{"--deposit", "2000000"}, "8307" + certTestStakeCred + "1a001e8480"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := runStakeCertCommand(
				t, certStakeRegistrationCommand, tc.extra...,
			)
			if got != tc.want {
				t.Fatalf("cborHex %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCertStakeDeregistrationDepositRefundFlag(t *testing.T) {
	tests := []struct {
		name  string
		extra []string
		want  string
	}{
		{"absent", nil, "8201" + certTestStakeCred},
		{"zero", []string{"--deposit-refund", "0"}, "8308" + certTestStakeCred + "00"},
		{"set", []string{"--deposit-refund", "2000000"}, "8308" + certTestStakeCred + "1a001e8480"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := runStakeCertCommand(
				t, certStakeDeregistrationCommand, tc.extra...,
			)
			if got != tc.want {
				t.Fatalf("cborHex %s, want %s", got, tc.want)
			}
		})
	}
}
