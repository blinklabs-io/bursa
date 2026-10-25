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

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
)

func readEnvelopeType(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var env bursa.CborEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("parse envelope %s: %v", path, err)
	}
	return env.Type
}

func TestTxEnvelopesNameTheEra(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "payment.skey")
	keyJSON := `{"type":"PaymentSigningKeyShelley_ed25519",` +
		`"description":"Payment Signing Key",` +
		`"cborHex":"5820` + strings.Repeat("01", 32) + `"}`
	if err := os.WriteFile(keyFile, []byte(keyJSON), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	txFile := filepath.Join("..", "..", "testdata", "conway-unsigned.tx")

	signedFile := filepath.Join(dir, "signed.tx")
	if err := RunTxSign(txFile, []string{keyFile}, signedFile); err != nil {
		t.Fatalf("RunTxSign: %v", err)
	}
	if got := readEnvelopeType(t, signedFile); got != "Tx ConwayEra" {
		t.Errorf("sign envelope type = %q, want %q", got, "Tx ConwayEra")
	}

	witFile := filepath.Join(dir, "tx.witness")
	if err := RunTxWitness(txFile, keyFile, witFile); err != nil {
		t.Fatalf("RunTxWitness: %v", err)
	}
	if got := readEnvelopeType(t, witFile); got != "TxWitness ConwayEra" {
		t.Errorf("witness envelope type = %q, want %q", got, "TxWitness ConwayEra")
	}

	// The era-typed witness must remain readable by assemble.
	assembledFile := filepath.Join(dir, "assembled.tx")
	if err := RunTxAssemble(txFile, []string{witFile}, assembledFile); err != nil {
		t.Fatalf("RunTxAssemble: %v", err)
	}
	if got := readEnvelopeType(t, assembledFile); got != "Tx ConwayEra" {
		t.Errorf("assemble envelope type = %q, want %q", got, "Tx ConwayEra")
	}
}
