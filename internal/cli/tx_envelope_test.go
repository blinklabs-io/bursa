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
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/gouroboros/cbor"
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
	if err := RunTxSign(txFile, []string{keyFile}, signedFile, ""); err != nil {
		t.Fatalf("RunTxSign: %v", err)
	}
	if got := readEnvelopeType(t, signedFile); got != "Tx ConwayEra" {
		t.Errorf("sign envelope type = %q, want %q", got, "Tx ConwayEra")
	}

	witFile := filepath.Join(dir, "tx.witness")
	if err := RunTxWitness(txFile, keyFile, witFile, ""); err != nil {
		t.Fatalf("RunTxWitness: %v", err)
	}
	if got := readEnvelopeType(t, witFile); got != "TxWitness ConwayEra" {
		t.Errorf("witness envelope type = %q, want %q", got, "TxWitness ConwayEra")
	}

	// The era-typed witness must remain readable by assemble.
	assembledFile := filepath.Join(dir, "assembled.tx")
	if err := RunTxAssemble(txFile, []string{witFile}, assembledFile, ""); err != nil {
		t.Fatalf("RunTxAssemble: %v", err)
	}
	if got := readEnvelopeType(t, assembledFile); got != "Tx ConwayEra" {
		t.Errorf("assemble envelope type = %q, want %q", got, "Tx ConwayEra")
	}
}

// babbageTxHex is the reference GenTx_Babbage payload. It decodes as Alonzo,
// Babbage and Conway, so its era cannot be inferred from the CBOR.
const babbageTxHex = "84a3008001800200a0f5f6"

func writeTestSigningKey(t *testing.T, dir string) string {
	t.Helper()
	keyFile := filepath.Join(dir, "payment.skey")
	keyJSON := `{"type":"PaymentSigningKeyShelley_ed25519",` +
		`"description":"Payment Signing Key",` +
		`"cborHex":"5820` + strings.Repeat("01", 32) + `"}`
	if err := os.WriteFile(keyFile, []byte(keyJSON), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return keyFile
}

// writeTxFile writes cborHex as a text envelope of envType, or as raw hex
// when envType is empty.
func writeTxFile(t *testing.T, dir, name, envType, cborHex string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	content := cborHex
	if envType != "" {
		content = `{"type":"` + envType + `","description":"","cborHex":"` + cborHex + `"}`
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write tx: %v", err)
	}
	return path
}

func readEnvelope(t *testing.T, path string) bursa.CborEnvelope {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var env bursa.CborEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("parse envelope %s: %v", path, err)
	}
	return env
}

// vkeyWitnessesTagged reports whether the vkey witness field of a signed
// transaction is wrapped in CBOR tag 258, which only Conway and later accept.
func vkeyWitnessesTagged(t *testing.T, cborHex string) bool {
	t.Helper()
	raw, err := hex.DecodeString(cborHex)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	var arr []cbor.RawMessage
	if _, err := cbor.Decode(raw, &arr); err != nil {
		t.Fatalf("decode tx: %v", err)
	}
	ws := map[uint64]cbor.RawMessage{}
	if _, err := cbor.Decode(arr[1], &ws); err != nil {
		t.Fatalf("decode witness set: %v", err)
	}
	field, ok := ws[0]
	if !ok || len(field) == 0 {
		t.Fatalf("no vkey witness field")
	}
	return field[0] == 0xd9
}

func TestTxBabbageEnvelopeKeepsEra(t *testing.T) {
	t.Parallel()
	for _, inType := range []string{"Tx BabbageEra", "Unwitnessed Tx BabbageEra"} {
		t.Run(inType, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			keyFile := writeTestSigningKey(t, dir)
			txFile := writeTxFile(t, dir, "tx.unsigned", inType, babbageTxHex)

			signedFile := filepath.Join(dir, "signed.tx")
			if err := RunTxSign(txFile, []string{keyFile}, signedFile, ""); err != nil {
				t.Fatalf("RunTxSign: %v", err)
			}
			signed := readEnvelope(t, signedFile)
			if signed.Type != "Tx BabbageEra" {
				t.Errorf("sign envelope type = %q, want %q", signed.Type, "Tx BabbageEra")
			}
			if vkeyWitnessesTagged(t, signed.CborHex) {
				t.Errorf("sign wrapped Babbage vkey witnesses in tag 258")
			}

			witFile := filepath.Join(dir, "tx.witness")
			if err := RunTxWitness(txFile, keyFile, witFile, ""); err != nil {
				t.Fatalf("RunTxWitness: %v", err)
			}
			if got := readEnvelope(t, witFile).Type; got != "TxWitness BabbageEra" {
				t.Errorf("witness envelope type = %q, want %q", got, "TxWitness BabbageEra")
			}

			assembledFile := filepath.Join(dir, "assembled.tx")
			if err := RunTxAssemble(txFile, []string{witFile}, assembledFile, ""); err != nil {
				t.Fatalf("RunTxAssemble: %v", err)
			}
			assembled := readEnvelope(t, assembledFile)
			if assembled.Type != "Tx BabbageEra" {
				t.Errorf("assemble envelope type = %q, want %q", assembled.Type, "Tx BabbageEra")
			}
			if vkeyWitnessesTagged(t, assembled.CborHex) {
				t.Errorf("assemble wrapped Babbage vkey witnesses in tag 258")
			}
		})
	}
}

func TestTxAmbiguousEraRequiresContext(t *testing.T) {
	t.Parallel()
	zeroWitness := "825820" + strings.Repeat("00", 32) + "5840" + strings.Repeat("00", 64)
	for _, tc := range []struct{ name, envType string }{
		{"raw hex", ""},
		{"legacy Tx envelope", "Tx"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			keyFile := writeTestSigningKey(t, dir)
			txFile := writeTxFile(t, dir, "tx.unsigned", tc.envType, babbageTxHex)
			err := RunTxSign(txFile, []string{keyFile}, filepath.Join(dir, "signed.tx"), "")
			if err == nil || !strings.Contains(err.Error(), "--era") {
				t.Errorf("RunTxSign error = %v, want an error asking for --era", err)
			}
			err = RunTxWitness(txFile, keyFile, filepath.Join(dir, "tx.witness"), "")
			if err == nil || !strings.Contains(err.Error(), "--era") {
				t.Errorf("RunTxWitness error = %v, want an error asking for --era", err)
			}
			witFile := writeTxFile(t, dir, "w.witness", "TxWitness", zeroWitness)
			err = RunTxAssemble(txFile, []string{witFile}, filepath.Join(dir, "assembled.tx"), "")
			if err == nil || !strings.Contains(err.Error(), "--era") {
				t.Errorf("RunTxAssemble error = %v, want an error asking for --era", err)
			}
		})
	}
}

func TestTxLegacyEnvelopeConwayStillWorks(t *testing.T) {
	t.Parallel()
	raw, err := bursa.ReadCborInputFile(filepath.Join("..", "..", "testdata", "conway-unsigned.tx"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	for _, envType := range []string{"", "Tx"} {
		dir := t.TempDir()
		keyFile := writeTestSigningKey(t, dir)
		txFile := writeTxFile(t, dir, "tx.unsigned", envType, hex.EncodeToString(raw))
		signedFile := filepath.Join(dir, "signed.tx")
		if err := RunTxSign(txFile, []string{keyFile}, signedFile, ""); err != nil {
			t.Fatalf("RunTxSign (%q): %v", envType, err)
		}
		if got := readEnvelope(t, signedFile).Type; got != "Tx ConwayEra" {
			t.Errorf("sign envelope type for %q input = %q, want %q", envType, got, "Tx ConwayEra")
		}
	}
}

func TestTxEraFlag(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyFile := writeTestSigningKey(t, dir)

	rawFile := writeTxFile(t, dir, "raw.unsigned", "", babbageTxHex)
	signedFile := filepath.Join(dir, "signed.tx")
	if err := RunTxSign(rawFile, []string{keyFile}, signedFile, "babbage"); err != nil {
		t.Fatalf("RunTxSign --era babbage: %v", err)
	}
	signed := readEnvelope(t, signedFile)
	if signed.Type != "Tx BabbageEra" {
		t.Errorf("sign envelope type = %q, want %q", signed.Type, "Tx BabbageEra")
	}
	if vkeyWitnessesTagged(t, signed.CborHex) {
		t.Errorf("sign wrapped Babbage vkey witnesses in tag 258")
	}
	witFile := filepath.Join(dir, "tx.witness")
	if err := RunTxWitness(rawFile, keyFile, witFile, "Babbage"); err != nil {
		t.Fatalf("RunTxWitness --era Babbage: %v", err)
	}
	if got := readEnvelope(t, witFile).Type; got != "TxWitness BabbageEra" {
		t.Errorf("witness envelope type = %q, want %q", got, "TxWitness BabbageEra")
	}

	envFile := writeTxFile(t, dir, "env.unsigned", "Tx BabbageEra", babbageTxHex)
	err := RunTxSign(envFile, []string{keyFile}, filepath.Join(dir, "conflict.tx"), "conway")
	if err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Errorf("RunTxSign with conflicting --era error = %v, want a conflict error", err)
	}
	err = RunTxSign(rawFile, []string{keyFile}, filepath.Join(dir, "bad.tx"), "goguen")
	if err == nil || !strings.Contains(err.Error(), "unknown era") {
		t.Errorf("RunTxSign with unknown --era error = %v, want an unknown era error", err)
	}
}
