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
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTxSignRequiresSigningKeyFile(t *testing.T) {
	cmd := txSignCommand()
	cmd.SetArgs([]string{"--tx-file", "unused.tx"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected tx sign to require --signing-key-file")
	}
}

func TestTxAssembleRequiresWitnessFile(t *testing.T) {
	cmd := txAssembleCommand()
	cmd.SetArgs([]string{"--tx-file", "unused.tx"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected tx assemble to require --witness-file")
	}
}

func captureTxDecodeStdout(t *testing.T, f func() error) (string, error) {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	runErr := f()
	os.Stdout = oldStdout
	if err := w.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	<-done
	if err := r.Close(); err != nil {
		t.Fatalf("close stdout reader: %v", err)
	}
	return strings.TrimSpace(buf.String()), runErr
}

func TestTxDecodeMinFeeWitnessEstimate(t *testing.T) {
	paramsFile := filepath.Join(t.TempDir(), "protocol-params.json")
	if err := os.WriteFile(paramsFile, []byte(`{"txFeePerByte":44,"txFeeFixed":155381}`), 0o600); err != nil {
		t.Fatalf("write protocol params: %v", err)
	}
	for _, tc := range []struct {
		name        string
		args        []string
		addedBytes  int
		witnessNote string
	}{
		{name: "transaction as decoded"},
		{
			name:        "additional vkey witnesses",
			args:        []string{"--witness-count", "4"},
			addedBytes:  4 * 102,
			witnessNote: "4 additional vkey witnesses",
		},
		{
			name:        "additional bootstrap witnesses",
			args:        []string{"--byron-witness-count", "2"},
			addedBytes:  2 * 139,
			witnessNote: "2 additional bootstrap witnesses",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := txDecodeCommand()
			args := []string{
				"--tx-file", filepath.Join("..", "..", "testdata", "conway-unsigned.tx"),
				"--protocol-params", paramsFile,
			}
			cmd.SetArgs(append(args, tc.args...))
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			output, err := captureTxDecodeStdout(t, cmd.Execute)
			if err != nil {
				t.Fatalf("tx decode: %v", err)
			}
			var got struct {
				SizeBytes  int    `json:"size_bytes"`
				MinFee     uint64 `json:"min_fee"`
				MinFeeNote string `json:"min_fee_note"`
			}
			if err := json.Unmarshal([]byte(output), &got); err != nil {
				t.Fatalf("decode output %q: %v", output, err)
			}
			wantFee := uint64(155381 + 44*(got.SizeBytes+tc.addedBytes))
			if got.MinFee != wantFee {
				t.Errorf("min_fee = %d, want %d for decoded size %d plus %d witness bytes", got.MinFee, wantFee, got.SizeBytes, tc.addedBytes)
			}
			if !strings.Contains(got.MinFeeNote, "transaction as decoded") {
				t.Errorf("min_fee_note = %q, want decoded-transaction fee basis", got.MinFeeNote)
			}
			if tc.witnessNote != "" && !strings.Contains(got.MinFeeNote, tc.witnessNote) {
				t.Errorf("min_fee_note = %q, want %q", got.MinFeeNote, tc.witnessNote)
			}
		})
	}
}
