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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/sops"
)

func TestRunKeyEncryptInPlaceTightensPermissions(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "payment.skey")
	plaintext := []byte(`{"type":"PaymentSigningKeyShelley_ed25519","cborHex":"5820deadbeef"}`)
	if err := os.WriteFile(keyFile, plaintext, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	if err := os.Chmod(keyFile, 0o644); err != nil {
		t.Fatalf("chmod key file: %v", err)
	}

	if err := RunKeyEncrypt(keyFile, "", "right"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %v, want 0600", got)
	}
	encrypted, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read encrypted file: %v", err)
	}
	if bytes.Contains(encrypted, []byte("deadbeef")) {
		t.Fatalf("encrypted file leaks plaintext")
	}
	decrypted, err := sops.DecryptWithPassphrase(encrypted, "right")
	if err != nil {
		t.Fatalf("decrypt encrypted file: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted data mismatch")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".payment.skey.tmp-") {
			t.Fatalf("temporary file was not cleaned up: %s", entry.Name())
		}
	}
}

func TestRunKeyDecryptTightensOutputPermissions(t *testing.T) {
	dir := t.TempDir()
	encryptedFile := filepath.Join(dir, "payment.skey.enc")
	outFile := filepath.Join(dir, "payment.skey")
	plaintext := []byte(`{"type":"PaymentSigningKeyShelley_ed25519","cborHex":"5820deadbeef"}`)

	encrypted, err := sops.EncryptWithPassphrase(plaintext, "right")
	if err != nil {
		t.Fatalf("encrypt fixture: %v", err)
	}
	if err := os.WriteFile(encryptedFile, encrypted, 0o600); err != nil {
		t.Fatalf("write encrypted key file: %v", err)
	}
	if err := os.WriteFile(outFile, []byte("old"), 0o644); err != nil {
		t.Fatalf("write existing output file: %v", err)
	}

	if err := RunKeyDecrypt(encryptedFile, outFile, "right"); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	info, err := os.Stat(outFile)
	if err != nil {
		t.Fatalf("stat output file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %v, want 0600", got)
	}
	decrypted, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted data mismatch")
	}
}
