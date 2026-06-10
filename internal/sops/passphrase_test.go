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

package sops

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPassphraseRoundTrip(t *testing.T) {
	plaintext := []byte(`{"type":"PaymentSigningKeyShelley_ed25519","cborHex":"5820deadbeef"}`)
	enc, err := EncryptWithPassphrase(plaintext, "correct horse battery staple")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(enc, []byte("deadbeef")) {
		t.Fatalf("ciphertext leaks plaintext")
	}
	dec, err := DecryptWithPassphrase(enc, "correct horse battery staple")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Fatalf("round trip mismatch")
	}
}

func TestPassphraseWrongPassword(t *testing.T) {
	enc, err := EncryptWithPassphrase([]byte("secret"), "right")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := DecryptWithPassphrase(enc, "wrong"); err == nil {
		t.Fatalf("expected error decrypting with wrong passphrase")
	}
}

func TestPassphraseRejectsUntrustedScryptParameters(t *testing.T) {
	container := testPassphraseContainer(t)
	tests := []struct {
		name   string
		mutate func(*passphraseContainer)
	}{
		{
			name: "n",
			mutate: func(c *passphraseContainer) {
				c.N = scryptN / 2
			},
		},
		{
			name: "r",
			mutate: func(c *passphraseContainer) {
				c.R = scryptR + 1
			},
		},
		{
			name: "p",
			mutate: func(c *passphraseContainer) {
				c.P = scryptP + 1
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := container
			tt.mutate(&c)
			data, err := json.Marshal(c)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			_, err = DecryptWithPassphrase(data, "right")
			if err == nil {
				t.Fatalf("expected invalid scrypt parameter error")
			}
			if !strings.Contains(err.Error(), "unsupported scrypt parameters") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPassphraseRejectsInvalidNonceLengthWithoutPanic(t *testing.T) {
	container := testPassphraseContainer(t)
	container.Nonce = "abcd"
	data, err := json.Marshal(container)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decryptErr error
	var recovered any
	func() {
		defer func() {
			recovered = recover()
		}()
		_, decryptErr = DecryptWithPassphrase(data, "right")
	}()
	if recovered != nil {
		t.Fatalf("decrypt panicked on invalid nonce length: %v", recovered)
	}
	if decryptErr == nil {
		t.Fatalf("expected invalid nonce length error")
	}
	if !strings.Contains(decryptErr.Error(), "invalid nonce length") {
		t.Fatalf("unexpected error: %v", decryptErr)
	}
}

func testPassphraseContainer(t *testing.T) passphraseContainer {
	t.Helper()
	enc, err := EncryptWithPassphrase([]byte("secret"), "right")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	var container passphraseContainer
	if err := json.Unmarshal(enc, &container); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return container
}
