// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tpm

import (
	"bytes"
	"testing"
)

func TestPCRSelectionRejectsInvalidIndices(t *testing.T) {
	if _, err := pcrSelection(nil); err == nil {
		t.Fatal("pcrSelection(nil) should fail")
	}
	if _, err := pcrSelection([]uint{24}); err == nil {
		t.Fatal("pcrSelection(24) should fail")
	}
}

func TestAuthValueNormalizesPasswordLength(t *testing.T) {
	salt := bytes.Repeat([]byte{0xA5}, authSaltLen)
	short, err := authValue("vault-password", salt)
	if err != nil {
		t.Fatalf("authValue short: %v", err)
	}
	long, err := authValue("vault-password-with-a-long-passphrase-that-exceeds-common-tpm-auth-buffer-limits", salt)
	if err != nil {
		t.Fatalf("authValue long: %v", err)
	}
	if len(short) != 32 || len(long) != 32 {
		t.Fatalf("authValue lengths = %d, %d; want 32, 32", len(short), len(long))
	}
	if string(short) == "vault-password" {
		t.Fatal("authValue should not return raw password bytes")
	}
}

func TestAuthValueUsesSalt(t *testing.T) {
	saltA := bytes.Repeat([]byte{0xA5}, authSaltLen)
	saltB := bytes.Repeat([]byte{0x5A}, authSaltLen)
	a1, err := authValue("vault-password", saltA)
	if err != nil {
		t.Fatalf("authValue salt A: %v", err)
	}
	a2, err := authValue("vault-password", saltA)
	if err != nil {
		t.Fatalf("authValue salt A repeat: %v", err)
	}
	b, err := authValue("vault-password", saltB)
	if err != nil {
		t.Fatalf("authValue salt B: %v", err)
	}
	if !bytes.Equal(a1, a2) {
		t.Fatal("authValue must be deterministic for the same password and salt")
	}
	if bytes.Equal(a1, b) {
		t.Fatal("authValue should differ when the salt differs")
	}
}

func TestAuthValueRejectsInvalidSalt(t *testing.T) {
	if _, err := authValue("vault-password", []byte("short")); err == nil {
		t.Fatal("authValue should reject an invalid salt length")
	}
}
