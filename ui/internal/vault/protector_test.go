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

package vault

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/keystore"
)

func testProtector(t *testing.T) *passwordProtector {
	t.Helper()
	seal, open := keystore.CheapTestSealer()
	return newPasswordProtector(seal, open)
}

func TestPasswordProtectorWrapUnwrapRoundTrip(t *testing.T) {
	p := testProtector(t)
	vek := make([]byte, vekLen)
	if _, err := rand.Read(vek); err != nil {
		t.Fatalf("rand: %v", err)
	}

	blob, err := p.Wrap(vek, vaultPw)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	// The wrapped blob must be a real scrypt container, never the VEK in clear.
	if blob.Ciphertext == "" || blob.KDF != "scrypt" {
		t.Fatalf("Wrap produced a non-container blob: %+v", blob)
	}
	if bytes.Contains([]byte(blob.Ciphertext), vek) {
		t.Fatal("VEK appears in the wrapped ciphertext")
	}

	got, err := p.Unwrap(blob, vaultPw)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, vek) {
		t.Fatal("Unwrap did not recover the original VEK")
	}
}

func TestPasswordProtectorWrongPassword(t *testing.T) {
	p := testProtector(t)
	vek := make([]byte, vekLen)
	if _, err := rand.Read(vek); err != nil {
		t.Fatalf("rand: %v", err)
	}
	blob, err := p.Wrap(vek, vaultPw)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := p.Unwrap(blob, "wrong-vault-password"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Unwrap wrong password = %v, want ErrWrongPassword", err)
	}
}

func TestPasswordProtectorRejectsWrongVEKLength(t *testing.T) {
	p := testProtector(t)
	if _, err := p.Wrap([]byte("too-short"), vaultPw); err == nil {
		t.Fatal("Wrap should reject a VEK that is not vekLen bytes")
	}
}

func TestPasswordProtectorAlwaysAvailable(t *testing.T) {
	ok, reason := testProtector(t).Available()
	if !ok {
		t.Fatalf("password protector should always be available, reason=%q", reason)
	}
}
