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

//go:build !pkcs11

package backend

import (
	"errors"
	"testing"
)

// TestNewPKCS11Backend_StubNotCompiled verifies the pure-Go build returns a
// clear not-compiled-in error instead of silently doing nothing.
func TestNewPKCS11Backend_StubNotCompiled(t *testing.T) {
	b, err := NewPKCS11Backend(PKCS11Config{
		Name:       "hsm",
		Module:     "/usr/lib/softhsm/libsofthsm2.so",
		TokenLabel: "bursa",
		PIN:        "1234",
	})
	if b != nil {
		t.Fatalf("expected nil backend from stub, got %#v", b)
	}
	if !errors.Is(err, ErrPKCS11NotCompiled) {
		t.Fatalf("expected ErrPKCS11NotCompiled, got %v", err)
	}
}
