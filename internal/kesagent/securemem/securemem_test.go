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

package securemem_test

import (
	"bytes"
	"testing"

	"github.com/blinklabs-io/bursa/internal/kesagent/securemem"
)

func TestNewRejectsNonPositiveSize(t *testing.T) {
	if _, err := securemem.New(0); err == nil {
		t.Fatal("expected error for zero size")
	}
	if _, err := securemem.New(-1); err == nil {
		t.Fatal("expected error for negative size")
	}
}

func TestSetBytesRoundTrip(t *testing.T) {
	b, err := securemem.New(4)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = b.Close() }()

	// mlock may or may not succeed depending on RLIMIT_MEMLOCK; either way the
	// buffer must be usable. Log the outcome for the record.
	t.Logf("mlock locked=%v", b.Locked())

	if err := b.Set([]byte{1, 2, 3, 4}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if !bytes.Equal(b.Bytes(), []byte{1, 2, 3, 4}) {
		t.Fatalf("Bytes mismatch: %v", b.Bytes())
	}
	if b.Len() != 4 {
		t.Fatalf("Len = %d, want 4", b.Len())
	}
}

func TestSetWrongSize(t *testing.T) {
	b, err := securemem.New(4)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = b.Close() }()
	if err := b.Set([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for mismatched length")
	}
}

func TestZeroizeWipes(t *testing.T) {
	b, err := securemem.New(8)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = b.Close() }()
	if err := b.Set([]byte{9, 9, 9, 9, 9, 9, 9, 9}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	b.Zeroize()
	for i, v := range b.Bytes() {
		if v != 0 {
			t.Fatalf("byte %d not wiped: %d", i, v)
		}
	}
	// Still usable after Zeroize.
	if err := b.Set([]byte{1, 1, 1, 1, 1, 1, 1, 1}); err != nil {
		t.Fatalf("Set after Zeroize: %v", err)
	}
}

func TestCloneIsIndependent(t *testing.T) {
	b, err := securemem.New(4)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = b.Close() }()
	_ = b.Set([]byte{1, 2, 3, 4})
	c := b.Clone()
	b.Zeroize()
	if !bytes.Equal(c, []byte{1, 2, 3, 4}) {
		t.Fatalf("clone was affected by Zeroize: %v", c)
	}
}

func TestCloseIsIdempotentAndUnusable(t *testing.T) {
	b, err := securemem.New(4)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = b.Set([]byte{1, 2, 3, 4})
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if b.Bytes() != nil {
		t.Fatal("Bytes should be nil after Close")
	}
	if err := b.Set([]byte{1, 2, 3, 4}); err == nil {
		t.Fatal("Set after Close should fail")
	}
	if b.Len() != 0 {
		t.Fatalf("Len after Close = %d, want 0", b.Len())
	}
}

func TestWipe(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	securemem.Wipe(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not wiped: %d", i, v)
		}
	}
}
