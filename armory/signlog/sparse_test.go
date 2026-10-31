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

package signlog

import (
	"bytes"
	"errors"
	"testing"
)

func TestSparseMediumVerifiesAPrefix(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 16)
	w := f.open(t)
	f.fill(t, w, 3)

	img := f.medium.Image()
	// keep the header and the three entries only
	prefix := img[:(1+3*RecordBlocks)*BlockSize]

	m, err := NewSparseMedium(f.medium.NumBlocks(), prefix)
	if err != nil {
		t.Fatal(err)
	}

	log, err := Verify(m, f.pub)
	if err != nil || len(log.Entries) != 3 || log.Head() != w.Head() {
		t.Fatalf("verify: %v", err)
	}

	// a prefix that stops short of the real entries is a shorter log, and
	// its head differs from the writer's
	short, _ := NewSparseMedium(f.medium.NumBlocks(), img[:(1+2*RecordBlocks)*BlockSize])

	log, err = Verify(short, f.pub)
	if err != nil || len(log.Entries) != 2 || log.Head() == w.Head() {
		t.Fatalf("short prefix: %v, %d entries", err, len(log.Entries))
	}
}

func TestSparseMediumBounds(t *testing.T) {
	t.Parallel()

	m, err := NewSparseMedium(8, bytes.Repeat([]byte{1}, 2*BlockSize))
	if err != nil {
		t.Fatal(err)
	}

	p := make([]byte, 2*BlockSize)
	if err = m.ReadBlocks(1, p); err != nil || p[0] != 1 || p[BlockSize] != 0 {
		t.Fatalf("read across the prefix end: %v", err)
	}

	for name, err := range map[string]error{
		"past the end":  m.ReadBlocks(7, p),
		"partial block": m.ReadBlocks(0, make([]byte, 10)),
		"write":         m.WriteBlocks(0, p),
		"sync":          m.Sync(),
	} {
		if err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	if _, err = NewSparseMedium(1, make([]byte, 2*BlockSize)); !errors.Is(err, ErrMedium) {
		t.Errorf("oversize prefix: %v", err)
	}

	if _, err = NewSparseMedium(8, make([]byte, 100)); !errors.Is(err, ErrMedium) {
		t.Errorf("partial block prefix: %v", err)
	}
}
