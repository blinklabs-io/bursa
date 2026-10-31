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
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestReadFixedHexFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorization.hex")
	want := []byte{1, 2, 3}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(want)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readFixedHexFile(path, "authorization", len(want))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("readFixedHexFile() = %x, want %x", got, want)
	}

	if _, err := readFixedHexFile(path, "authorization", len(want)+1); err == nil {
		t.Fatal("accepted authorization with the wrong size")
	}
	if err := os.WriteFile(path, []byte("not-hex"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFixedHexFile(path, "authorization", len(want)); err == nil {
		t.Fatal("accepted malformed authorization")
	}
}
