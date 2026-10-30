//go:build unix

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
	"errors"
	"os"
	"testing"

	"github.com/blinklabs-io/bursa"
)

func TestListenAttestedKESRejectsPermissiveKey(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o644} {
		t.Run(mode.String(), func(t *testing.T) {
			certFile, keyFile := writeConfidentialSpaceTLSFixture(t)
			if err := os.Chmod(keyFile, mode); err != nil {
				t.Fatal(err)
			}
			listener, err := listenAttestedKES(
				"127.0.0.1:0",
				certFile,
				keyFile,
				certFile,
			)
			if listener != nil {
				_ = listener.Close()
			}
			if !errors.Is(err, bursa.ErrInsecureFileMode) {
				t.Fatalf("listenAttestedKES error = %v, want ErrInsecureFileMode", err)
			}
		})
	}
}
