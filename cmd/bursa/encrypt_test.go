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

import "testing"

func TestKeyEncryptCommandDoesNotExposePassphraseArg(t *testing.T) {
	cmd := keyEncryptCommand()
	if cmd.Flags().Lookup("passphrase") != nil {
		t.Fatalf("key encrypt must not accept passphrase via argv")
	}
	if cmd.Flags().Lookup("passphrase-file") == nil {
		t.Fatalf("key encrypt should accept --passphrase-file")
	}
}

func TestKeyDecryptCommandDoesNotExposePassphraseArg(t *testing.T) {
	cmd := keyDecryptCommand()
	if cmd.Flags().Lookup("passphrase") != nil {
		t.Fatalf("key decrypt must not accept passphrase via argv")
	}
	if cmd.Flags().Lookup("passphrase-file") == nil {
		t.Fatalf("key decrypt should accept --passphrase-file")
	}
}
