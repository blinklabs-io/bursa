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
	"io"
	"testing"
)

func TestTxSignRequiresSigningKeyFile(t *testing.T) {
	cmd := txSignCommand()
	cmd.SetArgs([]string{"--tx-file", "unused.tx"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected tx sign to require --signing-key-file")
	}
}

func TestTxAssembleRequiresWitnessFile(t *testing.T) {
	cmd := txAssembleCommand()
	cmd.SetArgs([]string{"--tx-file", "unused.tx"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected tx assemble to require --witness-file")
	}
}
