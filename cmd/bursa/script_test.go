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
	"regexp"
	"strings"
	"testing"
)

func TestScriptCreateHelpExamplesUseValidKeyHashes(t *testing.T) {
	longHelp := scriptCreateCommand().Long
	keyHashesPattern := regexp.MustCompile(`--key-hashes ([^ ]+)`)
	exampleCount := 0

	for _, line := range strings.Split(longHelp, "\n") {
		matches := keyHashesPattern.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		exampleCount++
		for _, hash := range strings.Split(matches[1], ",") {
			decoded, err := hex.DecodeString(hash)
			if err != nil {
				t.Errorf("example contains invalid hex key hash %q: %v", hash, err)
				continue
			}
			if len(decoded) != 28 {
				t.Errorf(
					"example contains %d-byte key hash %q; want 28 bytes",
					len(decoded),
					hash,
				)
			}
		}
	}

	if exampleCount == 0 {
		t.Fatal("help text contains no script creation examples")
	}
	for _, command := range []string{
		"cardano-cli conway address key-hash",
		"bursa address info",
	} {
		if !strings.Contains(longHelp, command) {
			t.Errorf("help text does not explain how to get a key hash with %q", command)
		}
	}
}
