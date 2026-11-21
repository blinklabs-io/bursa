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

package cli

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The cold key is 32 bytes of 0xbb. The expected hash comes from
// `printf 'bb%.0s' $(seq 32) | basenc --base16 -d | b2sum -l 224` and the
// bech32 form from an independent Python bech32 encoder, not from bursa.
const (
	knownPoolIDHex    = "3984ee65457a47e2c847c9a9a3870d466e06a13d3fb08b5b29dfeb22"
	knownPoolIDBech32 = "pool18xzwue290fr79jz8ex568pcdgehqdgfa87cgkkefml4jyjgwm7e"
)

func poolIDColdVKey(t *testing.T) string {
	t.Helper()
	return createTestVkeyFile(
		t, t.TempDir(), "pool-cold.vkey",
		"StakePoolVerificationKey_ed25519",
		"Stake Pool Operator Verification Key",
		testColdVKeyCborHex,
	)
}

func TestRunKeyPoolID_VKeyFile(t *testing.T) {
	t.Parallel()
	vkey := poolIDColdVKey(t)
	tests := []struct {
		name, format, want string
	}{
		{"default is bech32", "", knownPoolIDBech32},
		{"bech32", "bech32", knownPoolIDBech32},
		{"hex", "hex", knownPoolIDHex},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			outFile := filepath.Join(t.TempDir(), "pool.id")
			require.NoError(
				t,
				RunKeyPoolID("", "", "", vkey, tt.format, outFile, 0),
			)
			data, err := os.ReadFile(outFile)
			require.NoError(t, err)
			assert.Equal(t, tt.want+"\n", string(data))
		})
	}
}

func TestRunKeyPoolID_Stdout(t *testing.T) {
	// Not t.Parallel: captureStdout swaps os.Stdout.
	vkey := poolIDColdVKey(t)
	out := captureStdout(t, func() {
		require.NoError(t, RunKeyPoolID("", "", "", vkey, "", "", 0))
	})
	assert.Equal(t, knownPoolIDBech32, strings.TrimSpace(out))
}

func TestRunKeyPoolID_OutputAcceptedAsPoolID(t *testing.T) {
	t.Parallel()
	for _, id := range []string{knownPoolIDBech32, knownPoolIDHex} {
		got, err := parsePoolID(id)
		require.NoError(t, err)
		assert.Equal(t, knownPoolIDHex, hex.EncodeToString(got))
	}
}

func TestRunKeyPoolID_RejectsBadInput(t *testing.T) {
	t.Parallel()
	vkey := poolIDColdVKey(t)
	err := RunKeyPoolID("", "", "", vkey, "base58", "", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "output format")

	badKey := createTestVkeyFile(
		t, t.TempDir(), "bad.vkey",
		"StakePoolVerificationKey_ed25519", "bad", "4101",
	)
	require.Error(t, RunKeyPoolID("", "", "", badKey, "", "", 0))
	require.Error(
		t,
		RunKeyPoolID(
			"", "", "", filepath.Join(t.TempDir(), "missing.vkey"), "", "", 0,
		),
	)
}

func TestRunKeyPoolID_FromMnemonicMatchesColdVKey(t *testing.T) {
	t.Parallel()
	mnemonic := strings.TrimSpace(strings.Repeat("abandon ", 11) + "about")
	dir := t.TempDir()
	vkeyPath := filepath.Join(dir, "pool-cold.vkey")
	require.NoError(
		t,
		RunKeyPoolCold("", writeSeed(t, dir, mnemonic), "", "", vkeyPath, 0),
	)

	fromVKey := filepath.Join(dir, "from-vkey.id")
	require.NoError(
		t, RunKeyPoolID("", "", "", vkeyPath, "hex", fromVKey, 0),
	)
	fromMnemonic := filepath.Join(dir, "from-mnemonic.id")
	require.NoError(
		t, RunKeyPoolID(mnemonic, "", "", "", "hex", fromMnemonic, 0),
	)

	a, err := os.ReadFile(fromVKey)
	require.NoError(t, err)
	b, err := os.ReadFile(fromMnemonic)
	require.NoError(t, err)
	assert.Len(t, strings.TrimSpace(string(a)), 56)
	assert.Equal(t, string(a), string(b))
}

func writeSeed(t *testing.T, dir, mnemonic string) string {
	t.Helper()
	path := filepath.Join(dir, "seed.txt")
	require.NoError(t, os.WriteFile(path, []byte(mnemonic), 0o600))
	return path
}
