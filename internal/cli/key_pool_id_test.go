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
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The cold key is 32 bytes of 0xbb. Both expected values are cardano-cli
// `stake-pool id` output for that key, not bursa's.
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

// Expected values are cardano-cli `stake-pool id --output-format hex` on the
// pool cold vkey derived from the all-"abandon" mnemonic at each index.
func TestRunKeyPoolID_FromMnemonicKnownIDs(t *testing.T) {
	t.Parallel()
	mnemonic := strings.TrimSpace(strings.Repeat("abandon ", 11) + "about")
	for index, want := range map[uint32]string{
		0: "b875f7452266acb53bcc349ee3b2aa9c843b73d26a43a73a54a737f2",
		1: "0996bee5ed9ce72755f315a3d3c142f63b6cbd8ab29424380c71b55b",
	} {
		outFile := filepath.Join(t.TempDir(), "pool.id")
		require.NoError(
			t, RunKeyPoolID(mnemonic, "", "", "", "hex", outFile, index),
		)
		got, err := os.ReadFile(outFile)
		require.NoError(t, err)
		assert.Equal(t, want+"\n", string(got), "index %d", index)
	}
}

func writeSeed(t *testing.T, dir, mnemonic string) string {
	t.Helper()
	path := filepath.Join(dir, "seed.txt")
	require.NoError(t, os.WriteFile(path, []byte(mnemonic), 0o600))
	return path
}

func TestRunKeyPoolID_RejectsNonColdVKeyEnvelope(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Each input carries 32 key bytes, so only the envelope type separates
	// it from a cold verification key.
	inputs := map[string]string{
		"signing key": createTestVkeyFile(
			t, dir, "pool-cold.skey",
			"StakePoolSigningKey_ed25519",
			"Stake Pool Operator Signing Key",
			testColdVKeyCborHex,
		),
		"payment vkey": createTestVkeyFile(
			t, dir, "payment.vkey",
			"PaymentVerificationKeyShelley_ed25519",
			"Payment Verification Key",
			testColdVKeyCborHex,
		),
		"bare hex": func() string {
			path := filepath.Join(dir, "bare.hex")
			require.NoError(
				t,
				os.WriteFile(path, []byte(strings.Repeat("bb", 32)), 0o600),
			)
			return path
		}(),
	}
	for name, path := range inputs {
		err := RunKeyPoolID("", "", "", path, "hex", "", 0)
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "cold verification key", name)
	}

	shelley := createTestVkeyFile(
		t, dir, "pool-cold-shelley.vkey",
		"StakePoolVerificationKeyShelley_ed25519",
		"Stake Pool Operator Verification Key",
		testColdVKeyCborHex,
	)
	outFile := filepath.Join(dir, "pool.id")
	require.NoError(t, RunKeyPoolID("", "", "", shelley, "hex", outFile, 0))
	got, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, knownPoolIDHex+"\n", string(got))
}

func TestRunKeyPoolID_OutFileExistingModeIs0600(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes")
	}
	outFile := filepath.Join(t.TempDir(), "pool.id")
	require.NoError(t, os.WriteFile(outFile, []byte("stale\n"), 0o600))
	require.NoError(t, os.Chmod(outFile, 0o644))

	require.NoError(
		t, RunKeyPoolID("", "", "", poolIDColdVKey(t), "hex", outFile, 0),
	)
	info, err := os.Stat(outFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	got, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, knownPoolIDHex+"\n", string(got))
}

func TestRunKeyPoolID_StdoutWriteError(t *testing.T) {
	// Not t.Parallel: swaps os.Stdout.
	vkey := poolIDColdVKey(t)
	readOnly, err := os.Open(vkey)
	require.NoError(t, err)
	defer readOnly.Close()
	old := os.Stdout
	os.Stdout = readOnly
	defer func() { os.Stdout = old }()

	require.Error(t, RunKeyPoolID("", "", "", vkey, "", "", 0))
}
