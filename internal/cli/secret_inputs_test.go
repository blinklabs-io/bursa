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
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureLog returns what f writes to the diagnostic log.
// The tests below are not parallel: they replace os.Stderr, the logging
// package's global logger, and the secret stdin reader.
func captureLog(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	oldStderr := os.Stderr
	os.Stderr = w
	logging.ConfigureText()
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	defer func() {
		os.Stderr = oldStderr
		logging.ConfigureText()
	}()
	f()
	_ = w.Close()
	<-done
	_ = r.Close()
	return buf.String()
}

func TestResolveMnemonicReadsStdin(t *testing.T) {
	old := secretStdin
	secretStdin = strings.NewReader(testKeyMnemonic + "\n")
	t.Cleanup(func() { secretStdin = old })

	got, err := resolveMnemonic("", "-")
	require.NoError(t, err)
	assert.Equal(t, testKeyMnemonic, got)
}

func TestReadSecretFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "pw")
	require.NoError(t, os.WriteFile(path, []byte(" pass word \r\n"), 0o600))
	got, err := ReadSecretFile(path, nil)
	require.NoError(t, err)
	assert.Equal(t, " pass word ", got)

	got, err = ReadSecretFile("-", strings.NewReader("from-stdin\n"))
	require.NoError(t, err)
	assert.Equal(t, "from-stdin", got)

	_, err = ReadSecretFile(filepath.Join(t.TempDir(), "missing"), nil)
	assert.Error(t, err)
}

func TestRunCreateRequiresOutputAndLogsNoSecrets(t *testing.T) {
	cfg := &config.Config{Network: "preview", Mnemonic: testKeyMnemonic}
	var err error
	logged := captureLog(t, func() { err = RunCreate(cfg, "") })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "output directory is required")
	assert.NotContains(t, logged, "abandon")
	assert.NotContains(t, logged, "cborHex")
}

func TestRunCreateWritesSecretsOnlyToOutput(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wallet")
	cfg := &config.Config{Network: "preview", Mnemonic: testKeyMnemonic}
	var err error
	logged := captureLog(t, func() { err = RunCreate(cfg, dir) })
	require.NoError(t, err)
	seed, err := os.ReadFile(filepath.Join(dir, "seed.txt"))
	require.NoError(t, err)
	assert.Equal(t, testKeyMnemonic, string(seed))
	assert.NotContains(t, logged, "abandon")
	assert.NotContains(t, logged, "cborHex")
	if runtime.GOOS != "windows" {
		info, err := os.Stat(dir)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	}
}

func TestRunRestoreWithoutOutputKeepsKeysOutOfLog(t *testing.T) {
	cfg := &config.Config{Network: "preview"}
	var err error
	logged := captureLog(t, func() {
		err = RunRestore(cfg, testKeyMnemonic, "", "", "")
	})
	require.NoError(t, err)
	assert.Contains(t, logged, "PAYMENT_ADDRESS")
	assert.NotContains(t, logged, "cborHex")
	assert.NotContains(t, logged, ".skey")
}

func TestRunCreateRefusesWritableOutputDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory mode bits do not describe access on windows")
	}
	cfg := &config.Config{Network: "preview", Mnemonic: testKeyMnemonic}
	for _, mode := range []os.FileMode{0o770, 0o707, 0o1777} {
		dir := filepath.Join(t.TempDir(), "wallet")
		require.NoError(t, os.Mkdir(dir, 0o700))
		require.NoError(t, os.Chmod(dir, mode))
		var err error
		captureLog(t, func() { err = RunCreate(cfg, dir) })
		require.Error(t, err, "mode %04o", mode)
		_, statErr := os.Stat(filepath.Join(dir, "seed.txt"))
		assert.ErrorIs(t, statErr, os.ErrNotExist, "mode %04o", mode)
	}
	dir := filepath.Join(t.TempDir(), "wallet")
	require.NoError(t, os.Mkdir(dir, 0o700))
	require.NoError(t, os.Chmod(dir, 0o755))
	var err error
	captureLog(t, func() { err = RunCreate(cfg, dir) })
	require.NoError(t, err)
}

func TestResolveMnemonicRejectsEmptySource(t *testing.T) {
	old := secretStdin
	secretStdin = strings.NewReader("\n")
	t.Cleanup(func() { secretStdin = old })
	_, err := resolveMnemonic("", "-")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"-" is empty`)

	path := filepath.Join(t.TempDir(), "seed.txt")
	require.NoError(t, os.WriteFile(path, []byte(" \n"), 0o600))
	_, err = resolveMnemonic("", path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is empty")
}
