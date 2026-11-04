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

package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/sops"
	"golang.org/x/crypto/blake2b"
)

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestDirSecretSource_ListAndGet lists the regular *.json files of the
// directory, including the symlinks a Kubernetes Secret volume creates, and
// skips hidden entries, other extensions and directories.
func TestDirSecretSource_ListAndGet(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "b.json"), []byte("b"))
	writeFile(t, filepath.Join(dir, "a.json"), []byte("a"))
	writeFile(t, filepath.Join(dir, "notes.txt"), []byte("n"))
	writeFile(t, filepath.Join(dir, ".hidden.json"), []byte("h"))
	if err := os.Mkdir(filepath.Join(dir, "sub.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A Secret volume: ..data -> ..<timestamp>/, name -> ..data/name
	if err := os.Mkdir(filepath.Join(dir, "..2026_11_04"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "..2026_11_04", "c.json"), []byte("c"))
	if err := os.Symlink("..2026_11_04", filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..data", "c.json"), filepath.Join(dir, "c.json")); err != nil {
		t.Fatal(err)
	}

	src, err := NewDirSecretSource(dir)
	if err != nil {
		t.Fatalf("NewDirSecretSource: %v", err)
	}
	names, err := src.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if want := []string{"a.json", "b.json", "c.json"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("List = %v, want %v", names, want)
	}
	for _, n := range names {
		got, err := src.Get(context.Background(), n)
		if err != nil {
			t.Fatalf("Get(%q): %v", n, err)
		}
		if want := strings.TrimSuffix(n, ".json"); string(got) != want {
			t.Fatalf("Get(%q) = %q, want %q", n, got, want)
		}
	}
}

func TestDirSecretSource_GetRejectsPaths(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.json"), []byte("a"))
	src, err := NewDirSecretSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../a.json", "sub/a.json", ".hidden.json", "", "a.txt"} {
		if _, err := src.Get(context.Background(), name); err == nil {
			t.Fatalf("Get(%q): expected error", name)
		}
	}
}

func TestDirSecretSource_GetRejectsOversized(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "big.json"), bytes.Repeat([]byte{'x'}, maxDirSecretSize+1))
	src, err := NewDirSecretSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Get(context.Background(), "big.json"); err == nil {
		t.Fatal("expected error for oversized secret")
	}
}

func TestNewDirSecretSource_MissingDir(t *testing.T) {
	if _, err := NewDirSecretSource(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("expected error for missing directory")
	}
}

// ageEncrypted returns envelope encrypted by SOPS to a fresh age identity and
// makes that identity available to SOPS decryption through SOPS_AGE_KEY.
func ageEncrypted(t *testing.T, envelope string) []byte {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Age.Recipients = id.Recipient().String()
	enc, err := sops.EncryptWithConfig([]byte(envelope), cfg)
	if err != nil {
		t.Fatalf("EncryptWithConfig: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY", id.String())
	return enc
}

// TestBuildBackends_SopsDir loads a SOPS/age-encrypted pool cold key from a
// directory and checks that the key is served as a pool key under its pool
// ID, the blake2b-224 hash of the cold verification key.
func TestBuildBackends_SopsDir(t *testing.T) {
	seed := bytes.Repeat([]byte{0x44}, 32)
	envelope := fmt.Sprintf(
		`{"type":"StakePoolSigningKey_ed25519","description":"Stake Pool Operator Signing Key","cborHex":"5820%x"}`,
		seed,
	)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "otg@prime-testnet.skey.json"), ageEncrypted(t, envelope))

	backends, err := BuildBackends(context.Background(), []config.SignerBackendConfig{
		{Name: "cold", Type: "sops", Path: dir},
	})
	if err != nil {
		t.Fatalf("BuildBackends: %v", err)
	}
	keys, err := backends[0].ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Type() != backend.KeyTypePool {
		t.Fatalf("expected pool key, got %q", keys[0].Type())
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	h, err := blake2b.New(28, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.Write(pub)
	if poolID := hex.EncodeToString(h.Sum(nil)); keys[0].Hash().String() != poolID {
		t.Fatalf("key hash %s, want pool ID %s", keys[0].Hash(), poolID)
	}
}

func TestBuildBackends_SopsDirRejectsNonKey(t *testing.T) {
	envelope := `{"type":"NodeOperationalCertificateIssueCounter","description":"Next certificate issue number: 9","cborHex":"82095820` +
		strings.Repeat("00", 32) + `"}`
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "counter.json"), ageEncrypted(t, envelope))
	if _, err := BuildBackends(context.Background(), []config.SignerBackendConfig{
		{Name: "cold", Type: "sops", Path: dir},
	}); err == nil {
		t.Fatal("expected error for a file that holds no signing key")
	}
}

func TestBuildBackends_SopsDirEmpty(t *testing.T) {
	dir := t.TempDir()
	_, err := BuildBackends(context.Background(), []config.SignerBackendConfig{
		{Name: "cold", Type: "sops", Path: dir},
	})
	if err == nil || !strings.Contains(err.Error(), dir) {
		t.Fatalf("expected an error naming %q, got %v", dir, err)
	}
}

func TestBuildBackends_SopsPathAndPrefix(t *testing.T) {
	_, err := BuildBackends(context.Background(), []config.SignerBackendConfig{
		{Name: "cold", Type: "sops", Path: t.TempDir(), SecretPrefix: "signer-"},
	})
	if err == nil {
		t.Fatal("expected error when both path and secret_prefix are set")
	}
}
