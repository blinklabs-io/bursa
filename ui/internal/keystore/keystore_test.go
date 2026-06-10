package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/scrypt"
)

// testKDF keeps scrypt cheap (~4 MiB, sub-millisecond) so the suite stays
// fast. The production cost is exercised once in
// TestRoundTripProductionParams, which is skipped under -short.
var testKDF = kdfParams{
	n: 1 << 12, r: 8, p: 1,
	minN: 1 << 12, maxN: 1 << 14,
	minR: 8, maxR: 32,
	minP: 1, maxP: 4,
}

func newTestKeystore(t *testing.T) *Keystore {
	t.Helper()
	ks := New(filepath.Join(t.TempDir(), "keystore.json"))
	ks.kdf = &testKDF
	return ks
}

func TestCreateUnlockRoundTrip(t *testing.T) {
	ks := newTestKeystore(t)
	if ks.Exists() {
		t.Fatal("Exists() true before Create")
	}
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	if err := ks.Create(mnemonic, "s3cret-pass"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !ks.Exists() {
		t.Fatal("Exists() false after Create")
	}
	got, err := ks.Unlock("s3cret-pass")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if string(got) != mnemonic {
		t.Fatalf("round-trip mismatch: got %q", got)
	}
}

// One full round trip at production scrypt cost (~1 GiB, seconds per
// derivation), so the shipped defaults are known to work end to end.
func TestRoundTripProductionParams(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping production-cost scrypt in -short mode")
	}
	ks := New(filepath.Join(t.TempDir(), "keystore.json"))
	const mnemonic = "abandon abandon about"
	if err := ks.Create(mnemonic, "s3cret-pass"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := ks.Unlock("s3cret-pass")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if string(got) != mnemonic {
		t.Fatalf("round-trip mismatch: got %q", got)
	}
}

func TestUnlockWrongPassword(t *testing.T) {
	ks := newTestKeystore(t)
	if err := ks.Create("abandon about", "right-password"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := ks.Unlock("wrong-password"); !errors.Is(err, ErrDecryptFailed) {
		t.Fatal("Unlock with wrong password should fail")
	}
}

func TestCreateRefusesOverwrite(t *testing.T) {
	ks := newTestKeystore(t)
	if err := ks.Create("m", "password1"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := ks.Create("m2", "password2"); err == nil {
		t.Fatal("Create should refuse to overwrite an existing keystore")
	}
}

func TestCreateRejectsEmptyMnemonic(t *testing.T) {
	ks := newTestKeystore(t)
	if err := ks.Create("", "password1"); err == nil {
		t.Fatal("Create should reject an empty mnemonic")
	}
	if ks.Exists() {
		t.Fatal("Create persisted a keystore for an empty mnemonic")
	}
}

func TestCreateRejectsShortPassword(t *testing.T) {
	ks := newTestKeystore(t)
	if err := ks.Create("m", "1234567"); err == nil {
		t.Fatal("Create should reject a password shorter than 8 characters")
	}
	if ks.Exists() {
		t.Fatal("Create persisted a keystore for a too-short password")
	}
}

func TestContainerFormat(t *testing.T) {
	ks := newTestKeystore(t)
	if err := ks.Create("m", "longpassword"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	blob, err := os.ReadFile(ks.Path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var c struct {
		Version int    `json:"version"`
		KDF     string `json:"kdf"`
		N       int    `json:"n"`
		R       int    `json:"r"`
		P       int    `json:"p"`
	}
	if err := json.Unmarshal(blob, &c); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if c.Version != 1 {
		t.Errorf("version = %d, want 1", c.Version)
	}
	if c.KDF != "scrypt" {
		t.Errorf("kdf = %q, want scrypt", c.KDF)
	}
	if c.N != testKDF.n || c.R != testKDF.r || c.P != testKDF.p {
		t.Errorf("scrypt params = n=%d r=%d p=%d, want n=%d r=%d p=%d",
			c.N, c.R, c.P, testKDF.n, testKDF.r, testKDF.p)
	}
}

// Pins the shipped scrypt cost (the x/crypto-recommended file-encryption
// cost) and the acceptance ranges, without running the KDF.
func TestProductionKDFDefaults(t *testing.T) {
	want := kdfParams{
		n: 1 << 20, r: 8, p: 1,
		minN: 1 << 20, maxN: 1 << 22,
		minR: 8, maxR: 32,
		minP: 1, maxP: 4,
	}
	if productionKDF != want {
		t.Fatalf("productionKDF = %+v, want %+v", productionKDF, want)
	}
	if got := New("unused").params(); got != want {
		t.Fatalf("New().params() = %+v, want %+v", got, want)
	}
}

func TestUnlockRejectsUnknownVersion(t *testing.T) {
	ks := newTestKeystore(t)
	if err := ks.Create("m", "longpassword"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	blob, err := os.ReadFile(ks.Path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	m["version"] = 99
	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(ks.Path, tampered, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := ks.Unlock("longpassword"); err == nil {
		t.Fatal("Unlock should reject an unknown container version")
	} else if errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("unsupported version should not be ErrDecryptFailed: %v", err)
	}
}

// A keystore written with stronger-than-default scrypt params (here p=2) must
// still unlock, so params can be raised later without a format break.
func TestUnlockAcceptsStrongerParams(t *testing.T) {
	ks := newTestKeystore(t)
	const mnemonic = "abandon abandon about"
	const password = "correct horse battery staple"
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	key, err := scrypt.Key([]byte(password), salt, testKDF.n, testKDF.r, testKDF.p+1, 32)
	if err != nil {
		t.Fatalf("scrypt: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}
	ct := gcm.Seal(nil, nonce, []byte(mnemonic), nil)
	blob, err := json.Marshal(map[string]any{
		"version": 1, "kdf": "scrypt", "n": testKDF.n, "r": testKDF.r, "p": testKDF.p + 1,
		"salt":       hex.EncodeToString(salt),
		"nonce":      hex.EncodeToString(nonce),
		"ciphertext": hex.EncodeToString(ct),
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(ks.Path, blob, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := ks.Unlock(password)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if string(got) != mnemonic {
		t.Fatalf("mnemonic mismatch: got %q", got)
	}
}

// A crafted container with sub-minimum scrypt cost must be refused before the
// KDF runs, so an attacker can't swap in a cheap-to-brute-force file.
func TestUnlockRejectsWeakParams(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	blob, err := json.Marshal(map[string]any{
		"version": 1, "kdf": "scrypt", "n": 1 << 10, "r": 8, "p": 1,
		"salt": "00", "nonce": "00", "ciphertext": "00",
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := New(path).Unlock("longpassword"); err == nil {
		t.Fatal("Unlock should reject scrypt params below the production minimum")
	}
}

func TestUnlockRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	junk := bytes.Repeat([]byte("a"), maxContainerLen+1)
	if err := os.WriteFile(path, junk, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := New(path).Unlock("longpassword"); err == nil {
		t.Fatal("Unlock should reject a file larger than maxContainerLen")
	}
}

// Unlock returns mutable bytes so callers can wipe the mnemonic after use.
func TestUnlockReturnsZeroableBytes(t *testing.T) {
	ks := newTestKeystore(t)
	if err := ks.Create("abandon about", "s3cret-pass"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := ks.Unlock("s3cret-pass")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	Zero(got)
	for i, b := range got {
		if b != 0 {
			t.Fatalf("byte %d not zeroed after Zero()", i)
		}
	}
}

func TestCreateWritesOwnerOnlyPermissions(t *testing.T) {
	ks := newTestKeystore(t)
	if err := ks.Create("m", "password1"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	info, err := os.Stat(ks.Path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("keystore permissions = %o, want 600", got)
	}
}
