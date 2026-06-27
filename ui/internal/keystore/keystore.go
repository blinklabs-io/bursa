// Package keystore stores the wallet mnemonic encrypted at rest with a spending
// password (scrypt + AES-256-GCM). It is decrypted only transiently, to derive
// signing keys for a single transaction.
package keystore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"unicode/utf8"
)

const (
	containerVersion = 1

	// MinPasswordLen is the minimum spending-password length, exported so the
	// API enforces the same floor before the keystore is ever reached. The
	// password encrypts the mnemonic at rest, so a longer floor raises the cost
	// of brute-forcing the keystore file if it leaks. Length is a coarse proxy
	// for entropy, not a guarantee — a strength estimator could tighten this.
	MinPasswordLen = 12
	keyLen         = 32
	gcmNonceLen    = 12
	saltLen        = 16

	// maxContainerLen caps Unlock's read of the keystore file. A real
	// container is under 1 KiB; anything larger is not one of ours.
	maxContainerLen = 64 * 1024
)

// ErrDecryptFailed is returned when the keystore ciphertext cannot be
// authenticated with the supplied password. AES-GCM cannot distinguish a wrong
// password from ciphertext corruption.
var ErrDecryptFailed = errors.New("keystore decryption failed")

// kdfParams is the scrypt cost Create writes plus the range Unlock accepts,
// so cost can be raised in future releases without a format break, while
// refusing absurd params from a crafted file.
type kdfParams struct {
	n, r, p                            int
	minN, maxN, minR, maxR, minP, maxP int
}

// productionKDF uses the x/crypto/scrypt-recommended cost for file
// encryption (~1 GiB, ~1 s per derivation).
var productionKDF = kdfParams{
	n: 1 << 20, r: 8, p: 1,
	minN: 1 << 20, maxN: 1 << 22,
	minR: 8, maxR: 32,
	minP: 1, maxP: 4,
}

// Keystore is an encrypted mnemonic file at Path (mode 0600).
type Keystore struct {
	Path string

	// kdf overrides productionKDF; only tests set it, to keep scrypt cheap.
	kdf *kdfParams
}

func New(path string) *Keystore { return &Keystore{Path: path} }

func (k *Keystore) params() kdfParams {
	if k.kdf != nil {
		return *k.kdf
	}
	return productionKDF
}

// Exists reports whether a keystore file is present.
func (k *Keystore) Exists() bool {
	_, err := os.Stat(k.Path)
	return err == nil
}

// Create encrypts the mnemonic under password (minimum MinPasswordLen
// characters) and writes the keystore. It refuses to overwrite an existing
// keystore.
func (k *Keystore) Create(mnemonic, password string) error {
	if utf8.RuneCountInString(password) < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if mnemonic == "" {
		return errors.New("mnemonic must not be empty")
	}
	// Fast-fail before the expensive KDF; the O_EXCL open below remains the
	// authoritative overwrite guard.
	if k.Exists() {
		return fmt.Errorf("keystore already exists at %s", k.Path)
	}
	c, err := encrypt([]byte(mnemonic), password, k.params())
	if err != nil {
		return err
	}
	blob, err := json.Marshal(c)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(k.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("keystore already exists at %s", k.Path)
		}
		return err
	}
	n, err := f.Write(blob)
	if err == nil && n != len(blob) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		// Remove the partial file: leaving it behind would block every
		// future Create via the write-once guard above.
		_ = os.Remove(k.Path)
		return err
	}
	return nil
}

// Unlock decrypts and returns the mnemonic. A wrong password or tampered file
// fails (AES-GCM authentication). Callers should Zero the returned bytes as
// soon as the mnemonic is no longer needed.
func (k *Keystore) Unlock(password string) ([]byte, error) {
	f, err := os.Open(k.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	blob, err := io.ReadAll(io.LimitReader(f, maxContainerLen+1))
	if err != nil {
		return nil, err
	}
	if len(blob) > maxContainerLen {
		return nil, fmt.Errorf("keystore file exceeds %d bytes", maxContainerLen)
	}
	var c container
	if err := json.Unmarshal(blob, &c); err != nil {
		return nil, fmt.Errorf("not a keystore container: %w", err)
	}
	return decrypt(c, password, k.params())
}

// Zero overwrites b in place, e.g. a mnemonic returned by Unlock once signing
// keys have been derived from it.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
