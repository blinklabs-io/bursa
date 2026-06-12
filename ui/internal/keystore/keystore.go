// Package keystore stores the wallet mnemonic encrypted at rest with a spending
// password (scrypt + AES-256-GCM). It is decrypted only transiently, to derive
// signing keys for a single transaction.
package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"
)

const (
	containerVersion = 1

	minPasswordLen = 8
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

type container struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	N          int    `json:"n"`
	R          int    `json:"r"`
	P          int    `json:"p"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// Create encrypts the mnemonic under password (minimum 8 characters) and
// writes the keystore. It refuses to overwrite an existing keystore.
func (k *Keystore) Create(mnemonic, password string) error {
	if utf8.RuneCountInString(password) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	if mnemonic == "" {
		return errors.New("mnemonic must not be empty")
	}
	// Fast-fail before the expensive KDF; the O_EXCL open below remains the
	// authoritative overwrite guard.
	if k.Exists() {
		return fmt.Errorf("keystore already exists at %s", k.Path)
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	kdf := k.params()
	key, err := scrypt.Key([]byte(password), salt, kdf.n, kdf.r, kdf.p, keyLen)
	if err != nil {
		return fmt.Errorf("scrypt: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := gcm.Seal(nil, nonce, []byte(mnemonic), nil)
	blob, err := json.Marshal(container{
		Version: containerVersion,
		KDF:     "scrypt", N: kdf.n, R: kdf.r, P: kdf.p,
		Salt: hex.EncodeToString(salt), Nonce: hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ct),
	})
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
	if c.Version != containerVersion {
		return nil, fmt.Errorf("unsupported keystore version %d", c.Version)
	}
	kdf := k.params()
	if c.KDF != "scrypt" ||
		c.N < kdf.minN || c.N > kdf.maxN ||
		c.R < kdf.minR || c.R > kdf.maxR ||
		c.P < kdf.minP || c.P > kdf.maxP {
		return nil, fmt.Errorf("unsupported KDF params (kdf=%q n=%d r=%d p=%d)", c.KDF, c.N, c.R, c.P)
	}
	salt, err := hex.DecodeString(c.Salt)
	if err != nil {
		return nil, err
	}
	nonce, err := hex.DecodeString(c.Nonce)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcmNonceLen {
		return nil, fmt.Errorf("invalid nonce length %d", len(nonce))
	}
	ct, err := hex.DecodeString(c.Ciphertext)
	if err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(password), salt, c.N, c.R, c.P, keyLen)
	if err != nil {
		return nil, fmt.Errorf("scrypt: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: wrong password or corrupt keystore", ErrDecryptFailed)
	}
	return pt, nil
}

// Zero overwrites b in place, e.g. a mnemonic returned by Unlock once signing
// keys have been derived from it.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
