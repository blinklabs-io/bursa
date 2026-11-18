package connector

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type tokenData struct {
	ExtensionID string `json:"extension_id"`
	PublicKey   string `json:"public_key"`
}

var ErrInvalidExtensionID = errors.New("connector: invalid extension id")

// TokenStore holds the single paired extension's public key, persisted
// atomically. The extension's private key never leaves browser-managed storage.
type TokenStore struct {
	path string
	rnd  func() (string, error)

	mu   sync.RWMutex
	data tokenData
}

// defaultRand creates a test-compatible pairing authority. Production pairing
// supplies the extension-generated public key to Mint.
func defaultRand() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("connector: key generation: %w", err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("connector: encode public key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func NewTokenStore(path string, rnd func() (string, error)) *TokenStore {
	if rnd == nil {
		rnd = defaultRand
	}
	ts := &TokenStore{path: path, rnd: rnd}
	if b, err := os.ReadFile(path); err == nil {
		var data tokenData
		if err := json.Unmarshal(b, &data); err == nil {
			data.ExtensionID = normalizeExtensionID(data.ExtensionID)
			if data.PublicKey != "" && validExtensionID(data.ExtensionID) {
				ts.data = data
			}
		}
	}
	return ts
}

func (s *TokenStore) Mint(extensionID string, suppliedPublicKey ...string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	extensionID = normalizeExtensionID(extensionID)
	if !validExtensionID(extensionID) {
		return "", ErrInvalidExtensionID
	}
	publicKey := ""
	if len(suppliedPublicKey) > 0 {
		publicKey = suppliedPublicKey[0]
		if _, err := parsePublicKey(publicKey); err != nil {
			return "", err
		}
	} else {
		var err error
		publicKey, err = s.rnd()
		if err != nil {
			return "", err
		}
	}
	next := tokenData{ExtensionID: extensionID, PublicKey: publicKey}
	if err := s.persist(next); err != nil {
		return "", err
	}
	s.data = next
	return s.data.PublicKey, nil
}

func (s *TokenStore) Verify(publicKey, extensionID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	extensionID = normalizeExtensionID(extensionID)
	if !validExtensionID(extensionID) {
		return false
	}
	if s.data.PublicKey == "" || s.data.ExtensionID != extensionID {
		return false
	}
	return len(publicKey) == len(s.data.PublicKey) &&
		subtle.ConstantTimeCompare([]byte(publicKey), []byte(s.data.PublicKey)) == 1
}

func (s *TokenStore) VerifySignature(
	extensionID, challenge, method, path string,
	body []byte,
	signature string,
) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	extensionID = normalizeExtensionID(extensionID)
	if s.data.PublicKey == "" || s.data.ExtensionID != extensionID {
		return "", false
	}
	key, err := parsePublicKey(s.data.PublicKey)
	if err != nil {
		return "", false
	}
	rawSignature, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(rawSignature) != 64 {
		return "", false
	}
	digest := sha256.Sum256(canonicalRequest(challenge, method, path, body))
	r := new(big.Int).SetBytes(rawSignature[:32])
	sigS := new(big.Int).SetBytes(rawSignature[32:])
	if !ecdsa.Verify(key, digest[:], r, sigS) {
		return "", false
	}
	return s.data.PublicKey, true
}

func (s *TokenStore) Pair() (string, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.ExtensionID, s.data.PublicKey, s.data.PublicKey != ""
}

// Clear revokes the pairing. Authorization ends immediately. A pairing file that
// cannot be removed is truncated instead, which NewTokenStore loads as no
// pairing; an error is returned only when neither succeeds, so the file may
// authorize again after a restart.
func (s *TokenStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = tokenData{}
	err := os.Remove(s.path)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if truncErr := os.Truncate(s.path, 0); truncErr != nil {
		return fmt.Errorf(
			"connector: pairing revoked but key file not removed: %w",
			errors.Join(err, truncErr),
		)
	}
	return nil
}

func parsePublicKey(encoded string) (*ecdsa.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("connector: invalid public key: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("connector: invalid public key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("connector: public key must use P-256")
	}
	return key, nil
}

func canonicalRequest(challenge, method, path string, body []byte) []byte {
	bodyDigest := sha256.Sum256(body)
	return []byte(
		"bursa-connector-v1\n" + challenge + "\n" + method + "\n" + path + "\n" +
			base64.RawURLEncoding.EncodeToString(bodyDigest[:]),
	)
}

func (s *TokenStore) persist(data tokenData) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".token-*")
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return err
	}
	if err := os.Rename(f.Name(), s.path); err != nil {
		_ = os.Remove(f.Name())
		return err
	}
	return nil
}

func normalizeExtensionID(extensionID string) string {
	extensionID = strings.TrimSpace(extensionID)
	if extensionID == "" || strings.Contains(extensionID, "://") {
		return extensionID
	}
	return "chrome-extension://" + extensionID
}

// validExtensionID accepts the origin of a Chromium or Firefox extension page.
func validExtensionID(extensionID string) bool {
	for _, prefix := range []string{"chrome-extension://", "moz-extension://"} {
		if id, ok := strings.CutPrefix(extensionID, prefix); ok {
			return id != "" && !strings.Contains(id, "/")
		}
	}
	return false
}
