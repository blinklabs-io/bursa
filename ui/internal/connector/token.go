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
	"math/big"
	"os"
	"strings"
	"sync"

	"github.com/blinklabs-io/bursa/ui/internal/atomicfile"
)

type tokenData struct {
	ExtensionID string `json:"extension_id"`
	PublicKey   string `json:"public_key"`
	Binding     string `json:"binding"`
}

var (
	ErrInvalidExtensionID = errors.New("connector: invalid extension id")
	syncDirectory         = atomicfile.SyncDir
	replaceAuthFile       = atomicfile.Replace
	removeAuthFile        = atomicfile.Remove
	syncTokenFile         = func(f *os.File) error { return f.Sync() }
)

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
			data.ExtensionID = NormalizeExtensionID(data.ExtensionID)
			if data.PublicKey != "" && validExtensionID(data.ExtensionID) {
				ts.data = data
			}
		}
	}
	return ts
}

func (s *TokenStore) Mint(extensionID string, suppliedPublicKey ...string) (string, error) {
	key, _, err := s.mint(extensionID, suppliedPublicKey...)
	if err != nil {
		return "", err
	}
	return key, nil
}

func (s *TokenStore) mint(extensionID string, suppliedPublicKey ...string) (publicKey string, committed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	extensionID = NormalizeExtensionID(extensionID)
	if !validExtensionID(extensionID) {
		return "", false, ErrInvalidExtensionID
	}
	if len(suppliedPublicKey) > 0 {
		publicKey = suppliedPublicKey[0]
		if _, err := parsePublicKey(publicKey); err != nil {
			return "", false, err
		}
	} else {
		var err error
		publicKey, err = s.rnd()
		if err != nil {
			return "", false, err
		}
	}
	binding := make([]byte, 32)
	if _, err := rand.Read(binding); err != nil {
		return "", false, err
	}
	next := tokenData{ExtensionID: extensionID, PublicKey: publicKey, Binding: base64.RawURLEncoding.EncodeToString(binding)}
	committed, err = s.persist(next)
	if committed {
		s.data = next
	}
	return next.PublicKey, committed, err
}

func (s *TokenStore) Verify(publicKey, extensionID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	extensionID = NormalizeExtensionID(extensionID)
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
	extensionID = NormalizeExtensionID(extensionID)
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
	return s.authorityLocked(), true
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
	removed, err := removeAuthFile(s.path, syncDirectory)
	if err == nil {
		return nil
	}
	if removed {
		return err
	}
	if truncErr := truncateTokenFile(s.path); truncErr != nil {
		return fmt.Errorf("connector: pairing revoked but key file not removed: %w", errors.Join(err, truncErr))
	}
	return nil
}

func truncateTokenFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	if err := syncTokenFile(f); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
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

func (s *TokenStore) persist(data tokenData) (committed bool, err error) {
	b, err := json.Marshal(data)
	if err != nil {
		return false, err
	}
	return replaceAuthFile(s.path, b, syncDirectory)
}

// NormalizeExtensionID accepts raw Chromium IDs and full extension origins.
func NormalizeExtensionID(extensionID string) string {
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

// authorityLocked identifies one binding even when the extension reuses its key.
func (s *TokenStore) authorityLocked() string {
	return s.data.PublicKey + "." + s.data.Binding
}

// VerifyAuthority accepts only the current key and binding generation.
func (s *TokenStore) VerifyAuthority(authority, extensionID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.PublicKey != "" && NormalizeExtensionID(extensionID) == s.data.ExtensionID &&
		subtle.ConstantTimeCompare([]byte(authority), []byte(s.authorityLocked())) == 1
}

// Authority returns the identifier of the current pairing binding.
func (s *TokenStore) Authority() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.authorityLocked()
}
