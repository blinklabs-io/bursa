package connector

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type tokenData struct {
	ExtensionID string `json:"extension_id"`
	Token       string `json:"token"`
}

var ErrInvalidExtensionID = errors.New("connector: invalid extension id")

// TokenStore holds the single paired-extension token, persisted atomically.
type TokenStore struct {
	path string
	rnd  func() (string, error)

	mu   sync.RWMutex
	data tokenData
}

// defaultRand mints a 32-byte random token. It fails closed: a crypto/rand
// failure must never produce a predictable (zeroed) token, so the error is
// surfaced to the caller rather than ignored.
func defaultRand() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("connector: token entropy: %w", err)
	}
	return hex.EncodeToString(b), nil
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
			if data.Token != "" && validExtensionID(data.ExtensionID) {
				ts.data = data
			}
		}
	}
	return ts
}

func (s *TokenStore) Mint(extensionID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	extensionID = normalizeExtensionID(extensionID)
	if !validExtensionID(extensionID) {
		return "", ErrInvalidExtensionID
	}
	tok, err := s.rnd()
	if err != nil {
		return "", err
	}
	next := tokenData{ExtensionID: extensionID, Token: tok}
	if err := s.persist(next); err != nil {
		return "", err
	}
	s.data = next
	return s.data.Token, nil
}

func (s *TokenStore) Verify(token, extensionID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	extensionID = normalizeExtensionID(extensionID)
	if !validExtensionID(extensionID) {
		return false
	}
	if s.data.Token == "" || s.data.ExtensionID != extensionID {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.data.Token)) == 1
}

func (s *TokenStore) Pair() (string, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.ExtensionID, s.data.Token, s.data.Token != ""
}

func (s *TokenStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	s.data = tokenData{}
	return nil
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

func validExtensionID(extensionID string) bool {
	const prefix = "chrome-extension://"
	if !strings.HasPrefix(extensionID, prefix) {
		return false
	}
	id := strings.TrimPrefix(extensionID, prefix)
	return id != "" && !strings.Contains(id, "/")
}
