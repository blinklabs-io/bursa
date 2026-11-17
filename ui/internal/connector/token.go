package connector

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/blinklabs-io/bursa/ui/internal/atomicfile"
)

type tokenData struct {
	ExtensionID string `json:"extension_id"`
	Token       string `json:"token"`
}

var (
	ErrInvalidExtensionID = errors.New("connector: invalid extension id")

	syncDirectory   = atomicfile.SyncDir
	replaceAuthFile = atomicfile.Replace
	removeAuthFile  = atomicfile.Remove
	syncTokenFile   = func(f *os.File) error { return f.Sync() }
)

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
	token, _, err := s.mint(extensionID)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *TokenStore) mint(
	extensionID string,
) (token string, committed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	extensionID = normalizeExtensionID(extensionID)
	if !validExtensionID(extensionID) {
		return "", false, ErrInvalidExtensionID
	}
	tok, err := s.rnd()
	if err != nil {
		return "", false, err
	}
	next := tokenData{ExtensionID: extensionID, Token: tok}
	committed, err = s.persist(next)
	if committed {
		s.data = next
	}
	return next.Token, committed, err
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

// Clear revokes the pairing. Authorization ends immediately. A token file that
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
		return fmt.Errorf(
			"connector: pairing revoked but token file not removed: %w",
			errors.Join(err, truncErr),
		)
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

func (s *TokenStore) persist(data tokenData) (committed bool, err error) {
	b, err := json.Marshal(data)
	if err != nil {
		return false, err
	}
	return replaceAuthFile(s.path, b, syncDirectory)
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
