package connector

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// GrantStore is the set of dApp origins the user has approved to connect.
type GrantStore struct {
	path string
	mu   sync.RWMutex
	set  map[string]bool
}

func NewGrantStore(path string) *GrantStore {
	g := &GrantStore{path: path, set: map[string]bool{}}
	if b, err := os.ReadFile(path); err == nil {
		var origins []string
		if json.Unmarshal(b, &origins) == nil {
			for _, o := range origins {
				if validDAppOrigin(o) {
					g.set[o] = true
				}
			}
		}
	}
	return g
}

func (g *GrantStore) Grant(origin string) error {
	if !validDAppOrigin(origin) {
		return ErrInvalidOrigin
	}
	return g.mutate(func(s map[string]bool) { s[origin] = true })
}

func (g *GrantStore) Revoke(origin string) error {
	if !validDAppOrigin(origin) {
		return ErrInvalidOrigin
	}
	return g.mutate(func(s map[string]bool) { delete(s, origin) })
}

func (g *GrantStore) IsGranted(origin string) bool {
	if !validDAppOrigin(origin) {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.set[origin]
}

func (g *GrantStore) List() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]string, 0, len(g.set))
	for o := range g.set {
		out = append(out, o)
	}
	return out
}

// mutate applies fn to a COPY of the grant set, persists the result, and only
// swaps the live set in once the write succeeds. A failed Grant/Revoke therefore
// leaves the in-memory authorization state unchanged (no phantom grant or
// orphaned revocation when the disk write fails).
func (g *GrantStore) mutate(fn func(map[string]bool)) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	next := make(map[string]bool, len(g.set))
	for o := range g.set {
		next[o] = true
	}
	fn(next)

	out := make([]string, 0, len(next))
	for o := range next {
		out = append(out, o)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	tmp := g.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(g.path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, g.path); err != nil {
		return err
	}

	// Persistence succeeded — commit the new set.
	g.set = next
	return nil
}

func validDAppOrigin(origin string) bool {
	if strings.TrimSpace(origin) != origin || origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	if u.User != nil {
		return false
	}
	if u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}
