package connector

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type accountIdentity struct {
	WalletID     string `json:"wallet_id"`
	AccountIndex uint32 `json:"account_index"`
}

func (i accountIdentity) valid() bool {
	return i.WalletID != "" && strings.TrimSpace(i.WalletID) == i.WalletID && i.AccountIndex < 1<<31
}

type grant struct {
	Origin       string `json:"origin"`
	WalletID     string `json:"wallet_id"`
	AccountIndex uint32 `json:"account_index"`
}

func (g grant) identity() accountIdentity {
	return accountIdentity{WalletID: g.WalletID, AccountIndex: g.AccountIndex}
}

// GrantStore is the set of dApp origins the user has approved for a specific
// wallet and CIP-1852 account.
type GrantStore struct {
	path string
	mu   sync.RWMutex
	set  map[grant]bool
}

func NewGrantStore(path string) *GrantStore {
	g := &GrantStore{path: path, set: map[grant]bool{}}
	if b, err := os.ReadFile(path); err == nil {
		var grants []grant
		if json.Unmarshal(b, &grants) == nil {
			for _, item := range grants {
				if validDAppOrigin(item.Origin) && item.identity().valid() {
					g.set[item] = true
				}
			}
		}
	}
	return g
}

func (g *GrantStore) Grant(origin string, identity accountIdentity) error {
	if !validDAppOrigin(origin) {
		return ErrInvalidOrigin
	}
	if !identity.valid() {
		return ErrNotGranted
	}
	item := grant{Origin: origin, WalletID: identity.WalletID, AccountIndex: identity.AccountIndex}
	return g.mutate(func(s map[grant]bool) { s[item] = true })
}

func (g *GrantStore) Revoke(origin string, identity accountIdentity) error {
	if !validDAppOrigin(origin) {
		return ErrInvalidOrigin
	}
	if !identity.valid() {
		return ErrNotGranted
	}
	item := grant{Origin: origin, WalletID: identity.WalletID, AccountIndex: identity.AccountIndex}
	return g.mutate(func(s map[grant]bool) { delete(s, item) })
}

func (g *GrantStore) IsGranted(origin string, identity accountIdentity) bool {
	if !validDAppOrigin(origin) || !identity.valid() {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.set[grant{Origin: origin, WalletID: identity.WalletID, AccountIndex: identity.AccountIndex}]
}

func (g *GrantStore) List(identity accountIdentity) []string {
	if !identity.valid() {
		return nil
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]string, 0, len(g.set))
	for item := range g.set {
		if item.identity() == identity {
			out = append(out, item.Origin)
		}
	}
	sort.Strings(out)
	return out
}

// mutate applies fn to a COPY of the grant set, persists the result, and only
// swaps the live set in once the write succeeds. A failed Grant/Revoke therefore
// leaves the in-memory authorization state unchanged (no phantom grant or
// orphaned revocation when the disk write fails).
func (g *GrantStore) mutate(fn func(map[grant]bool)) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	next := make(map[grant]bool, len(g.set))
	for item := range g.set {
		next[item] = true
	}
	fn(next)

	out := make([]grant, 0, len(next))
	for item := range next {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Origin != out[j].Origin {
			return out[i].Origin < out[j].Origin
		}
		if out[i].WalletID != out[j].WalletID {
			return out[i].WalletID < out[j].WalletID
		}
		return out[i].AccountIndex < out[j].AccountIndex
	})
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
