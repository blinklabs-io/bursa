package connector

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestGrantStore(t *testing.T) {
	path := t.TempDir() + "/grants.json"
	g := NewGrantStore(path)
	identity := accountIdentity{WalletID: "wallet-a", AccountIndex: 0}
	if g.IsGranted("https://a.io", identity) {
		t.Fatal("nothing granted yet")
	}
	if err := g.Grant("https://a.io", identity); err != nil {
		t.Fatal(err)
	}
	if err := g.Grant("https://b.io", identity); err != nil {
		t.Fatal(err)
	}
	if !g.IsGranted("https://a.io", identity) {
		t.Fatal("a.io should be granted")
	}
	// survives reload
	g2 := NewGrantStore(path)
	got := g2.List(identity)
	sort.Strings(got)
	if len(got) != 2 || got[0] != "https://a.io" || got[1] != "https://b.io" {
		t.Fatalf("reload list = %v", got)
	}
	if g2.IsGranted("https://a.io", accountIdentity{WalletID: "wallet-a", AccountIndex: 1}) {
		t.Fatal("account 0 grant must not authorize account 1")
	}
	if g2.IsGranted("https://a.io", accountIdentity{WalletID: "wallet-b", AccountIndex: 0}) {
		t.Fatal("wallet-a grant must not authorize wallet-b")
	}
	if err := g2.Revoke("https://a.io", identity); err != nil {
		t.Fatal(err)
	}
	if g2.IsGranted("https://a.io", identity) {
		t.Fatal("a.io revoked")
	}
}

func TestGrantStoreRejectsInvalidOrigins(t *testing.T) {
	path := t.TempDir() + "/grants.json"
	g := NewGrantStore(path)
	identity := accountIdentity{WalletID: "wallet-a", AccountIndex: 0}

	for _, origin := range []string{
		"",
		" ",
		"unknown",
		"https://a.io/path",
		"http://localhost:8080/sample-dapp.html",
		"file:///tmp/sample-dapp.html",
		"null",
		"https://user@example.com",
		"https://user:pass@example.com",
		"chrome-extension://abc",
	} {
		if err := g.Grant(origin, identity); !errors.Is(err, ErrInvalidOrigin) {
			t.Fatalf("Grant(%q) err = %v, want ErrInvalidOrigin", origin, err)
		}
		if g.IsGranted(origin, identity) {
			t.Fatalf("invalid origin %q should not be granted", origin)
		}
	}
	if got := g.List(identity); len(got) != 0 {
		t.Fatalf("invalid grants persisted in memory: %v", got)
	}
}

func TestGrantStoreAcceptsExactHTTPOrigins(t *testing.T) {
	g := NewGrantStore(filepath.Join(t.TempDir(), "grants.json"))
	identity := accountIdentity{WalletID: "wallet-a", AccountIndex: 0}
	for _, origin := range []string{
		"http://localhost:8080",
		"https://dapp.example",
	} {
		if err := g.Grant(origin, identity); err != nil {
			t.Fatalf("Grant(%q) err = %v, want success", origin, err)
		}
		if !g.IsGranted(origin, identity) {
			t.Fatalf("origin %q was not granted", origin)
		}
	}
}

func TestGrantStoreIgnoresLegacyOriginOnlyPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grants.json")
	b, err := json.Marshal([]string{"", "https://user@example.com", "https://valid.example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	g := NewGrantStore(path)
	identity := accountIdentity{WalletID: "wallet-a", AccountIndex: 0}
	if g.IsGranted("https://valid.example", identity) {
		t.Fatal("origin-only persisted grant must not authorize a wallet account")
	}
	if got := g.List(identity); len(got) != 0 {
		t.Fatalf("legacy origin-only grants loaded: %v", got)
	}
}
