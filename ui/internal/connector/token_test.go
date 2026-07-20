package connector

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestTokenStoreMintVerify(t *testing.T) {
	seq := 0
	ts := NewTokenStore(t.TempDir()+"/token.json", func() (string, error) { seq++; return "tok", nil })
	tok, err := ts.Mint("abc")
	if err != nil || tok != "tok" {
		t.Fatalf("mint: %q %v", tok, err)
	}
	if !ts.Verify("tok", "chrome-extension://abc") {
		t.Fatal("verify should pass for matching token+chrome-extension origin")
	}
	if ts.Verify("tok", "chrome-extension://evil") {
		t.Fatal("verify must fail for wrong extension id")
	}
	if ts.Verify("wrong", "chrome-extension://abc") {
		t.Fatal("verify must fail for wrong token")
	}
}

func TestTokenStoreMintDoesNotChangeMemoryOnPersistFailure(t *testing.T) {
	blockedPath := t.TempDir()
	ts := NewTokenStore(blockedPath, func() (string, error) { return "tok", nil })
	if _, err := ts.Mint("abc"); err == nil {
		t.Fatal("Mint to a directory path should fail")
	}
	if ts.Verify("tok", "chrome-extension://abc") {
		t.Fatal("failed Mint must not leave token in memory")
	}
}

func TestTokenStoreRejectsInvalidExtensionIDs(t *testing.T) {
	calls := 0
	ts := NewTokenStore(t.TempDir()+"/token.json", func() (string, error) {
		calls++
		return "tok", nil
	})
	for _, extID := range []string{"", "https://example.com", "moz-extension://abc", "chrome-extension://"} {
		if _, err := ts.Mint(extID); !errors.Is(err, ErrInvalidExtensionID) {
			t.Fatalf("Mint(%q) error = %v, want ErrInvalidExtensionID", extID, err)
		}
		if ts.Verify("tok", extID) {
			t.Fatalf("Verify(%q) should fail for invalid extension id", extID)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid Mint called random source %d times, want 0", calls)
	}
}

func TestTokenStoreClearKeepsMemoryOnRemoveFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	ts := NewTokenStore(path, func() (string, error) { return "tok", nil })
	if _, err := ts.Mint("abc"); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	blockedDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(blockedDir, "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts.path = blockedDir
	if err := ts.Clear(); err == nil {
		t.Fatal("Clear on non-empty directory path should fail")
	}
	if !ts.Verify("tok", "chrome-extension://abc") {
		t.Fatal("failed Clear must keep token in memory")
	}
}

func TestTokenStorePersistsAndClears(t *testing.T) {
	path := t.TempDir() + "/token.json"
	a := NewTokenStore(path, func() (string, error) { return "tok", nil })
	if _, err := a.Mint("ext1"); err != nil {
		t.Fatal(err)
	}
	b := NewTokenStore(path, func() (string, error) { return "tok", nil })
	if !b.Verify("tok", "ext1") {
		t.Fatal("token should survive reload")
	}
	if err := b.Clear(); err != nil {
		t.Fatal(err)
	}
	c := NewTokenStore(path, func() (string, error) { return "tok", nil })
	if c.Verify("tok", "ext1") {
		t.Fatal("cleared token must not verify")
	}
}

func TestTokenStoreLoadsOnlyValidPersistedPairings(t *testing.T) {
	dir := t.TempDir()

	validPath := filepath.Join(dir, "valid-token.json")
	if err := os.WriteFile(validPath, []byte(`{"extension_id":"abc","token":"tok"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := NewTokenStore(validPath, func() (string, error) { return "unused", nil })
	extID, tok, ok := valid.Pair()
	if !ok || extID != "chrome-extension://abc" || tok != "tok" {
		t.Fatalf("Pair() = (%q, %q, %v), want normalized valid persisted pair", extID, tok, ok)
	}

	invalidPath := filepath.Join(dir, "invalid-token.json")
	if err := os.WriteFile(invalidPath, []byte(`{"extension_id":"https://evil.example","token":"tok"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	invalid := NewTokenStore(invalidPath, func() (string, error) { return "unused", nil })
	extID, tok, ok = invalid.Pair()
	if ok || extID != "" || tok != "" {
		t.Fatalf("Pair() = (%q, %q, %v), want invalid persisted pair ignored", extID, tok, ok)
	}
}

func TestTokenStoreClearWhenAbsent(t *testing.T) {
	ts := NewTokenStore(t.TempDir()+"/token.json", func() (string, error) { return "tok", nil })
	if err := ts.Clear(); err != nil {
		t.Fatalf("Clear on never-minted store should return nil, got %v", err)
	}
}
