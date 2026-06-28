package connector

import "testing"

func TestTokenStoreMintVerify(t *testing.T) {
	seq := 0
	ts := NewTokenStore(t.TempDir()+"/token.json", nil, func() (string, error) { seq++; return "tok", nil })
	tok, err := ts.Mint("chrome-extension://abc")
	if err != nil || tok != "tok" {
		t.Fatalf("mint: %q %v", tok, err)
	}
	if !ts.Verify("tok", "chrome-extension://abc") {
		t.Fatal("verify should pass for matching token+id")
	}
	if ts.Verify("tok", "chrome-extension://evil") {
		t.Fatal("verify must fail for wrong extension id")
	}
	if ts.Verify("wrong", "chrome-extension://abc") {
		t.Fatal("verify must fail for wrong token")
	}
}

func TestTokenStorePersistsAndClears(t *testing.T) {
	path := t.TempDir() + "/token.json"
	a := NewTokenStore(path, nil, func() (string, error) { return "tok", nil })
	if _, err := a.Mint("ext1"); err != nil {
		t.Fatal(err)
	}
	b := NewTokenStore(path, nil, func() (string, error) { return "tok", nil })
	if !b.Verify("tok", "ext1") {
		t.Fatal("token should survive reload")
	}
	if err := b.Clear(); err != nil {
		t.Fatal(err)
	}
	c := NewTokenStore(path, nil, func() (string, error) { return "tok", nil })
	if c.Verify("tok", "ext1") {
		t.Fatal("cleared token must not verify")
	}
}

func TestTokenStoreClearWhenAbsent(t *testing.T) {
	ts := NewTokenStore(t.TempDir()+"/token.json", nil, func() (string, error) { return "tok", nil })
	if err := ts.Clear(); err != nil {
		t.Fatalf("Clear on never-minted store should return nil, got %v", err)
	}
}
