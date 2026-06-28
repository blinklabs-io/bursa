package connector

import (
	"sort"
	"testing"
)

func TestGrantStore(t *testing.T) {
	path := t.TempDir() + "/grants.json"
	g := NewGrantStore(path)
	if g.IsGranted("https://a.io") {
		t.Fatal("nothing granted yet")
	}
	if err := g.Grant("https://a.io"); err != nil {
		t.Fatal(err)
	}
	if err := g.Grant("https://b.io"); err != nil {
		t.Fatal(err)
	}
	if !g.IsGranted("https://a.io") {
		t.Fatal("a.io should be granted")
	}
	// survives reload
	g2 := NewGrantStore(path)
	got := g2.List()
	sort.Strings(got)
	if len(got) != 2 || got[0] != "https://a.io" || got[1] != "https://b.io" {
		t.Fatalf("reload list = %v", got)
	}
	if err := g2.Revoke("https://a.io"); err != nil {
		t.Fatal(err)
	}
	if g2.IsGranted("https://a.io") {
		t.Fatal("a.io revoked")
	}
}
