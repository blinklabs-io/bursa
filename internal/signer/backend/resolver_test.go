// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package backend

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/blinklabs-io/bursa"
)

func mkSoftware(t *testing.T, name string) (*SoftwareBackend, KeyHash) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	b := NewSoftwareBackend(name)
	h, err := b.AddKey(&bursa.LoadedKey{SKey: []byte(priv), VKey: priv.Public().(ed25519.PublicKey)}, KeyTypePayment)
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	return b, h
}

func TestResolver_Resolve(t *testing.T) {
	b1, h1 := mkSoftware(t, "a")
	b2, h2 := mkSoftware(t, "b")
	r := NewResolver(b1, b2)

	ref, err := r.Resolve(context.Background(), h2, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ref.Backend() != "b" {
		t.Fatalf("expected backend b, got %s", ref.Backend())
	}
	if _, err := r.Resolve(context.Background(), h1, ""); err != nil {
		t.Fatalf("Resolve h1: %v", err)
	}

	var missing KeyHash
	if _, err := r.Resolve(context.Background(), missing, ""); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestResolver_ListKeys(t *testing.T) {
	b1, _ := mkSoftware(t, "a")
	b2, _ := mkSoftware(t, "b")
	r := NewResolver(b1, b2)
	keys, err := r.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
}

// TestCheckAmbiguous verifies that the same key hash present in two backends
// is detected as a config error at startup.
func TestCheckAmbiguous(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	lk := &bursa.LoadedKey{SKey: []byte(priv), VKey: priv.Public().(ed25519.PublicKey)}

	b1 := NewSoftwareBackend("primary")
	b2 := NewSoftwareBackend("secondary")
	if _, err := b1.AddKey(lk, KeyTypePayment); err != nil {
		t.Fatalf("AddKey b1: %v", err)
	}
	if _, err := b2.AddKey(lk, KeyTypePayment); err != nil {
		t.Fatalf("AddKey b2: %v", err)
	}

	// Two distinct backends with unique keys — no conflict.
	bUniq1, _ := mkSoftware(t, "u1")
	bUniq2, _ := mkSoftware(t, "u2")
	if err := NewResolver(bUniq1, bUniq2).CheckAmbiguous(context.Background()); err != nil {
		t.Errorf("expected no error for distinct keys, got: %v", err)
	}

	// Same key in both backends — must be rejected.
	if err := NewResolver(b1, b2).CheckAmbiguous(context.Background()); err == nil {
		t.Error("expected error for duplicate key hash across backends, got nil")
	}
}

// profiledBackend binds a backend to a profile for routing tests.
type profiledBackend struct {
	Backend
	profile string
}

func (b profiledBackend) Profile() string { return b.profile }

// mkSharedKey loads one key into a software backend per name and returns the
// backends and the shared hash.
func mkSharedKey(t *testing.T, names ...string) ([]*SoftwareBackend, KeyHash) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	lk := &bursa.LoadedKey{SKey: []byte(priv), VKey: priv.Public().(ed25519.PublicKey)}
	var out []*SoftwareBackend
	var h KeyHash
	for _, n := range names {
		b := NewSoftwareBackend(n)
		var err error
		if h, err = b.AddKey(lk, KeyTypePool); err != nil {
			t.Fatalf("AddKey: %v", err)
		}
		out = append(out, b)
	}
	return out, h
}

func TestResolver_ProfileRouting(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	bs, h := mkSharedKey(t, "preview-dev", "musashi-dev", "plain-dev")
	preview := profiledBackend{bs[0], "otg@preview"}
	musashi := profiledBackend{bs[1], "otg@musashi"}
	plain := bs[2]

	t.Run("no profile, one unprofiled holder", func(t *testing.T) {
		t.Parallel()
		ref, err := NewResolver(plain).Resolve(ctx, h, "")
		if err != nil || ref.Backend() != "plain-dev" {
			t.Fatalf("got %v, %v", ref, err)
		}
	})
	t.Run("no profile, one profiled holder", func(t *testing.T) {
		t.Parallel()
		ref, err := NewResolver(preview).Resolve(ctx, h, "")
		if err != nil || ref.Backend() != "preview-dev" {
			t.Fatalf("got %v, %v", ref, err)
		}
	})
	t.Run("no profile, several holders", func(t *testing.T) {
		t.Parallel()
		_, err := NewResolver(preview, musashi).Resolve(ctx, h, "")
		if !errors.Is(err, ErrProfileRequired) {
			t.Fatalf("want ErrProfileRequired, got %v", err)
		}
	})
	t.Run("profile selects its holder", func(t *testing.T) {
		t.Parallel()
		r := NewResolver(preview, musashi)
		for profile, want := range map[string]string{"otg@preview": "preview-dev", "otg@musashi": "musashi-dev"} {
			ref, err := r.Resolve(ctx, h, profile)
			if err != nil || ref.Backend() != want {
				t.Fatalf("profile %s: got %v, %v want %s", profile, ref, err, want)
			}
		}
	})
	t.Run("profile with no matching holder", func(t *testing.T) {
		t.Parallel()
		for name, r := range map[string]*Resolver{
			"other profile only": NewResolver(preview),
			"unprofiled only":    NewResolver(plain),
			"unknown profile":    NewResolver(preview, musashi),
		} {
			if _, err := r.Resolve(ctx, h, "otg@preprod"); !errors.Is(err, ErrKeyNotFound) {
				t.Fatalf("%s: want ErrKeyNotFound, got %v", name, err)
			}
		}
	})
}

func TestCheckAmbiguous_Profiles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	bs, _ := mkSharedKey(t, "a", "b", "c")
	cases := []struct {
		name     string
		backends []Backend
		wantErr  bool
	}{
		{"distinct profiles", []Backend{profiledBackend{bs[0], "p1"}, profiledBackend{bs[1], "p2"}, profiledBackend{bs[2], "p3"}}, false},
		{"profiled and unprofiled", []Backend{profiledBackend{bs[0], "p1"}, bs[1]}, true},
		{"unprofiled and profiled", []Backend{bs[0], profiledBackend{bs[1], "p1"}}, true},
		{"same profile twice", []Backend{profiledBackend{bs[0], "p1"}, profiledBackend{bs[1], "p1"}}, true},
		{"two unprofiled", []Backend{bs[0], bs[1]}, true},
		{"third holder repeats a profile", []Backend{profiledBackend{bs[0], "p1"}, profiledBackend{bs[1], "p2"}, profiledBackend{bs[2], "p1"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := NewResolver(tc.backends...).CheckAmbiguous(ctx)
			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr=%v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestAttestedBackend_Profile(t *testing.T) {
	t.Parallel()
	if got := NewProfiledAttestedBackend("n", "otg@preview", nil, nil).Profile(); got != "otg@preview" {
		t.Fatalf("profile = %q", got)
	}
	if got := NewAttestedBackend("n", nil, nil).Profile(); got != "" {
		t.Fatalf("unprofiled backend profile = %q", got)
	}
}
