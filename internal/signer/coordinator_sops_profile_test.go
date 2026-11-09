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

package signer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
)

// memSecretSource serves already-decrypted key envelopes.
type memSecretSource map[string][]byte

func (m memSecretSource) List(context.Context) ([]string, error) {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out, nil
}

func (m memSecretSource) Get(_ context.Context, name string) ([]byte, error) {
	if v, ok := m[name]; ok {
		return v, nil
	}
	return nil, fmt.Errorf("no secret %q", name)
}

const sopsProfileSeedByte = 0x5a

func sopsPoolEnvelope() []byte {
	return fmt.Appendf(nil,
		`{"type":"StakePoolSigningKey_ed25519","description":"Stake Pool Operator Signing Key","cborHex":"5820%x"}`,
		bytes.Repeat([]byte{sopsProfileSeedByte}, 32),
	)
}

// newSopsProfileBackend loads the one pool cold key into an in-memory sops
// backend under profile ("" for an unprofiled backend).
func newSopsProfileBackend(t *testing.T, name, profile string) *backend.SopsBackend {
	t.Helper()
	b := backend.NewProfiledSopsBackend(
		name,
		profile,
		memSecretSource{"cold.skey.json": sopsPoolEnvelope()},
		func(d []byte) ([]byte, error) { return d, nil },
	)
	b.Register("cold.skey.json", "")
	if err := b.Load(context.Background()); err != nil {
		t.Fatalf("Load %s: %v", name, err)
	}
	return b
}

func newSopsProfileCoordinator(
	t *testing.T,
	backends ...backend.Backend,
) (*Coordinator, *watermark.MemWatermark, backend.KeyHash) {
	t.Helper()
	keys, err := backends[0].ListKeys(context.Background())
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListKeys: %v len=%d", err, len(keys))
	}
	hash := keys[0].Hash()
	eng, err := policy.NewEngine([]policy.KeyPolicy{{
		Hash:            hash.String(),
		AllowedRequests: []string{"opcert"},
	}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	wm := watermark.NewMemWatermark()
	return New(Deps{
		Resolver:  backend.NewResolver(backends...),
		Policy:    eng,
		Watermark: wm,
		WMMode:    watermark.ModeEnforce,
		Metrics:   NewMetrics(),
	}), wm, hash
}

// Two sops backends holding one cold key under distinct profiles keep
// independent opcert counters, chain floors and issued records.
func TestSopsProfile_IndependentHistories(t *testing.T) {
	t.Parallel()
	c, wm, hash := newSopsProfileCoordinator(t,
		newSopsProfileBackend(t, "cold-preview", profPreview),
		newSopsProfileBackend(t, "cold-musashi", profMusashi))
	kes := make([]byte, kesVkeySize)
	id := hash.String()
	preview := WithProfile(context.Background(), profPreview)
	musashi := WithProfile(context.Background(), profMusashi)
	bg := context.Background()

	res, code, err := c.SignOpCertFromChain(preview, kes, 6, 1, id)
	if err != nil || res.IssueCounter != 7 {
		t.Fatalf("preview chain 6: res=%v code=%s err=%v", res, code, err)
	}
	res, code, err = c.SignOpCertFromChain(musashi, kes, 0, 1, id)
	if err != nil || res.IssueCounter != 1 {
		t.Fatalf("musashi chain 0: res=%v code=%s err=%v", res, code, err)
	}
	if _, code, err = c.SignOpCertFromChain(preview, kes, 0, 1, id); err == nil || code != CodeConflict {
		t.Fatalf("preview chain 0 after 6: want conflict, got code=%s err=%v", code, err)
	}
	if _, code, err = c.SignOpCert(musashi, kes, 2, 1, id); err != nil {
		t.Fatalf("musashi issue 2: code=%s err=%v", code, err)
	}
	if _, code, err = c.SignOpCert(preview, kes, 8, 1, id); err != nil {
		t.Fatalf("preview issue 8: code=%s err=%v", code, err)
	}
	if _, code, err = c.SignOpCert(musashi, kes, 2, 1, id); err == nil || code != CodeConflict {
		t.Fatalf("musashi issue 2 repeat: want conflict, got code=%s err=%v", code, err)
	}

	want := map[string]uint64{
		opcertChainFloorScope + "|" + profPreview:  6,
		opcertChainIssuedScope + "|" + profPreview: 8,
		opcertCounterScope + "|" + profPreview:     8,
		opcertChainFloorScope + "|" + profMusashi:  0,
		opcertChainIssuedScope + "|" + profMusashi: 2,
		opcertCounterScope + "|" + profMusashi:     2,
	}
	for scope, v := range want {
		got, ok, err := wm.CounterFor(bg, hash, scope)
		if err != nil || !ok || got != v {
			t.Errorf("scope %q: got %d ok=%v err=%v, want %d", scope, got, ok, err, v)
		}
	}
	for _, scope := range []string{opcertChainFloorScope, opcertChainIssuedScope, opcertCounterScope} {
		if _, ok, _ := wm.CounterFor(bg, hash, scope); ok {
			t.Errorf("profiled sops key wrote the unprofiled scope %q", scope)
		}
	}
}

// A profiled sops backend refuses a request naming another profile before any
// record is written; a profile-less request is served while it is the only
// holder, and refused once a second profile holds the key.
func TestSopsProfile_RefusesOtherProfile(t *testing.T) {
	t.Parallel()
	kes := make([]byte, kesVkeySize)
	bg := context.Background()

	t.Run("other profile", func(t *testing.T) {
		t.Parallel()
		c, wm, hash := newSopsProfileCoordinator(t, newSopsProfileBackend(t, "cold-preview", profPreview))
		_, code, err := c.SignOpCertFromChain(WithProfile(bg, profMusashi), kes, 3, 1, hash.String())
		if err == nil || code != CodeNotFound {
			t.Fatalf("code=%s err=%v, want not found", code, err)
		}
		for _, scope := range []string{opcertChainFloorScope, opcertChainIssuedScope, opcertCounterScope} {
			for _, suffix := range []string{"", "|" + profPreview, "|" + profMusashi} {
				if _, ok, _ := wm.CounterFor(bg, hash, scope+suffix); ok {
					t.Errorf("refused request recorded scope %q", scope+suffix)
				}
			}
		}
	})
	t.Run("no profile, only holder", func(t *testing.T) {
		t.Parallel()
		c, wm, hash := newSopsProfileCoordinator(t, newSopsProfileBackend(t, "cold-preview", profPreview))
		res, code, err := c.SignOpCertFromChain(bg, kes, 3, 1, hash.String())
		if err != nil || res.IssueCounter != 4 {
			t.Fatalf("res=%v code=%s err=%v", res, code, err)
		}
		// served, and recorded under the backend's profile
		if v, ok, _ := wm.CounterFor(bg, hash, opcertChainFloorScope+"|"+profPreview); !ok || v != 3 {
			t.Fatalf("floor under profile = %d ok=%v, want 3", v, ok)
		}
	})
	t.Run("no profile, two holders", func(t *testing.T) {
		t.Parallel()
		c, _, hash := newSopsProfileCoordinator(t,
			newSopsProfileBackend(t, "cold-preview", profPreview),
			newSopsProfileBackend(t, "cold-musashi", profMusashi))
		_, code, err := c.SignOpCertFromChain(bg, kes, 3, 1, hash.String())
		if code != CodeBadRequest || !errors.Is(err, backend.ErrProfileRequired) {
			t.Fatalf("code=%s err=%v", code, err)
		}
	})
}

// An unprofiled sops backend keeps the unscoped record names it had before
// profiles.
func TestSopsProfile_UnprofiledUnchanged(t *testing.T) {
	t.Parallel()
	c, wm, hash := newSopsProfileCoordinator(t, newSopsProfileBackend(t, "cold", ""))
	kes := make([]byte, kesVkeySize)
	bg := context.Background()
	if _, code, err := c.SignOpCertFromChain(WithProfile(bg, profPreview), kes, 4, 1, hash.String()); err != nil {
		t.Fatalf("unprofiled backend must serve any profile: code=%s err=%v", code, err)
	}
	if v, ok, _ := wm.CounterFor(bg, hash, opcertChainFloorScope); !ok || v != 4 {
		t.Fatalf("unscoped floor = %d ok=%v, want 4", v, ok)
	}
	if _, ok, _ := wm.CounterFor(bg, hash, opcertChainFloorScope+"|"+profPreview); ok {
		t.Fatal("unprofiled sops key wrote a profiled scope")
	}
}

// writeSopsDir writes one age-encrypted pool cold key and returns its dir.
// Not t.Parallel for callers: ageEncrypted sets SOPS_AGE_KEY with t.Setenv.
func writeSopsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir+"/cold.skey.json", ageEncrypted(t, string(sopsPoolEnvelope())))
	return dir
}

// Not t.Parallel: ageEncrypted sets SOPS_AGE_KEY with t.Setenv.
func TestBuildBackends_SopsProfile(t *testing.T) {
	dir := writeSopsDir(t)
	ctx := context.Background()
	cfgs := func(profiles ...string) []config.SignerBackendConfig {
		out := make([]config.SignerBackendConfig, len(profiles))
		for i, p := range profiles {
			out[i] = config.SignerBackendConfig{
				Name: fmt.Sprintf("cold-%d", i), Type: "sops", Path: dir, Profile: p,
			}
		}
		return out
	}
	build := func(profiles ...string) (*backend.Resolver, error) {
		bs, err := BuildBackends(ctx, cfgs(profiles...))
		if err != nil {
			return nil, err
		}
		return backend.NewResolver(bs...), nil
	}

	t.Run("distinct profiles on one path", func(t *testing.T) {
		r, err := build(profPreview, profMusashi)
		if err != nil {
			t.Fatalf("BuildBackends: %v", err)
		}
		if err := r.CheckAmbiguous(ctx); err != nil {
			t.Fatalf("CheckAmbiguous: %v", err)
		}
		keys, _ := r.ListKeys(ctx)
		for i, want := range []string{profPreview, profMusashi} {
			p, ok := keys[i].(backend.Profiled)
			if !ok || p.Profile() != want {
				t.Fatalf("key %d not Profiled under %q: %v", i, want, keys[i])
			}
		}
	})
	t.Run("same profile twice", func(t *testing.T) {
		r, err := build(profPreview, profPreview)
		if err != nil {
			t.Fatalf("BuildBackends: %v", err)
		}
		if err := r.CheckAmbiguous(ctx); err == nil || !strings.Contains(err.Error(), "same profile") {
			t.Fatalf("CheckAmbiguous = %v, want same-profile error", err)
		}
	})
	t.Run("profiled and unprofiled", func(t *testing.T) {
		r, err := build(profPreview, "")
		if err != nil {
			t.Fatalf("BuildBackends: %v", err)
		}
		if err := r.CheckAmbiguous(ctx); err == nil {
			t.Fatal("CheckAmbiguous = nil, want error")
		}
	})
	t.Run("unprofiled key is not Profiled", func(t *testing.T) {
		bs, err := BuildBackends(ctx, cfgs(""))
		if err != nil {
			t.Fatalf("BuildBackends: %v", err)
		}
		keys, _ := bs[0].ListKeys(ctx)
		if _, ok := keys[0].(backend.Profiled); ok {
			t.Fatal("unprofiled sops key implements Profiled")
		}
	})
	for _, bad := range []string{"has space", strings.Repeat("a", 33), "a/b", "otg#1"} {
		t.Run("invalid profile "+bad, func(t *testing.T) {
			_, err := build(bad)
			if err == nil || !strings.Contains(err.Error(), "profile") {
				t.Fatalf("err = %v, want a profile name error", err)
			}
		})
	}
}
