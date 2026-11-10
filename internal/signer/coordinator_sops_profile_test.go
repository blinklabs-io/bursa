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

	"github.com/blinklabs-io/bursa"
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
	first backend.Backend,
	more ...backend.Backend,
) (*Coordinator, *watermark.MemWatermark, backend.KeyHash) {
	t.Helper()
	wm := watermark.NewMemWatermark()
	c, hash := newSopsProfileCoordinatorOn(t, wm, first, more...)
	return c, wm, hash
}

// newSopsProfileCoordinatorOn builds a coordinator over first and more that
// records in wm, allowing opcert, tx and cip8 requests for the one pool cold
// key that first holds.
func newSopsProfileCoordinatorOn(
	t *testing.T,
	wm *watermark.MemWatermark,
	first backend.Backend,
	more ...backend.Backend,
) (*Coordinator, backend.KeyHash) {
	t.Helper()
	keys, err := first.ListKeys(context.Background())
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListKeys: %v len=%d", err, len(keys))
	}
	hash := keys[0].Hash()
	eng, err := policy.NewEngine([]policy.KeyPolicy{{
		Hash:            hash.String(),
		AllowedRequests: []string{"opcert", "tx", "cip8"},
		Tx:              &policy.TxPolicy{},
		CIP8:            &policy.CIP8Policy{MaxPayloadBytes: 64},
	}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return New(Deps{
		Resolver:  backend.NewResolver(append([]backend.Backend{first}, more...)...),
		Policy:    eng,
		Watermark: wm,
		WMMode:    watermark.ModeEnforce,
		Cardano: fakeCardano{
			insp: &bursa.TxInspection{TxId: "abc", TTL: 10},
			txid: make([]byte, 32),
		},
		Metrics: NewMetrics(),
	}), hash
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

// A profiled sops key is the one profiled key whose private key is in
// process, so it serves CIP-8: under its own profile, refused under another,
// and a profile-less request is refused while two profiles hold the key.
func TestSopsProfile_CIP8(t *testing.T) {
	t.Parallel()
	bg := context.Background()
	preview := newSopsProfileBackend(t, "cold-preview", profPreview)
	keys, err := preview.ListKeys(bg)
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListKeys: %v len=%d", err, len(keys))
	}
	addr := addrForKey(t, keys[0].PublicKey())

	c, _, hash := newSopsProfileCoordinator(t, preview)
	res, code, err := c.SignCIP8(WithProfile(bg, profPreview), []byte("hello"), addr, hash.String())
	// the COSE_Key carries the sops key's public key
	if err != nil || res.SignatureHex == "" || !strings.Contains(res.KeyHex, fmt.Sprintf("%x", keys[0].PublicKey())) {
		t.Fatalf("own profile: res=%v code=%s err=%v", res, code, err)
	}
	if _, code, err = c.SignCIP8(WithProfile(bg, profMusashi), []byte("hello"), addr, hash.String()); err == nil || code != CodeNotFound {
		t.Fatalf("other profile: code=%s err=%v, want not found", code, err)
	}

	c2, _, _ := newSopsProfileCoordinator(t, preview,
		newSopsProfileBackend(t, "cold-musashi", profMusashi))
	if _, code, err = c2.SignCIP8(bg, []byte("hello"), addr, hash.String()); code != CodeBadRequest || !errors.Is(err, backend.ErrProfileRequired) {
		t.Fatalf("no profile, two holders: code=%s err=%v", code, err)
	}
	if res, code, err = c2.SignCIP8(WithProfile(bg, profMusashi), []byte("hello"), addr, hash.String()); err != nil || res.SignatureHex == "" {
		t.Fatalf("second profile: res=%v code=%s err=%v", res, code, err)
	}
}

// A tx signed by a profiled sops key is recorded under the profile only.
func TestSopsProfile_TxRecordScope(t *testing.T) {
	t.Parallel()
	bg := context.Background()
	c, wm, hash := newSopsProfileCoordinator(t,
		newSopsProfileBackend(t, "cold-preview", profPreview),
		newSopsProfileBackend(t, "cold-musashi", profMusashi))
	res, perr, err := c.SignTx(WithProfile(bg, profPreview), []byte(testTxCbor), testTxEra, []string{hash.String()})
	if err != nil || len(perr) != 0 || len(res.Witnesses) != 1 {
		t.Fatalf("tx: res=%v perr=%v err=%v", res, perr, err)
	}
	txScope := "tx:" + strings.Repeat("00", 32)
	if err := wm.Check(bg, hash, txScope+"|"+profPreview, []byte("other")); !errors.Is(err, watermark.ErrConflict) {
		t.Errorf("tx record under %s: want ErrConflict, got %v", profPreview, err)
	}
	for _, scope := range []string{txScope, txScope + "|" + profMusashi} {
		if err := wm.Check(bg, hash, scope, []byte("other")); err != nil {
			t.Errorf("tx record written under scope %q: %v", scope, err)
		}
	}
}

// Records written before a sops backend had a profile still bound its opcert
// requests while that profiled backend is the key's only holder. Once a
// second profile holds the key they are not read, so each profile starts
// empty.
func TestSopsProfile_UnprofiledRecordsWhileOnlyHolder(t *testing.T) {
	t.Parallel()
	bg := context.Background()
	kes := make([]byte, kesVkeySize)
	wm := watermark.NewMemWatermark()

	before, hash := newSopsProfileCoordinatorOn(t, wm, newSopsProfileBackend(t, "cold", ""))
	id := hash.String()
	if _, code, err := before.SignOpCertFromChain(bg, kes, 6, 1, id); err != nil {
		t.Fatalf("unprofiled chain 6: code=%s err=%v", code, err)
	}

	only, _ := newSopsProfileCoordinatorOn(t, wm, newSopsProfileBackend(t, "cold", profPreview))
	if _, code, err := only.SignOpCertFromChain(WithProfile(bg, profPreview), kes, 0, 1, id); err == nil || code != CodeConflict {
		t.Fatalf("only holder, chain 0 below the unprofiled floor: code=%s err=%v, want conflict", code, err)
	}
	if _, code, err := only.SignOpCert(WithProfile(bg, profPreview), kes, 7, 1, id); err == nil || code != CodeConflict {
		t.Fatalf("only holder, issue 7 at the unprofiled issued record: code=%s err=%v, want conflict", code, err)
	}

	two, _ := newSopsProfileCoordinatorOn(t, wm,
		newSopsProfileBackend(t, "cold-preview", profPreview),
		newSopsProfileBackend(t, "cold-musashi", profMusashi))
	res, code, err := two.SignOpCertFromChain(WithProfile(bg, profPreview), kes, 0, 1, id)
	if err != nil || res.IssueCounter != 1 {
		t.Fatalf("two holders, chain 0: res=%v code=%s err=%v, want issue 1", res, code, err)
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
		keys, err := r.ListKeys(ctx)
		if err != nil || len(keys) != 2 {
			t.Fatalf("ListKeys: %v len=%d", err, len(keys))
		}
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
		if len(bs) != 1 {
			t.Fatalf("BuildBackends: %d backends, want 1", len(bs))
		}
		keys, err := bs[0].ListKeys(ctx)
		if err != nil || len(keys) != 1 {
			t.Fatalf("ListKeys: %v len=%d", err, len(keys))
		}
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
