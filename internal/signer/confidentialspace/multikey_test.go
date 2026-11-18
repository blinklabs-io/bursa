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

package confidentialspace

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

const (
	multiMainnetNext = 3
	multiPreviewNext = 0
)

// multiKeys is the operator's two pool cold keys, one per profile.
type multiKeys struct {
	seeds map[string][]byte
	pubs  map[string]ed25519.PublicKey
}

func newMultiKeys(t *testing.T) multiKeys {
	t.Helper()
	k := multiKeys{
		seeds: map[string][]byte{},
		pubs:  map[string]ed25519.PublicKey{},
	}
	for _, profile := range []string{profileMainnet, profilePreview} {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			t.Fatal(err)
		}
		k.seeds[profile] = seed
		k.pubs[profile] = ed25519.NewKeyFromSeed(seed).
			Public().(ed25519.PublicKey)
	}
	return k
}

func (k multiKeys) params(h *importHarness) ImportParams {
	keys := make(map[string]ImportKey, len(k.seeds))
	for profile, seed := range k.seeds {
		keys[profile] = ImportKey{
			Seed: bytes.Clone(seed), VKey: bytes.Clone(k.pubs[profile]),
		}
	}
	return ImportParams{
		KMSKey: testKMSKey,
		Keys:   keys,
		Profiles: []ImportProfile{
			{Profile: profileMainnet, NextIssueNumber: multiMainnetNext},
			{Profile: profilePreview, NextIssueNumber: multiPreviewNext},
		},
		Authority: h.authority,
	}
}

// multiKeyImported runs a whole per-profile-key import and returns the secret.
func multiKeyImported(
	t *testing.T,
) (*fakeSecretClient, multiKeys, *importHarness) {
	t.Helper()
	h := newImportHarness(t)
	keys := newMultiKeys(t)
	req, err := buildImportRequest(ImportRoute, h.challenge(), keys.params(h))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.importer.Import(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	h.secret.settle()
	return h.secret, keys, h
}

func multiKeyWorkload(
	t *testing.T,
	c *fakeSecretClient,
) *Workload {
	t.Helper()
	w, _, err := stateWorkload(t, c, nil, profileMainnet, profilePreview)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func keyRequest(
	hash backend.KeyHash,
	profile string,
	nonce byte,
	issue uint64,
) backend.AttestedRequest {
	return backend.AttestedRequest{
		Version: backend.AttestedProtocol,
		Purpose: backend.PurposeOpCert,
		KeyHash: hash.String(),
		Role:    backend.KeyTypePool,
		Nonce:   bytes.Repeat([]byte{nonce}, 32),
		Payload: lcommon.OpCertSignableBytes(
			bytes.Repeat([]byte{0x23}, 32), issue, 10,
		),
		Profile: profile,
	}
}

func hashOf(pub ed25519.PublicKey) backend.KeyHash {
	return backend.HashPublicKey(pub)
}

func TestMultiKeyEachProfileSignsAndInventoriesWithItsOwnKey(t *testing.T) {
	t.Parallel()
	c, keys, _ := multiKeyImported(t)
	w := multiKeyWorkload(t, c)
	nonce := bytes.Repeat([]byte{9}, 32)
	if bytes.Equal(keys.pubs[profileMainnet], keys.pubs[profilePreview]) {
		t.Fatal("fixture keys are equal")
	}
	for profile, next := range map[string]uint64{
		profileMainnet: multiMainnetNext,
		profilePreview: multiPreviewNext,
	} {
		own, other := keys.pubs[profile], keys.pubs[otherProfile(profile)]
		inv, err := w.Inventory(t.Context(), nonce, profile)
		if err != nil {
			t.Fatal(err)
		}
		if len(inv.Keys) != 1 || !bytes.Equal(inv.Keys[0].PublicKey, own) {
			t.Fatalf("%s inventory does not report only its own key", profile)
		}
		req := keyRequest(hashOf(own), profile, nonceOf(profile, 1), next)
		resp, err := w.Sign(t.Context(), req)
		if err != nil || resp.Error != "" {
			t.Fatalf("%s: err=%v refusal=%q", profile, err, resp.Error)
		}
		if !ed25519.Verify(own, req.Payload, resp.Signature) {
			t.Fatalf("%s signature does not verify under its own key", profile)
		}
		if ed25519.Verify(other, req.Payload, resp.Signature) {
			t.Fatalf("%s signature verifies under the other profile's key", profile)
		}
		binding := backend.AttestedResponseBinding(req, resp.Signature, "")
		if !ed25519.Verify(own, binding, resp.BindingSignature) {
			t.Fatalf("%s binding is not signed by its own key", profile)
		}
	}
	// Counters stayed per profile: each advanced once from its own start.
	for profile, next := range map[string]uint64{
		profileMainnet: multiMainnetNext + 1,
		profilePreview: multiPreviewNext + 1,
	} {
		req := keyRequest(
			hashOf(keys.pubs[profile]), profile, nonceOf(profile, 2), next,
		)
		if resp, err := w.Sign(t.Context(), req); err != nil || resp.Error != "" {
			t.Fatalf("%s second issue: err=%v refusal=%q", profile, err, resp.Error)
		}
	}
}

// nonceOf is a request nonce no other profile or round uses: the workload
// remembers nonces across profiles.
func nonceOf(profile string, round byte) byte {
	if profile == profileMainnet {
		return round
	}
	return round + 100
}

func otherProfile(profile string) string {
	if profile == profileMainnet {
		return profilePreview
	}
	return profileMainnet
}

func TestMultiKeyProfileCannotGetTheOthersSignature(t *testing.T) {
	t.Parallel()
	c, keys, _ := multiKeyImported(t)
	w := multiKeyWorkload(t, c)
	for _, profile := range []string{profileMainnet, profilePreview} {
		// the other profile's key hash under this profile is refused and
		// consumes neither nonce nor counter
		wrong := keyRequest(hashOf(keys.pubs[otherProfile(profile)]), profile, 5, 0)
		resp, err := w.Sign(t.Context(), wrong)
		if err != nil || resp.Error == "" || len(resp.Signature) != 0 {
			t.Fatalf("%s: other key's request not refused: %+v err=%v", profile, resp, err)
		}
	}
	req := keyRequest(
		hashOf(keys.pubs[profileMainnet]), profileMainnet, 5, multiMainnetNext,
	)
	resp, err := w.Sign(t.Context(), req)
	if err != nil || resp.Error != "" {
		t.Fatalf("refused request consumed state: err=%v refusal=%q", err, resp.Error)
	}
}

// multiBackend is the signer host's backend for one profile of a multi-key
// workload, keyed by that profile's own key hash.
func multiBackend(
	t *testing.T,
	w *Workload,
	profile string,
	pub ed25519.PublicKey,
	rewrite func(*backend.AttestedRequest),
) backend.OpCertNextSigner {
	t.Helper()
	b := backend.NewProfiledAttestedBackend(
		"gcp-"+profile,
		profile,
		profileEnclave{w: w, profile: profile, rewrite: rewrite},
		acceptEvidence{},
	)
	if err := b.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	ref, err := b.GetKey(t.Context(), hashOf(pub))
	if err != nil {
		t.Fatal(err)
	}
	next, ok := ref.(backend.OpCertNextSigner)
	if !ok {
		t.Fatal("attested key does not implement OpCertNextSigner")
	}
	return next
}

func TestMultiKeyHostBackendsVerifyOnlyTheirOwnProfile(t *testing.T) {
	t.Parallel()
	c, keys, _ := multiKeyImported(t)
	w := multiKeyWorkload(t, c)
	kes := bytes.Repeat([]byte{0x23}, 32)
	for profile, chain := range map[string]uint64{
		profileMainnet: multiMainnetNext - 1, profilePreview: 0,
	} {
		key := multiBackend(t, w, profile, keys.pubs[profile], nil)
		sig, issue, err := key.SignOpCertNext(t.Context(), kes, chain, 100)
		if err != nil {
			t.Fatalf("%s: %v", profile, err)
		}
		signed := lcommon.OpCertSignableBytes(kes, issue, 100)
		if !ed25519.Verify(keys.pubs[profile], signed, sig) ||
			ed25519.Verify(keys.pubs[otherProfile(profile)], signed, sig) {
			t.Fatalf("%s signature is not by its own key alone", profile)
		}
	}
	// A proxy moves the mainnet request to the preview profile: the workload
	// signs it with the preview key, which the mainnet backend rejects.
	swapped := multiBackend(
		t, w, profileMainnet, keys.pubs[profileMainnet],
		func(r *backend.AttestedRequest) {
			r.Profile = profilePreview
			r.KeyHash = hashOf(keys.pubs[profilePreview]).String()
		},
	)
	_, _, err := swapped.SignOpCertNext(t.Context(), kes, 0, 100)
	if !errors.Is(err, backend.ErrInvalidSignature) {
		t.Fatalf("swapped profile: err = %v, want ErrInvalidSignature", err)
	}
}

func TestMultiKeyRestartKeepsKeysAndCounters(t *testing.T) {
	t.Parallel()
	c, keys, _ := multiKeyImported(t)
	w := multiKeyWorkload(t, c)
	req := keyRequest(
		hashOf(keys.pubs[profileMainnet]), profileMainnet, 1, multiMainnetNext,
	)
	if resp, err := w.Sign(t.Context(), req); err != nil || resp.Error != "" {
		t.Fatalf("err=%v refusal=%q", err, resp.Error)
	}
	c.settle()
	restarted := multiKeyWorkload(t, c)
	replay := keyRequest(
		hashOf(keys.pubs[profileMainnet]), profileMainnet, 2, multiMainnetNext,
	)
	resp, err := restarted.Sign(t.Context(), replay)
	if err != nil || resp.Error == "" {
		t.Fatalf("restart forgot the counter: err=%v resp=%+v", err, resp)
	}
	next := keyRequest(
		hashOf(keys.pubs[profileMainnet]), profileMainnet, 3, multiMainnetNext+1,
	)
	if resp, err := restarted.Sign(t.Context(), next); err != nil || resp.Error != "" {
		t.Fatalf("err=%v refusal=%q", err, resp.Error)
	}
}

func TestMultiKeyEnvelopeShape(t *testing.T) {
	t.Parallel()
	c, keys, _ := multiKeyImported(t)
	doc := latestDoc(t, c)
	var e envelope
	if err := json.Unmarshal(doc.Envelope, &e); err != nil {
		t.Fatal(err)
	}
	if e.Version != envelopeVersionKeys || e.Phase != envelopeActive ||
		len(e.PublicKey) != 0 || len(e.Keys) != 2 {
		t.Fatalf("unexpected envelope %+v", e)
	}
	for _, k := range e.Keys {
		if !bytes.Equal(k.PublicKey, keys.pubs[k.Profile]) {
			t.Fatalf("profile %q holds another key", k.Profile)
		}
	}
	cfg := Config{KMSKey: testKMSKey, Wrapper: &testWrapper{}}
	opened, err := openEnvelope(t.Context(), cfg, doc.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.wipe()
	for profile, seed := range keys.seeds {
		if !bytes.Equal(opened.profileKeys[profile].Seed(), seed) {
			t.Fatalf("profile %q holds another seed", profile)
		}
	}

	// Moving one profile's sealed seed to the other, or changing the
	// profile-to-key map, must not open.
	swapped := e
	swapped.Keys = []envelopeKey{e.Keys[0], e.Keys[1]}
	swapped.Keys[0].Ciphertext, swapped.Keys[1].Ciphertext =
		e.Keys[1].Ciphertext, e.Keys[0].Ciphertext
	swapped.Keys[0].Nonce, swapped.Keys[1].Nonce =
		e.Keys[1].Nonce, e.Keys[0].Nonce
	remapped := e
	remapped.Keys = []envelopeKey{e.Keys[0], e.Keys[1]}
	remapped.Keys[0].PublicKey, remapped.Keys[1].PublicKey =
		e.Keys[1].PublicKey, e.Keys[0].PublicKey
	for name, bad := range map[string]envelope{
		"seeds swapped": swapped, "keys remapped": remapped,
	} {
		data, err := json.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		if k, err := openEnvelope(t.Context(), cfg, data); err == nil {
			k.wipe()
			t.Fatalf("%s: envelope opened", name)
		}
	}
	// Shape rules.
	pending := e
	pending.Phase = envelopePending
	topLevel := e
	topLevel.PublicKey = e.Keys[0].PublicKey
	dup := e
	dup.Keys = []envelopeKey{e.Keys[0], e.Keys[1]}
	dup.Keys[1].PublicKey = e.Keys[0].PublicKey
	for name, bad := range map[string]envelope{
		"pending": pending, "top-level key": topLevel, "duplicate key": dup,
	} {
		data, err := json.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		if k, err := openEnvelope(t.Context(), cfg, data); err == nil {
			k.wipe()
			t.Fatalf("%s: envelope opened", name)
		}
	}
}

func TestMultiKeyWorkloadRequiresExactlyTheEnvelopeProfiles(t *testing.T) {
	t.Parallel()
	c, _, _ := multiKeyImported(t)
	for name, profiles := range map[string][]string{
		"unprofiled":      nil,
		"missing profile": {profileMainnet},
		"extra profile":   {profileMainnet, profilePreview, "pool@sanchonet"},
		"other profile":   {profileMainnet, "pool@sanchonet"},
	} {
		if w, _, err := stateWorkload(t, c, nil, profiles...); err == nil {
			_ = w.Close()
			t.Fatalf("%s: workload started", name)
		}
	}
	// A profile with no key cannot have its counter created.
	if w, _, err := stateWorkload(
		t, c, []string{"pool@sanchonet"},
		profileMainnet, profilePreview, "pool@sanchonet",
	); err == nil {
		_ = w.Close()
		t.Fatal("workload created a counter for a profile with no key")
	}
}

func TestMultiKeyImportRefusals(t *testing.T) {
	t.Parallel()
	t.Run("one key under two profiles", func(t *testing.T) {
		t.Parallel()
		h := newImportHarness(t)
		keys := newMultiKeys(t)
		p := keys.params(h)
		p.Keys[profilePreview] = p.Keys[profileMainnet]
		req, err := buildImportRequest(ImportRoute, h.challenge(), p)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.importer.Import(t.Context(), req); err == nil {
			t.Fatal("import accepted one key under two profiles")
		}
		if h.versions() != 0 {
			t.Fatal("a refused import wrote state")
		}
	})
	t.Run("a key that does not derive its vkey", func(t *testing.T) {
		t.Parallel()
		h := newImportHarness(t)
		keys := newMultiKeys(t)
		p := keys.params(h)
		k := p.Keys[profilePreview]
		k.VKey = bytes.Clone(keys.pubs[profileMainnet])
		p.Keys[profilePreview] = k
		req, err := buildImportRequest(ImportRoute, h.challenge(), p)
		if err != nil {
			t.Fatal(err)
		}
		h.requireRefused(req, errImportVKey)
	})
	t.Run("version relabelled", func(t *testing.T) {
		t.Parallel()
		h := newImportHarness(t)
		keys := newMultiKeys(t)
		req, err := buildImportRequest(ImportRoute, h.challenge(), keys.params(h))
		if err != nil {
			t.Fatal(err)
		}
		req.Version = ImportProtocol
		h.requireRefused(req, errImportAuthorization)
	})
	t.Run("keys must name the profiles", func(t *testing.T) {
		t.Parallel()
		h := newImportHarness(t)
		keys := newMultiKeys(t)
		p := keys.params(h)
		delete(p.Keys, profilePreview)
		p.Keys["pool@sanchonet"] = ImportKey{
			Seed: keys.seeds[profilePreview], VKey: keys.pubs[profilePreview],
		}
		if _, err := buildImportRequest(ImportRoute, h.challenge(), p); err == nil {
			t.Fatal("built a request whose keys miss a profile")
		}
		p = keys.params(h)
		p.Seed, p.VKey = keys.seeds[profileMainnet], keys.pubs[profileMainnet]
		if _, err := buildImportRequest(ImportRoute, h.challenge(), p); err == nil {
			t.Fatal("built a request with both a shared key and per-profile keys")
		}
	})
}

func TestSingleKeyEnvelopeStillServesOneKeyUnderEveryProfile(t *testing.T) {
	t.Parallel()
	c, h := importedSecret(t, &fakeSecretClient{})
	w, _, err := stateWorkload(t, c, nil, profileMainnet, profilePreview)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{profileMainnet, profilePreview} {
		inv, err := w.Inventory(t.Context(), bytes.Repeat([]byte{1}, 32), profile)
		if err != nil || len(inv.Keys) != 1 ||
			!bytes.Equal(inv.Keys[0].PublicKey, h.vkey) {
			t.Fatalf("%s: single-key envelope changed: err=%v", profile, err)
		}
	}
	var e envelope
	if err := json.Unmarshal(latestDoc(t, c).Envelope, &e); err != nil {
		t.Fatal(err)
	}
	if e.Version != envelopeVersion || len(e.Keys) != 0 {
		t.Fatalf("shared-key import wrote %q", e.Version)
	}
}
