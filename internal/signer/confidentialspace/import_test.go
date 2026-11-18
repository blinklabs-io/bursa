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
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	importAudience = "https://signer.example/pool"
	importDigest   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	importStart    = 5
)

func newEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// importHarness is an import-mode workload over an empty fake secret, with
// the operator's key material.
type importHarness struct {
	t         *testing.T
	secret    *fakeSecretClient
	wrapper   *testWrapper
	tokens    *testTokens
	store     *SecretStateStore
	importer  *Importer
	authority ed25519.PrivateKey
	seed      []byte
	vkey      ed25519.PublicKey
	profiles  []ImportProfile
}

func newImportHarnessOn(
	t *testing.T,
	secret *fakeSecretClient,
) *importHarness {
	t.Helper()
	h := &importHarness{
		t:       t,
		secret:  secret,
		wrapper: &testWrapper{},
		tokens:  &testTokens{},
		seed:    make([]byte, ed25519.SeedSize),
		profiles: []ImportProfile{
			{Profile: profilePreview, NextIssueNumber: importStart},
			{Profile: profileMainnet, NextIssueNumber: 0},
		},
	}
	if _, err := rand.Read(h.seed); err != nil {
		t.Fatal(err)
	}
	h.vkey = ed25519.NewKeyFromSeed(h.seed).Public().(ed25519.PublicKey)
	var authorityPub ed25519.PublicKey
	authorityPub, h.authority = newEd25519(t)
	store, err := newSecretStateStore(
		t.Context(), secret, testStateSecret, testKMSKey, h.wrapper,
	)
	if err != nil {
		t.Fatal(err)
	}
	secret.mu.Lock()
	secret.stores = append(secret.stores, store)
	secret.mu.Unlock()
	h.store = store
	h.importer, err = NewImporter(ImportConfig{
		Audience:  importAudience,
		KMSKey:    testKMSKey,
		Tokens:    h.tokens,
		Wrapper:   h.wrapper,
		Store:     store,
		Authority: authorityPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.importer.Close() })
	return h
}

func newImportHarness(t *testing.T) *importHarness {
	t.Helper()
	return newImportHarnessOn(t, &fakeSecretClient{})
}

func (h *importHarness) challenge() ImportChallenge {
	h.t.Helper()
	ch, err := h.importer.Challenge(h.t.Context())
	if err != nil {
		h.t.Fatal(err)
	}
	return ch
}

func (h *importHarness) params() ImportParams {
	return ImportParams{
		KMSKey:    testKMSKey,
		Seed:      bytes.Clone(h.seed),
		VKey:      bytes.Clone(h.vkey),
		Profiles:  append([]ImportProfile(nil), h.profiles...),
		Authority: h.authority,
	}
}

func (h *importHarness) request(ch ImportChallenge) ImportRequest {
	h.t.Helper()
	req, err := buildImportRequest(ImportRoute, ch, h.params())
	if err != nil {
		h.t.Fatal(err)
	}
	return req
}

// versions is the number of versions ever added to the secret.
func (h *importHarness) versions() int {
	adds, _ := h.secret.counts()
	return adds
}

func (h *importHarness) requireRefused(
	req ImportRequest,
	want error,
) {
	h.t.Helper()
	err := h.importer.Import(h.t.Context(), req)
	if !errors.Is(err, want) {
		h.t.Fatalf("import error = %v, want %v", err, want)
	}
	if n := h.versions(); n != 0 {
		h.t.Fatalf("%d versions written by a refused import", n)
	}
	select {
	case <-h.importer.Done():
		h.t.Fatal("a refused import finished")
	default:
	}
}

// importedSecret runs a whole import and returns the secret it wrote.
func importedSecret(
	t *testing.T,
	secret *fakeSecretClient,
) (*fakeSecretClient, *importHarness) {
	t.Helper()
	h := newImportHarnessOn(t, secret)
	req := h.request(h.challenge())
	if err := h.importer.Import(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	secret.settle()
	return secret, h
}

func TestImportWritesKeyAndNormalStartSignsAtSeededCounter(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		secret func() *fakeSecretClient
	}{
		{"no version", func() *fakeSecretClient { return &fakeSecretClient{} }},
		{"empty payload", func() *fakeSecretClient {
			c := &fakeSecretClient{}
			c.seed([]byte{})
			return c
		}},
		{"project number names", func() *fakeSecretClient {
			return &fakeSecretClient{projectNumber: "123456"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, h := importedSecret(t, tc.secret())
			select {
			case <-h.importer.Done():
			default:
				t.Fatal("import did not finish")
			}
			if c.enabled() != 1 {
				t.Fatalf("%d enabled versions, want 1", c.enabled())
			}
			// The envelope holds the imported key, not a generated one.
			doc := latestDoc(t, c)
			var e envelope
			if err := json.Unmarshal(doc.Envelope, &e); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(e.PublicKey, h.vkey) {
				t.Fatal("stored envelope is not the imported key")
			}
			if e.Version != envelopeVersion || e.Phase != envelopeActive {
				t.Fatalf("envelope %q phase %q is not active v2", e.Version, e.Phase)
			}
			key, err := openEnvelope(t.Context(), Config{
				KMSKey: testKMSKey, Wrapper: h.wrapper,
			}, doc.Envelope)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(key.priv.Seed(), h.seed) {
				t.Fatal("stored envelope does not hold the imported seed")
			}
			addsBefore, _ := c.counts()

			// A normal start loads it unchanged and writes nothing.
			w, _, err := stateWorkload(t, c, nil, profileMainnet, profilePreview)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(w.pub, h.vkey) {
				t.Fatal("workload serves another key")
			}
			if adds, _ := c.counts(); adds != addsBefore {
				t.Fatalf("startup wrote %d versions", adds-addsBefore)
			}
			// The preview profile signs at the seeded counter and below it
			// is refused; the mainnet profile starts at 0.
			requireRefusedResp(t, w, explicitReq(w, profilePreview, 1, importStart-1))
			requireProfiledIssue(
				t, w, explicitReq(w, profilePreview, 2, importStart), importStart,
			)
			requireProfiledIssue(t, w, explicitReq(w, profileMainnet, 3, 0), 0)
		})
	}
}

func TestImportSeedsOpCertNextFromStartingCounter(t *testing.T) {
	t.Parallel()
	c, _ := importedSecret(t, &fakeSecretClient{})
	w := mustStateWorkload(t, c, profileMainnet, profilePreview)
	// A chain counter above the last number the imported record says was
	// issued is refused.
	resp, err := w.Sign(t.Context(), profiledRequest(
		w, profilePreview, backend.PurposeOpCertNext, 2, importStart, 10,
	))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Error == "" {
		t.Fatal("a chain counter above the starting counter was signed")
	}
	// The chain counter is the last number issued: the next issue number
	// minus one.
	requireProfiledIssue(t, w, profiledRequest(
		w, profilePreview, backend.PurposeOpCertNext, 1, importStart-1, 10,
	), importStart)
}

// The starting counter is the chain counter plus one, so the chain counter
// seeds the floor: a lower report would reissue the on-chain number at a KES
// period nothing recorded.
func TestImportSeedsOpCertNextFloorFromStartingCounter(t *testing.T) {
	t.Parallel()
	c, _ := importedSecret(t, &fakeSecretClient{})
	w := mustStateWorkload(t, c, profileMainnet, profilePreview)
	requireRefusedResp(t, w, profiledRequest(
		w, profilePreview, backend.PurposeOpCertNext, 1, importStart-2, 1,
	))
}

func TestImportedSecretRefusesUnimportedProfile(t *testing.T) {
	t.Parallel()
	c, _ := importedSecret(t, &fakeSecretClient{})
	_, _, err := stateWorkload(t, c, nil, profileMainnet, "pool@other")
	if err == nil || !strings.Contains(err.Error(), "counter state is missing") {
		t.Fatalf("a profile that was not imported started: %v", err)
	}
}

func TestImportRequestsAttestationOfChallengeAndChannelKey(t *testing.T) {
	t.Parallel()
	h := newImportHarness(t)
	ch := h.challenge()
	h.tokens.mu.Lock()
	audience, nonces := h.tokens.audience, h.tokens.nonces
	h.tokens.mu.Unlock()
	want := []string{
		hex.EncodeToString(ch.Challenge),
		hex.EncodeToString(tokenNonceOf(ch.PublicKey)),
	}
	if audience != importAudience || len(nonces) != 2 ||
		nonces[0] != want[0] || nonces[1] != want[1] {
		t.Fatalf("token audience %q nonces %q, want %q", audience, nonces, want)
	}
	if len(ch.PublicKey) != curve25519.PointSize ||
		len(ch.Challenge) != importChallengeSize {
		t.Fatalf("challenge has %d bytes, key %d", len(ch.Challenge), len(ch.PublicKey))
	}
	other := h.challenge()
	if bytes.Equal(ch.Challenge, other.Challenge) ||
		bytes.Equal(ch.PublicKey, other.PublicKey) {
		t.Fatal("two challenges share a challenge or a channel key")
	}
}

func TestImportRefusesTamperedRequest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		want   error
		mutate func(h *importHarness, ch ImportChallenge, req *ImportRequest)
	}{
		{
			name: "ciphertext",
			want: errImportAuthorization,
			mutate: func(_ *importHarness, _ ImportChallenge, r *ImportRequest) {
				r.Ciphertext[0] ^= 1
			},
		},
		{
			// The authority signed the tampered bytes, so only the AEAD
			// can refuse them.
			name: "ciphertext authorized again",
			want: errImportOpen,
			mutate: func(h *importHarness, ch ImportChallenge, r *ImportRequest) {
				r.Ciphertext[0] ^= 1
				reauthorize(h, ch, r)
			},
		},
		{
			// The nonce is not under the authorization.
			name: "nonce",
			want: errImportOpen,
			mutate: func(_ *importHarness, _ ImportChallenge, r *ImportRequest) {
				r.Nonce[0] ^= 1
			},
		},
		{
			name: "client key",
			want: errImportAuthorization,
			mutate: func(_ *importHarness, _ ImportChallenge, r *ImportRequest) {
				r.ClientPublicKey[0] ^= 1
			},
		},
		{
			name: "profile list",
			want: errImportAuthorization,
			mutate: func(_ *importHarness, _ ImportChallenge, r *ImportRequest) {
				r.Profiles = []string{profileMainnet, "pool@zzz"}
			},
		},
		{
			name: "truncated authorization",
			want: errImportRequest,
			mutate: func(_ *importHarness, _ ImportChallenge, r *ImportRequest) {
				r.Authorization = r.Authorization[:10]
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newImportHarness(t)
			ch := h.challenge()
			req := h.request(ch)
			tt.mutate(h, ch, &req)
			h.requireRefused(req, tt.want)
		})
	}
}

// reauthorize signs the request as it now stands under its binding.
func reauthorize(h *importHarness, ch ImportChallenge, r *ImportRequest) {
	binding := importBinding(
		ImportRoute, ch.Challenge, tokenNonceOf(ch.PublicKey), ch.PublicKey,
		r.ClientPublicKey, testKMSKey, r.Profiles,
	)
	r.Authorization = ed25519.Sign(
		h.authority, importAuthorizationDigest(binding, r.Ciphertext),
	)
}

func TestImportRefusesAnotherRoutesBinding(t *testing.T) {
	t.Parallel()
	for _, route := range []string{"/v1/inventory", "/v1/sign", ""} {
		t.Run("route "+route, func(t *testing.T) {
			t.Parallel()
			h := newImportHarness(t)
			ch := h.challenge()
			req, err := buildImportRequest(route, ch, h.params())
			if err != nil {
				t.Fatal(err)
			}
			h.requireRefused(req, errImportAuthorization)

			// With an authorization that does cover this route's binding,
			// the AEAD still refuses the other route's ciphertext.
			reauthorize(h, ch, &req)
			h.requireRefused(req, errImportOpen)
		})
	}
}

func TestImportRefusesReplayedChallenge(t *testing.T) {
	t.Parallel()
	t.Run("after a failed write", func(t *testing.T) {
		t.Parallel()
		h := newImportHarness(t)
		req := h.request(h.challenge())
		h.wrapper.denyWrap = true
		err := h.importer.Import(t.Context(), req)
		if err == nil || errors.Is(err, errImportChallenge) {
			t.Fatalf("first attempt error = %v, want a KMS failure", err)
		}
		// Only the spent challenge can refuse the same request now.
		h.wrapper.denyWrap = false
		h.requireRefused(req, errImportChallenge)
	})
	t.Run("after a refusal past the open", func(t *testing.T) {
		t.Parallel()
		h := newImportHarness(t)
		h.vkey = bytes.Repeat([]byte{7}, ed25519.PublicKeySize)
		req := h.request(h.challenge())
		h.requireRefused(req, errImportVKey)
		h.requireRefused(req, errImportChallenge)
	})
	t.Run("a newer challenge replaces the older", func(t *testing.T) {
		t.Parallel()
		h := newImportHarness(t)
		old := h.request(h.challenge())
		h.challenge()
		h.requireRefused(old, errImportChallenge)
	})
	t.Run("a finished import takes no more", func(t *testing.T) {
		t.Parallel()
		_, h := importedSecret(t, &fakeSecretClient{})
		if _, err := h.importer.Challenge(t.Context()); !errors.Is(err, errImportDone) {
			t.Fatalf("challenge after import: %v", err)
		}
		err := h.importer.Import(t.Context(), h.request(ImportChallenge{
			Challenge: bytes.Repeat([]byte{1}, importChallengeSize),
			PublicKey: bytes.Repeat([]byte{9}, curve25519.PointSize),
		}))
		if !errors.Is(err, errImportDone) {
			t.Fatalf("import after import: %v", err)
		}
	})
}

func TestImportRefusesWrongAuthority(t *testing.T) {
	t.Parallel()
	h := newImportHarness(t)
	_, other := newEd25519(t)
	h.authority = other
	h.requireRefused(h.request(h.challenge()), errImportAuthorization)
}

func TestNewImporterRefusesBadAuthority(t *testing.T) {
	t.Parallel()
	h := newImportHarness(t)
	for name, key := range map[string]ed25519.PublicKey{
		"empty": nil,
		"short": make([]byte, 31),
		"zero":  make([]byte, ed25519.PublicKeySize),
	} {
		_, err := NewImporter(ImportConfig{
			Audience: importAudience, KMSKey: testKMSKey, Tokens: h.tokens,
			Wrapper: h.wrapper, Store: h.store, Authority: key,
		})
		if err == nil {
			t.Errorf("%s authority accepted", name)
		}
	}
}

func TestImportRefusesKeyThatDoesNotDeriveExpectedVKey(t *testing.T) {
	t.Parallel()
	h := newImportHarness(t)
	other, _ := newEd25519(t)
	h.vkey = other
	h.requireRefused(h.request(h.challenge()), errImportVKey)
}

// sealRaw seals body with the same channel the client uses, for bodies the
// client refuses to build.
func sealRaw(
	t *testing.T,
	h *importHarness,
	ch ImportChallenge,
	names []string,
	body []byte,
) ImportRequest {
	t.Helper()
	clientSeed := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(clientSeed); err != nil {
		t.Fatal(err)
	}
	clientKey, err := curve25519.X25519(clientSeed, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := curve25519.X25519(clientSeed, ch.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	binding := importBinding(
		ImportRoute, ch.Challenge, tokenNonceOf(ch.PublicKey), ch.PublicKey,
		clientKey, testKMSKey, names,
	)
	key, err := importChannelKey(shared, binding)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, nonce, body, binding)
	return ImportRequest{
		Version:         ImportProtocol,
		Challenge:       ch.Challenge,
		Profiles:        names,
		ClientPublicKey: clientKey,
		Nonce:           nonce,
		Ciphertext:      ciphertext,
		Authorization: ed25519.Sign(
			h.authority, importAuthorizationDigest(binding, ciphertext),
		),
	}
}

func TestImportRefusesSealedProfilesOutsideTheBinding(t *testing.T) {
	t.Parallel()
	fixed := func(h *importHarness) []byte {
		return append(bytes.Clone(h.seed), h.vkey...)
	}
	tests := []struct {
		name  string
		names []string
		body  func(h *importHarness) []byte
	}{
		{
			name:  "another profile sealed",
			names: []string{profileMainnet},
			body: func(h *importHarness) []byte {
				return append(fixed(h),
					`[{"profile":"pool@preview","next_issue_number":9}]`...)
			},
		},
		{
			name:  "extra profile sealed",
			names: []string{profileMainnet},
			body: func(h *importHarness) []byte {
				return append(fixed(h), `[{"profile":"pool@mainnet","next_issue_number":0},`+
					`{"profile":"pool@preview","next_issue_number":0}]`...)
			},
		},
		{
			name:  "duplicate profile sealed",
			names: []string{profileMainnet, profilePreview},
			body: func(h *importHarness) []byte {
				return append(fixed(h), `[{"profile":"pool@mainnet","next_issue_number":0},`+
					`{"profile":"pool@mainnet","next_issue_number":0}]`...)
			},
		},
		{
			name:  "counter without a successor",
			names: []string{profileMainnet},
			body: func(h *importHarness) []byte {
				return append(fixed(h),
					`[{"profile":"pool@mainnet","next_issue_number":18446744073709551615}]`...)
			},
		},
		{
			name:  "unknown field",
			names: []string{profileMainnet},
			body: func(h *importHarness) []byte {
				return append(fixed(h),
					`[{"profile":"pool@mainnet","next_issue_number":0,"x":1}]`...)
			},
		},
		{
			name:  "no counters",
			names: []string{profileMainnet},
			body:  fixed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newImportHarness(t)
			ch := h.challenge()
			h.requireRefused(
				sealRaw(t, h, ch, tt.names, tt.body(h)), errImportRequest,
			)
		})
	}
}

func TestImportRefusesNonEmptySecret(t *testing.T) {
	t.Parallel()
	t.Run("existing envelope", func(t *testing.T) {
		t.Parallel()
		c := provisionedSecret(t)
		before := c.latest()
		h := newImportHarnessOn(t, c)
		err := h.importer.Import(t.Context(), h.request(h.challenge()))
		if !errors.Is(err, ErrStateNotEmpty) {
			t.Fatalf("import into a provisioned secret: %v", err)
		}
		if adds, _ := c.counts(); adds != 0 || !bytes.Equal(c.latest(), before) {
			t.Fatal("the existing state was changed")
		}
		select {
		case <-h.importer.Done():
			t.Fatal("a refused import finished")
		default:
		}
	})
	t.Run("older version under an empty newest", func(t *testing.T) {
		t.Parallel()
		// The write's cleanup destroys every older enabled version, so the
		// older envelope would be lost.
		c := provisionedSecret(t)
		c.seed([]byte{})
		h := newImportHarnessOn(t, c)
		err := h.importer.Import(t.Context(), h.request(h.challenge()))
		if !errors.Is(err, ErrStateNotEmpty) {
			t.Fatalf("import over an older envelope: %v", err)
		}
		if adds, destroys := c.counts(); adds != 0 || destroys != 0 {
			t.Fatalf("%d versions added and %d destroyed", adds, destroys)
		}
	})
	t.Run("provisioned after the challenge", func(t *testing.T) {
		t.Parallel()
		c := &fakeSecretClient{}
		h := newImportHarnessOn(t, c)
		req := h.request(h.challenge())
		other := provisionedSecret(t)
		c.seed(other.latest())
		err := h.importer.Import(t.Context(), req)
		if !errors.Is(err, ErrStateNotEmpty) {
			t.Fatalf("import into a secret provisioned since: %v", err)
		}
		if adds, _ := c.counts(); adds != 0 {
			t.Fatal("a version was added over the existing state")
		}
	})
	t.Run("after an import", func(t *testing.T) {
		t.Parallel()
		c, h := importedSecret(t, &fakeSecretClient{})
		err := h.store.Import(t.Context(), latestDoc(t, c).Envelope, map[string]uint64{profilePreview: 0})
		if !errors.Is(err, ErrStateNotEmpty) {
			t.Fatalf("second import: %v", err)
		}
	})
}

func TestImportNeverGeneratesKey(t *testing.T) {
	t.Parallel()
	h := newImportHarness(t)
	// Challenges and refused requests write nothing and create no key.
	for range 3 {
		h.challenge()
	}
	_, other := newEd25519(t)
	bad := h.request(h.challenge())
	bad.Authorization = ed25519.Sign(other, []byte("x"))
	h.requireRefused(bad, errImportAuthorization)
	if err := h.store.Create([]byte("x")); !errors.Is(err, ErrStateCreateRefused) {
		t.Fatalf("store create: %v", err)
	}
	if n := h.versions(); n != 0 {
		t.Fatalf("%d versions written", n)
	}
	// Without the import, the empty secret is still a startup error.
	_, _, err := stateWorkload(t, h.secret, nil)
	if !errors.Is(err, ErrStateNotProvisioned) {
		t.Fatalf("empty secret start: %v", err)
	}
	if n := h.versions(); n != 0 {
		t.Fatalf("startup wrote %d versions", n)
	}
}

func TestImporterWipesSessionOnClose(t *testing.T) {
	t.Parallel()
	h := newImportHarness(t)
	h.challenge()
	h.importer.mu.Lock()
	seed := h.importer.session.seed
	h.importer.mu.Unlock()
	if err := h.importer.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seed, make([]byte, len(seed))) {
		t.Fatal("ephemeral private key was not wiped")
	}
}

func authenticated(r *http.Request, key any) *http.Request {
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{PublicKey: key}},
		VerifiedChains:   [][]*x509.Certificate{{{}}},
	}
	return r
}

func TestImporterHandlerServesOnlyImportRoutes(t *testing.T) {
	t.Parallel()
	h := newImportHarness(t)
	handler := h.importer.Handler()
	post := func(path string, body []byte, authed bool, key any) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if authed {
			r = authenticated(r, key)
		}
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, r)
		return rw
	}
	clientKey, _ := newEd25519(t)

	for _, path := range []string{ImportChallengeRoute, ImportRoute} {
		if rw := post(path, []byte(`{}`), false, nil); rw.Code != http.StatusUnauthorized {
			t.Errorf("%s without a client certificate: %d", path, rw.Code)
		}
	}
	// The workload never signs in import mode.
	for _, path := range []string{"/v1/sign", "/v1/inventory"} {
		if rw := post(path, []byte(`{}`), true, clientKey); rw.Code != http.StatusNotFound {
			t.Errorf("%s status = %d, want %d", path, rw.Code, http.StatusNotFound)
		}
	}
	// A client whose key is the authority is refused.
	authority := h.authority.Public().(ed25519.PublicKey)
	for _, path := range []string{ImportChallengeRoute, ImportRoute} {
		if rw := post(path, []byte(`{}`), true, authority); rw.Code != http.StatusForbidden {
			t.Errorf("%s as the authority: %d", path, rw.Code)
		}
	}

	rw := post(ImportChallengeRoute, []byte(`{}`), true, clientKey)
	if rw.Code != http.StatusOK {
		t.Fatalf("challenge status %d: %s", rw.Code, rw.Body)
	}
	var ch ImportChallenge
	if err := json.Unmarshal(rw.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	req, err := BuildImportRequest(t.Context(), acceptEvidence{}, ch, h.params())
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(body, []byte(`"version":"`+ImportProtocol), []byte(`"version":"x`), 1)
	if rw := post(ImportRoute, tampered, true, clientKey); rw.Code != http.StatusForbidden {
		t.Fatalf("tampered import status %d", rw.Code)
	}
	if rw := post(ImportRoute, body, true, clientKey); rw.Code != http.StatusOK {
		t.Fatalf("import status %d: %s", rw.Code, rw.Body)
	}
	select {
	case <-h.importer.Done():
	default:
		t.Fatal("import did not finish")
	}
	if rw := post(ImportRoute, body, true, clientKey); rw.Code != http.StatusForbidden {
		t.Fatalf("replayed import status %d", rw.Code)
	}
}

// tokenFixture mints Confidential Space tokens a real verifier accepts.
type tokenFixture struct {
	key *rsa.PrivateKey
}

func newTokenFixture(t *testing.T) *tokenFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &tokenFixture{key: key}
}

func (f *tokenFixture) verifier(t *testing.T) *backend.ConfidentialSpaceVerifier {
	t.Helper()
	v, err := backend.NewConfidentialSpaceVerifier(
		func(context.Context) (jose.JSONWebKeySet, error) {
			return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig",
			}}}, nil
		},
		importAudience, importDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (f *tokenFixture) token(
	t *testing.T,
	nonces []string,
	mutate func(jwt.MapClaims),
) []byte {
	t.Helper()
	now := time.Now()
	c := jwt.MapClaims{
		"iss": backend.ConfidentialSpaceIssuer, "aud": importAudience,
		"iat": now.Add(-time.Minute).Unix(), "nbf": now.Add(-time.Minute).Unix(),
		"exp":       now.Add(time.Hour).Unix(),
		"eat_nonce": nonces,
		"dbgstat":   "disabled-since-boot", "swname": "CONFIDENTIAL_SPACE",
		"secboot": true, "hwmodel": "GCP_AMD_SEV",
		"submods": map[string]any{
			"container": map[string]any{"image_digest": importDigest},
			"confidential_space": map[string]any{
				"support_attributes": []string{"STABLE", "USABLE"},
			},
		},
	}
	if mutate != nil {
		mutate(c)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(s)
}

func TestBuildImportRequestVerifiesTheAttestation(t *testing.T) {
	t.Parallel()
	f := newTokenFixture(t)
	verifier := f.verifier(t)
	h := newImportHarness(t)
	ch := h.challenge()
	otherPub, _ := curve25519.X25519(bytes.Repeat([]byte{3}, 32), curve25519.Basepoint)
	chNonce := hex.EncodeToString(ch.Challenge)
	keyNonce := hex.EncodeToString(tokenNonceOf(ch.PublicKey))
	tests := []struct {
		name    string
		nonces  []string
		mutate  func(jwt.MapClaims)
		wantErr string
	}{
		{name: "valid", nonces: []string{chNonce, keyNonce}},
		{
			name:    "nonce of another public key",
			nonces:  []string{chNonce, hex.EncodeToString(tokenNonceOf(otherPub))},
			wantErr: "channel key",
		},
		{
			name:    "no public key nonce",
			nonces:  []string{chNonce},
			wantErr: "channel key",
		},
		{
			name:    "another challenge",
			nonces:  []string{strings.Repeat("ab", 32), keyNonce},
			wantErr: "challenge",
		},
		{
			name:   "debug workload",
			nonces: []string{chNonce, keyNonce},
			mutate: func(c jwt.MapClaims) {
				c["dbgstat"] = "enabled"
			},
			wantErr: "debug",
		},
		{
			name:   "another image",
			nonces: []string{chNonce, keyNonce},
			mutate: func(c jwt.MapClaims) {
				c["submods"].(map[string]any)["container"] = map[string]any{
					"image_digest": "sha256:" + strings.Repeat("b", 64),
				}
			},
			wantErr: "image digest",
		},
		{
			name:   "another audience",
			nonces: []string{chNonce, keyNonce},
			mutate: func(c jwt.MapClaims) {
				c["aud"] = "https://elsewhere.example"
			},
			wantErr: "token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			signed := ch
			signed.Attestation = f.token(t, tt.nonces, tt.mutate)
			req, err := BuildImportRequest(t.Context(), verifier, signed, h.params())
			if tt.wantErr == "" {
				if err != nil || len(req.Ciphertext) == 0 {
					t.Fatalf("valid attestation refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
			}
			if len(req.Ciphertext) != 0 {
				t.Fatal("a request was built despite the refusal")
			}
		})
	}
}

func TestBuildImportRequestRefusesBadInputs(t *testing.T) {
	t.Parallel()
	h := newImportHarness(t)
	ch := h.challenge()
	for name, mutate := range map[string]func(*ImportParams){
		"short seed":       func(p *ImportParams) { p.Seed = p.Seed[:31] },
		"short vkey":       func(p *ImportParams) { p.VKey = p.VKey[:31] },
		"no authority":     func(p *ImportParams) { p.Authority = nil },
		"no profile":       func(p *ImportParams) { p.Profiles = nil },
		"bad profile name": func(p *ImportParams) { p.Profiles[0].Profile = "a b" },
		"duplicate profile": func(p *ImportParams) {
			p.Profiles[1].Profile = p.Profiles[0].Profile
		},
		"counter without successor": func(p *ImportParams) {
			p.Profiles[0].NextIssueNumber = 1<<64 - 1
		},
	} {
		p := h.params()
		mutate(&p)
		if _, err := BuildImportRequest(t.Context(), acceptEvidence{}, ch, p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestImportClientTalksToTheWorkload(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var gotPath, gotType string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath, gotType = r.URL.Path, r.Header.Get("Content-Type")
		mu.Unlock()
		switch r.URL.Path {
		case ImportChallengeRoute:
			_ = json.NewEncoder(rw).Encode(ImportChallenge{
				Version: ImportProtocol, Challenge: []byte{1}, Attestation: []byte("t"),
			})
		default:
			http.Error(rw, "import refused", http.StatusForbidden)
		}
	}))
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	authority, _ := newEd25519(t)
	c, err := newImportClient(srv.URL, authority, &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots,
	})
	if err != nil {
		t.Fatal(err)
	}
	ch, err := c.Challenge(t.Context())
	mu.Lock()
	path, ctype := gotPath, gotType
	mu.Unlock()
	if err != nil || ch.Version != ImportProtocol ||
		path != ImportChallengeRoute || ctype != "application/json" {
		t.Fatalf("challenge %+v, %v (path %q, type %q)", ch, err, path, ctype)
	}
	err = c.Import(t.Context(), ImportRequest{})
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("refused import: %v", err)
	}
}

func TestImportClientRefusesAuthorityAsTLSIdentity(t *testing.T) {
	t.Parallel()
	pub, priv := newEd25519(t)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{der}, PrivateKey: priv,
	}}}
	if _, err := newImportClient("https://workload.example", pub, cfg); err == nil ||
		!strings.Contains(err.Error(), "must not be the TLS client identity") {
		t.Fatalf("authority key as the client identity: %v", err)
	}
	other, _ := newEd25519(t)
	if _, err := newImportClient("https://workload.example", other, cfg); err != nil {
		t.Fatalf("distinct authority refused: %v", err)
	}
	if _, err := newImportClient("http://workload.example", other, cfg); err == nil {
		t.Fatal("plain http accepted")
	}
}
