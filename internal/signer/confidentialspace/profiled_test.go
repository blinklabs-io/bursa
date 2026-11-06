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
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

const (
	profileMainnet = "pool@mainnet"
	profilePreview = "pool@preview"
)

// profiledWorkload serves one key under profileMainnet and profilePreview,
// each over its own counter object. A second call with the same arguments is
// a restart.
func profiledWorkload(
	t *testing.T,
	envelopes *memoryStore,
	objs map[string]*memoryCounterObject,
	create []string,
) (*Workload, *testTokens, error) {
	t.Helper()
	profiles := make(map[string]CounterStore, len(objs))
	for name, obj := range objs {
		profiles[name] = &CloudCounterStore{object: obj, profile: name}
	}
	tokens := &testTokens{}
	w, err := New(t.Context(), Config{
		Audience:              "https://signer.example/pool",
		KMSKey:                testKMSKey,
		Tokens:                tokens,
		Wrapper:               &testWrapper{},
		Store:                 envelopes,
		Profiles:              profiles,
		CreateProfileCounters: create,
	})
	if err == nil {
		t.Cleanup(func() { _ = w.Close() })
	}
	return w, tokens, err
}

func twoProfiles(t *testing.T) (*Workload, map[string]*memoryCounterObject) {
	t.Helper()
	objs := map[string]*memoryCounterObject{
		profileMainnet: {},
		profilePreview: {},
	}
	w, _, err := profiledWorkload(t, &memoryStore{}, objs, nil)
	if err != nil {
		t.Fatal(err)
	}
	return w, objs
}

// profileObject returns the counter object of profile.
func profileObject(
	t *testing.T,
	objs map[string]*memoryCounterObject,
	profile string,
) *memoryCounterObject {
	t.Helper()
	obj, ok := objs[profile]
	if !ok || obj == nil {
		t.Fatalf("no counter object for profile %q", profile)
	}
	return obj
}

func profiledRequest(
	w *Workload,
	profile string,
	purpose backend.Purpose,
	nonce byte,
	counter, period uint64,
) backend.AttestedRequest {
	return backend.AttestedRequest{
		Version: backend.AttestedProtocol,
		Purpose: purpose,
		KeyHash: w.hash.String(),
		Role:    backend.KeyTypePool,
		Nonce:   bytes.Repeat([]byte{nonce}, 32),
		Payload: lcommon.OpCertSignableBytes(
			bytes.Repeat([]byte{0x23}, 32), counter, period,
		),
		Profile: profile,
	}
}

func requireProfiledIssue(
	t *testing.T,
	w *Workload,
	req backend.AttestedRequest,
	issue uint64,
) backend.AttestedResponse {
	t.Helper()
	resp, err := w.Sign(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Error != "" {
		t.Fatalf("profile %q refused: %q", req.Profile, resp.Error)
	}
	signed := bytes.Clone(req.Payload)
	binary.BigEndian.PutUint64(signed[32:40], issue)
	if !ed25519.Verify(w.pub, signed, resp.Signature) {
		t.Fatalf(
			"profile %q: signature does not cover issue %d",
			req.Profile,
			issue,
		)
	}
	if req.Purpose == backend.PurposeOpCertNext &&
		(resp.IssueCounter == nil || *resp.IssueCounter != issue) {
		t.Fatalf(
			"profile %q: issue counter %v, want %d",
			req.Profile,
			resp.IssueCounter,
			issue,
		)
	}
	return resp
}

func TestProfiledSignCarriesVerifiableBinding(t *testing.T) {
	t.Parallel()
	w, _ := twoProfiles(t)
	for i, purpose := range []backend.Purpose{
		backend.PurposeOpCert, backend.PurposeOpCertNext,
	} {
		req := profiledRequest(w, profileMainnet, purpose, byte(i+1), 0, 100)
		// explicit opcert 0 is issued first, so opcert-next at chain 0
		// issues 1
		issue := uint64(i)
		resp := requireProfiledIssue(t, w, req, issue)
		if len(resp.BindingSignature) != ed25519.SignatureSize {
			t.Fatalf(
				"%s: binding signature has %d bytes",
				purpose,
				len(resp.BindingSignature),
			)
		}
		if !ed25519.Verify(
			w.pub,
			backend.AttestedResponseBinding(req, resp.Signature, ""),
			resp.BindingSignature,
		) {
			t.Fatalf("%s: binding signature does not verify", purpose)
		}
		other := req
		other.Profile = profilePreview
		if ed25519.Verify(
			w.pub,
			backend.AttestedResponseBinding(other, resp.Signature, ""),
			resp.BindingSignature,
		) {
			t.Fatalf("%s: binding verifies for another profile", purpose)
		}
	}
}

func TestProfiledRefusals(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*backend.AttestedRequest){
		"unconfigured profile": func(r *backend.AttestedRequest) { r.Profile = "pool@sanchonet" },
		"no profile":           func(r *backend.AttestedRequest) { r.Profile = "" },
		"other key":            func(r *backend.AttestedRequest) { r.KeyHash = backend.KeyHash{9}.String() },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w, objs := twoProfiles(t)
			before := profileObject(t, objs, profileMainnet).data
			req := profiledRequest(
				w,
				profileMainnet,
				backend.PurposeOpCert,
				1,
				0,
				100,
			)
			bad := req
			mutate(&bad)
			resp, err := w.Sign(t.Context(), bad)
			if err != nil || resp.Error == "" || resp.Signature != nil ||
				resp.BindingSignature != nil {
				t.Fatalf("response=%+v err=%v", resp, err)
			}
			if !bytes.Equal(
				before,
				profileObject(t, objs, profileMainnet).data,
			) {
				t.Fatal("refused request changed the counter state")
			}
			// the refusal consumed neither the nonce nor the counter
			requireProfiledIssue(t, w, req, 0)
		})
	}
}

func TestProfiledCountersAreIsolated(t *testing.T) {
	t.Parallel()
	w, _ := twoProfiles(t)
	// explicit counters advance independently
	requireProfiledIssue(
		t,
		w,
		profiledRequest(w, profileMainnet, backend.PurposeOpCert, 1, 0, 100),
		0,
	)
	requireProfiledIssue(
		t,
		w,
		profiledRequest(w, profileMainnet, backend.PurposeOpCert, 2, 1, 100),
		1,
	)
	requireProfiledIssue(
		t,
		w,
		profiledRequest(w, profilePreview, backend.PurposeOpCert, 3, 0, 100),
		0,
	)
	resp, err := w.Sign(
		t.Context(),
		profiledRequest(w, profilePreview, backend.PurposeOpCert, 4, 2, 100),
	)
	if err != nil || resp.Error == "" {
		t.Fatalf("preview skipped a counter: %+v err=%v", resp, err)
	}

	// opcert-next: mainnet raises its floor to 7, preview is unaffected
	requireProfiledIssue(
		t,
		w,
		profiledRequest(
			w,
			profileMainnet,
			backend.PurposeOpCertNext,
			5,
			1,
			100,
		),
		2,
	)
	requireProfiledIssue(
		t,
		w,
		profiledRequest(
			w,
			profileMainnet,
			backend.PurposeOpCertNext,
			6,
			2,
			100,
		),
		3,
	)
	resp, err = w.Sign(
		t.Context(),
		profiledRequest(
			w,
			profileMainnet,
			backend.PurposeOpCertNext,
			7,
			1,
			100,
		),
	)
	if err != nil || resp.Error != refusalBelowFloor {
		t.Fatalf("mainnet below floor: %+v err=%v", resp, err)
	}
	requireProfiledIssue(
		t,
		w,
		profiledRequest(
			w,
			profilePreview,
			backend.PurposeOpCertNext,
			8,
			0,
			100,
		),
		1,
	)
	resp, err = w.Sign(
		t.Context(),
		profiledRequest(
			w,
			profilePreview,
			backend.PurposeOpCertNext,
			9,
			3,
			100,
		),
	)
	if err != nil || resp.Error != refusalAboveIssued {
		t.Fatalf("preview above issued: %+v err=%v", resp, err)
	}
}

func TestProfiledStateIsBoundToItsProfile(t *testing.T) {
	t.Parallel()
	envelopes := &memoryStore{}
	objs := map[string]*memoryCounterObject{
		profileMainnet: {},
		profilePreview: {},
	}
	w, _, err := profiledWorkload(t, envelopes, objs, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireProfiledIssue(
		t,
		w,
		profiledRequest(w, profileMainnet, backend.PurposeOpCert, 1, 0, 100),
		0,
	)
	var state map[string]any
	if err := json.Unmarshal(profileObject(t, objs, profileMainnet).data, &state); err != nil {
		t.Fatal(err)
	}
	if state["profile"] != profileMainnet {
		t.Fatalf(
			"stored state does not name its profile: %s",
			profileObject(t, objs, profileMainnet).data,
		)
	}
	// the mainnet object presented as the preview counter is refused
	swapped := map[string]*memoryCounterObject{
		profileMainnet: objs[profilePreview],
		profilePreview: objs[profileMainnet],
	}
	if _, _, err := profiledWorkload(t, envelopes, swapped, nil); err == nil {
		t.Fatal("workload started with swapped profile counters")
	}
	// the same objects restart and keep their counters
	w, _, err = profiledWorkload(t, envelopes, objs, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := w.Sign(
		t.Context(),
		profiledRequest(w, profileMainnet, backend.PurposeOpCert, 2, 0, 100),
	)
	if err != nil || resp.Error == "" {
		t.Fatalf("restart reissued counter 0: %+v err=%v", resp, err)
	}
	requireProfiledIssue(
		t,
		w,
		profiledRequest(w, profileMainnet, backend.PurposeOpCert, 3, 1, 100),
		1,
	)
}

func TestProfiledWorkloadRefusesLegacyCounterObject(t *testing.T) {
	t.Parallel()
	envelopes := &memoryStore{}
	legacy := &memoryCounterObject{}
	w := cloudWorkload(t, envelopes, legacy)
	requireIssued(t, w, nextRequest(w, 1, 0, 100), 1)
	// a profile cannot adopt the unprofiled object
	_, _, err := profiledWorkload(
		t,
		envelopes,
		map[string]*memoryCounterObject{profileMainnet: legacy},
		[]string{profileMainnet},
	)
	if err == nil {
		t.Fatal("profile adopted an unprofiled counter object")
	}
}

func TestUnprofiledCounterObjectBytesUnchanged(t *testing.T) {
	t.Parallel()
	obj := &memoryCounterObject{}
	w := cloudWorkload(t, &memoryStore{}, obj)
	requireIssued(t, w, nextRequest(w, 1, 4, 100), 5)
	want := `{"version":"bursa-confidential-space-counter/2","key_hash":"` +
		w.hash.String() +
		`","next_issue_number":6,"opcert_floor":4,"last_issued":5,"last_issued_period":100}`
	if string(obj.data) != want {
		t.Fatalf("object = %s\nwant     %s", obj.data, want)
	}
}

func TestProfiledWorkloadRefusesUnprofiledRequests(t *testing.T) {
	t.Parallel()
	w, _ := twoProfiles(t)
	resp, err := w.Sign(
		t.Context(),
		profiledRequest(w, "", backend.PurposeOpCertNext, 1, 0, 100),
	)
	if err != nil || resp.Error == "" || resp.Signature != nil {
		t.Fatalf(
			"unprofiled request on a profiled workload: %+v err=%v",
			resp,
			err,
		)
	}
}

func TestProfiledConfigValidation(t *testing.T) {
	t.Parallel()
	base := func() Config {
		return Config{
			Audience: "a", KMSKey: testKMSKey, Tokens: &testTokens{},
			Wrapper: &testWrapper{},
		}
	}
	// bound is a counter store bound to profile, so each case is refused by
	// its own rule rather than by the store binding.
	bound := func(profile string) CounterStore {
		return &CloudCounterStore{
			object:  &memoryCounterObject{},
			profile: profile,
		}
	}
	long := strings.Repeat("p", 33)
	for name, mutate := range map[string]func(*Config){
		"counter and profiles": func(c *Config) {
			c.Counter = &memoryStore{}
			c.Profiles = map[string]CounterStore{"p": bound("p")}
		},
		"empty profile name": func(c *Config) {
			c.Profiles = map[string]CounterStore{"": bound("")}
		},
		"nil profile counter": func(c *Config) {
			c.Profiles = map[string]CounterStore{"p": nil}
		},
		"no counter": func(c *Config) {},
		"profile name longer than armory allows": func(c *Config) {
			c.Profiles = map[string]CounterStore{long: bound(long)}
		},
		"profile name with a slash": func(c *Config) {
			c.Profiles = map[string]CounterStore{
				"pool/mainnet": bound("pool/mainnet"),
			}
		},
		"profile counter creation without profiles": func(c *Config) {
			c.Counter = &memoryStore{}
			c.CreateProfileCounters = []string{"p"}
		},
		"profile counter creation for an unserved profile": func(c *Config) {
			c.Profiles = map[string]CounterStore{"p": bound("p")}
			c.CreateProfileCounters = []string{"q"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := base()
			cfg.Store = &memoryStore{}
			mutate(&cfg)
			if _, err := New(t.Context(), cfg); err == nil {
				t.Fatal("New accepted the configuration")
			}
		})
	}
}

// Profile names follow the armory device's rule: 1 to 32 of A-Z a-z 0-9 @ . _ -
func TestValidateProfileMatchesArmory(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"p", "otg@preview", "a.b_c-d@E9", strings.Repeat("p", 32),
	} {
		if err := ValidateProfile(name); err != nil {
			t.Errorf("%q refused: %v", name, err)
		}
	}
	for _, name := range []string{
		"", strings.Repeat("p", 33), "pool mainnet", "pool/mainnet", "p\u00e9",
	} {
		if ValidateProfile(name) == nil {
			t.Errorf("%q accepted", name)
		}
	}
}

func TestProfileCounterCreationNeedsOptIn(t *testing.T) {
	t.Parallel()
	envelopes := &memoryStore{}
	objs := map[string]*memoryCounterObject{profileMainnet: {}}
	if _, _, err := profiledWorkload(t, envelopes, objs, nil); err != nil {
		t.Fatal(err)
	}
	// adding a profile to an active key needs the explicit opt-in
	objs[profilePreview] = &memoryCounterObject{}
	if _, _, err := profiledWorkload(t, envelopes, objs, nil); err == nil {
		t.Fatal("a new profile counter was created without the opt-in")
	}
	if profileObject(t, objs, profilePreview).data != nil {
		t.Fatal("refused start wrote the counter")
	}
	if _, _, err := profiledWorkload(
		t, envelopes, objs, []string{profilePreview},
	); err != nil {
		t.Fatal(err)
	}
	if profileObject(t, objs, profilePreview).data == nil {
		t.Fatal("opt-in did not create the profile counter")
	}
}

func profiledInventoryRequest(body string) *http.Request {
	req := httptest.NewRequest(
		http.MethodPost,
		"/v1/inventory",
		strings.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{}},
		VerifiedChains:   [][]*x509.Certificate{{{}}},
	}
	return req
}

func TestProfiledInventory(t *testing.T) {
	t.Parallel()
	objs := map[string]*memoryCounterObject{
		profileMainnet: {},
		profilePreview: {},
	}
	w, tokens, err := profiledWorkload(t, &memoryStore{}, objs, nil)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{7}, 32)
	nonceJSON, _ := json.Marshal(nonce)
	for _, profile := range []string{profileMainnet, profilePreview} {
		inv, err := w.Inventory(t.Context(), nonce, profile)
		if err != nil {
			t.Fatalf("%s: %v", profile, err)
		}
		if len(inv.Keys) != 1 || !bytes.Equal(inv.Keys[0].PublicKey, w.pub) {
			t.Fatalf("%s: inventory %+v", profile, inv)
		}
		if tokens.nonces[0] != hex.EncodeToString(
			backend.InventoryBinding(nonce, inv.Keys),
		) {
			t.Fatalf("%s: token not bound to the inventory", profile)
		}
	}
	for _, profile := range []string{"", "pool@sanchonet"} {
		if _, err := w.Inventory(t.Context(), nonce, profile); err == nil {
			t.Fatalf("inventory served profile %q", profile)
		}
	}

	handle := func(profile string) int {
		body := `{"nonce":` + string(nonceJSON)
		if profile != "" {
			body += `,"profile":"` + profile + `"`
		}
		rw := httptest.NewRecorder()
		w.Handler().ServeHTTP(rw, profiledInventoryRequest(body+`}`))
		return rw.Code
	}
	if got := handle(profileMainnet); got != http.StatusOK {
		t.Fatalf("configured profile: status %d", got)
	}
	for _, profile := range []string{"", "pool@sanchonet"} {
		if got := handle(profile); got != http.StatusBadRequest {
			t.Fatalf(
				"profile %q: status %d, want %d",
				profile,
				got,
				http.StatusBadRequest,
			)
		}
	}
}

// profileEnclave is the signer host's view of the workload. rewrite stands in
// for an untrusted proxy between the two.
type profileEnclave struct {
	w       *Workload
	profile string
	rewrite func(*backend.AttestedRequest)
}

func (e profileEnclave) Inventory(
	ctx context.Context,
	nonce []byte,
) (backend.AttestedInventory, error) {
	return e.w.Inventory(ctx, nonce, e.profile)
}

func (e profileEnclave) Sign(
	ctx context.Context,
	req backend.AttestedRequest,
) (backend.AttestedResponse, error) {
	if e.rewrite != nil {
		e.rewrite(&req)
	}
	return e.w.Sign(ctx, req)
}

func profiledKey(
	t *testing.T,
	w *Workload,
	profile string,
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
	ref, err := b.GetKey(t.Context(), w.hash)
	if err != nil {
		t.Fatal(err)
	}
	next, ok := ref.(backend.OpCertNextSigner)
	if !ok {
		t.Fatal("attested key does not implement OpCertNextSigner")
	}
	return next
}

func TestHostProfiledBackendsAgainstWorkload(t *testing.T) {
	t.Parallel()
	w, _ := twoProfiles(t)
	kes := bytes.Repeat([]byte{0x23}, 32)
	mainnet := profiledKey(t, w, profileMainnet, nil)
	preview := profiledKey(t, w, profilePreview, nil)

	for _, tc := range []struct {
		key   backend.OpCertNextSigner
		chain uint64
		want  uint64
	}{
		{mainnet, 9, 10},
		{preview, 0, 1},
		{mainnet, 10, 11},
		{preview, 1, 2},
	} {
		sig, issue, err := tc.key.SignOpCertNext(
			t.Context(),
			kes,
			tc.chain,
			100,
		)
		if err != nil || issue != tc.want {
			t.Fatalf(
				"chain %d: issue=%d err=%v, want %d",
				tc.chain,
				issue,
				err,
				tc.want,
			)
		}
		if !ed25519.Verify(
			w.pub,
			lcommon.OpCertSignableBytes(kes, issue, 100),
			sig,
		) {
			t.Fatal("signature does not verify")
		}
	}
	_, _, err := preview.SignOpCertNext(t.Context(), kes, 9, 100)
	if !errors.Is(err, backend.ErrCustodyCounterConflict) {
		t.Fatalf("preview with the mainnet counter: %v", err)
	}
}

func TestProxyProfileSwapIsRefused(t *testing.T) {
	t.Parallel()
	w, objs := twoProfiles(t)
	kes := bytes.Repeat([]byte{0x23}, 32)

	// a proxy moves a mainnet request to the preview profile: the workload
	// signs for preview, and the mainnet backend rejects the binding
	swap := profiledKey(t, w, profileMainnet, func(r *backend.AttestedRequest) {
		r.Profile = profilePreview
	})
	_, _, err := swap.SignOpCertNext(t.Context(), kes, 0, 100)
	if !errors.Is(err, backend.ErrInvalidSignature) {
		t.Fatalf("swapped profile: err = %v, want ErrInvalidSignature", err)
	}
	if profileObject(t, objs, profileMainnet).data == nil {
		t.Fatal("mainnet counter missing")
	}

	// a proxy strips the profile: the workload refuses it
	strip := profiledKey(
		t,
		w,
		profileMainnet,
		func(r *backend.AttestedRequest) {
			r.Profile = ""
		},
	)
	if _, _, err := strip.SignOpCertNext(t.Context(), kes, 0, 100); err == nil ||
		errors.Is(err, backend.ErrInvalidSignature) {
		t.Fatalf("stripped profile: err = %v, want an enclave refusal", err)
	}
}

// A profile's counter store must hold that profile's state: a store bound to
// one profile must not serve another, and the unprofiled counter must not be
// a profile's store.
func TestProfileCounterStoreMustBeBoundToItsProfile(t *testing.T) {
	t.Parallel()
	for name, configure := range map[string]func(*Config, CounterStore){
		"one store under two profiles": func(c *Config, s CounterStore) {
			c.Profiles = map[string]CounterStore{
				profileMainnet: s,
				profilePreview: s,
			}
		},
		"store under another profile": func(c *Config, s CounterStore) {
			c.Profiles = map[string]CounterStore{profilePreview: s}
		},
		"profile store as the unprofiled counter": func(c *Config, s CounterStore) {
			c.Counter = s
		},
		"store bound to no profile": func(c *Config, _ CounterStore) {
			c.Profiles = map[string]CounterStore{profileMainnet: &memoryStore{}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			obj := &memoryCounterObject{}
			cfg := Config{
				Audience: "https://signer.example/pool",
				KMSKey:   testKMSKey,
				Tokens:   &testTokens{},
				Wrapper:  &testWrapper{},
				Store:    &memoryStore{},
			}
			configure(&cfg, &CloudCounterStore{object: obj, profile: profileMainnet})
			if w, err := New(t.Context(), cfg); err == nil {
				_ = w.Close()
				t.Fatal("New accepted the configuration")
			}
			if obj.data != nil {
				t.Fatal("refused configuration wrote the counter")
			}
		})
	}
}

// The profile counter object is derived from --counter-object, so an empty
// base name is refused rather than composed into "/profiles/<profile>".
func TestProfiledCounterStoreNeedsBaseObject(t *testing.T) {
	t.Parallel()
	for _, base := range []string{"", "  "} {
		_, err := NewProfiledCloudCounterStore(
			t.Context(), "bucket", base, profileMainnet, "",
		)
		if !errors.Is(err, errCounterLocationRequired) {
			t.Errorf("base %q: err = %v, want the missing object refusal", base, err)
		}
	}
	if got, want := profileCounterObject(
		"pool-cold/counter.json", profileMainnet,
	), "pool-cold/counter.json/profiles/pool@mainnet"; got != want {
		t.Fatalf("profile counter object = %q, want %q", got, want)
	}
}

// Creating the counter of a profile being added must not recreate the
// missing counter of another profile, which would reset its issue history.
func TestProfileCounterCreationIsScopedToNamedProfiles(t *testing.T) {
	t.Parallel()
	envelopes := &memoryStore{}
	objs := map[string]*memoryCounterObject{profileMainnet: {}}
	w, _, err := profiledWorkload(t, envelopes, objs, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireProfiledIssue(t, w, profiledRequest(
		w, profileMainnet, backend.PurposeOpCert, 1, 0, 100,
	), 0)
	_ = w.Close()
	// the mainnet counter object is lost while preview is being added
	objs[profileMainnet] = &memoryCounterObject{}
	objs[profilePreview] = &memoryCounterObject{}
	if _, _, err := profiledWorkload(
		t, envelopes, objs, []string{profilePreview},
	); err == nil {
		t.Fatal("start recreated a missing counter of a profile not named")
	}
	if profileObject(t, objs, profileMainnet).data != nil {
		t.Fatal("start recreated the missing counter of a profile not named")
	}
}
