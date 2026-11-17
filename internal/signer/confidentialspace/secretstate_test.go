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
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const testStateSecret = "projects/data/secrets/pool-state"

type fakeSecretVersion struct {
	data  []byte
	state secretmanagerpb.SecretVersion_State
}

// fakeSecretClient models one Secret Manager secret. Version n is
// versions[n-1].
type fakeSecretClient struct {
	mu       sync.Mutex
	versions []*fakeSecretVersion
	// missing makes the secret not exist.
	missing    bool
	accessErr  error
	addErr     error
	destroyErr error
	adds       int
	destroys   int
	// projectNumber, when set, is the project the API names in the resource
	// names it returns, as Secret Manager does for a request naming the
	// project by ID.
	projectNumber string
	// visible, when nonzero, is the newest version the latest alias and the
	// version list show: both are eventually consistent. Reads by version
	// number see every version.
	visible int
	// onList runs when a version list is requested.
	onList func(*fakeSecretClient)
	// cleanupBudgets records the time left on the context of every list and
	// destroy call.
	cleanupBudgets []time.Duration
}

func (c *fakeSecretClient) nameLocked(n int) string {
	parent := testStateSecret
	if c.projectNumber != "" {
		parent = "projects/" + c.projectNumber + "/secrets/pool-state"
	}
	return fmt.Sprintf("%s/versions/%d", parent, n)
}

// numberLocked resolves a version name in either project form.
func (c *fakeSecretClient) numberLocked(name string) (int, bool) {
	for _, parent := range []string{
		testStateSecret,
		"projects/" + c.projectNumber + "/secrets/pool-state",
	} {
		number, ok := strings.CutPrefix(name, parent+"/versions/")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(number)
		if err != nil || n < 1 || n > len(c.versions) {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

func (c *fakeSecretClient) shownLocked(n int) bool {
	return c.visible == 0 || n <= c.visible
}

func (c *fakeSecretClient) recordBudgetLocked(ctx context.Context) {
	if deadline, ok := ctx.Deadline(); ok {
		c.cleanupBudgets = append(c.cleanupBudgets, time.Until(deadline))
	}
}

func (c *fakeSecretClient) addLocked(data []byte) int {
	c.versions = append(c.versions, &fakeSecretVersion{
		data:  bytes.Clone(data),
		state: secretmanagerpb.SecretVersion_ENABLED,
	})
	return len(c.versions)
}

// seed adds a version out of band, as provisioning or an attacker would.
func (c *fakeSecretClient) seed(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addLocked(data)
}

func (c *fakeSecretClient) latest() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.versions) - 1; i >= 0; i-- {
		if c.versions[i].state == secretmanagerpb.SecretVersion_ENABLED {
			return bytes.Clone(c.versions[i].data)
		}
	}
	return nil
}

func (c *fakeSecretClient) enabled() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, v := range c.versions {
		if v.state == secretmanagerpb.SecretVersion_ENABLED {
			n++
		}
	}
	return n
}

func (c *fakeSecretClient) counts() (adds, destroys int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.adds, c.destroys
}

func (c *fakeSecretClient) accessResponseLocked(
	n int,
) *secretmanagerpb.AccessSecretVersionResponse {
	v := c.versions[n-1]
	crc := checksumValue(v.data)
	return &secretmanagerpb.AccessSecretVersionResponse{
		Name: c.nameLocked(n),
		Payload: &secretmanagerpb.SecretPayload{
			Data:       bytes.Clone(v.data),
			DataCrc32C: &crc,
		},
	}
}

func (c *fakeSecretClient) AccessSecretVersion(
	_ context.Context,
	req *secretmanagerpb.AccessSecretVersionRequest,
) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.accessErr != nil {
		return nil, c.accessErr
	}
	if c.missing {
		return nil, status.Error(codes.NotFound, "no such secret")
	}
	if req.GetName() == testStateSecret+"/versions/latest" {
		for n := len(c.versions); n >= 1; n-- {
			if c.shownLocked(n) &&
				c.versions[n-1].state == secretmanagerpb.SecretVersion_ENABLED {
				return c.accessResponseLocked(n), nil
			}
		}
		return nil, status.Error(codes.NotFound, "no such version")
	}
	n, ok := c.numberLocked(req.GetName())
	if !ok {
		return nil, status.Error(codes.NotFound, "no such version")
	}
	if c.versions[n-1].state != secretmanagerpb.SecretVersion_ENABLED {
		return nil, status.Error(
			codes.FailedPrecondition,
			"version is not enabled",
		)
	}
	return c.accessResponseLocked(n), nil
}

func (c *fakeSecretClient) AddSecretVersion(
	_ context.Context,
	req *secretmanagerpb.AddSecretVersionRequest,
) (*secretmanagerpb.SecretVersion, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.addErr != nil {
		return nil, c.addErr
	}
	if req.GetParent() != testStateSecret || c.missing {
		return nil, status.Error(codes.NotFound, "no such secret")
	}
	data := req.GetPayload().GetData()
	if got := req.GetPayload().DataCrc32C; got == nil ||
		*got != checksumValue(data) {
		return nil, status.Error(codes.InvalidArgument, "bad checksum")
	}
	c.adds++
	n := c.addLocked(data)
	return &secretmanagerpb.SecretVersion{
		Name:  c.nameLocked(n),
		State: secretmanagerpb.SecretVersion_ENABLED,
	}, nil
}

type fakeVersionIterator struct {
	versions []*secretmanagerpb.SecretVersion
	err      error
}

func (i *fakeVersionIterator) Next() (*secretmanagerpb.SecretVersion, error) {
	if i.err != nil {
		return nil, i.err
	}
	if len(i.versions) == 0 {
		return nil, iterator.Done
	}
	v := i.versions[0]
	i.versions = i.versions[1:]
	return v, nil
}

// ListSecretVersions lists newest first, as Secret Manager does.
func (c *fakeSecretClient) ListSecretVersions(
	ctx context.Context,
	req *secretmanagerpb.ListSecretVersionsRequest,
) secretVersionIterator {
	c.mu.Lock()
	hook := c.onList
	c.mu.Unlock()
	if hook != nil {
		hook(c)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recordBudgetLocked(ctx)
	if c.missing {
		return &fakeVersionIterator{
			err: status.Error(codes.NotFound, "no such secret"),
		}
	}
	it := &fakeVersionIterator{}
	for n := len(c.versions); n >= 1; n-- {
		v := c.versions[n-1]
		if !c.shownLocked(n) ||
			(req.GetFilter() == "state:ENABLED" &&
				v.state != secretmanagerpb.SecretVersion_ENABLED) {
			continue
		}
		it.versions = append(it.versions, &secretmanagerpb.SecretVersion{
			Name: c.nameLocked(n), State: v.state,
		})
	}
	return it
}

func (c *fakeSecretClient) DestroySecretVersion(
	ctx context.Context,
	req *secretmanagerpb.DestroySecretVersionRequest,
) (*secretmanagerpb.SecretVersion, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recordBudgetLocked(ctx)
	if c.destroyErr != nil {
		return nil, c.destroyErr
	}
	n, ok := c.numberLocked(req.GetName())
	if !ok {
		return nil, status.Error(codes.NotFound, "no such version")
	}
	v := c.versions[n-1]
	v.state = secretmanagerpb.SecretVersion_DESTROYED
	v.data = nil
	c.destroys++
	return &secretmanagerpb.SecretVersion{
		Name: c.nameLocked(n), State: v.state,
	}, nil
}

func (*fakeSecretClient) Close() error { return nil }

// provisionedSecret returns a secret provisioned the way key import will: one
// version holding a pending envelope and no counters.
func provisionedSecret(t *testing.T) *fakeSecretClient {
	t.Helper()
	key, err := createEnvelope(t.Context(), Config{
		KMSKey:  testKMSKey,
		Wrapper: &testWrapper{},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(stateDocument{
		Version:  stateDocumentVersion,
		Envelope: key.stored,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &fakeSecretClient{}
	c.seed(data)
	return c
}

func newTestStateStore(
	t *testing.T,
	c *fakeSecretClient,
) *SecretStateStore {
	t.Helper()
	s, err := newSecretStateStore(
		t.Context(), c, testStateSecret, testKMSKey, &testWrapper{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// stateWorkload starts a workload over a fresh store on c, serving profiles
// (or the unprofiled state when none). A second call is a restart.
func stateWorkload(
	t *testing.T,
	c *fakeSecretClient,
	create []string,
	profiles ...string,
) (*Workload, *SecretStateStore, error) {
	t.Helper()
	s := newTestStateStore(t, c)
	cfg := Config{
		Audience:              "https://signer.example/pool",
		KMSKey:                testKMSKey,
		Tokens:                &testTokens{},
		Wrapper:               &testWrapper{},
		Store:                 s,
		CreateProfileCounters: create,
	}
	if len(profiles) == 0 {
		counter, err := s.Counter("")
		if err != nil {
			t.Fatal(err)
		}
		cfg.Counter = counter
	} else {
		cfg.Profiles = make(map[string]CounterStore, len(profiles))
		for _, p := range profiles {
			counter, err := s.Counter(p)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Profiles[p] = counter
		}
	}
	w, err := New(t.Context(), cfg)
	if err == nil {
		t.Cleanup(func() { _ = w.Close() })
	}
	return w, s, err
}

func mustStateWorkload(
	t *testing.T,
	c *fakeSecretClient,
	profiles ...string,
) *Workload {
	t.Helper()
	w, _, err := stateWorkload(t, c, nil, profiles...)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func explicitReq(
	w *Workload,
	profile string,
	nonce byte,
	counter uint64,
) backend.AttestedRequest {
	return profiledRequest(
		w,
		profile,
		backend.PurposeOpCert,
		nonce,
		counter,
		10,
	)
}

func requireRefusedResp(
	t *testing.T,
	w *Workload,
	req backend.AttestedRequest,
) backend.AttestedResponse {
	t.Helper()
	resp, err := w.Sign(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Error == "" || len(resp.Signature) != 0 {
		t.Fatalf("request was not refused: %+v", resp)
	}
	return resp
}

func latestDoc(t *testing.T, c *fakeSecretClient) stateDocument {
	t.Helper()
	var doc stateDocument
	if err := json.Unmarshal(c.latest(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestSecretStateStartupActivatesAndKeepsOneVersion(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	w := mustStateWorkload(t, c)
	doc := latestDoc(t, c)
	var e envelope
	if err := json.Unmarshal(doc.Envelope, &e); err != nil {
		t.Fatal(err)
	}
	if e.Phase != envelopeActive {
		t.Fatalf("envelope phase %q, want %q", e.Phase, envelopeActive)
	}
	if _, ok := doc.Counters[""]; !ok {
		t.Fatal("unprofiled counter record was not created")
	}
	requireProfiledIssue(t, w, explicitReq(w, "", 1, 0), 0)
	if n := c.enabled(); n != 1 {
		t.Fatalf("%d enabled versions, want 1", n)
	}
	adds, destroys := c.counts()
	if destroys != adds {
		t.Fatalf(
			"%d adds but %d destroys: older versions remain",
			adds,
			destroys,
		)
	}
}

func TestSecretStateDestroyFailureIsNotFatalAndRetried(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	w := mustStateWorkload(t, c)
	c.mu.Lock()
	c.destroyErr = errors.New("destroy denied")
	c.mu.Unlock()

	requireProfiledIssue(t, w, explicitReq(w, "", 1, 0), 0)
	if n := c.enabled(); n < 2 {
		t.Fatalf("%d enabled versions, the failed destroy left none", n)
	}
	requireProfiledIssue(t, w, explicitReq(w, "", 2, 1), 1)

	c.mu.Lock()
	c.destroyErr = nil
	c.mu.Unlock()
	requireProfiledIssue(t, w, explicitReq(w, "", 3, 2), 2)
	if n := c.enabled(); n != 1 {
		t.Fatalf("%d enabled versions after the retry, want 1", n)
	}
}

func TestSecretStateNeverGeneratesKey(t *testing.T) {
	t.Parallel()
	emptyEnvelope, err := json.Marshal(stateDocument{
		Version: stateDocumentVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		build      func() *fakeSecretClient
		notProvis  bool
		wantSubstr string
	}{
		{
			name:      "missing secret",
			build:     func() *fakeSecretClient { return &fakeSecretClient{missing: true} },
			notProvis: true,
		},
		{
			name:      "secret without a version",
			build:     func() *fakeSecretClient { return &fakeSecretClient{} },
			notProvis: true,
		},
		{
			name: "empty payload",
			build: func() *fakeSecretClient {
				c := &fakeSecretClient{}
				c.seed([]byte{})
				return c
			},
			notProvis: true,
		},
		{
			name: "document without an envelope",
			build: func() *fakeSecretClient {
				c := &fakeSecretClient{}
				c.seed(emptyEnvelope)
				return c
			},
			notProvis: true,
		},
		{
			name: "oversized document",
			build: func() *fakeSecretClient {
				c := &fakeSecretClient{}
				c.seed(bytes.Repeat([]byte{' '}, maxStateDocumentSize+1))
				return c
			},
			wantSubstr: "size limit",
		},
		{
			name: "read denied",
			build: func() *fakeSecretClient {
				return &fakeSecretClient{
					accessErr: status.Error(codes.PermissionDenied, "denied"),
				}
			},
			wantSubstr: "read state secret",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := tt.build()
			_, _, err := stateWorkload(t, c, nil)
			if err == nil {
				t.Fatal("workload started without a provisioned key")
			}
			if errors.Is(err, ErrEnvelopeNotFound) {
				t.Fatalf(
					"error would make the workload generate a key: %v",
					err,
				)
			}
			if tt.notProvis && !errors.Is(err, ErrStateNotProvisioned) {
				t.Fatalf("error %v is not ErrStateNotProvisioned", err)
			}
			if tt.wantSubstr != "" &&
				!strings.Contains(err.Error(), tt.wantSubstr) {
				t.Fatalf("error %q lacks %q", err, tt.wantSubstr)
			}
			if adds, _ := c.counts(); adds != 0 {
				t.Fatalf("%d versions written: a key was persisted", adds)
			}
		})
	}
}

func TestSecretStateCreateAlwaysRefuses(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	s := newTestStateStore(t, c)
	if err := s.Create([]byte("anything")); !errors.Is(
		err,
		ErrStateCreateRefused,
	) {
		t.Fatalf("Create = %v, want ErrStateCreateRefused", err)
	}
	if errors.Is(ErrStateCreateRefused, ErrEnvelopeExists) {
		t.Fatal("refusal must not look like a lost create race")
	}
	if adds, _ := c.counts(); adds != 0 {
		t.Fatal("Create wrote a version")
	}
}

func TestSecretStateSurvivesRestart(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	w := mustStateWorkload(t, c)
	requireProfiledIssue(t, w, explicitReq(w, "", 1, 0), 0)
	requireProfiledIssue(t, w, explicitReq(w, "", 2, 1), 1)

	w2 := mustStateWorkload(t, c)
	if w2.hash != w.hash {
		t.Fatal("restart changed the pool identity")
	}
	requireRefusedResp(t, w2, explicitReq(w2, "", 3, 1))
	requireRefusedResp(t, w2, explicitReq(w2, "", 4, 0))
	requireProfiledIssue(t, w2, explicitReq(w2, "", 5, 2), 2)
}

func TestSecretStateProfilesAreIsolatedAndPersisted(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	w := mustStateWorkload(t, c, profileMainnet, profilePreview)
	requireProfiledIssue(t, w, explicitReq(w, profileMainnet, 1, 0), 0)
	requireProfiledIssue(t, w, explicitReq(w, profileMainnet, 2, 1), 1)
	requireProfiledIssue(t, w, explicitReq(w, profilePreview, 3, 0), 0)

	w2 := mustStateWorkload(t, c, profileMainnet, profilePreview)
	requireProfiledIssue(t, w2, explicitReq(w2, profileMainnet, 4, 2), 2)
	requireProfiledIssue(t, w2, explicitReq(w2, profilePreview, 5, 1), 1)
}

// rewriteLatest adds a version holding the latest document after edit.
func rewriteLatest(
	t *testing.T,
	c *fakeSecretClient,
	edit func(*stateDocument),
) {
	t.Helper()
	doc := latestDoc(t, c)
	edit(&doc)
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	c.seed(data)
}

func TestSecretStateRefusesUnauthenticState(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T) *fakeSecretClient {
		t.Helper()
		c := provisionedSecret(t)
		w := mustStateWorkload(t, c, profileMainnet, profilePreview)
		requireProfiledIssue(t, w, explicitReq(w, profileMainnet, 1, 0), 0)
		return c
	}
	tests := []struct {
		name string
		edit func(*stateDocument)
	}{
		{"tampered record", func(d *stateDocument) {
			d.Counters[profileMainnet][len(d.Counters[profileMainnet])-1] ^= 1
		}},
		{"truncated record", func(d *stateDocument) {
			d.Counters[profileMainnet] = d.Counters[profileMainnet][:4]
		}},
		{"record moved to another profile", func(d *stateDocument) {
			d.Counters[profileMainnet], d.Counters[profilePreview] =
				d.Counters[profilePreview], d.Counters[profileMainnet]
		}},
		{"record moved to the unprofiled slot", func(d *stateDocument) {
			d.Counters[""] = d.Counters[profileMainnet]
		}},
		{"document version", func(d *stateDocument) {
			d.Version = "bursa-confidential-space-state/0"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := setup(t)
			rewriteLatest(t, c, tt.edit)
			if _, _, err := stateWorkload(
				t, c, nil, profileMainnet, profilePreview,
			); err == nil {
				t.Fatal("workload started on state that must be refused")
			}
		})
	}
}

// sealedWith replaces a document whose record of profile holds state, sealed
// correctly by a store of the same key, so only the plaintext is wrong.
func sealedWith(
	t *testing.T,
	c *fakeSecretClient,
	profile string,
	state counterState,
) {
	t.Helper()
	s := newTestStateStore(t, c)
	if _, err := s.Load(); err != nil {
		t.Fatal(err)
	}
	sealed, err := s.sealCounter(profile, state)
	if err != nil {
		t.Fatal(err)
	}
	rewriteLatest(t, c, func(d *stateDocument) { d.Counters[profile] = sealed })
}

func TestSecretStateRefusesWrongPlaintext(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		state func(hash string) counterState
	}{
		{"another key", func(string) counterState {
			return counterState{
				Version: counterStateVersion,
				KeyHash: strings.Repeat("ab", 28),
			}
		}},
		{"legacy version", func(h string) counterState {
			return counterState{Version: counterStateVersionV1, KeyHash: h}
		}},
		{"another profile named inside", func(h string) counterState {
			return counterState{
				Version: counterStateVersion, KeyHash: h, Profile: profilePreview,
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := provisionedSecret(t)
			w := mustStateWorkload(t, c)
			sealedWith(t, c, "", tt.state(w.hash.String()))
			if _, _, err := stateWorkload(t, c, nil); err == nil {
				t.Fatal("workload started on a record it must refuse")
			}
		})
	}
}

func TestSecretStateRefusesOtherKMSKey(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	s, err := newSecretStateStore(
		t.Context(), c, testStateSecret, testKMSKey+"-other", &testWrapper{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("state of another KMS key loaded")
	}
}

func TestSecretStateRefusesWhenKMSDenies(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	s, err := newSecretStateStore(
		t.Context(), c, testStateSecret, testKMSKey,
		&testWrapper{denyUnwrap: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil || errors.Is(err, ErrEnvelopeNotFound) {
		t.Fatalf("Load = %v, want a KMS failure", err)
	}
}

func TestSecretStateMemoryIsNeverLowered(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	w := mustStateWorkload(t, c)
	requireProfiledIssue(t, w, explicitReq(w, "", 1, 0), 0)
	older := c.latest()
	requireProfiledIssue(t, w, explicitReq(w, "", 2, 1), 1)
	// A lower state shows up as the newest version while the workload runs.
	c.seed(older)

	requireRefusedResp(t, w, explicitReq(w, "", 3, 1))
	requireProfiledIssue(t, w, explicitReq(w, "", 4, 2), 2)

	w2 := mustStateWorkload(t, c)
	requireRefusedResp(t, w2, explicitReq(w2, "", 5, 2))
	requireProfiledIssue(t, w2, explicitReq(w2, "", 6, 3), 3)
}

func TestSecretStateSaveFailureStopsUntilRestart(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	w := mustStateWorkload(t, c)
	requireProfiledIssue(t, w, explicitReq(w, "", 1, 0), 0)

	addsBefore, _ := c.counts()
	c.mu.Lock()
	c.addErr = errors.New("secret manager unavailable")
	c.mu.Unlock()
	requireRefusedResp(t, w, explicitReq(w, "", 2, 1))

	// The store stays stopped after the outage ends, for either path.
	c.mu.Lock()
	c.addErr = nil
	c.mu.Unlock()
	requireRefusedResp(t, w, explicitReq(w, "", 3, 1))
	requireRefusedResp(t, w, profiledRequest(
		w, "", backend.PurposeOpCertNext, 4, 5, 10,
	))
	before := c.latest()
	if adds, _ := c.counts(); adds != addsBefore {
		t.Fatalf(
			"%d versions added, want the %d before the outage",
			adds,
			addsBefore,
		)
	}
	if !bytes.Equal(before, c.latest()) {
		t.Fatal("a stopped store wrote")
	}

	// A restart reloads the last saved state: counter 1 was never committed.
	w2 := mustStateWorkload(t, c)
	requireProfiledIssue(t, w2, explicitReq(w2, "", 5, 1), 1)
}

func TestSecretStateSaveFailureDoesNotAdvanceMemory(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	_, s, err := stateWorkload(t, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	counter, err := s.Counter("")
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	hash := s.hash
	s.mu.Unlock()
	c.mu.Lock()
	c.addErr = errors.New("secret manager unavailable")
	c.mu.Unlock()
	if err := counter.CheckAndAdvance(t.Context(), hash, 0, 10); err == nil {
		t.Fatal("failed save reported success")
	}
	s.mu.Lock()
	next := s.states[""].NextIssueNumber
	stopped := s.stopped
	s.mu.Unlock()
	if next != 0 {
		t.Fatalf("memory advanced to %d on a failed save", next)
	}
	if !errors.Is(stopped, ErrStateStopped) {
		t.Fatalf("store not stopped: %v", stopped)
	}
	c.mu.Lock()
	c.addErr = nil
	c.mu.Unlock()
	if _, err := counter.NextOpCert(
		t.Context(), hash, 5, 10,
	); !errors.Is(err, ErrStateStopped) {
		t.Fatalf("NextOpCert after a failed save = %v", err)
	}
}

func TestSecretStateReplaceChecksEnvelope(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	_, s, err := stateWorkload(t, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	current, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Replace([]byte("stale"), current); !errors.Is(
		err,
		ErrEnvelopeChanged,
	) {
		t.Fatalf("Replace with stale expected = %v", err)
	}
	// An envelope of another key, whose data key is not the sealing key's.
	other, err := createEnvelope(t.Context(), Config{
		KMSKey: testKMSKey, Wrapper: &testWrapper{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Replace(current, other.active); err == nil {
		t.Fatal("Replace accepted another key's envelope")
	}
	if err := s.Replace(current, []byte("{")); err == nil {
		t.Fatal("Replace accepted a malformed envelope")
	}
	got, err := s.Load()
	if err != nil || !bytes.Equal(got, current) {
		t.Fatalf("a refused Replace changed the envelope: %v", err)
	}
}

// TestSecretStateMatchesCloudCounterRules drives the same requests through
// the Cloud Storage counter and the Secret Manager counter: every decision
// and issue number must agree.
func TestSecretStateMatchesCloudCounterRules(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	w := mustStateWorkload(t, c)
	_, s, err := stateWorkload(t, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.Counter("")
	if err != nil {
		t.Fatal(err)
	}
	cloud := &CloudCounterStore{object: &memoryCounterObject{}}
	if err := cloud.Prepare(t.Context(), w.hash, true); err != nil {
		t.Fatal(err)
	}
	type step struct {
		next          bool
		chain, period uint64
	}
	steps := []step{
		{true, 5, 10}, {true, 5, 10}, {true, 5, 9}, {true, 3, 10},
		{false, 6, 10}, {true, 6, 11}, {true, 9, 11}, {false, 7, 11},
		{true, 6, 12}, {true, 9, 12}, {true, 12, 12}, {false, 0, 0},
	}
	for i, st := range steps {
		var gotCloud, gotSecret uint64
		var errCloud, errSecret error
		if st.next {
			gotCloud, errCloud = cloud.NextOpCert(
				t.Context(), w.hash, st.chain, st.period,
			)
			gotSecret, errSecret = secret.NextOpCert(
				t.Context(), w.hash, st.chain, st.period,
			)
		} else {
			errCloud = cloud.CheckAndAdvance(
				t.Context(), w.hash, st.chain, st.period,
			)
			errSecret = secret.CheckAndAdvance(
				t.Context(), w.hash, st.chain, st.period,
			)
		}
		if fmt.Sprint(errCloud) != fmt.Sprint(errSecret) ||
			gotCloud != gotSecret {
			t.Fatalf(
				"step %d %+v: cloud (%d, %v), secret (%d, %v)",
				i, st, gotCloud, errCloud, gotSecret, errSecret,
			)
		}
	}
}

func TestSecretStateRepeatedOpCertNextWritesNothing(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	_, s, err := stateWorkload(t, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	counter, err := s.Counter("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := counter.NextOpCert(t.Context(), s.hash, 5, 10); err != nil {
		t.Fatal(err)
	}
	before, _ := c.counts()
	if _, err := counter.NextOpCert(t.Context(), s.hash, 5, 10); err != nil {
		t.Fatal(err)
	}
	if after, _ := c.counts(); after != before {
		t.Fatal("a repeated request wrote a version")
	}
}

func TestSecretStateCountersNeedPreparationOrOptIn(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	// First start activates the envelope with only the unprofiled counter.
	mustStateWorkload(t, c)
	// An active envelope never creates a missing counter silently.
	_, _, err := stateWorkload(t, c, nil, profileMainnet)
	if err == nil {
		t.Fatal("a missing profile counter was created without opt-in")
	}
	w, _, err := stateWorkload(t, c, []string{profileMainnet}, profileMainnet)
	if err != nil {
		t.Fatal(err)
	}
	requireProfiledIssue(t, w, explicitReq(w, profileMainnet, 1, 0), 0)
}

func TestSecretStateCounterRejectsInvalidProfile(t *testing.T) {
	t.Parallel()
	s := newTestStateStore(t, provisionedSecret(t))
	for _, name := range []string{"bad name", strings.Repeat("a", 33)} {
		if _, err := s.Counter(name); err == nil {
			t.Fatalf("profile %q accepted", name)
		}
	}
}

func TestSecretStateRejectsBadSecretName(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"", "pool-state", "projects/p/secrets/", "projects/p/secrets/s/versions/1",
		"projects/p/locations/l/secrets/s",
	} {
		if err := validateStateSecret(name); err == nil {
			t.Fatalf("secret %q accepted", strconv.Quote(name))
		}
	}
	if err := validateStateSecret(testStateSecret); err != nil {
		t.Fatal(err)
	}
}

// TestSecretStateBindsProfileInAdditionalData seals a record whose plaintext
// claims profilePreview under the additional data of profilePreview's
// neighbour. Only the additional data can refuse it: the plaintext is
// consistent with the slot it is in.
func TestSecretStateBindsProfileInAdditionalData(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	w := mustStateWorkload(t, c, profileMainnet, profilePreview)
	s := newTestStateStore(t, c)
	if _, err := s.Load(); err != nil {
		t.Fatal(err)
	}
	sealed, err := s.sealCounter(profileMainnet, counterState{
		Version: counterStateVersion,
		KeyHash: w.hash.String(),
		Profile: profilePreview,
	})
	if err != nil {
		t.Fatal(err)
	}
	rewriteLatest(t, c, func(d *stateDocument) {
		d.Counters[profilePreview] = sealed
	})
	if _, _, err := stateWorkload(
		t, c, nil, profileMainnet, profilePreview,
	); err == nil {
		t.Fatal("record sealed for another profile opened")
	}
}

func TestSecretStateRefusesOtherKeyHash(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	_, s, err := stateWorkload(t, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	counter, err := s.Counter("")
	if err != nil {
		t.Fatal(err)
	}
	var other backend.KeyHash
	other[0] = 1
	if err := counter.Prepare(t.Context(), other, true); err == nil {
		t.Fatal("Prepare accepted another key")
	}
	if err := counter.CheckAndAdvance(t.Context(), other, 0, 10); err == nil {
		t.Fatal("CheckAndAdvance accepted another key")
	}
	if _, err := counter.NextOpCert(t.Context(), other, 5, 10); err == nil {
		t.Fatal("NextOpCert accepted another key")
	}
}

func TestSecretStateAcceptsProjectNumberNames(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	c.mu.Lock()
	c.projectNumber = "123456789012"
	c.mu.Unlock()
	w := mustStateWorkload(t, c)
	requireProfiledIssue(t, w, explicitReq(w, "", 1, 0), 0)
	requireProfiledIssue(t, w, explicitReq(w, "", 2, 1), 1)
	if n := c.enabled(); n != 1 {
		t.Fatalf("%d enabled versions, want 1", n)
	}

	w2 := mustStateWorkload(t, c)
	requireRefusedResp(t, w2, explicitReq(w2, "", 3, 1))
	requireProfiledIssue(t, w2, explicitReq(w2, "", 4, 2), 2)
}

func TestSecretStateVersionNumber(t *testing.T) {
	t.Parallel()
	s := newTestStateStore(t, &fakeSecretClient{})
	tests := []struct {
		name string
		want uint64
	}{
		{testStateSecret + "/versions/7", 7},
		{"projects/123456789012/secrets/pool-state/versions/7", 7},
		{"projects/123456789012/secrets/other-state/versions/7", 0},
		{testStateSecret + "/versions/latest", 0},
		{testStateSecret + "/versions/0", 0},
		{testStateSecret + "/versions/7/extra", 0},
		{testStateSecret, 0},
	}
	for _, tt := range tests {
		got, ok := s.versionNumber(tt.name)
		if ok != (tt.want != 0) || got != tt.want {
			t.Errorf(
				"versionNumber(%q) = %d, %v, want %d",
				tt.name,
				got,
				ok,
				tt.want,
			)
		}
	}
}

// The serve command's HTTP write timeout is 30 seconds, and a signing request
// waits for the cleanup that follows its write.
const cleanupResponseBudget = 10 * time.Second

func TestSecretStateCleanupFitsTheResponseBudget(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	w := mustStateWorkload(t, c)
	c.mu.Lock()
	c.cleanupBudgets = nil
	c.mu.Unlock()

	requireProfiledIssue(t, w, explicitReq(w, "", 1, 0), 0)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cleanupBudgets) == 0 {
		t.Fatal("no cleanup call was made")
	}
	for _, budget := range c.cleanupBudgets {
		if budget > cleanupResponseBudget {
			t.Fatalf(
				"cleanup call allowed %v, want at most %v",
				budget,
				cleanupResponseBudget,
			)
		}
	}
}

func TestSecretStateCleanupNeverDestroysANewerVersion(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	w := mustStateWorkload(t, c)
	newer := 0
	c.mu.Lock()
	c.onList = func(c *fakeSecretClient) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if newer == 0 {
			newer = c.addLocked([]byte("newer"))
		}
	}
	c.mu.Unlock()

	requireProfiledIssue(t, w, explicitReq(w, "", 1, 0), 0)
	c.mu.Lock()
	defer c.mu.Unlock()
	if newer == 0 {
		t.Fatal("no cleanup listed the versions")
	}
	if got := c.versions[newer-1].state; got != secretmanagerpb.SecretVersion_ENABLED {
		t.Fatalf("version newer than the write is %v, want ENABLED", got)
	}
}

func TestSecretStateRestartReadsTheNewestVersionByNumber(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name       string
		destroyErr error
	}{
		{"cleanup failed", errors.New("destroy denied")},
		{"cleanup succeeded", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := provisionedSecret(t)
			w := mustStateWorkload(t, c)
			c.mu.Lock()
			c.destroyErr = tt.destroyErr
			c.mu.Unlock()
			requireProfiledIssue(t, w, explicitReq(w, "", 1, 0), 0)

			// The latest alias and the version list lag behind the
			// version the issue added.
			c.mu.Lock()
			c.visible = len(c.versions) - 1
			c.mu.Unlock()
			w2 := mustStateWorkload(t, c)
			requireRefusedResp(t, w2, explicitReq(w2, "", 2, 0))
			requireProfiledIssue(t, w2, explicitReq(w2, "", 3, 1), 1)
		})
	}
}

func TestSecretStateRefusesWhenNewestVersionIsNotEnabled(t *testing.T) {
	t.Parallel()
	c := provisionedSecret(t)
	w := mustStateWorkload(t, c)
	c.mu.Lock()
	c.destroyErr = errors.New("destroy denied")
	c.mu.Unlock()
	requireProfiledIssue(t, w, explicitReq(w, "", 1, 0), 0)
	c.mu.Lock()
	c.versions[len(c.versions)-1].state = secretmanagerpb.SecretVersion_DISABLED
	c.mu.Unlock()

	if _, _, err := stateWorkload(t, c, nil); err == nil {
		t.Fatal("startup loaded an older version below a disabled newest one")
	}
}
