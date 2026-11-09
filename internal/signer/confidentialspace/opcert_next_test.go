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
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/opcertrule"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// Refusal texts the signer host maps to ErrCustodyCounterConflict.
const (
	refusalBelowFloor  = "chain counter below the recorded on-chain counter"
	refusalAboveIssued = "chain counter above the last counter the device issued"
	refusalBackdated   = "KES period below the logged opcert at this counter"
)

// cloudWorkload starts a workload whose counter is a real CloudCounterStore
// over obj and whose envelope lives in envelopes, so a second call with the
// same two arguments is a restart.
func cloudWorkload(
	t *testing.T,
	envelopes *memoryStore,
	obj *memoryCounterObject,
) *Workload {
	t.Helper()
	w, err := New(t.Context(), Config{
		Audience: "https://signer.example/pool",
		KMSKey:   testKMSKey,
		Tokens:   &testTokens{},
		Wrapper:  &testWrapper{},
		Store:    envelopes,
		Counter:  &CloudCounterStore{object: obj},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func nextRequest(
	w *Workload,
	nonce byte,
	chain, period uint64,
) backend.AttestedRequest {
	payload := lcommon.OpCertSignableBytes(
		bytes.Repeat([]byte{0x23}, 32),
		chain,
		period,
	)
	return backend.AttestedRequest{
		Version: backend.AttestedProtocol,
		Purpose: backend.PurposeOpCertNext,
		KeyHash: w.hash.String(),
		Role:    backend.KeyTypePool,
		Nonce:   bytes.Repeat([]byte{nonce}, 32),
		Payload: payload,
	}
}

func requireIssued(
	t *testing.T,
	w *Workload,
	req backend.AttestedRequest,
	issue uint64,
) {
	t.Helper()
	resp, err := w.Sign(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Error != "" || resp.IssueCounter == nil ||
		*resp.IssueCounter != issue {
		t.Fatalf("want issue %d, got response %+v", issue, resp)
	}
	signed := bytes.Clone(req.Payload)
	binary.BigEndian.PutUint64(signed[32:40], issue)
	if !ed25519.Verify(w.pub, signed, resp.Signature) {
		t.Fatalf("signature does not cover issue %d", issue)
	}
}

func requireRefused(
	t *testing.T,
	w *Workload,
	req backend.AttestedRequest,
	text string,
) {
	t.Helper()
	resp, err := w.Sign(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Error != text || resp.Signature != nil ||
		resp.IssueCounter != nil {
		t.Fatalf("want refusal %q, got response %+v", text, resp)
	}
}

func TestOpCertNextRules(t *testing.T) {
	t.Parallel()
	w := cloudWorkload(t, &memoryStore{}, &memoryCounterObject{})

	// first issue: chain 0 -> issue 1
	requireIssued(t, w, nextRequest(w, 1, 0, 100), 1)
	// the same number again at the same period and at a higher one
	requireIssued(t, w, nextRequest(w, 2, 0, 100), 1)
	requireIssued(t, w, nextRequest(w, 3, 0, 101), 1)
	// a lower period than the recorded one is refused
	requireRefused(t, w, nextRequest(w, 4, 0, 100), refusalBackdated)
	// the pool forged with counter 1: next is 2
	requireIssued(t, w, nextRequest(w, 5, 1, 102), 2)
	// a chain counter below the highest reported one is refused
	requireRefused(t, w, nextRequest(w, 6, 0, 200), refusalBelowFloor)
	// a chain counter above the last issued is refused
	requireRefused(t, w, nextRequest(w, 7, 3, 200), refusalAboveIssued)
	// a refusal changed nothing: reissue of 2 still works
	requireIssued(t, w, nextRequest(w, 8, 1, 102), 2)
}

func TestOpCertNextReplayAndRefusalKeepNonce(t *testing.T) {
	t.Parallel()
	w := cloudWorkload(t, &memoryStore{}, &memoryCounterObject{})
	req := nextRequest(w, 1, 0, 100)
	requireIssued(t, w, req, 1)
	resp, err := w.Sign(t.Context(), req)
	if err != nil || resp.Error != "request refused" || resp.Signature != nil {
		t.Fatalf("replay response = %+v, err = %v", resp, err)
	}

	// a refused request does not consume its nonce
	low := nextRequest(w, 2, 0, 50)
	requireRefused(t, w, low, refusalBackdated)
	low.Payload = nextRequest(w, 2, 0, 100).Payload
	requireIssued(t, w, low, 1)
}

func TestOpCertNextPersistsAcrossRestart(t *testing.T) {
	t.Parallel()
	envelopes := &memoryStore{}
	obj := &memoryCounterObject{}
	w := cloudWorkload(t, envelopes, obj)
	requireIssued(t, w, nextRequest(w, 1, 4, 300), 5)
	_ = w.Close()

	restarted := cloudWorkload(t, envelopes, obj)
	// the floor, last issued and period survived
	requireRefused(
		t,
		restarted,
		nextRequest(restarted, 2, 3, 300),
		refusalBelowFloor,
	)
	requireRefused(
		t,
		restarted,
		nextRequest(restarted, 3, 6, 300),
		refusalAboveIssued,
	)
	requireRefused(
		t,
		restarted,
		nextRequest(restarted, 4, 4, 299),
		refusalBackdated,
	)
	requireIssued(t, restarted, nextRequest(restarted, 5, 4, 300), 5)
	requireIssued(t, restarted, nextRequest(restarted, 6, 5, 301), 6)
}

func TestOpCertNextWritesNothingOnRepeat(t *testing.T) {
	t.Parallel()
	obj := &memoryCounterObject{}
	w := cloudWorkload(t, &memoryStore{}, obj)
	requireIssued(t, w, nextRequest(w, 1, 0, 100), 1)
	obj.mu.Lock()
	generation := obj.generation
	obj.mu.Unlock()
	requireIssued(t, w, nextRequest(w, 2, 0, 100), 1)
	obj.mu.Lock()
	defer obj.mu.Unlock()
	if obj.generation != generation {
		t.Fatalf(
			"generation %d -> %d on an identical repeat",
			generation,
			obj.generation,
		)
	}
}

// An object written before opcert-next existed has neither floor, last-issued
// nor period. It still loads, the last issued number is derived from the
// explicit sequence, and the unknown period never refuses.
func TestOpCertNextOldCounterObject(t *testing.T) {
	t.Parallel()
	wrapper := &testWrapper{}
	envelopeData, publicKey := legacyEnvelope(t, wrapper)
	keyHash := backend.HashPublicKey(publicKey)
	next := uint64(7) // numbers 0..6 were issued explicitly
	old, err := json.Marshal(counterStateWire{
		Version:         counterStateVersion,
		KeyHash:         keyHash.String(),
		NextIssueNumber: &next,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(old, []byte("opcert_floor")) ||
		bytes.Contains(old, []byte("last_issued")) {
		t.Fatalf("old object carries new fields: %s", old)
	}
	obj := &memoryCounterObject{data: old, generation: 1}
	w, err := New(t.Context(), Config{
		Audience: "https://signer.example/pool",
		KMSKey:   testKMSKey,
		Tokens:   &testTokens{},
		Wrapper:  wrapper,
		Store:    &memoryStore{data: envelopeData},
		Counter:  &CloudCounterStore{object: obj},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })

	// above the derived last issued (6): refused
	requireRefused(t, w, nextRequest(w, 1, 7, 10), refusalAboveIssued)
	// reissue of 6 at any period (the old record has none)
	requireIssued(t, w, nextRequest(w, 2, 5, 0), 6)
	requireIssued(t, w, nextRequest(w, 3, 6, 10), 7)
	// the explicit path continues after opcert-next
	payload := lcommon.OpCertSignableBytes(
		bytes.Repeat([]byte{0x23}, 32),
		8,
		11,
	)
	resp, err := w.Sign(t.Context(), backend.AttestedRequest{
		Version: backend.AttestedProtocol,
		Purpose: backend.PurposeOpCert,
		KeyHash: w.hash.String(),
		Role:    backend.KeyTypePool,
		Nonce:   bytes.Repeat([]byte{4}, 32),
		Payload: payload,
	})
	if err != nil || resp.Error != "" ||
		!ed25519.Verify(w.pub, payload, resp.Signature) {
		t.Fatalf("explicit issue 8 after opcert-next: %+v err=%v", resp, err)
	}
}

// Explicit issues count as issued: a chain counter beyond them is refused,
// and the explicit path is unchanged by opcert-next history.
func TestOpCertNextAfterExplicitIssue(t *testing.T) {
	t.Parallel()
	w := cloudWorkload(t, &memoryStore{}, &memoryCounterObject{})
	for i := range 3 {
		payload := lcommon.OpCertSignableBytes(
			bytes.Repeat([]byte{0x23}, 32), uint64(i), 11,
		)
		resp, err := w.Sign(t.Context(), backend.AttestedRequest{
			Version: backend.AttestedProtocol,
			Purpose: backend.PurposeOpCert,
			KeyHash: w.hash.String(),
			Role:    backend.KeyTypePool,
			Nonce:   bytes.Repeat([]byte{byte(10 + i)}, 32),
			Payload: payload,
		})
		if err != nil || resp.Error != "" {
			t.Fatalf("explicit issue %d: %+v err=%v", i, resp, err)
		}
	}
	requireRefused(t, w, nextRequest(w, 1, 3, 11), refusalAboveIssued)
	requireIssued(t, w, nextRequest(w, 2, 1, 11), 2)
	// an explicit counter that is not the next one is still refused
	payload := lcommon.OpCertSignableBytes(
		bytes.Repeat([]byte{0x23}, 32),
		2,
		11,
	)
	resp, err := w.Sign(t.Context(), backend.AttestedRequest{
		Version: backend.AttestedProtocol,
		Purpose: backend.PurposeOpCert,
		KeyHash: w.hash.String(),
		Role:    backend.KeyTypePool,
		Nonce:   bytes.Repeat([]byte{20}, 32),
		Payload: payload,
	})
	if err != nil || resp.Error != "request refused" {
		t.Fatalf("repeated explicit counter: %+v err=%v", resp, err)
	}
}

func TestOpCertNextRefusesProfileAndOtherKey(t *testing.T) {
	t.Parallel()
	w := cloudWorkload(t, &memoryStore{}, &memoryCounterObject{})
	req := nextRequest(w, 1, 0, 100)
	req.Profile = "pool@mainnet"
	requireRefused(t, w, req, "request refused")
	req = nextRequest(w, 2, 0, 100)
	req.KeyHash = backend.KeyHash{9}.String()
	requireRefused(t, w, req, "request refused")
	// neither consumed state
	requireIssued(t, w, nextRequest(w, 3, 0, 100), 1)
}

func TestOpCertNextStorageFailureIsNotDisclosed(t *testing.T) {
	t.Parallel()
	if got := opCertNextRefusal(errors.New("gcs: boom")); got != "request refused" {
		t.Fatalf("refusal = %q", got)
	}
}

// enclaveFromWorkload lets the signer host's attested backend talk to the
// workload without TLS.
type enclaveFromWorkload struct{ w *Workload }

func (e enclaveFromWorkload) Inventory(
	ctx context.Context,
	nonce []byte,
) (backend.AttestedInventory, error) {
	return e.w.Inventory(ctx, nonce, "")
}

func (e enclaveFromWorkload) Sign(
	ctx context.Context,
	req backend.AttestedRequest,
) (backend.AttestedResponse, error) {
	return e.w.Sign(ctx, req)
}

// The signer host sends opcert-next to this backend as it does to the armory:
// it accepts the issue number, and a counter refusal becomes
// ErrCustodyCounterConflict.
func TestHostOpCertNextAgainstWorkload(t *testing.T) {
	t.Parallel()
	w := cloudWorkload(t, &memoryStore{}, &memoryCounterObject{})
	b := backend.NewAttestedBackend(
		"gcp",
		enclaveFromWorkload{w},
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
	kes := bytes.Repeat([]byte{0x23}, 32)
	sig, issue, err := next.SignOpCertNext(t.Context(), kes, 4, 100)
	if err != nil || issue != 5 {
		t.Fatalf("issue=%d err=%v", issue, err)
	}
	if !ed25519.Verify(
		ref.PublicKey(),
		lcommon.OpCertSignableBytes(kes, 5, 100),
		sig,
	) {
		t.Fatal("signature does not verify")
	}
	for _, tc := range []struct {
		name   string
		chain  uint64
		period uint64
	}{
		{"below floor", 3, 100},
		{"above issued", 6, 100},
		{"backdated reissue", 4, 99},
	} {
		_, _, err := next.SignOpCertNext(t.Context(), kes, tc.chain, tc.period)
		if !errors.Is(err, backend.ErrCustodyCounterConflict) {
			t.Fatalf("%s: err = %v, want ErrCustodyCounterConflict", tc.name, err)
		}
	}
}

// An explicit issue records its KES period, so an opcert-next reissue of that
// number at a lower period is refused.
func TestOpCertNextAfterExplicitIssueChecksPeriod(t *testing.T) {
	t.Parallel()
	w := cloudWorkload(t, &memoryStore{}, &memoryCounterObject{})
	for i := range 2 {
		payload := lcommon.OpCertSignableBytes(
			bytes.Repeat([]byte{0x23}, 32), uint64(i), 11,
		)
		resp, err := w.Sign(t.Context(), backend.AttestedRequest{
			Version: backend.AttestedProtocol,
			Purpose: backend.PurposeOpCert,
			KeyHash: w.hash.String(),
			Role:    backend.KeyTypePool,
			Nonce:   bytes.Repeat([]byte{byte(10 + i)}, 32),
			Payload: payload,
		})
		if err != nil || resp.Error != "" {
			t.Fatalf("explicit issue %d: %+v err=%v", i, resp, err)
		}
	}
	requireRefused(t, w, nextRequest(w, 1, 0, 10), refusalBackdated)
	requireIssued(t, w, nextRequest(w, 2, 0, 11), 1)
}

// A chain counter with no successor is refused with the rule's own text.
func TestOpCertNextOutOfRange(t *testing.T) {
	t.Parallel()
	w := cloudWorkload(t, &memoryStore{}, &memoryCounterObject{})
	requireRefused(
		t,
		w,
		nextRequest(w, 1, math.MaxUint64, 10),
		"chain counter out of range",
	)
}

// A chain counter that lags explicit issues would reissue an earlier number
// whose KES period is not recorded. It is refused and leaves the state as it
// was, so the last issued number never decreases.
func TestOpCertNextRefusesNumberBelowLastIssued(t *testing.T) {
	t.Parallel()
	cur := counterState{
		Version:          counterStateVersion,
		NextIssueNumber:  7,
		LastIssued:       6,
		LastIssuedPeriod: 60,
	}
	if _, _, err := applyOpCertNext(cur, 3, 10); !errors.Is(
		err,
		opcertrule.ErrKESBackdated,
	) {
		t.Fatalf("chain 3 after explicit issue 6: err = %v", err)
	}
	for chain, want := range map[uint64]uint64{5: 6, 6: 7} {
		next, issue, err := applyOpCertNext(cur, chain, 60)
		if err != nil || issue != want {
			t.Fatalf("chain %d: issue %d err %v", chain, issue, err)
		}
		if next.LastIssued < cur.LastIssued {
			t.Fatalf("chain %d lowered last issued: %+v", chain, next)
		}
	}

	w := cloudWorkload(t, &memoryStore{}, &memoryCounterObject{})
	for i := range 7 {
		payload := lcommon.OpCertSignableBytes(
			bytes.Repeat([]byte{0x23}, 32), uint64(i), 60,
		)
		resp, err := w.Sign(t.Context(), backend.AttestedRequest{
			Version: backend.AttestedProtocol,
			Purpose: backend.PurposeOpCert,
			KeyHash: w.hash.String(),
			Role:    backend.KeyTypePool,
			Nonce:   bytes.Repeat([]byte{byte(10 + i)}, 32),
			Payload: payload,
		})
		if err != nil || resp.Error != "" {
			t.Fatalf("explicit issue %d: %+v err=%v", i, resp, err)
		}
	}
	requireRefused(t, w, nextRequest(w, 1, 3, 10), refusalBackdated)
	// the pool forges with the explicitly issued 6: renewal still works
	requireIssued(t, w, nextRequest(w, 2, 6, 60), 7)
}

// Explicit issues 0, 1 and 2 at period 30, then chain 0 (which selects issue
// 1) at a lower period: refused, and issue 2 and its period stay recorded.
func TestOpCertNextChainZeroAfterExplicitThree(t *testing.T) {
	t.Parallel()
	w := cloudWorkload(t, &memoryStore{}, &memoryCounterObject{})
	for i := range 3 {
		payload := lcommon.OpCertSignableBytes(
			bytes.Repeat([]byte{0x23}, 32), uint64(i), 30,
		)
		resp, err := w.Sign(t.Context(), backend.AttestedRequest{
			Version: backend.AttestedProtocol,
			Purpose: backend.PurposeOpCert,
			KeyHash: w.hash.String(),
			Role:    backend.KeyTypePool,
			Nonce:   bytes.Repeat([]byte{byte(10 + i)}, 32),
			Payload: payload,
		})
		if err != nil || resp.Error != "" {
			t.Fatalf("explicit issue %d: %+v err=%v", i, resp, err)
		}
	}
	requireRefused(t, w, nextRequest(w, 1, 0, 20), refusalBackdated)
	// issue 2 is still the last issued: a lower period for it is refused
	requireRefused(t, w, nextRequest(w, 2, 1, 20), refusalBackdated)
	requireIssued(t, w, nextRequest(w, 3, 1, 30), 2)
}
