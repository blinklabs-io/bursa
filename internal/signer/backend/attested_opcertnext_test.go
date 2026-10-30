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
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"testing"
)

func opCertNextSignable(kes []byte, issue, period uint64) []byte {
	out := bytes.Clone(kes)
	out = binary.BigEndian.AppendUint64(out, issue)
	return binary.BigEndian.AppendUint64(out, period)
}

// opCertNextKey loads the enclave's first key as an OpCertNextSigner. profile
// selects a profiled backend.
func opCertNextKey(t *testing.T, e *fakeEnclave, profile string) (KeyRef, OpCertNextSigner) {
	t.Helper()
	b := NewAttestedBackend("enclave", e, stubVerifier{})
	if profile != "" {
		b = NewProfiledAttestedBackend("enclave", profile, e, stubVerifier{})
	}
	if err := b.Load(t.Context()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	ref := mustKey(t, b, e.hashOf(0))
	s, ok := ref.(OpCertNextSigner)
	if !ok {
		t.Fatal("attested key does not implement OpCertNextSigner")
	}
	return ref, s
}

func TestAttestedKeySignOpCertNext(t *testing.T) {
	t.Parallel()
	kes := bytes.Repeat([]byte{7}, 32)
	for _, tc := range []struct {
		name      string
		profile   string
		floor     uint64
		chain     uint64
		wantIssue uint64
	}{
		{"chain plus one", "", 0, 5, 6},
		{"profiled", "profile-a", 0, 5, 6},
		{"device floor above chain", "", 20, 5, 20},
		{"chain zero", "", 0, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newFakeEnclave(t, KeyTypePool)
			e.opcertFloor = tc.floor
			ref, s := opCertNextKey(t, e, tc.profile)
			sig, issue, err := s.SignOpCertNext(t.Context(), kes, tc.chain, 300)
			if err != nil {
				t.Fatalf("SignOpCertNext: %v", err)
			}
			if issue != tc.wantIssue {
				t.Fatalf("issue = %d, want %d", issue, tc.wantIssue)
			}
			if !ed25519.Verify(ref.PublicKey(), opCertNextSignable(kes, tc.wantIssue, 300), sig) {
				t.Fatal("signature does not verify over kes_vkey||issue||period")
			}
			if len(e.requests) != 1 {
				t.Fatalf("enclave requests = %d, want 1", len(e.requests))
			}
			req := e.requests[0]
			if req.Purpose != PurposeOpCertNext || req.Role != KeyTypePool || req.Era != nil {
				t.Fatalf("request = %+v", req)
			}
			if want := opCertNextSignable(kes, tc.chain, 300); !bytes.Equal(req.Payload, want) {
				t.Fatalf("payload carries %x, want chain counter payload %x", req.Payload, want)
			}
		})
	}
}

func TestAttestedKeySignOpCertNextRefusals(t *testing.T) {
	t.Parallel()
	kes := bytes.Repeat([]byte{7}, 32)
	const chain, period = 5, 300
	u64 := func(v uint64) *uint64 { return &v }
	for _, tc := range []struct {
		name    string
		profile string
		tamper  func(req AttestedRequest, resp *AttestedResponse, priv ed25519.PrivateKey)
		want    error
	}{
		{"issue equals chain", "", func(_ AttestedRequest, resp *AttestedResponse, priv ed25519.PrivateKey) {
			resp.IssueCounter = u64(chain)
			resp.Signature = ed25519.Sign(priv, opCertNextSignable(kes, chain, period))
		}, ErrAttestedProtocol},
		{"issue below chain", "", func(_ AttestedRequest, resp *AttestedResponse, priv ed25519.PrivateKey) {
			resp.IssueCounter = u64(chain - 1)
			resp.Signature = ed25519.Sign(priv, opCertNextSignable(kes, chain-1, period))
		}, ErrAttestedProtocol},
		{"missing issue_counter", "", func(_ AttestedRequest, resp *AttestedResponse, _ ed25519.PrivateKey) {
			resp.IssueCounter = nil
		}, ErrAttestedProtocol},
		{"signature over wrong issue", "", func(_ AttestedRequest, resp *AttestedResponse, priv ed25519.PrivateKey) {
			resp.IssueCounter = u64(chain + 1)
			resp.Signature = ed25519.Sign(priv, opCertNextSignable(kes, chain+2, period))
		}, ErrInvalidSignature},
		{"signature over chain counter", "", func(req AttestedRequest, resp *AttestedResponse, priv ed25519.PrivateKey) {
			resp.Signature = ed25519.Sign(priv, req.Payload)
		}, ErrInvalidSignature},
		{"signature over wrong period", "", func(_ AttestedRequest, resp *AttestedResponse, priv ed25519.PrivateKey) {
			resp.Signature = ed25519.Sign(priv, opCertNextSignable(kes, chain+1, period+1))
		}, ErrInvalidSignature},
		{"bad binding signature", "profile-a", func(_ AttestedRequest, resp *AttestedResponse, _ ed25519.PrivateKey) {
			resp.BindingSignature[0] ^= 0xff
		}, ErrInvalidSignature},
		{"missing binding signature", "profile-a", func(_ AttestedRequest, resp *AttestedResponse, _ ed25519.PrivateKey) {
			resp.BindingSignature = nil
		}, ErrAttestedProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newFakeEnclave(t, KeyTypePool)
			priv := e.keys[0].priv
			e.tamperResp = func(req AttestedRequest, resp *AttestedResponse) { tc.tamper(req, resp, priv) }
			_, s := opCertNextKey(t, e, tc.profile)
			sig, issue, err := s.SignOpCertNext(t.Context(), kes, chain, period)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if sig != nil || issue != 0 {
				t.Fatalf("refusal returned sig=%x issue=%d", sig, issue)
			}
		})
	}
}

func TestAttestedKeySignOpCertNextRefusesBeforeEnclave(t *testing.T) {
	t.Parallel()
	e := newFakeEnclave(t, KeyTypePool, KeyTypePayment)
	b := loadAttested(t, e)
	pool := mustKey(t, b, e.hashOf(0)).(OpCertNextSigner)
	pay := mustKey(t, b, e.hashOf(1)).(OpCertNextSigner)

	if _, _, err := pay.SignOpCertNext(t.Context(), make([]byte, 32), 1, 1); !errors.Is(err, ErrAttestedProtocol) {
		t.Fatalf("wrong role: %v", err)
	}
	for _, n := range []int{0, 31, 33, 48} {
		if _, _, err := pool.SignOpCertNext(t.Context(), make([]byte, n), 1, 1); !errors.Is(err, ErrAttestedProtocol) {
			t.Fatalf("kes vkey length %d: %v", n, err)
		}
	}
	// The generic path cannot carry opcert-next: it returns no issue number.
	if _, err := mustKey(t, b, e.hashOf(0)).(PurposeSigner).SignPurpose(t.Context(), PurposeOpCertNext, make([]byte, 48)); !errors.Is(err, ErrAttestedProtocol) {
		t.Fatalf("SignPurpose opcert-next: %v", err)
	}
	if e.signCalls != 0 {
		t.Fatalf("enclave contacted %d times, want 0", e.signCalls)
	}
}

func TestPurposeOpCertNextValidate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		role    KeyType
		payload []byte
		ok      bool
	}{
		{"pool 48", KeyTypePool, make([]byte, 48), true},
		{"pool 47", KeyTypePool, make([]byte, 47), false},
		{"pool 49", KeyTypePool, make([]byte, 49), false},
		{"payment 48", KeyTypePayment, make([]byte, 48), false},
	} {
		err := PurposeOpCertNext.validate(tc.role, tc.payload)
		if tc.ok != (err == nil) || (err != nil && !errors.Is(err, ErrAttestedProtocol)) {
			t.Fatalf("%s: err = %v", tc.name, err)
		}
	}
}
