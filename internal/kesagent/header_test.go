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

package kesagent

import (
	"errors"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/kes"
	"github.com/blinklabs-io/gouroboros/ledger/babbage"
)

// headerSpec describes a Praos header body; zero fields take the values of the
// agent installed by newHeaderAgent.
type headerSpec struct {
	slot      uint64
	issuer    []byte
	hotVkey   []byte
	sequence  uint64
	kesPeriod uint64
	coldSig   []byte
}

// newHeaderAgent returns a sign-mode agent at KES period 5 (slot 50..59) with
// an opcert issued at period 3 with counter 7, and the header spec that
// matches it.
func newHeaderAgent(t *testing.T) (*Agent, coldKeyPair, headerSpec) {
	t.Helper()
	cold := newColdKey(t)
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(5))
	vkey, err := a.GenStagedKey()
	if err != nil {
		t.Fatalf("GenStagedKey: %v", err)
	}
	opcert := makeOpCert(t, vkey, 7, 3, cold)
	if _, err := a.InstallKey(opcert); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
	return a, cold, headerSpec{slot: 52, issuer: cold.pub, hotVkey: vkey, sequence: 7, kesPeriod: 3, coldSig: opCertColdSig(t, opcert)}
}

// opCertColdSig returns the cold-key signature an encoded opcert carries.
func opCertColdSig(t *testing.T, opcert []byte) []byte {
	t.Helper()
	dec, err := bursa.DecodeOpCert(opcert)
	if err != nil {
		t.Fatalf("DecodeOpCert: %v", err)
	}
	return dec.ColdSig
}

func (s headerSpec) encode(t *testing.T) []byte {
	t.Helper()
	var hb babbage.BabbageBlockHeaderBody
	hb.BlockNumber = 1
	hb.Slot = s.slot
	copy(hb.IssuerVkey[:], s.issuer)
	hb.VrfKey = make([]byte, 32)
	hb.VrfResult.Output = make([]byte, 64)
	hb.VrfResult.Proof = make([]byte, 80)
	hb.OpCert = babbage.BabbageOpCert{
		HotVkey: s.hotVkey, SequenceNumber: s.sequence, KesPeriod: s.kesPeriod, Signature: s.coldSig,
	}
	hb.ProtoVersion = babbage.BabbageProtoVersion{Major: 10}
	b, err := cbor.Encode(&hb)
	if err != nil {
		t.Fatalf("encode header body: %v", err)
	}
	return b
}

func TestSignHeaderAcceptsMatchingHeaderBody(t *testing.T) {
	t.Parallel()
	a, _, spec := newHeaderAgent(t)
	msg := spec.encode(t)
	sig, err := a.SignHeader(5, msg)
	if err != nil {
		t.Fatalf("SignHeader: %v", err)
	}
	if !kes.VerifySignedKES(spec.hotVkey, 5-3, msg, sig) {
		t.Fatal("signature does not verify")
	}
}

func TestSignHeaderRefusesUntypedOrMismatchedRequests(t *testing.T) {
	t.Parallel()
	other := newColdKey(t)
	// Each case breaks exactly one rule and names the rule that must refuse it,
	// so a different rule refusing the request does not satisfy the test.
	for _, tc := range []struct {
		name   string
		reason string
		spec   func(s *headerSpec)
		raw    func(valid []byte) []byte
	}{
		{name: "arbitrary bytes", reason: "unexpected", raw: func([]byte) []byte { return []byte("not a header") }},
		{name: "empty message", reason: "EOF", raw: func([]byte) []byte { return nil }},
		{name: "a different CBOR structure", reason: "cbor", raw: func([]byte) []byte {
			b, _ := cbor.Encode([]any{uint64(1), "x"})
			return b
		}},
		{name: "trailing data after the header", reason: "trailing", raw: func(v []byte) []byte { return append(v, 0x00) }},
		{name: "slot after the requested period", reason: "KES period", spec: func(s *headerSpec) { s.slot = 60 }},
		{name: "slot before the requested period", reason: "KES period", spec: func(s *headerSpec) { s.slot = 49 }},
		{name: "another pool's issuer key", reason: "issuer", spec: func(s *headerSpec) { s.issuer = other.pub }},
		{name: "another KES key", reason: "different KES key", spec: func(s *headerSpec) { s.hotVkey = make([]byte, 32) }},
		{name: "superseded issue counter", reason: "counter/period", spec: func(s *headerSpec) { s.sequence = 6 }},
		{name: "opcert start period not the installed one", reason: "counter/period", spec: func(s *headerSpec) { s.kesPeriod = 4 }},
		{name: "opcert signature not the installed one", reason: "cold signature", spec: func(s *headerSpec) { s.coldSig = make([]byte, 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, _, spec := newHeaderAgent(t)
			valid := spec.encode(t)
			if tc.spec != nil {
				tc.spec(&spec)
			}
			msg := spec.encode(t)
			if tc.raw != nil {
				msg = tc.raw(msg)
			}
			sig, err := a.SignHeader(5, msg)
			if !errors.Is(err, ErrInvalidHeader) || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("SignHeader: got sig=%d bytes err=%v, want ErrInvalidHeader mentioning %q", len(sig), err, tc.reason)
			}
			// A refusal leaves the key intact.
			if _, err := a.SignHeader(5, valid); err != nil {
				t.Fatalf("valid request after a refusal: %v", err)
			}
		})
	}
}

// TestSignHeaderStillEnforcesPeriodRules guards that typed validation sits in
// front of, not instead of, the existing period checks.
func TestSignHeaderStillEnforcesPeriodRules(t *testing.T) {
	t.Parallel()
	a, _, spec := newHeaderAgent(t)
	spec.slot = 62 // period 6, in the future
	if _, err := a.SignHeader(6, spec.encode(t)); !errors.Is(err, ErrFuturePeriod) {
		t.Fatalf("future period: got %v, want ErrFuturePeriod", err)
	}
	spec.slot = 42 // period 4, before the key's current period
	if _, err := a.SignHeader(4, spec.encode(t)); !errors.Is(err, ErrPastPeriod) {
		t.Fatalf("past period: got %v, want ErrPastPeriod", err)
	}
}
