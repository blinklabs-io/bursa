// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package survey

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Round 100 was published long ago, so a survey revealing at round 100 can be
// opened with the genuine beacon in seal_test.go. futureRound is not yet
// published.
func futureRound() uint64 { return CurrentRound(time.Now()) + 100000 }

func sealedSimple(owner byte, endEpoch, round uint64) Definition {
	d := simple(owner, endEpoch, RoleKeyholder)
	d.Mode = sealedMode(round, 128)
	return d
}

// sealedResponse is a Keyholder response whose answers are sealed to round.
func sealedResponse(t *testing.T, s Ref, who byte, round, choice uint64) Response {
	t.Helper()
	ct, err := SealAnswers(answer(choice), sealedMode(round, 128))
	noErr(t, err)
	return Response{Survey: s, Role: RoleKeyholder, Credential: cred(false, who), Sealed: ct}
}

func relayStub(t *testing.T, sig string) (*Service, *fakeChain, *atomic.Int32) {
	t.Helper()
	f := newFakeChain()
	svc := NewService(f, "preview")
	var calls atomic.Int32
	svc.fetchBeacon = func(_ context.Context, round uint64) ([]byte, error) {
		calls.Add(1)
		if round != 100 {
			t.Errorf("fetched round %d, want 100", round)
		}
		return sigBytes(t, sig), nil
	}
	return svc, f, &calls
}

// revealFixture is a sealed survey revealing at round 100 with three
// responses: two valid and one whose ciphertext is garbage.
func revealFixture(t *testing.T, sig string) (*Service, *atomic.Int32) {
	t.Helper()
	svc, f, calls := relayStub(t, sig)
	s := ref(0xa1, 0)
	f.add(t, 0xa1, 100, 0, 40, defPayload(sealedSimple(1, 60, 100)), credHex(1))
	f.add(t, 0xd1, 110, 0, 41, respPayload(sealedResponse(t, s, 10, 100, 0)), credHex(10))
	f.add(t, 0xd2, 111, 0, 41, respPayload(sealedResponse(t, s, 11, 100, 1)), credHex(11))
	f.add(t, 0xd3, 112, 0, 41, respPayload(Response{Survey: s, Role: RoleKeyholder, Credential: cred(false, 12), Sealed: []byte("garbage")}), credHex(12))
	return svc, calls
}

func keyholder(t *testing.T, d Detail) RoleTally {
	t.Helper()
	isTrue(t, d.Tally != nil)
	return roleTally(t, *d.Tally, RoleKeyholder)
}

func TestSealedResponsesStayCountedButUntalliedUntilRevealed(t *testing.T) {
	t.Parallel()
	svc, calls := revealFixture(t, quicknetRound100Sig)
	d, err := svc.Get(context.Background(), surveyID(0xa1, 0))
	noErr(t, err)
	rt := keyholder(t, d)
	equal(t, uint64(3), rt.Responses)
	equal(t, uint64(3), rt.Sealed)
	equal(t, uint64(0), rt.Questions[0].Answered)
	equal(t, int32(0), calls.Load()) // reading never fetches a beacon
	equal(t, true, d.Sealed)
}

func TestRevealNeedsConsentBeforeFetchingAndThenTallies(t *testing.T) {
	t.Parallel()
	svc, calls := revealFixture(t, quicknetRound100Sig)
	ctx := context.Background()
	id := surveyID(0xa1, 0)

	_, err := svc.Reveal(ctx, RevealRequest{Survey: id})
	if !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("err = %v, want ErrConsentRequired", err)
	}
	equal(t, int32(0), calls.Load())

	d, err := svc.Reveal(ctx, RevealRequest{Survey: id, Consent: true})
	noErr(t, err)
	equal(t, int32(1), calls.Load())
	rt := keyholder(t, d)
	equal(t, uint64(2), rt.Responses)
	equal(t, uint64(0), rt.Sealed)
	equal(t, []OptionTally{{Count: 1}, {Count: 1}}, rt.Questions[0].Options)
	isTrue(t, reasons(*d.Tally)[txHash(0xd3)] != "") // unopenable ciphertext is excluded

	// The beacon is now cached: reading tallies the revealed answers without
	// another fetch, and revealing again does not need consent.
	d, err = svc.Get(ctx, id)
	noErr(t, err)
	equal(t, []OptionTally{{Count: 1}, {Count: 1}}, keyholder(t, d).Questions[0].Options)
	_, err = svc.Reveal(ctx, RevealRequest{Survey: id})
	noErr(t, err)
	equal(t, int32(1), calls.Load())
}

func TestRevealAcceptsAUserSuppliedBeaconWithoutFetching(t *testing.T) {
	t.Parallel()
	svc, calls := revealFixture(t, quicknetRound100Sig)
	d, err := svc.Reveal(context.Background(), RevealRequest{Survey: surveyID(0xa1, 0), Beacon: quicknetRound100Sig})
	noErr(t, err)
	equal(t, int32(0), calls.Load())
	equal(t, uint64(2), keyholder(t, d).Responses)
}

func TestRevealRejectsBadBeaconsAndCachesNothing(t *testing.T) {
	t.Parallel()
	// A relay answering with another round's signature.
	svc, calls := revealFixture(t, quicknetRound1Sig)
	ctx := context.Background()
	id := surveyID(0xa1, 0)
	_, err := svc.Reveal(ctx, RevealRequest{Survey: id, Consent: true})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("relay beacon: err = %v, want ErrInvalid", err)
	}
	equal(t, int32(1), calls.Load())

	for name, beacon := range map[string]string{
		"not hex":       "zz",
		"another round": quicknetRound1Sig,
		"truncated":     quicknetRound100Sig[:40],
	} {
		if _, err := svc.Reveal(ctx, RevealRequest{Survey: id, Beacon: beacon}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}

	d, err := svc.Get(ctx, id)
	noErr(t, err)
	equal(t, uint64(3), keyholder(t, d).Sealed) // still sealed: no bad beacon was kept
}

func TestRevealRefusesBeforeTheRoundPublishes(t *testing.T) {
	t.Parallel()
	svc, f, calls := relayStub(t, quicknetRound100Sig)
	f.add(t, 0xa1, 100, 0, 40, defPayload(sealedSimple(1, 60, futureRound())), credHex(1))
	_, err := svc.Reveal(context.Background(), RevealRequest{Survey: surveyID(0xa1, 0), Consent: true})
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "not yet published") {
		t.Fatalf("err = %v, want a not-yet-published rejection", err)
	}
	equal(t, int32(0), calls.Load())
}

func TestRevealRejectsPublicAndUnknownSurveys(t *testing.T) {
	t.Parallel()
	svc, f, calls := relayStub(t, quicknetRound100Sig)
	f.add(t, 0xa1, 100, 0, 40, defPayload(simple(1, 60)), credHex(1))
	if _, err := svc.Reveal(context.Background(), RevealRequest{Survey: surveyID(0xa1, 0), Consent: true}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("public survey: err = %v, want ErrInvalid", err)
	}
	if _, err := svc.Reveal(context.Background(), RevealRequest{Survey: surveyID(0xee, 0), Consent: true}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown survey: err = %v, want ErrNotFound", err)
	}
	equal(t, int32(0), calls.Load())
}

func TestRespondSealsAnswersForASealedSurvey(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	round := futureRound()
	f.add(t, 0xa1, 100, 0, 40, defPayload(sealedSimple(1, 60, round)), credHex(1))
	svc := NewService(f, "preview")
	b := &fakeBuilder{}
	svc.SetBuilder(b)

	_, err := svc.Respond(context.Background(), RespondRequest{Survey: surveyID(0xa1, 0), Role: RoleKeyholder, Answers: answer(1)})
	noErr(t, err)
	_, p := b.built(t)
	r := p.Responses[0]
	equal(t, 0, len(r.Answers))
	isTrue(t, len(r.Sealed) >= 128)
	isTrue(t, strings.HasPrefix(string(r.Sealed), "age-encryption.org/"))
}

func TestRespondToASealedSurveyRejectsWithoutBuilding(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		round   uint64
		answers []Answer
	}{
		"reveal round already published": {100, answer(0)},
		"invalid answers":                {futureRound(), answer(7)},
		"no answers":                     {futureRound(), nil},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFakeChain()
			f.add(t, 0xa1, 100, 0, 40, defPayload(sealedSimple(1, 60, tc.round)), credHex(1))
			svc := NewService(f, "preview")
			b := &fakeBuilder{}
			svc.SetBuilder(b)
			_, err := svc.Respond(context.Background(), RespondRequest{Survey: surveyID(0xa1, 0), Role: RoleKeyholder, Answers: tc.answers})
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
			equal(t, 0, len(b.requests))
		})
	}
}

func TestCreateSealedSurvey(t *testing.T) {
	t.Parallel()
	round := futureRound()
	svc, _, b := newBuilderService(t)
	req := createRequest()
	req.Seal = &SealOptions{Round: round, PaddingSize: 256}
	_, err := svc.Create(context.Background(), req)
	noErr(t, err)
	_, p := b.built(t)
	equal(t, sealedMode(round, 256), p.Definitions[0].Mode)

	for name, seal := range map[string]*SealOptions{
		"round already published": {Round: 100, PaddingSize: 256},
		"no round":                {PaddingSize: 256},
		"no padding":              {Round: round},
	} {
		svc, _, b := newBuilderService(t)
		req := createRequest()
		req.Seal = seal
		if _, err := svc.Create(context.Background(), req); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
		equal(t, 0, len(b.requests))
	}
}

// Only quicknet beacons are fetched and cached, keyed by round. A sealed survey
// on another drand chain shares round numbers with quicknet but not beacons,
// so its responses stay sealed rather than failing to unseal.
func TestOtherDrandChainsStaySealed(t *testing.T) {
	t.Parallel()
	svc, f, calls := relayStub(t, quicknetRound100Sig)
	other := sealedSimple(2, 60, 100)
	other.Mode.ChainHash = [32]byte(rep(0x77, 32))
	f.add(t, 0xa1, 100, 0, 40, defPayload(sealedSimple(1, 60, 100)), credHex(1))
	f.add(t, 0xa2, 101, 0, 40, defPayload(other), credHex(2))
	f.add(t, 0xd1, 110, 0, 41, respPayload(Response{Survey: ref(0xa2, 0), Role: RoleKeyholder, Credential: cred(false, 10), Sealed: []byte("ciphertext")}), credHex(10))
	ctx := context.Background()

	if _, err := svc.Reveal(ctx, RevealRequest{Survey: surveyID(0xa2, 0), Consent: true}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Reveal on another drand chain: err = %v, want ErrInvalid", err)
	}
	equal(t, int32(0), calls.Load())

	_, err := svc.Reveal(ctx, RevealRequest{Survey: surveyID(0xa1, 0), Consent: true})
	noErr(t, err)
	d, err := svc.Get(ctx, surveyID(0xa2, 0))
	noErr(t, err)
	rt := keyholder(t, d)
	equal(t, uint64(1), rt.Responses)
	equal(t, uint64(1), rt.Sealed)
	equal(t, 0, len(d.Tally.Excluded))
}
