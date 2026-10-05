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
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/gouroboros/cbor"
	"golang.org/x/crypto/blake2b"
)

// fakeBuilder records the metadata transaction requests the service builds. Each
// signer kind has its own credential so a role mapped to the wrong key shows.
type fakeBuilder struct {
	requests []spend.MetadataRequest
	err      error
}

func (b *fakeBuilder) WalletCredential(kind spend.SignerKind) ([28]byte, error) {
	var h [28]byte
	copy(h[:], rep(map[spend.SignerKind]byte{spend.SignerPayment: 0x91, spend.SignerStake: 0x92, spend.SignerDRep: 0x93}[kind], 28))
	return h, nil
}

func (b *fakeBuilder) BuildMetadata(_ context.Context, req spend.MetadataRequest) (spend.Preview, error) {
	if b.err != nil {
		return spend.Preview{}, b.err
	}
	b.requests = append(b.requests, req)
	return spend.Preview{PendingID: "pending-1"}, nil
}

// built decodes the single metadata request the builder received back through
// the codec, so assertions are on what a reader of the chain would see.
func (b *fakeBuilder) built(t *testing.T) (spend.MetadataRequest, Payload) {
	t.Helper()
	equal(t, 1, len(b.requests))
	req := b.requests[0]
	raw, err := cbor.Encode(req.Value)
	noErr(t, err)
	p, err := Decode(raw)
	noErr(t, err)
	return req, p
}

func newBuilderService(t *testing.T) (*Service, *fakeChain, *fakeBuilder) {
	t.Helper()
	f := newFakeChain()
	f.add(t, 0xa1, 100, 0, 40, defPayload(simple(1, 60, RoleDRep, RoleStakeholder, RoleKeyholder, RoleSPO)), credHex(1))
	svc := NewService(f, "preview")
	b := &fakeBuilder{}
	svc.SetBuilder(b)
	return svc, f, b
}

func answer(choice uint64) []Answer {
	return []Answer{{Kind: KindSingleChoice, Question: 0, Choice: choice}}
}

func TestRespondBuildsALabel17ResponseSignedByTheRoleKey(t *testing.T) {
	t.Parallel()
	for role, tc := range map[Role]struct {
		signer spend.SignerKind
		cred   byte
	}{
		RoleDRep:        {spend.SignerDRep, 0x93},
		RoleStakeholder: {spend.SignerStake, 0x92},
		RoleKeyholder:   {spend.SignerPayment, 0x91},
	} {
		t.Run(string(rune('0'+role)), func(t *testing.T) {
			t.Parallel()
			svc, _, b := newBuilderService(t)
			pv, err := svc.Respond(context.Background(), RespondRequest{Survey: surveyID(0xa1, 0), Role: role, Answers: answer(1)})
			noErr(t, err)
			equal(t, "pending-1", pv.PendingID)

			req, p := b.built(t)
			equal(t, Label, req.Label)
			equal(t, tc.signer, req.Signer)
			equal(t, KindResponses, p.Kind)
			equal(t, []Response{{
				Survey: ref(0xa1, 0), Role: role, Credential: cred(false, tc.cred), Answers: answer(1),
			}}, p.Responses)
		})
	}
}

func TestRespondRejectsWithoutBuilding(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		prepare func(*testing.T, *fakeChain)
		req     RespondRequest
		want    error
	}{
		"unknown survey":      {nil, RespondRequest{Survey: surveyID(0xee, 0), Role: RoleDRep, Answers: answer(0)}, ErrNotFound},
		"malformed id":        {nil, RespondRequest{Survey: "nope", Role: RoleDRep, Answers: answer(0)}, ErrNotFound},
		"ineligible role":     {nil, RespondRequest{Survey: surveyID(0xa2, 0), Role: RoleKeyholder, Answers: answer(0)}, ErrInvalid},
		"spo not signable":    {nil, RespondRequest{Survey: surveyID(0xa1, 0), Role: RoleSPO, Answers: answer(0)}, ErrInvalid},
		"cc not signable":     {nil, RespondRequest{Survey: surveyID(0xa1, 0), Role: RoleCC, Answers: answer(0)}, ErrInvalid},
		"option out of range": {nil, RespondRequest{Survey: surveyID(0xa1, 0), Role: RoleDRep, Answers: answer(2)}, ErrInvalid},
		"no answers":          {nil, RespondRequest{Survey: surveyID(0xa1, 0), Role: RoleDRep}, ErrInvalid},
		"role out of range":   {nil, RespondRequest{Survey: surveyID(0xa1, 0), Role: 9, Answers: answer(0)}, ErrInvalid},
		"closed survey": {func(t *testing.T, f *fakeChain) {
			f.add(t, 0xa3, 101, 0, 40, defPayload(simple(3, 45, RoleDRep)), credHex(3))
		}, RespondRequest{Survey: surveyID(0xa3, 0), Role: RoleDRep, Answers: answer(0)}, ErrInvalid},
		"cancelled survey": {func(t *testing.T, f *fakeChain) {
			f.add(t, 0xa4, 102, 0, 40, defPayload(simple(4, 60, RoleDRep)), credHex(4))
			f.add(t, 0xc4, 103, 0, 41, cancelPayload(ref(0xa4, 0)), credHex(4))
		}, RespondRequest{Survey: surveyID(0xa4, 0), Role: RoleDRep, Answers: answer(0)}, ErrInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			svc, f, b := newBuilderService(t)
			f.add(t, 0xa2, 104, 0, 40, defPayload(simple(2, 60, RoleDRep)), credHex(2))
			if tc.prepare != nil {
				tc.prepare(t, f)
			}
			_, err := svc.Respond(context.Background(), tc.req)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			equal(t, 0, len(b.requests))
		})
	}
}

func TestRespondWithoutAWalletBuilder(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	f.add(t, 0xa1, 100, 0, 40, defPayload(simple(1, 60)), credHex(1))
	_, err := NewService(f, "preview").Respond(context.Background(), RespondRequest{Survey: surveyID(0xa1, 0), Role: RoleDRep, Answers: answer(0)})
	if !errors.Is(err, spend.ErrNoWallet) {
		t.Fatalf("err = %v, want spend.ErrNoWallet", err)
	}
}

func TestRespondPassesBuilderErrorsThrough(t *testing.T) {
	t.Parallel()
	svc, _, b := newBuilderService(t)
	b.err = spend.ErrInsufficientFunds
	_, err := svc.Respond(context.Background(), RespondRequest{Survey: surveyID(0xa1, 0), Role: RoleDRep, Answers: answer(0)})
	if !errors.Is(err, spend.ErrInsufficientFunds) {
		t.Fatalf("err = %v, want ErrInsufficientFunds", err)
	}
}

func createRequest() CreateRequest {
	return CreateRequest{
		Title: "Poll", Description: "Pick one", Roles: []Role{RoleDRep, RoleStakeholder}, EndEpoch: 55,
		Questions: []Question{
			{Kind: KindSingleChoice, Prompt: "q1", Options: []string{"a", "b"}},
			{Kind: KindNumericRange, Prompt: "q2", Range: &Range{Min: 1, Max: 10}, Required: true},
		},
	}
}

func TestCreateBuildsADefinitionOwnedByThePaymentKey(t *testing.T) {
	t.Parallel()
	svc, _, b := newBuilderService(t)
	req := createRequest()
	_, err := svc.Create(context.Background(), req)
	noErr(t, err)

	built, p := b.built(t)
	equal(t, Label, built.Label)
	equal(t, spend.SignerPayment, built.Signer)
	equal(t, KindDefinitions, p.Kind)
	equal(t, []Definition{{
		Owner: cred(false, 0x91), Title: "Poll", Description: "Pick one",
		Roles: []Role{RoleDRep, RoleStakeholder}, EndEpoch: 55, Questions: req.Questions,
	}}, p.Definitions)
}

func TestCreateRejectsWithoutBuilding(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*CreateRequest){
		"ends in the current epoch": func(r *CreateRequest) { r.EndEpoch = 50 },
		"ended already":             func(r *CreateRequest) { r.EndEpoch = 3 },
		"no title":                  func(r *CreateRequest) { r.Title = "" },
		"no questions":              func(r *CreateRequest) { r.Questions = nil },
		"no roles":                  func(r *CreateRequest) { r.Roles = nil },
		"invalid question":          func(r *CreateRequest) { r.Questions[0].Options = []string{"only"} },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			svc, _, b := newBuilderService(t)
			req := createRequest()
			mutate(&req)
			_, err := svc.Create(context.Background(), req)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
			equal(t, 0, len(b.requests))
		})
	}
}

func TestCreateAllowsEmptyTextOnlyWithAnExternalAnchor(t *testing.T) {
	t.Parallel()
	svc, _, b := newBuilderService(t)
	req := createRequest()
	req.Title, req.Description = "", ""
	req.AnchorURI, req.AnchorDocument = "ipfs://doc", `{"title":"On IPFS"}`
	_, err := svc.Create(context.Background(), req)
	noErr(t, err)
	_, p := b.built(t)
	equal(t, "ipfs://doc", p.Definitions[0].Anchor.URI)
}

// The anchor hash is the blake2b-256 of the exact bytes the author publishes at
// the URI, so readers can tell the document was not changed.
func TestCreateHashesTheAnchorDocumentExactly(t *testing.T) {
	t.Parallel()
	doc := "{\"specVersion\":5,\"kind\":\"cardano-survey-presentation\",\"title\":\"A long title\"}\n"
	svc, _, b := newBuilderService(t)
	req := createRequest()
	req.AnchorURI, req.AnchorDocument = "https://example.test/survey.json", doc
	_, err := svc.Create(context.Background(), req)
	noErr(t, err)
	_, p := b.built(t)

	want := blake2b.Sum256([]byte(doc))
	equal(t, &Anchor{URI: "https://example.test/survey.json", Hash: want}, p.Definitions[0].Anchor)

	// One changed byte changes the hash.
	svc, _, b = newBuilderService(t)
	req.AnchorDocument = strings.TrimSuffix(doc, "\n")
	_, err = svc.Create(context.Background(), req)
	noErr(t, err)
	_, p = b.built(t)
	isTrue(t, p.Definitions[0].Anchor.Hash != want)
}

func TestCreateRejectsAHalfSpecifiedAnchor(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*CreateRequest){
		"uri without a document": func(r *CreateRequest) { r.AnchorURI = "ipfs://doc" },
		"document without a uri": func(r *CreateRequest) { r.AnchorDocument = "{}" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			svc, _, b := newBuilderService(t)
			req := createRequest()
			mutate(&req)
			if _, err := svc.Create(context.Background(), req); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
			equal(t, 0, len(b.requests))
		})
	}
}

func TestCancelBuildsACancellationForTheOwner(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	// The fake wallet's payment credential is 0x91.
	f.add(t, 0xa1, 100, 0, 40, defPayload(simple(0x91, 60)), credHex(0x91))
	svc := NewService(f, "preview")
	b := &fakeBuilder{}
	svc.SetBuilder(b)

	_, err := svc.Cancel(context.Background(), CancelRequest{Survey: surveyID(0xa1, 0)})
	noErr(t, err)
	built, p := b.built(t)
	equal(t, spend.SignerPayment, built.Signer)
	equal(t, KindCancellations, p.Kind)
	equal(t, []Ref{ref(0xa1, 0)}, p.Cancellations)
}

func TestCancelRejectsWithoutBuilding(t *testing.T) {
	t.Parallel()
	script := simple(0x91, 60)
	script.Owner = cred(true, 0x91)
	for name, tc := range map[string]struct {
		prepare func(*testing.T, *fakeChain)
		id      string
		want    error
	}{
		"someone else's survey": {func(t *testing.T, f *fakeChain) { f.add(t, 0xa1, 100, 0, 40, defPayload(simple(2, 60)), credHex(2)) }, surveyID(0xa1, 0), ErrInvalid},
		"script owner":          {func(t *testing.T, f *fakeChain) { f.add(t, 0xa1, 100, 0, 40, defPayload(script)) }, surveyID(0xa1, 0), ErrNotFound},
		"already cancelled": {func(t *testing.T, f *fakeChain) {
			f.add(t, 0xa1, 100, 0, 40, defPayload(simple(0x91, 60)), credHex(0x91))
			f.add(t, 0xc1, 101, 0, 41, cancelPayload(ref(0xa1, 0)), credHex(0x91))
		}, surveyID(0xa1, 0), ErrInvalid},
		"already ended": {func(t *testing.T, f *fakeChain) {
			f.add(t, 0xa1, 100, 0, 40, defPayload(simple(0x91, 45)), credHex(0x91))
		}, surveyID(0xa1, 0), ErrInvalid},
		"unknown": {nil, surveyID(0xee, 0), ErrNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFakeChain()
			if tc.prepare != nil {
				tc.prepare(t, f)
			}
			svc := NewService(f, "preview")
			b := &fakeBuilder{}
			svc.SetBuilder(b)
			_, err := svc.Cancel(context.Background(), CancelRequest{Survey: tc.id})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			equal(t, 0, len(b.requests))
		})
	}
}

func TestSurveysOwnedByTheWalletAreMarkedOwned(t *testing.T) {
	t.Parallel()
	script := simple(0x91, 60)
	script.Owner = cred(true, 0x91)
	f := newFakeChain()
	f.add(t, 0xa1, 100, 0, 40, defPayload(simple(0x91, 60)), credHex(0x91)) // the fake wallet's payment key
	f.add(t, 0xa2, 101, 0, 40, defPayload(simple(0x92, 60)), credHex(0x92)) // someone else
	f.add(t, 0xa3, 102, 0, 40, defPayload(script), credHex(0x91))           // same hash, but a script: never verified

	svc := NewService(f, "preview")
	list, err := svc.List(context.Background())
	noErr(t, err)
	for _, s := range list {
		equal(t, false, s.Owned) // no wallet builder: nothing is owned
	}

	svc.SetBuilder(&fakeBuilder{})
	list, err = svc.List(context.Background())
	noErr(t, err)
	equal(t, true, summaryByID(t, list, surveyID(0xa1, 0)).Owned)
	equal(t, false, summaryByID(t, list, surveyID(0xa2, 0)).Owned)
	equal(t, 2, len(list))

	d, err := svc.Get(context.Background(), surveyID(0xa1, 0))
	noErr(t, err)
	equal(t, true, d.Owned)
}
