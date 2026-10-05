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
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// fakeChain serves the label-17 history and the lookups the service makes.
// Epoch 50 is current; an epoch lasts 100 seconds and starts at
// 10000 - (50-epoch)*100.
type fakeChain struct {
	labels   []chain.LabelMetadata
	txs      map[string]chain.TxInfo
	signers  map[string][]string
	dreps    map[string]bool // credential hex
	pools    map[string]bool // pool id bech32
	accounts map[string]chain.AccountInfo
	docs     []chain.AnchorDocument
	roleErr  error
	pages    []int // label pages read, in order
	start    int64 // current epoch's start; timeIn assumes the default
	junk     int   // junk rows ever added, so each has a distinct hash
}

func newFakeChain() *fakeChain {
	return &fakeChain{
		txs:      map[string]chain.TxInfo{},
		signers:  map[string][]string{},
		dreps:    map[string]bool{},
		pools:    map[string]bool{},
		accounts: map[string]chain.AccountInfo{},
	}
}

func timeIn(epoch uint64) int64 { return 10000 - int64(50-epoch)*100 + 10 }

func txHash(b byte) string { return hex.EncodeToString(rep(b, 32)) }

// add records a label-17 payload sent in transaction b, included in epoch
// `epoch` at (height, index), requiring the given signer hashes (hex).
func (f *fakeChain) add(t *testing.T, b byte, height uint64, index int, epoch uint64, p Payload, signers ...string) {
	t.Helper()
	raw, err := Marshal(p)
	noErr(t, err)
	f.addRaw(b, height, index, epoch, raw, signers...)
}

func (f *fakeChain) addRaw(b byte, height uint64, index int, epoch uint64, raw []byte, signers ...string) {
	h := txHash(b)
	f.labels = append(f.labels, chain.LabelMetadata{TxHash: h, CBOR: raw})
	f.txs[h] = chain.TxInfo{Hash: h, BlockHeight: height, Index: index, BlockTime: timeIn(epoch)}
	f.signers[h] = signers
}

func (f *fakeChain) MetadataByLabelPage(_ context.Context, label uint64, page int) ([]chain.LabelMetadata, error) {
	if label != Label {
		return nil, fmt.Errorf("unexpected label %d", label)
	}
	f.pages = append(f.pages, page)
	start := min((page-1)*chain.LabelPageSize, len(f.labels))
	end := min(start+chain.LabelPageSize, len(f.labels))
	return slices.Clone(f.labels[start:end]), nil
}

func (f *fakeChain) Transaction(_ context.Context, hash string) (chain.TxInfo, error) {
	tx, ok := f.txs[hash]
	if !ok {
		return chain.TxInfo{}, chain.ErrNotFound
	}
	return tx, nil
}

func (f *fakeChain) RequiredSigners(_ context.Context, hash string) ([]string, error) {
	return f.signers[hash], nil
}

func (f *fakeChain) LatestEpoch(context.Context) (chain.EpochInfo, error) {
	start := f.start
	if start == 0 {
		start = 10000
	}
	return chain.EpochInfo{Epoch: 50, StartTime: start, EndTime: start + 100}, nil
}

func (f *fakeChain) Genesis(context.Context) (chain.Genesis, error) {
	return chain.Genesis{EpochLength: 100, SlotLength: 1}, nil
}

func (f *fakeChain) DRep(_ context.Context, id string) (chain.DRepInfo, error) {
	if f.roleErr != nil {
		return chain.DRepInfo{}, f.roleErr
	}
	if !f.dreps[id] {
		return chain.DRepInfo{}, chain.ErrNotFound
	}
	return chain.DRepInfo{DRepID: id}, nil
}

func (f *fakeChain) Pool(_ context.Context, id string) (chain.PoolInfo, error) {
	if !f.pools[id] {
		return chain.PoolInfo{}, chain.ErrNotFound
	}
	return chain.PoolInfo{PoolID: id}, nil
}

func (f *fakeChain) Account(_ context.Context, addr string) (chain.AccountInfo, error) {
	a, ok := f.accounts[addr]
	if !ok {
		return chain.AccountInfo{}, chain.ErrNotFound
	}
	return a, nil
}

func (f *fakeChain) GovernanceAnchorDocuments(context.Context) ([]chain.AnchorDocument, error) {
	return f.docs, nil
}

func credHex(b byte) string { return hex.EncodeToString(rep(b, 28)) }

// simple builds a one-question single-choice survey owned by key credential
// owner.
func simple(owner byte, endEpoch uint64, roles ...Role) Definition {
	if len(roles) == 0 {
		roles = []Role{RoleDRep}
	}
	return Definition{
		Owner: cred(false, owner), Title: fmt.Sprintf("survey by %d", owner), Description: "d",
		Roles: roles, EndEpoch: endEpoch,
		Questions: []Question{{Kind: KindSingleChoice, Prompt: "q", Options: []string{"yes", "no"}}},
	}
}

func defPayload(ds ...Definition) Payload { return Payload{Kind: KindDefinitions, Definitions: ds} }

func respPayload(rs ...Response) Payload { return Payload{Kind: KindResponses, Responses: rs} }

func cancelPayload(rs ...Ref) Payload { return Payload{Kind: KindCancellations, Cancellations: rs} }

func respond(survey Ref, role Role, who byte, choice uint64) Response {
	return Response{
		Survey: survey, Role: role, Credential: cred(false, who),
		Answers: []Answer{{Kind: KindSingleChoice, Question: 0, Choice: choice}},
	}
}

func summaryByID(t *testing.T, list []Summary, id string) Summary {
	t.Helper()
	for _, s := range list {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("survey %s not listed in %+v", id, list)
	return Summary{}
}

func surveyID(b byte, idx int) string { return fmt.Sprintf("%s:%d", txHash(b), idx) }

func TestListClassifiesSurveys(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	f.add(t, 0xa1, 100, 0, 40, defPayload(simple(1, 60)), credHex(1))   // open
	f.add(t, 0xa2, 101, 0, 40, defPayload(simple(2, 49)), credHex(2))   // closed: end epoch passed
	f.add(t, 0xa3, 102, 0, 40, defPayload(simple(3, 60)), credHex(3))   // cancelled below
	f.add(t, 0xa4, 103, 0, 41, cancelPayload(ref(0xa3, 0)), credHex(3)) // by the owner
	f.add(t, 0xa5, 104, 0, 49, defPayload(simple(5, 50)), credHex(5))   // end epoch == current: still open

	list, err := NewService(f, "preview").List(context.Background())
	noErr(t, err)
	equal(t, 4, len(list))
	equal(t, "open", summaryByID(t, list, surveyID(0xa1, 0)).Status)
	equal(t, "closed", summaryByID(t, list, surveyID(0xa2, 0)).Status)
	equal(t, "cancelled", summaryByID(t, list, surveyID(0xa3, 0)).Status)
	equal(t, "open", summaryByID(t, list, surveyID(0xa5, 0)).Status)

	s := summaryByID(t, list, surveyID(0xa1, 0))
	equal(t, txHash(0xa1), s.TxHash)
	equal(t, "survey by 1", s.Title)
	equal(t, credHex(1), s.Owner)
	equal(t, 1, s.Questions)
	equal(t, uint64(60), s.EndEpoch)
}

func TestListIsNewestFirst(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	f.add(t, 0xa1, 100, 0, 40, defPayload(simple(1, 60)), credHex(1))
	f.add(t, 0xa2, 200, 0, 41, defPayload(simple(2, 60), simple(2, 61)), credHex(2))
	list, err := NewService(f, "preview").List(context.Background())
	noErr(t, err)
	var ids []string
	for _, s := range list {
		ids = append(ids, s.ID)
	}
	equal(t, []string{surveyID(0xa2, 1), surveyID(0xa2, 0), surveyID(0xa1, 0)}, ids)
}

func TestListSkipsMalformedAndInvalidDefinitions(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	f.addRaw(0xb1, 1, 0, 40, []byte{0xff, 0x00})                       // not CBOR
	f.addRaw(0xb2, 2, 0, 40, []byte{0x82, 0x09, 0x81, 0x00})           // unknown payload tag
	f.add(t, 0xb3, 3, 0, 40, defPayload(simple(3, 60)))                // owner did not sign
	f.add(t, 0xb4, 4, 0, 40, defPayload(simple(4, 40)), credHex(4))    // ends in the epoch it was published
	f.add(t, 0xb5, 5, 0, 40, defPayload(simple(5, 39)), credHex(5))    // already ended when published
	f.add(t, 0xb6, 6, 0, 40, defPayload(simple(6, 60)), credHex(0x66)) // someone else's signature
	f.add(t, 0xb7, 7, 0, 40, respPayload(respond(ref(0xb7, 0), RoleDRep, 7, 0)), credHex(7))
	f.add(t, 0xb8, 8, 0, 40, defPayload(simple(8, 60)), credHex(8)) // the only good one

	list, err := NewService(f, "preview").List(context.Background())
	noErr(t, err)
	if len(list) != 1 {
		t.Fatalf("listed %d surveys, want only the valid one", len(list))
	}
	equal(t, surveyID(0xb8, 0), list[0].ID)
}

// A script owner can only be proven by resolving the script and checking the
// transaction satisfies it (CIP-179 mechanism A), which this service does not
// do, so a script-owned definition is never shown as a verified survey.
func TestListSkipsScriptOwnedDefinitions(t *testing.T) {
	t.Parallel()
	script := simple(9, 60)
	script.Owner = cred(true, 9)
	f := newFakeChain()
	f.add(t, 0xb1, 1, 0, 40, defPayload(script))             // nobody signed
	f.add(t, 0xb2, 2, 0, 40, defPayload(script), credHex(9)) // signer hash equals the script hash
	f.add(t, 0xb3, 3, 0, 40, defPayload(simple(3, 60)), credHex(3))

	svc := NewService(f, "preview")
	list, err := svc.List(context.Background())
	noErr(t, err)
	if len(list) != 1 || list[0].ID != surveyID(0xb3, 0) {
		t.Fatalf("listed %+v, want only the key-owned survey", list)
	}
	if _, err := svc.Get(context.Background(), surveyID(0xb1, 0)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get script-owned survey: err = %v, want ErrNotFound", err)
	}
}

func TestCancellationRules(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		cancelEpoch uint64
		signers     []string
		ref         Ref
		cancelled   bool
	}{
		"owner before end epoch": {41, []string{credHex(1)}, ref(0xa1, 0), true},
		"someone else":           {41, []string{credHex(2)}, ref(0xa1, 0), false},
		"nobody signed":          {41, nil, ref(0xa1, 0), false},
		"unknown survey":         {41, []string{credHex(1)}, ref(0xee, 0), false},
		"unknown index":          {41, []string{credHex(1)}, ref(0xa1, 1), false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFakeChain()
			f.add(t, 0xa1, 100, 0, 40, defPayload(simple(1, 60)), credHex(1))
			f.add(t, 0xc1, 200, 0, tc.cancelEpoch, cancelPayload(tc.ref), tc.signers...)
			list, err := NewService(f, "preview").List(context.Background())
			noErr(t, err)
			id := surveyID(0xa1, 0)
			want := "open"
			if tc.cancelled {
				want = "cancelled"
			}
			if got := summaryByID(t, list, id).Status; got != want {
				t.Fatalf("status = %s, want %s", got, want)
			}
		})
	}
}

func TestCancellationAfterEndEpochIsIgnored(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	f.add(t, 0xa1, 100, 0, 30, defPayload(simple(1, 40)), credHex(1))
	f.add(t, 0xc1, 200, 0, 41, cancelPayload(ref(0xa1, 0)), credHex(1)) // epoch 41 > end epoch 40
	list, err := NewService(f, "preview").List(context.Background())
	noErr(t, err)
	equal(t, "closed", summaryByID(t, list, surveyID(0xa1, 0)).Status)
}

func TestGetTalliesVerifiedResponses(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	s := ref(0xa1, 0)
	f.add(t, 0xa1, 100, 0, 40, defPayload(simple(1, 45, RoleDRep, RoleKeyholder)), credHex(1))
	f.dreps[credHex(10)] = true
	f.dreps[credHex(11)] = true

	f.add(t, 0xd1, 110, 0, 41, respPayload(respond(s, RoleDRep, 10, 0)), credHex(10))
	f.add(t, 0xd2, 111, 0, 41, respPayload(respond(s, RoleDRep, 11, 1)), credHex(11))
	// Latest wins: DRep 10 changes their answer.
	f.add(t, 0xd3, 112, 0, 42, respPayload(respond(s, RoleDRep, 10, 1)), credHex(10))
	// Excluded: no signature, not a registered DRep, script credential, wrong role.
	f.add(t, 0xd4, 113, 0, 42, respPayload(respond(s, RoleDRep, 12, 0)))
	f.add(t, 0xd5, 114, 0, 42, respPayload(respond(s, RoleDRep, 13, 0)), credHex(13))
	scriptResp := respond(s, RoleDRep, 14, 0)
	scriptResp.Credential = cred(true, 14)
	f.add(t, 0xd6, 115, 0, 42, respPayload(scriptResp), credHex(14))
	f.add(t, 0xd7, 116, 0, 42, respPayload(respond(s, RoleSPO, 15, 0)), credHex(15))
	// A Keyholder needs no ledger registration, only its signature.
	f.add(t, 0xd8, 117, 0, 42, respPayload(respond(s, RoleKeyholder, 16, 0)), credHex(16))
	// A Keyholder passes role validation by definition, so only the missing
	// signature excludes this one.
	f.add(t, 0xda, 119, 0, 42, respPayload(respond(s, RoleKeyholder, 18, 0)))
	// Late: submitted in an epoch after the survey ended.
	f.add(t, 0xd9, 118, 0, 46, respPayload(respond(s, RoleKeyholder, 17, 0)), credHex(17))

	got, err := NewService(f, "preview").Get(context.Background(), surveyID(0xa1, 0))
	noErr(t, err)
	if got.Tally == nil {
		t.Fatal("no tally")
	}
	equal(t, "closed", got.Status)

	byRole := map[Role]RoleTally{}
	for _, r := range got.Tally.Roles {
		byRole[r.Role] = r
	}
	drep := byRole[RoleDRep]
	equal(t, uint64(2), drep.Responses)
	equal(t, []OptionTally{{}, {Count: 2}}, drep.Questions[0].Options)
	equal(t, uint64(1), byRole[RoleKeyholder].Responses)
	equal(t, 2, len(got.Tally.Roles))

	reasonByTx := reasons(*got.Tally)
	for _, h := range []byte{0xd1, 0xd4, 0xd5, 0xd6, 0xd7, 0xd9, 0xda} {
		if reasonByTx[txHash(h)] == "" {
			t.Errorf("tx %x should be excluded with a reason", h)
		}
	}
	for _, h := range []byte{0xd2, 0xd3, 0xd8} {
		if reasonByTx[txHash(h)] != "" {
			t.Errorf("tx %x was excluded: %s", h, reasonByTx[txHash(h)])
		}
	}
	equal(t, "superseded by a later response", reasonByTx[txHash(0xd1)])
}

func TestGetVerifiesRolesAgainstTheNode(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	s := ref(0xa1, 0)
	f.add(t, 0xa1, 100, 0, 40, defPayload(simple(1, 60, RoleSPO, RoleStakeholder, RoleCC, RoleKeyholder)), credHex(1))

	poolID := lcommon.PoolId(cred(false, 20).Hash).String()
	f.pools[poolID] = true
	stake, err := lcommon.NewAddressFromParts(lcommon.AddressTypeNoneKey, lcommon.AddressNetworkTestnet, nil, rep(21, 28))
	noErr(t, err)
	f.accounts[stake.String()] = chain.AccountInfo{Registered: true, ControlledAmount: "5000000"}
	empty, err := lcommon.NewAddressFromParts(lcommon.AddressTypeNoneKey, lcommon.AddressNetworkTestnet, nil, rep(22, 28))
	noErr(t, err)
	f.accounts[empty.String()] = chain.AccountInfo{Registered: true, ControlledAmount: "0"}

	f.add(t, 0xe1, 110, 0, 41, respPayload(respond(s, RoleSPO, 20, 0)), credHex(20))         // registered pool
	f.add(t, 0xe2, 111, 0, 41, respPayload(respond(s, RoleSPO, 23, 0)), credHex(23))         // unknown pool
	f.add(t, 0xe3, 112, 0, 41, respPayload(respond(s, RoleStakeholder, 21, 0)), credHex(21)) // staked
	f.add(t, 0xe4, 113, 0, 41, respPayload(respond(s, RoleStakeholder, 22, 0)), credHex(22)) // no stake
	f.add(t, 0xe5, 114, 0, 41, respPayload(respond(s, RoleStakeholder, 24, 0)), credHex(24)) // unknown account
	f.add(t, 0xe6, 115, 0, 41, respPayload(respond(s, RoleCC, 25, 0)), credHex(25))          // CC cannot be verified

	got, err := NewService(f, "preview").Get(context.Background(), surveyID(0xa1, 0))
	noErr(t, err)
	r := reasons(*got.Tally)
	for _, h := range []byte{0xe1, 0xe3} {
		if r[txHash(h)] != "" {
			t.Errorf("tx %x excluded: %s", h, r[txHash(h)])
		}
	}
	for _, h := range []byte{0xe2, 0xe4, 0xe5, 0xe6} {
		if r[txHash(h)] == "" {
			t.Errorf("tx %x should be excluded", h)
		}
	}
}

func TestGetFailsWhenTheNodeCannotVerify(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	f.add(t, 0xa1, 100, 0, 40, defPayload(simple(1, 60)), credHex(1))
	f.add(t, 0xd1, 110, 0, 41, respPayload(respond(ref(0xa1, 0), RoleDRep, 10, 0)), credHex(10))
	f.roleErr = errors.New("node down")

	_, err := NewService(f, "preview").Get(context.Background(), surveyID(0xa1, 0))
	if !errors.Is(err, f.roleErr) {
		t.Fatalf("err = %v, want the node failure, not an exclusion", err)
	}
}

func TestGetCancelledSurveyIsNotTallied(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	f.add(t, 0xa1, 100, 0, 40, defPayload(simple(1, 60, RoleKeyholder)), credHex(1))
	f.add(t, 0xd1, 110, 0, 41, respPayload(respond(ref(0xa1, 0), RoleKeyholder, 10, 0)), credHex(10))
	f.add(t, 0xc1, 120, 0, 42, cancelPayload(ref(0xa1, 0)), credHex(1))

	got, err := NewService(f, "preview").Get(context.Background(), surveyID(0xa1, 0))
	noErr(t, err)
	equal(t, "cancelled", got.Status)
	if got.Tally != nil {
		t.Fatalf("a cancelled survey must not be tallied: %+v", got.Tally)
	}
}

func TestGetIgnoresResponsesToOtherSurveysAndBatchIndex(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	f.add(t, 0xa1, 100, 0, 40, defPayload(simple(1, 60, RoleKeyholder), simple(1, 60, RoleKeyholder)), credHex(1))
	f.add(t, 0xd1, 110, 0, 41, respPayload(
		respond(ref(0xa1, 0), RoleKeyholder, 10, 0),
		respond(ref(0xa1, 1), RoleKeyholder, 10, 1),
	), credHex(10))

	got, err := NewService(f, "preview").Get(context.Background(), surveyID(0xa1, 1))
	noErr(t, err)
	equal(t, []OptionTally{{}, {Count: 1}}, got.Tally.Roles[0].Questions[0].Options)
	equal(t, uint64(1), got.Tally.Roles[0].Responses)
}

func TestGetBatchedResponsesKeepPayloadOrder(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	s := ref(0xa1, 0)
	f.add(t, 0xa1, 100, 0, 40, defPayload(simple(1, 60, RoleKeyholder)), credHex(1))
	// Same credential twice in one transaction: the later entry in the array wins.
	f.add(t, 0xd1, 110, 0, 41, respPayload(
		respond(s, RoleKeyholder, 10, 0),
		respond(s, RoleKeyholder, 10, 1),
	), credHex(10))
	got, err := NewService(f, "preview").Get(context.Background(), surveyID(0xa1, 0))
	noErr(t, err)
	equal(t, []OptionTally{{}, {Count: 1}}, got.Tally.Roles[0].Questions[0].Options)
}

func TestGetUnknownAndMalformedIDs(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	f.add(t, 0xa1, 100, 0, 40, defPayload(simple(1, 60)), credHex(1))
	svc := NewService(f, "preview")
	for _, id := range []string{surveyID(0xee, 0), surveyID(0xa1, 5), "nonsense", txHash(0xa1), txHash(0xa1) + ":x", "zz:0"} {
		if _, err := svc.Get(context.Background(), id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%q) err = %v, want ErrNotFound", id, err)
		}
	}
}

func TestLinkedGovernanceActions(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	f.add(t, 0xa1, 100, 0, 40, defPayload(simple(1, 60)), credHex(1))
	f.add(t, 0xa2, 101, 0, 40, defPayload(simple(2, 70)), credHex(2))
	link := func(b byte, idx int) []byte {
		return []byte(fmt.Sprintf(`{"body":{"cip179":{"specVersion":5,"kind":"survey-link","surveyTxId":"%s","surveyIndex":%d}}}`, txHash(b), idx))
	}
	f.docs = []chain.AnchorDocument{
		{ActionID: "gov_action_one", ExpiresEpoch: 60, Content: link(0xa1, 0)},
		{ActionID: "gov_action_two", ExpiresEpoch: 60, Content: link(0xa1, 0)},         // second action, same survey
		{ActionID: "gov_action_wrong_epoch", ExpiresEpoch: 61, Content: link(0xa1, 0)}, // survey end epoch != expiry
		{ActionID: "gov_action_unknown", ExpiresEpoch: 60, Content: link(0xee, 0)},
		{ActionID: "gov_action_bad_index", ExpiresEpoch: 60, Content: link(0xa1, 3)},
		{ActionID: "gov_action_junk", ExpiresEpoch: 60, Content: []byte("not json")},
		{ActionID: "gov_action_other", ExpiresEpoch: 70, Content: link(0xa2, 0)},
	}
	svc := NewService(f, "preview")

	list, err := svc.List(context.Background())
	noErr(t, err)
	equal(t, []string{"gov_action_one", "gov_action_two"}, summaryByID(t, list, surveyID(0xa1, 0)).LinkedActions)
	equal(t, []string{"gov_action_other"}, summaryByID(t, list, surveyID(0xa2, 0)).LinkedActions)

	got, err := svc.Get(context.Background(), surveyID(0xa1, 0))
	noErr(t, err)
	equal(t, []string{"gov_action_one", "gov_action_two"}, got.LinkedActions)

	// No link anywhere degrades to an empty list, not an error.
	f.docs = nil
	list, err = svc.List(context.Background())
	noErr(t, err)
	equal(t, 0, len(summaryByID(t, list, surveyID(0xa1, 0)).LinkedActions))
}

func TestEpochOf(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	svc := NewService(f, "preview")
	cl, err := svc.clock(context.Background())
	noErr(t, err)
	for blockTime, want := range map[int64]uint64{
		10000: 50, // first second of the current epoch
		10099: 50,
		9999:  49, // last second of the previous one
		9900:  49,
		9899:  48,
		5000:  0,
		-500:  0, // never below epoch 0
	} {
		if got := cl.epochOf(blockTime); got != want {
			t.Errorf("epochOf(%d) = %d, want %d", blockTime, got, want)
		}
	}
}

// An option or level count is a bare integer on chain, and tallying or showing
// a question allocates one entry per option, so a count no transaction could
// answer is refused rather than allocated.
func TestListSkipsDefinitionsTooLargeToTally(t *testing.T) {
	t.Parallel()
	counted := simple(1, 60)
	counted.Questions[0].Options, counted.Questions[0].OptionCount = nil, 1000
	levels := simple(2, 60)
	levels.Questions[0] = Question{Kind: KindRating, Prompt: "q", Options: []string{"a", "b"}, Scale: &RatingScale{Levels: 1000}}

	// 1000 encodes as 0x1903e8; swap it for 2^40 after encoding.
	huge := func(d Definition) []byte {
		raw, err := Marshal(defPayload(d))
		noErr(t, err)
		equal(t, 1, bytes.Count(raw, []byte{0x19, 0x03, 0xe8}))
		return bytes.Replace(raw, []byte{0x19, 0x03, 0xe8}, []byte{0x1b, 0, 0, 1, 0, 0, 0, 0, 0}, 1)
	}
	f := newFakeChain()
	f.addRaw(0xb1, 1, 0, 40, huge(counted), credHex(1))
	f.addRaw(0xb2, 2, 0, 40, huge(levels), credHex(2))
	f.add(t, 0xb3, 3, 0, 40, defPayload(simple(3, 60)), credHex(3))

	svc := NewService(f, "preview")
	list, err := svc.List(context.Background())
	noErr(t, err)
	if len(list) != 1 || list[0].ID != surveyID(0xb3, 0) {
		t.Fatalf("listed %d surveys, want only the one with a bounded option count", len(list))
	}
	if _, err := svc.Get(context.Background(), surveyID(0xb1, 0)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get: err = %v, want ErrNotFound", err)
	}
}

// addJunk appends n label-17 rows that do not decode as CIP-179 payloads, each
// in a distinct transaction.
func (f *fakeChain) addJunk(n int) {
	for range n {
		f.junk++
		f.labels = append(f.labels, chain.LabelMetadata{TxHash: fmt.Sprintf("%064x", 1<<20+f.junk), CBOR: []byte{0x00}})
	}
}

func titles(t *testing.T, s *Service) []string {
	t.Helper()
	list, err := s.List(context.Background())
	noErr(t, err)
	out := make([]string, len(list))
	for i, sm := range list {
		out[i] = sm.Title
	}
	return out
}

func TestLabelHistoryReadsOnlyNewPages(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	f.addJunk(250)
	s := NewService(f, "preview")
	titles(t, s)
	equal(t, []int{1, 2, 3}, f.pages)

	// The two full pages are kept; the last of them is re-read to detect a
	// rollback, then reading resumes after it.
	f.addJunk(60)
	f.pages = nil
	titles(t, s)
	equal(t, []int{2, 3, 4}, f.pages)
}

func TestLabelHistoryLongerThanOneRequestCompletesLater(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	f.addJunk((maxLabelPages + 3) * chain.LabelPageSize)
	f.add(t, 0xa1, 100, 0, 40, defPayload(simple(1, 60)), credHex(1))
	s := NewService(f, "preview")

	if _, err := s.List(context.Background()); !errors.Is(err, ErrIndexing) {
		t.Fatalf("first List err = %v, want ErrIndexing", err)
	}
	equal(t, []string{"survey by 1"}, titles(t, s))
}

func TestLabelHistoryDropsRolledBackTransactions(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	f.addJunk(99)
	f.add(t, 0xa1, 100, 0, 40, defPayload(simple(1, 60)), credHex(1))
	f.addJunk(105)
	s := NewService(f, "preview")
	equal(t, []string{"survey by 1"}, titles(t, s))

	// A rollback removes the survey and everything after it; the chain then
	// carries a different survey in its place.
	f.labels = f.labels[:99]
	f.add(t, 0xa2, 101, 0, 40, defPayload(simple(2, 60)), credHex(2))
	f.addJunk(120)
	equal(t, []string{"survey by 2"}, titles(t, s))
}
