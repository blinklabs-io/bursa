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
	"testing"
)

func singleDef() Definition {
	return Definition{
		Owner: cred(false, 1), Roles: []Role{RoleDRep, RoleStakeholder}, EndEpoch: 100,
		Questions: []Question{{Kind: KindSingleChoice, Options: []string{"yes", "no"}}},
	}
}

func vote(role Role, who byte, choice uint64) Response {
	return Response{
		Role: role, Credential: cred(false, who),
		Answers: []Answer{{Kind: KindSingleChoice, Question: 0, Choice: choice}},
	}
}

func obs(tx string, h uint64, txIdx, idx int, epoch uint64, r Response) Observed {
	return Observed{TxHash: tx, Pos: Position{Height: h, TxIndex: txIdx, Index: idx}, Epoch: epoch, Response: r}
}

func roleTally(t *testing.T, tally Tally, role Role) RoleTally {
	t.Helper()
	for _, r := range tally.Roles {
		if r.Role == role {
			return r
		}
	}
	t.Fatalf("no tally for role %d", role)
	return RoleTally{}
}

func reasons(tally Tally) map[string]string {
	out := map[string]string{}
	for _, e := range tally.Excluded {
		out[e.TxHash] = e.Reason
	}
	return out
}

func TestAggregateLatestValidResponseWins(t *testing.T) {
	t.Parallel()
	// The CIP-179 duplicate vectors: the older response is at (120100000, 2, 0),
	// the latest at (120100005, 0, 0). Input order must not matter.
	older := obs("older", 120100000, 2, 0, 50, vote(RoleStakeholder, 0x11, 1))
	latest := obs("latest", 120100005, 0, 0, 50, vote(RoleStakeholder, 0x11, 0))

	for name, in := range map[string][]Observed{
		"chain order":   {older, latest},
		"reverse order": {latest, older},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tally := singleDef().Aggregate(in)
			rt := roleTally(t, tally, RoleStakeholder)
			equal(t, uint64(1), rt.Responses)
			equal(t, []OptionTally{{Count: 1}, {}}, rt.Questions[0].Options)
			equal(t, "superseded by a later response", reasons(tally)["older"])
		})
	}
}

func TestAggregateOrdersWithinABlockAndBatch(t *testing.T) {
	t.Parallel()
	first := obs("a", 10, 1, 0, 5, vote(RoleDRep, 1, 0))
	secondInTx := obs("a", 10, 1, 1, 5, vote(RoleDRep, 1, 1))
	laterTx := obs("b", 10, 2, 0, 5, vote(RoleDRep, 1, 0))

	tally := singleDef().Aggregate([]Observed{laterTx, first, secondInTx})
	rt := roleTally(t, tally, RoleDRep)
	equal(t, uint64(1), rt.Responses)
	equal(t, []OptionTally{{Count: 1}, {}}, rt.Questions[0].Options)

	tally = singleDef().Aggregate([]Observed{secondInTx, first})
	equal(t, []OptionTally{{}, {Count: 1}}, roleTally(t, tally, RoleDRep).Questions[0].Options)
}

func TestAggregateInvalidLaterResponseDoesNotReplaceValidOne(t *testing.T) {
	t.Parallel()
	valid := obs("valid", 10, 0, 0, 5, vote(RoleDRep, 1, 0))
	badAnswer := obs("badanswer", 20, 0, 0, 5, vote(RoleDRep, 1, 7))
	late := obs("late", 30, 0, 0, 101, vote(RoleDRep, 1, 1))
	unproven := obs("unproven", 40, 0, 0, 5, vote(RoleDRep, 1, 1))
	unproven.Reject = "credential not proven"

	tally := singleDef().Aggregate([]Observed{valid, badAnswer, late, unproven})
	rt := roleTally(t, tally, RoleDRep)
	equal(t, uint64(1), rt.Responses)
	equal(t, []OptionTally{{Count: 1}, {}}, rt.Questions[0].Options)

	r := reasons(tally)
	equal(t, 3, len(r))
	isTrue(t, r["badanswer"] != "")
	isTrue(t, r["late"] != "")
	equal(t, "credential not proven", r["unproven"])
}

func TestAggregateEpochCutoffIsInclusive(t *testing.T) {
	t.Parallel()
	d := singleDef() // EndEpoch 100
	at := obs("at", 1, 0, 0, 100, vote(RoleDRep, 1, 0))
	after := obs("after", 2, 0, 0, 101, vote(RoleDRep, 2, 0))
	tally := d.Aggregate([]Observed{at, after})
	equal(t, uint64(1), roleTally(t, tally, RoleDRep).Responses)
	isTrue(t, reasons(tally)["after"] != "")
	isTrue(t, reasons(tally)["at"] == "")
}

func TestAggregateKeepsRolesAndCredentialsSeparate(t *testing.T) {
	t.Parallel()
	tally := singleDef().Aggregate([]Observed{
		obs("a", 1, 0, 0, 5, vote(RoleDRep, 1, 0)),
		obs("b", 2, 0, 0, 5, vote(RoleStakeholder, 1, 1)), // same credential, other role
		obs("c", 3, 0, 0, 5, vote(RoleDRep, 2, 1)),        // other credential
	})
	equal(t, uint64(2), roleTally(t, tally, RoleDRep).Responses)
	equal(t, uint64(1), roleTally(t, tally, RoleStakeholder).Responses)
	equal(t, 2, len(tally.Roles)) // one entry per eligible role, no weighted total
	equal(t, 0, len(tally.Excluded))
}

func TestAggregateReportsAbstainsPerRole(t *testing.T) {
	t.Parallel()
	d := singleDef()
	d.Questions = append(d.Questions, Question{Kind: KindSingleChoice, Options: []string{"x", "y"}})
	tally := d.Aggregate([]Observed{obs("a", 1, 0, 0, 5, vote(RoleDRep, 1, 0))})
	q := roleTally(t, tally, RoleDRep).Questions
	equal(t, uint64(1), q[0].Answered)
	equal(t, uint64(0), q[0].Abstained)
	equal(t, uint64(0), q[1].Answered)
	equal(t, uint64(1), q[1].Abstained)
}

func TestAggregateSealedResponses(t *testing.T) {
	t.Parallel()
	d := singleDef()
	d.Mode = SubmissionMode{Sealed: true, Round: 9, PaddingSize: 1}
	sealed := func(who byte) Response {
		return Response{Role: RoleDRep, Credential: cred(false, who), Sealed: []byte{1, 2, 3}}
	}

	// Still sealed: counted as participation, nothing to tally.
	tally := d.Aggregate([]Observed{obs("a", 1, 0, 0, 5, sealed(1))})
	rt := roleTally(t, tally, RoleDRep)
	equal(t, uint64(1), rt.Responses)
	equal(t, uint64(1), rt.Sealed)
	equal(t, uint64(0), rt.Questions[0].Answered)

	// Unsealed: the revealed answers are validated and tallied.
	revealed := obs("b", 2, 0, 0, 5, sealed(2))
	revealed.Unsealed = []Answer{{Kind: KindSingleChoice, Question: 0, Choice: 1}}
	invalid := obs("c", 3, 0, 0, 5, sealed(3))
	invalid.Unsealed = []Answer{{Kind: KindSingleChoice, Question: 0, Choice: 5}}
	tally = d.Aggregate([]Observed{revealed, invalid})
	rt = roleTally(t, tally, RoleDRep)
	equal(t, uint64(1), rt.Responses)
	equal(t, uint64(0), rt.Sealed)
	equal(t, []OptionTally{{}, {Count: 1}}, rt.Questions[0].Options)
	isTrue(t, reasons(tally)["c"] != "")
}
