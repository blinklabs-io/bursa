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
	"errors"
	"testing"
)

// fixtureDef has one question of every kind, in tag order, so a question index
// equals its kind.
func fixtureDef() Definition {
	return Definition{
		Owner:    cred(false, 1),
		Roles:    []Role{RoleDRep, RoleStakeholder},
		EndEpoch: 100,
		Questions: []Question{
			{Kind: KindCustom, Anchor: &Anchor{URI: "ipfs://x"}},
			{Kind: KindSingleChoice, Options: []string{"a", "b", "c"}},
			{Kind: KindMultiSelect, Options: []string{"a", "b", "c"}, Min: 0, Max: 2},
			{Kind: KindRanking, Options: []string{"a", "b", "c"}, Min: 1, Max: 2},
			{Kind: KindNumericRange, Range: &Range{Min: 10, Max: 1000, Step: 5}},
			{Kind: KindPointsAllocation, Options: []string{"a", "b", "c"}, Budget: 100},
			{Kind: KindRating, Options: []string{"a", "b", "c"}, Scale: &RatingScale{Grid: &Range{Min: 1, Max: 5}}},
		},
	}
}

func TestCheckAnswers(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		mutate  func(*Definition)
		answers []Answer
		ok      bool
	}{
		"abstain on everything but one": {nil, []Answer{{Kind: KindSingleChoice, Question: 1, Choice: 2}}, true},
		"single choice out of range":    {nil, []Answer{{Kind: KindSingleChoice, Question: 1, Choice: 3}}, false},
		"kind does not match question":  {nil, []Answer{{Kind: KindMultiSelect, Question: 1, Indices: []uint64{0}}}, false},
		"question index out of range":   {nil, []Answer{{Kind: KindSingleChoice, Question: 9}}, false},
		"question answered twice": {nil, []Answer{
			{Kind: KindSingleChoice, Question: 1, Choice: 0},
			{Kind: KindSingleChoice, Question: 1, Choice: 1},
		}, false},
		"multi none selected (min 0)":  {nil, []Answer{{Kind: KindMultiSelect, Question: 2, Indices: []uint64{}}}, true},
		"multi above max":              {nil, []Answer{{Kind: KindMultiSelect, Question: 2, Indices: []uint64{0, 1, 2}}}, false},
		"multi duplicate":              {nil, []Answer{{Kind: KindMultiSelect, Question: 2, Indices: []uint64{1, 1}}}, false},
		"multi option out of range":    {nil, []Answer{{Kind: KindMultiSelect, Question: 2, Indices: []uint64{3}}}, false},
		"ranking empty (min 1)":        {nil, []Answer{{Kind: KindRanking, Question: 3, Indices: []uint64{}}}, false},
		"ranking in order":             {nil, []Answer{{Kind: KindRanking, Question: 3, Indices: []uint64{2, 0}}}, true},
		"ranking above max":            {nil, []Answer{{Kind: KindRanking, Question: 3, Indices: []uint64{2, 0, 1}}}, false},
		"numeric on the grid":          {nil, []Answer{{Kind: KindNumericRange, Question: 4, Number: 325}}, true},
		"numeric at min":               {nil, []Answer{{Kind: KindNumericRange, Question: 4, Number: 10}}, true},
		"numeric at max":               {nil, []Answer{{Kind: KindNumericRange, Question: 4, Number: 1000}}, true},
		"numeric below min":            {nil, []Answer{{Kind: KindNumericRange, Question: 4, Number: 5}}, false},
		"numeric above max":            {nil, []Answer{{Kind: KindNumericRange, Question: 4, Number: 1005}}, false},
		"numeric off the step grid":    {nil, []Answer{{Kind: KindNumericRange, Question: 4, Number: 326}}, false},
		"points sum to budget":         {nil, []Answer{{Kind: KindPointsAllocation, Question: 5, Pairs: []Pair{{0, 60}, {2, 40}}}}, true},
		"points over budget":           {nil, []Answer{{Kind: KindPointsAllocation, Question: 5, Pairs: []Pair{{0, 60}, {2, 41}}}}, false},
		"points under budget":          {nil, []Answer{{Kind: KindPointsAllocation, Question: 5, Pairs: []Pair{{0, 60}}}}, false},
		"points duplicate option":      {nil, []Answer{{Kind: KindPointsAllocation, Question: 5, Pairs: []Pair{{0, 50}, {0, 50}}}}, false},
		"points negative":              {nil, []Answer{{Kind: KindPointsAllocation, Question: 5, Pairs: []Pair{{0, 50}, {1, -50}}}}, false},
		"rating subset on the grid":    {nil, []Answer{{Kind: KindRating, Question: 6, Pairs: []Pair{{0, 1}, {2, 5}}}}, true},
		"rating off the grid":          {nil, []Answer{{Kind: KindRating, Question: 6, Pairs: []Pair{{0, 6}}}}, false},
		"rating duplicate option":      {nil, []Answer{{Kind: KindRating, Question: 6, Pairs: []Pair{{0, 1}, {0, 2}}}}, false},
		"rating option out of range":   {nil, []Answer{{Kind: KindRating, Question: 6, Pairs: []Pair{{3, 1}}}}, false},
		"rating with nothing rated":    {nil, []Answer{{Kind: KindRating, Question: 6, Pairs: []Pair{}}}, false},
		"custom accepts anything":      {nil, []Answer{{Kind: KindCustom, Question: 0, Custom: mText("x")}}, true},
		"required question omitted":    {func(d *Definition) { d.Questions[1].Required = true }, []Answer{{Kind: KindNumericRange, Question: 4, Number: 10}}, false},
		"required question answered":   {func(d *Definition) { d.Questions[1].Required = true }, []Answer{{Kind: KindSingleChoice, Question: 1, Choice: 0}}, true},
		"rating require_all subset":    {func(d *Definition) { d.Questions[6].RequireAll = true }, []Answer{{Kind: KindRating, Question: 6, Pairs: []Pair{{0, 1}}}}, false},
		"rating require_all full":      {func(d *Definition) { d.Questions[6].RequireAll = true }, []Answer{{Kind: KindRating, Question: 6, Pairs: []Pair{{0, 1}, {1, 2}, {2, 3}}}}, true},
		"rating labels in range":       {func(d *Definition) { d.Questions[6].Scale = &RatingScale{Labels: []string{"bad", "ok"}} }, []Answer{{Kind: KindRating, Question: 6, Pairs: []Pair{{0, 1}}}}, true},
		"rating labels out of range":   {func(d *Definition) { d.Questions[6].Scale = &RatingScale{Labels: []string{"bad", "ok"}} }, []Answer{{Kind: KindRating, Question: 6, Pairs: []Pair{{0, 2}}}}, false},
		"rating levels out of range":   {func(d *Definition) { d.Questions[6].Scale = &RatingScale{Levels: 3} }, []Answer{{Kind: KindRating, Question: 6, Pairs: []Pair{{0, 3}}}}, false},
		"counted options out of range": {func(d *Definition) { d.Questions[1] = Question{Kind: KindSingleChoice, OptionCount: 2} }, []Answer{{Kind: KindSingleChoice, Question: 1, Choice: 2}}, false},
		"counted options in range":     {func(d *Definition) { d.Questions[1] = Question{Kind: KindSingleChoice, OptionCount: 2} }, []Answer{{Kind: KindSingleChoice, Question: 1, Choice: 1}}, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := fixtureDef()
			if tc.mutate != nil {
				tc.mutate(&d)
			}
			err := d.CheckAnswers(tc.answers)
			if tc.ok && err != nil {
				t.Fatalf("want valid, got %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestCheckResponse(t *testing.T) {
	t.Parallel()
	one := []Answer{{Kind: KindSingleChoice, Question: 1, Choice: 0}}
	sealed := fixtureDef()
	sealed.Mode = SubmissionMode{Sealed: true, Round: 5, PaddingSize: 1}

	for name, tc := range map[string]struct {
		def  Definition
		resp Response
		ok   bool
	}{
		"eligible role":        {fixtureDef(), Response{Role: RoleStakeholder, Answers: one}, true},
		"ineligible role":      {fixtureDef(), Response{Role: RoleSPO, Answers: one}, false},
		"public needs answers": {fixtureDef(), Response{Role: RoleDRep}, false},
		"public rejects ciphertext": {
			fixtureDef(),
			Response{Role: RoleDRep, Sealed: []byte{1}},
			false,
		},
		"sealed accepts ciphertext":    {sealed, Response{Role: RoleDRep, Sealed: []byte{1}}, true},
		"sealed rejects plaintext":     {sealed, Response{Role: RoleDRep, Answers: one}, false},
		"public checks answer content": {fixtureDef(), Response{Role: RoleDRep, Answers: []Answer{{Kind: KindSingleChoice, Question: 1, Choice: 9}}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := tc.def.CheckResponse(tc.resp)
			if tc.ok && err != nil {
				t.Fatalf("want valid, got %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestTallyAnswers(t *testing.T) {
	t.Parallel()
	d := fixtureDef()
	sets := [][]Answer{
		{
			{Kind: KindSingleChoice, Question: 1, Choice: 0},
			{Kind: KindMultiSelect, Question: 2, Indices: []uint64{0, 2}},
			{Kind: KindRanking, Question: 3, Indices: []uint64{2, 0}},
			{Kind: KindNumericRange, Question: 4, Number: 100},
			{Kind: KindPointsAllocation, Question: 5, Pairs: []Pair{{0, 70}, {1, 30}}},
			{Kind: KindRating, Question: 6, Pairs: []Pair{{0, 5}, {1, 2}}},
		},
		{
			{Kind: KindSingleChoice, Question: 1, Choice: 0},
			{Kind: KindMultiSelect, Question: 2, Indices: []uint64{}},
			{Kind: KindRanking, Question: 3, Indices: []uint64{0}},
			{Kind: KindNumericRange, Question: 4, Number: 40},
			{Kind: KindPointsAllocation, Question: 5, Pairs: []Pair{{0, 0}, {2, 100}}},
			{Kind: KindCustom, Question: 0, Custom: mText("x")},
		},
	}
	got := d.tallyAnswers(sets)

	equal(t, QuestionTally{Answered: 1, Abstained: 1}, got[0])
	equal(t, QuestionTally{Answered: 2, Options: []OptionTally{{Count: 2}, {}, {}}}, got[1])
	equal(t, QuestionTally{Answered: 2, Options: []OptionTally{{Count: 1}, {}, {Count: 1}}}, got[2])
	equal(t, QuestionTally{Answered: 2, Options: []OptionTally{{Count: 2, First: 1}, {}, {Count: 1, First: 1}}}, got[3])
	equal(t, QuestionTally{Answered: 2, Numeric: &NumericTally{Sum: 140, Min: 40, Max: 100}}, got[4])
	equal(t, QuestionTally{Answered: 2, Options: []OptionTally{{Count: 1, Sum: 70}, {Count: 1, Sum: 30}, {Count: 1, Sum: 100}}}, got[5])
	equal(t, QuestionTally{Answered: 1, Abstained: 1, Options: []OptionTally{{Count: 1, Sum: 5}, {Count: 1, Sum: 2}, {}}}, got[6])
}

// Four allocations of 2^62 sum to 2^64, which wraps to 0 in a uint64; adding a
// final 100 would then "total" the budget of 100 if the sum were not checked as
// it grows.
func TestCheckAnswersPointsCannotWrapToTheBudget(t *testing.T) {
	t.Parallel()
	d := Definition{
		Roles: []Role{RoleDRep}, EndEpoch: 1,
		Questions: []Question{{Kind: KindPointsAllocation, Options: []string{"a", "b", "c", "d", "e"}, Budget: 100}},
	}
	huge := int64(1) << 62
	err := d.CheckAnswers([]Answer{{Kind: KindPointsAllocation, Question: 0, Pairs: []Pair{
		{0, huge}, {1, huge}, {2, huge}, {3, huge}, {4, 100},
	}}})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}
