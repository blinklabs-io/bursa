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
	"math"
	"slices"
)

// CheckResponse validates a response against the definition it answers: the
// claimed role is eligible, the answer form matches the submission mode, and
// (for a public survey) every answer satisfies its question. A sealed response
// is checked for shape only; its answers are validated once unsealed.
func (d Definition) CheckResponse(r Response) error {
	if !slices.Contains(d.Roles, r.Role) {
		return invalidf("role %d is not eligible", r.Role)
	}
	if d.Mode.Sealed {
		if len(r.Sealed) == 0 || len(r.Answers) > 0 {
			return invalidf("sealed survey needs a ciphertext response")
		}
		return nil
	}
	if len(r.Sealed) > 0 || len(r.Answers) == 0 {
		return invalidf("public survey needs plaintext answers")
	}
	return d.CheckAnswers(r.Answers)
}

// CheckAnswers validates answer items against the questions: unique in-range
// question indices, matching kinds, per-kind constraints, and every required
// question answered. An unanswered question is an abstain.
func (d Definition) CheckAnswers(answers []Answer) error {
	answered := make(map[uint64]bool, len(answers))
	for _, a := range answers {
		if a.Question >= uint64(len(d.Questions)) {
			return invalidf("answer for question %d, survey has %d", a.Question, len(d.Questions))
		}
		if answered[a.Question] {
			return invalidf("question %d answered twice", a.Question)
		}
		answered[a.Question] = true
		q := d.Questions[a.Question]
		if a.Kind != q.Kind {
			return invalidf("question %d: answer kind %d for a kind %d question", a.Question, a.Kind, q.Kind)
		}
		if err := q.checkAnswer(a); err != nil {
			return invalidf("question %d: %v", a.Question, err)
		}
	}
	for i, q := range d.Questions {
		if q.Required && !answered[uint64(i)] {
			return invalidf("required question %d not answered", i)
		}
	}
	return nil
}

func (q Question) checkAnswer(a Answer) error {
	n := q.NumOptions()
	switch q.Kind {
	case KindSingleChoice:
		if a.Choice >= n {
			return invalidf("option %d out of range", a.Choice)
		}
	case KindMultiSelect, KindRanking:
		if uint64(len(a.Indices)) < q.Min || uint64(len(a.Indices)) > q.Max {
			return invalidf("%d selections outside %d..%d", len(a.Indices), q.Min, q.Max)
		}
		return checkDistinctOptions(a.Indices, n)
	case KindNumericRange:
		return q.Range.check(a.Number)
	case KindPointsAllocation:
		var sum uint64
		opts := make([]uint64, len(a.Pairs))
		for i, p := range a.Pairs {
			if p.Value < 0 {
				return invalidf("negative points")
			}
			// Checked as the sum grows so a crafted set cannot wrap to the budget.
			v := uint64(p.Value)
			if v > q.Budget-sum {
				return invalidf("points exceed the budget of %d", q.Budget)
			}
			sum += v
			opts[i] = p.Option
		}
		if err := checkDistinctOptions(opts, n); err != nil {
			return err
		}
		if sum != q.Budget {
			return invalidf("points sum to %d, budget is %d", sum, q.Budget)
		}
	case KindRating:
		opts := make([]uint64, len(a.Pairs))
		for i, p := range a.Pairs {
			opts[i] = p.Option
			if err := q.Scale.check(p.Value); err != nil {
				return err
			}
		}
		if err := checkDistinctOptions(opts, n); err != nil {
			return err
		}
		if q.RequireAll && uint64(len(opts)) != n {
			return invalidf("every option must be rated")
		}
	case KindCustom:
		// Interpreted by the schema at the question's anchor, which is off-chain.
	}
	return nil
}

// checkDistinctOptions requires at least one index, all unique and below n.
func checkDistinctOptions(indices []uint64, n uint64) error {
	seen := make(map[uint64]bool, len(indices))
	for _, i := range indices {
		if i >= n {
			return invalidf("option %d out of range", i)
		}
		if seen[i] {
			return invalidf("option %d repeated", i)
		}
		seen[i] = true
	}
	return nil
}

func (r Range) check(v int64) error {
	if v < r.Min || v > r.Max {
		return invalidf("value %d outside %d..%d", v, r.Min, r.Max)
	}
	// Both operands are within int64 and v >= Min, so the difference fits uint64.
	if r.Step > 0 && uint64(v-r.Min)%r.Step != 0 { //nolint:gosec // v >= r.Min
		return invalidf("value %d is not on the step grid", v)
	}
	return nil
}

func (s *RatingScale) check(v int64) error {
	switch {
	case s.Grid != nil:
		return s.Grid.check(v)
	case len(s.Labels) > 0:
		if v < 0 || v >= int64(len(s.Labels)) {
			return invalidf("rating %d outside the label scale", v)
		}
	default:
		if v < 0 || uint64(v) >= s.Levels {
			return invalidf("rating %d outside %d levels", v, s.Levels)
		}
	}
	return nil
}

// OptionTally counts what respondents did with one option. Count is how many
// responses selected, ranked, allocated to or rated it; First counts ranking
// first places; Sum totals allocated points or ratings.
type OptionTally struct {
	Count uint64 `json:"count"`
	First uint64 `json:"first,omitempty"`
	Sum   int64  `json:"sum,omitempty"`
}

// NumericTally summarises a numeric-range question's answers.
type NumericTally struct {
	Sum int64 `json:"sum"`
	Min int64 `json:"min"`
	Max int64 `json:"max"`
}

// QuestionTally is one question's result among a set of responses. Abstained
// responses omitted the question; custom questions only report counts.
type QuestionTally struct {
	Answered  uint64        `json:"answered"`
	Abstained uint64        `json:"abstained"`
	Options   []OptionTally `json:"options,omitempty"`
	Numeric   *NumericTally `json:"numeric,omitempty"`
}

// tallyAnswers folds validated answer sets into per-question tallies. CIP-179
// leaves weighting out of scope, so every response counts once.
func (d Definition) tallyAnswers(sets [][]Answer) []QuestionTally {
	out := make([]QuestionTally, len(d.Questions))
	for i, q := range d.Questions {
		if q.Kind != KindCustom && q.Kind != KindNumericRange {
			out[i].Options = make([]OptionTally, q.NumOptions())
		}
	}
	for _, set := range sets {
		byQuestion := make(map[uint64]Answer, len(set))
		for _, a := range set {
			byQuestion[a.Question] = a
		}
		for i := range d.Questions {
			a, ok := byQuestion[uint64(i)]
			if !ok {
				out[i].Abstained++
				continue
			}
			out[i].Answered++
			out[i].add(a)
		}
	}
	return out
}

func (t *QuestionTally) add(a Answer) {
	switch a.Kind {
	case KindSingleChoice:
		t.Options[a.Choice].Count++
	case KindMultiSelect:
		for _, i := range a.Indices {
			t.Options[i].Count++
		}
	case KindRanking:
		for _, i := range a.Indices {
			t.Options[i].Count++
		}
		t.Options[a.Indices[0]].First++
	case KindNumericRange:
		if t.Numeric == nil {
			t.Numeric = &NumericTally{Min: math.MaxInt64, Max: math.MinInt64}
		}
		t.Numeric.Sum += a.Number
		t.Numeric.Min = min(t.Numeric.Min, a.Number)
		t.Numeric.Max = max(t.Numeric.Max, a.Number)
	case KindPointsAllocation:
		for _, p := range a.Pairs {
			if p.Value > 0 {
				t.Options[p.Option].Count++
			}
			t.Options[p.Option].Sum += p.Value
		}
	case KindRating:
		for _, p := range a.Pairs {
			t.Options[p.Option].Count++
			t.Options[p.Option].Sum += p.Value
		}
	case KindCustom:
		// Only counted as answered, which the caller has already done.
	}
}
