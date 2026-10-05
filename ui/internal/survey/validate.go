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
	"fmt"
)

// ErrInvalid wraps every structural or semantic rejection of a survey,
// response or payload.
var ErrInvalid = errors.New("survey: invalid")

// MaxOptions bounds a question's option count and a rating's level count. In
// external-content mode either is a bare integer on chain, while the tally and
// the respond form hold one entry per option, so an unbounded count lets any
// definition make the wallet allocate without limit. A definition over the
// bound is treated as invalid.
const MaxOptions = 1024

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Validate checks a definition against the CIP-179 structural rules.
func (d Definition) Validate() error {
	if len(d.Roles) == 0 {
		return invalidf("no eligible roles")
	}
	for _, r := range d.Roles {
		if r > RoleKeyholder {
			return invalidf("role %d out of range", r)
		}
	}
	if len(d.Questions) == 0 {
		return invalidf("no questions")
	}
	if d.Mode.Sealed && (d.Mode.Round == 0 || d.Mode.PaddingSize == 0) {
		return invalidf("sealed mode needs a positive round and padding size")
	}
	for i, q := range d.Questions {
		if err := q.Validate(); err != nil {
			return fmt.Errorf("question %d: %w", i, err)
		}
	}
	return nil
}

// Validate checks a question's per-kind constraints.
func (q Question) Validate() error {
	if q.Kind > KindRating {
		return invalidf("unknown question kind %d", q.Kind)
	}
	if q.Kind == KindCustom {
		if q.Anchor == nil {
			return invalidf("custom question needs an anchor")
		}
		return nil
	}
	if q.Kind == KindNumericRange {
		if q.Range == nil {
			return invalidf("numeric range missing")
		}
		return q.Range.validate()
	}

	if err := q.validateOptions(); err != nil {
		return err
	}
	n := q.NumOptions()
	switch q.Kind {
	case KindMultiSelect:
		if q.Max < 1 || q.Min > q.Max || q.Max > n {
			return invalidf("multi-select needs 0 <= min <= max <= %d and max >= 1", n)
		}
	case KindRanking:
		if q.Min < 1 || q.Min > q.Max || q.Max > n {
			return invalidf("ranking needs 1 <= min <= max <= %d", n)
		}
	case KindPointsAllocation:
		if q.Budget < 1 {
			return invalidf("points budget must be positive")
		}
	case KindRating:
		return q.Scale.validate()
	case KindCustom, KindSingleChoice, KindNumericRange:
		// Fully checked above.
	}
	return nil
}

func (q Question) validateOptions() error {
	if len(q.Options) > 0 && q.OptionCount != 0 {
		return invalidf("options and option count are mutually exclusive")
	}
	if n := q.NumOptions(); n < 2 || n > MaxOptions {
		return invalidf("need 2 to %d options, have %d", MaxOptions, n)
	}
	for _, o := range q.Options {
		if len(o) > MaxChunk {
			return invalidf("option %q exceeds %d bytes", o, MaxChunk)
		}
	}
	return nil
}

func (r Range) validate() error {
	if r.Min > r.Max {
		return invalidf("range min %d above max %d", r.Min, r.Max)
	}
	return nil
}

func (s *RatingScale) validate() error {
	if s == nil {
		return invalidf("rating scale missing")
	}
	set := 0
	if s.Grid != nil {
		set++
	}
	if len(s.Labels) > 0 {
		set++
	}
	if s.Levels != 0 {
		set++
	}
	if set != 1 {
		return invalidf("rating scale must be exactly one of grid, labels or levels")
	}
	switch {
	case s.Grid != nil:
		return s.Grid.validate()
	case len(s.Labels) > 0:
		if len(s.Labels) < 2 || len(s.Labels) > MaxOptions {
			return invalidf("rating needs 2 to %d labels", MaxOptions)
		}
		for _, l := range s.Labels {
			if len(l) > MaxChunk {
				return invalidf("rating label %q exceeds %d bytes", l, MaxChunk)
			}
		}
	case s.Levels < 2 || s.Levels > MaxOptions:
		return invalidf("rating needs 2 to %d levels", MaxOptions)
	}
	return nil
}
