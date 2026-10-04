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
	"encoding/hex"
	"slices"
)

// Position is a response's place in chain order: block, transaction within the
// block, and index within the transaction's payload.
type Position struct {
	Height  uint64
	TxIndex int
	Index   int
}

func (p Position) before(o Position) bool {
	if p.Height != o.Height {
		return p.Height < o.Height
	}
	if p.TxIndex != o.TxIndex {
		return p.TxIndex < o.TxIndex
	}
	return p.Index < o.Index
}

// Observed is a response with its chain placement and the outcome of the
// checks that need the chain. A non-empty Reject excludes the response with
// that reason (credential proof or role validation failed). Unsealed carries
// the revealed answers of a sealed response once its round has published.
type Observed struct {
	TxHash   string
	Pos      Position
	Epoch    uint64
	Response Response
	Unsealed []Answer
	Reject   string
}

// Exclusion records a response left out of a tally and why.
type Exclusion struct {
	TxHash     string `json:"tx_hash"`
	Role       Role   `json:"role"`
	Credential string `json:"credential"`
	Reason     string `json:"reason"`
}

// RoleTally is one eligible role's participation. Sealed counts counted
// responses whose answers are still sealed; they have no question tally yet.
type RoleTally struct {
	Role      Role            `json:"role"`
	Responses uint64          `json:"responses"`
	Sealed    uint64          `json:"sealed,omitempty"`
	Questions []QuestionTally `json:"questions"`
}

// Tally is a survey's per-role results plus the responses left out. CIP-179
// defines no weighted or merged total, so none is produced.
type Tally struct {
	Roles    []RoleTally `json:"roles"`
	Excluded []Exclusion `json:"excluded"`
}

type identity struct {
	role Role
	cred Credential
}

// Aggregate applies the CIP-179 response rules to every response observed for
// the definition: reject those with a failed proof, past the end epoch, or with
// invalid answers; keep only the latest valid response per (role, credential);
// then tally what is left per role. A rejected response never displaces an
// earlier valid one.
func (d Definition) Aggregate(observed []Observed) Tally {
	tally := Tally{Excluded: []Exclusion{}}
	exclude := func(o Observed, reason string) {
		tally.Excluded = append(tally.Excluded, Exclusion{
			TxHash:     o.TxHash,
			Role:       o.Response.Role,
			Credential: hex.EncodeToString(o.Response.Credential.Hash[:]),
			Reason:     reason,
		})
	}

	valid := make([]Observed, 0, len(observed))
	for _, o := range observed {
		if reason := d.rejection(o); reason != "" {
			exclude(o, reason)
			continue
		}
		valid = append(valid, o)
	}
	slices.SortStableFunc(valid, func(a, b Observed) int {
		switch {
		case a.Pos.before(b.Pos):
			return -1
		case b.Pos.before(a.Pos):
			return 1
		}
		return 0
	})
	latest := make(map[identity]Observed, len(valid))
	for _, o := range valid {
		id := identity{o.Response.Role, o.Response.Credential}
		if prev, ok := latest[id]; ok {
			exclude(prev, "superseded by a later response")
		}
		latest[id] = o
	}

	for _, role := range d.Roles {
		rt := RoleTally{Role: role}
		var sets [][]Answer
		for _, o := range valid {
			id := identity{o.Response.Role, o.Response.Credential}
			if o.Response.Role != role || latest[id].TxHash != o.TxHash || latest[id].Pos != o.Pos {
				continue
			}
			rt.Responses++
			switch answers := o.answers(); {
			case answers != nil:
				sets = append(sets, answers)
			case d.Mode.Sealed:
				rt.Sealed++
			}
		}
		rt.Questions = d.tallyAnswers(sets)
		tally.Roles = append(tally.Roles, rt)
	}
	return tally
}

// answers is the plaintext answer set of an observed response, nil while a
// sealed response is still sealed.
func (o Observed) answers() []Answer {
	if o.Unsealed != nil {
		return o.Unsealed
	}
	return o.Response.Answers
}

func (d Definition) rejection(o Observed) string {
	if o.Reject != "" {
		return o.Reject
	}
	if o.Epoch > d.EndEpoch {
		return "submitted after the survey's end epoch"
	}
	if err := d.CheckResponse(o.Response); err != nil {
		return err.Error()
	}
	if o.Unsealed != nil {
		if err := d.CheckAnswers(o.Unsealed); err != nil {
			return err.Error()
		}
	}
	return ""
}
