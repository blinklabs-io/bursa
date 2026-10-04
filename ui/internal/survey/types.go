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

// Package survey implements CIP-179 on-chain surveys and polls: the label-17
// metadata codec, response validation and tallying, and the node-backed
// discovery service. It reaches only the embedded node.
package survey

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// Label is the transaction-metadata label CIP-179 reserves.
const Label uint64 = 17

// SpecVersion is the CIP-179 revision this package reads and writes.
const SpecVersion uint64 = 5

// MaxChunk is Cardano's metadatum text/bytes limit; longer values are chunked.
const MaxChunk = 64

// PayloadKind is the tag of a label-17 payload.
type PayloadKind uint64

const (
	KindDefinitions   PayloadKind = 0
	KindResponses     PayloadKind = 1
	KindCancellations PayloadKind = 2
)

// Payload is the value stored under label 17: exactly one of the three batches
// is populated, matching Kind.
type Payload struct {
	Kind          PayloadKind
	Definitions   []Definition
	Responses     []Response
	Cancellations []Ref
}

// Role is a responder role claim.
type Role uint64

const (
	RoleDRep Role = iota
	RoleSPO
	RoleCC
	RoleStakeholder
	RoleKeyholder
)

// Credential is a key-based or script-based Cardano credential.
type Credential struct {
	Script bool
	Hash   [28]byte
}

// Ref identifies a survey: the transaction carrying its definition and the
// definition's index in that transaction's payload.
type Ref struct {
	TxID  [32]byte
	Index uint64
}

// Anchor is an off-chain document reference: a URI and the blake2b-256 hash of
// the bytes at it.
type Anchor struct {
	URI  string
	Hash [32]byte
}

type anchorJSON struct {
	URI  string `json:"uri"`
	Hash string `json:"hash"`
}

// MarshalJSON renders the hash as hex.
func (a Anchor) MarshalJSON() ([]byte, error) {
	return json.Marshal(anchorJSON{URI: a.URI, Hash: hex.EncodeToString(a.Hash[:])})
}

// UnmarshalJSON reads the hash from hex.
func (a *Anchor) UnmarshalJSON(b []byte) error {
	var v anchorJSON
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	h, err := hex.DecodeString(v.Hash)
	if err != nil || len(h) != len(a.Hash) {
		return fmt.Errorf("%w: anchor hash must be 32 bytes of hex", ErrInvalid)
	}
	a.URI = v.URI
	copy(a.Hash[:], h)
	return nil
}

// SubmissionMode is public, or sealed under a Drand timelock.
type SubmissionMode struct {
	Sealed      bool     `json:"sealed"`
	ChainHash   [32]byte `json:"-"`
	Round       uint64   `json:"round,omitempty"`
	PaddingSize uint64   `json:"padding_size,omitempty"`
}

// QuestionKind is the question type tag; it is also the answer type tag.
type QuestionKind uint64

const (
	KindCustom QuestionKind = iota
	KindSingleChoice
	KindMultiSelect
	KindRanking
	KindNumericRange
	KindPointsAllocation
	KindRating
)

// Range is a numeric grid: Min..Max, optionally stepped.
type Range struct {
	Min  int64  `json:"min"`
	Max  int64  `json:"max"`
	Step uint64 `json:"step,omitempty"` // 0 = unstepped
}

// RatingScale is a numeric grid, ordered worst-to-best labels, or (external
// content mode) a bare level count. Exactly one is set.
type RatingScale struct {
	Grid   *Range   `json:"grid,omitempty"`
	Labels []string `json:"labels,omitempty"`
	Levels uint64   `json:"levels,omitempty"`
}

// Question is one survey question. Fields beyond Kind and Prompt apply per
// kind: Options/OptionCount (all but custom and numeric), Min/Max
// (multi-select selections, ranking length), Budget (points), Range
// (numeric), Scale and RequireAll (rating), Anchor (custom).
type Question struct {
	Kind        QuestionKind `json:"kind"`
	Prompt      string       `json:"prompt"`
	Options     []string     `json:"options,omitempty"`      // inline labels; empty in external-content mode
	OptionCount uint64       `json:"option_count,omitempty"` // option count when Options is empty
	Min         uint64       `json:"min,omitempty"`
	Max         uint64       `json:"max,omitempty"`
	Budget      uint64       `json:"budget,omitempty"`
	Range       *Range       `json:"range,omitempty"`
	Scale       *RatingScale `json:"scale,omitempty"`
	RequireAll  bool         `json:"require_all,omitempty"`
	Anchor      *Anchor      `json:"anchor,omitempty"`
	Required    bool         `json:"required,omitempty"`
}

// NumOptions is the number of options, inline or counted.
func (q Question) NumOptions() uint64 {
	if len(q.Options) > 0 {
		return uint64(len(q.Options))
	}
	return q.OptionCount
}

// Definition is a survey_definition.
type Definition struct {
	Owner       Credential     `json:"-"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Roles       []Role         `json:"roles"`
	EndEpoch    uint64         `json:"end_epoch"`
	Mode        SubmissionMode `json:"mode"`
	Questions   []Question     `json:"questions"`
	Anchor      *Anchor        `json:"anchor,omitempty"` // set in external-content mode
}

// Pair is an (option index, value) entry of a points or rating answer.
type Pair struct {
	Option uint64 `json:"option"`
	Value  int64  `json:"value"`
}

// Answer is one answer item. Kind matches the question's kind; Question is the
// question index. Which value field is set depends on Kind: Choice
// (single-choice), Indices (multi-select, ranking), Number (numeric), Pairs
// (points, rating), Custom (custom).
type Answer struct {
	Kind     QuestionKind                 `json:"kind"`
	Question uint64                       `json:"question"`
	Choice   uint64                       `json:"choice,omitempty"`
	Indices  []uint64                     `json:"indices,omitempty"`
	Number   int64                        `json:"number,omitempty"`
	Pairs    []Pair                       `json:"pairs,omitempty"`
	Custom   lcommon.TransactionMetadatum `json:"-"`
}

// Response is a survey_response. A sealed survey's response carries Sealed (the
// raw timelock ciphertext) instead of Answers.
type Response struct {
	Survey     Ref
	Role       Role
	Credential Credential
	Answers    []Answer
	Sealed     []byte
	Rationale  *Anchor
}
