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
	"strings"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// Decode parses the CBOR value stored under label 17. Unknown integer map keys
// are ignored, as CIP-179 asks of decoders; anything else malformed is
// rejected with an ErrInvalid.
func Decode(b []byte) (Payload, error) {
	md, err := lcommon.DecodeMetadatumRaw(b)
	if err != nil {
		return Payload{}, invalidf("metadata cbor: %v", err)
	}
	top, err := asList(md, 2, 2)
	if err != nil {
		return Payload{}, err
	}
	tag, err := asUint(top[0])
	if err != nil {
		return Payload{}, err
	}
	batch, err := asList(top[1], 1, -1)
	if err != nil {
		return Payload{}, err
	}
	p := Payload{Kind: PayloadKind(tag)}
	switch p.Kind {
	case KindDefinitions:
		for _, item := range batch {
			d, err := decodeDefinition(item)
			if err != nil {
				return Payload{}, err
			}
			p.Definitions = append(p.Definitions, d)
		}
	case KindResponses:
		for _, item := range batch {
			r, err := decodeResponse(item)
			if err != nil {
				return Payload{}, err
			}
			p.Responses = append(p.Responses, r)
		}
	case KindCancellations:
		for _, item := range batch {
			r, err := decodeRef(item)
			if err != nil {
				return Payload{}, err
			}
			p.Cancellations = append(p.Cancellations, r)
		}
	default:
		return Payload{}, invalidf("unknown payload tag %d", tag)
	}
	return p, nil
}

// typeName names a metadatum's kind for error messages; a map lookup that found
// nothing yields a nil metadatum.
func typeName(md metadatum) string {
	if md == nil {
		return "nothing"
	}
	return md.TypeName()
}

// asList returns a list's items; max < 0 leaves the length unbounded.
func asList(md metadatum, lo, hi int) ([]metadatum, error) {
	l, ok := md.(metaList)
	if !ok {
		return nil, invalidf("expected list, got %s", typeName(md))
	}
	if len(l.Items) < lo || (hi >= 0 && len(l.Items) > hi) {
		return nil, invalidf("list of %d items out of range", len(l.Items))
	}
	return l.Items, nil
}

func asUint(md metadatum) (uint64, error) {
	i, ok := md.(lcommon.MetaInt)
	if !ok || i.Value == nil || !i.Value.IsUint64() {
		return 0, invalidf("expected unsigned integer, got %s", typeName(md))
	}
	return i.Value.Uint64(), nil
}

func asInt(md metadatum) (int64, error) {
	i, ok := md.(lcommon.MetaInt)
	if !ok || i.Value == nil || !i.Value.IsInt64() {
		return 0, invalidf("expected integer, got %s", typeName(md))
	}
	return i.Value.Int64(), nil
}

func asBytes(md metadatum, size int) ([]byte, error) {
	b, ok := md.(lcommon.MetaBytes)
	if !ok || (size >= 0 && len(b.Value) != size) {
		return nil, invalidf("expected %d-byte string", size)
	}
	return b.Value, nil
}

func asText(md metadatum) (string, error) {
	t, ok := md.(lcommon.MetaText)
	if !ok {
		return "", invalidf("expected text, got %s", typeName(md))
	}
	return t.Value, nil
}

// asChunkedText accepts a single text or an array of text chunks.
func asChunkedText(md metadatum) (string, error) {
	if l, ok := md.(metaList); ok {
		var sb strings.Builder
		if len(l.Items) == 0 {
			return "", invalidf("empty chunked text")
		}
		for _, item := range l.Items {
			s, err := asText(item)
			if err != nil {
				return "", err
			}
			sb.WriteString(s)
		}
		return sb.String(), nil
	}
	return asText(md)
}

func asChunkedBytes(md metadatum) ([]byte, error) {
	if l, ok := md.(metaList); ok {
		var out []byte
		for _, item := range l.Items {
			b, err := asBytes(item, -1)
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		}
		return out, nil
	}
	return asBytes(md, -1)
}

// asKeyed reads an integer-keyed map, rejecting duplicate and non-integer keys.
func asKeyed(md metadatum) (map[uint64]metadatum, error) {
	m, ok := md.(metaMap)
	if !ok {
		return nil, invalidf("expected map, got %s", typeName(md))
	}
	out := make(map[uint64]metadatum, len(m.Pairs))
	for _, pair := range m.Pairs {
		k, err := asUint(pair.Key)
		if err != nil {
			return nil, err
		}
		if _, dup := out[k]; dup {
			return nil, invalidf("duplicate map key %d", k)
		}
		out[k] = pair.Value
	}
	return out, nil
}

// required fetches the mandatory keys 0..n-1 and checks the spec version.
func requiredKeys(m map[uint64]metadatum, n uint64) error {
	for k := range n {
		if _, ok := m[k]; !ok {
			return invalidf("missing map key %d", k)
		}
	}
	v, err := asUint(m[0])
	if err != nil {
		return err
	}
	if v != SpecVersion {
		return invalidf("unsupported spec version %d", v)
	}
	return nil
}

func decodeCredential(md metadatum) (Credential, error) {
	items, err := asList(md, 2, 2)
	if err != nil {
		return Credential{}, err
	}
	kind, err := asUint(items[0])
	if err != nil || kind > 1 {
		return Credential{}, invalidf("credential kind")
	}
	h, err := asBytes(items[1], 28)
	if err != nil {
		return Credential{}, err
	}
	c := Credential{Script: kind == 1}
	copy(c.Hash[:], h)
	return c, nil
}

func decodeRef(md metadatum) (Ref, error) {
	items, err := asList(md, 2, 2)
	if err != nil {
		return Ref{}, err
	}
	id, err := asBytes(items[0], 32)
	if err != nil {
		return Ref{}, err
	}
	idx, err := asUint(items[1])
	if err != nil {
		return Ref{}, err
	}
	r := Ref{Index: idx}
	copy(r.TxID[:], id)
	return r, nil
}

func decodeAnchor(md metadatum) (*Anchor, error) {
	items, err := asList(md, 2, 2)
	if err != nil {
		return nil, err
	}
	uri, err := asChunkedText(items[0])
	if err != nil {
		return nil, err
	}
	h, err := asBytes(items[1], 32)
	if err != nil {
		return nil, err
	}
	a := &Anchor{URI: uri}
	copy(a.Hash[:], h)
	return a, nil
}

func decodeDefinition(md metadatum) (Definition, error) {
	m, err := asKeyed(md)
	if err != nil {
		return Definition{}, err
	}
	if err := requiredKeys(m, 8); err != nil {
		return Definition{}, err
	}
	var d Definition
	if d.Owner, err = decodeCredential(m[1]); err != nil {
		return Definition{}, err
	}
	if d.Title, err = asChunkedText(m[2]); err != nil {
		return Definition{}, err
	}
	if d.Description, err = asChunkedText(m[3]); err != nil {
		return Definition{}, err
	}
	roles, err := asList(m[4], 1, -1)
	if err != nil {
		return Definition{}, err
	}
	for _, r := range roles {
		v, err := asUint(r)
		if err != nil {
			return Definition{}, err
		}
		d.Roles = append(d.Roles, Role(v))
	}
	if d.EndEpoch, err = asUint(m[5]); err != nil {
		return Definition{}, err
	}
	if d.Mode, err = decodeMode(m[6]); err != nil {
		return Definition{}, err
	}
	qs, err := asList(m[7], 1, -1)
	if err != nil {
		return Definition{}, err
	}
	for _, q := range qs {
		question, err := decodeQuestion(q)
		if err != nil {
			return Definition{}, err
		}
		d.Questions = append(d.Questions, question)
	}
	if a, ok := m[8]; ok {
		if d.Anchor, err = decodeAnchor(a); err != nil {
			return Definition{}, err
		}
	}
	return d, d.Validate()
}

func decodeMode(md metadatum) (SubmissionMode, error) {
	items, err := asList(md, 1, 4)
	if err != nil {
		return SubmissionMode{}, err
	}
	tag, err := asUint(items[0])
	if err != nil {
		return SubmissionMode{}, err
	}
	switch {
	case tag == 0 && len(items) == 1:
		return SubmissionMode{}, nil
	case tag == 1 && len(items) == 4:
		h, err := asBytes(items[1], 32)
		if err != nil {
			return SubmissionMode{}, err
		}
		round, err := asUint(items[2])
		if err != nil {
			return SubmissionMode{}, err
		}
		pad, err := asUint(items[3])
		if err != nil {
			return SubmissionMode{}, err
		}
		m := SubmissionMode{Sealed: true, Round: round, PaddingSize: pad}
		copy(m.ChainHash[:], h)
		return m, nil
	}
	return SubmissionMode{}, invalidf("malformed submission mode")
}

// takeFlag reads an optional trailing flag at items[i].
func takeFlag(items []metadatum, i int) (bool, error) {
	if i >= len(items) {
		return false, nil
	}
	v, err := asUint(items[i])
	if err != nil || v > 1 {
		return false, invalidf("flag must be 0 or 1")
	}
	return v == 1, nil
}

func decodeOptions(md metadatum) (labels []string, count uint64, err error) {
	if l, ok := md.(metaList); ok {
		for _, item := range l.Items {
			s, err := asText(item)
			if err != nil {
				return nil, 0, err
			}
			labels = append(labels, s)
		}
		return labels, 0, nil
	}
	count, err = asUint(md)
	return nil, count, err
}

func decodeRange(md metadatum) (*Range, error) {
	items, err := asList(md, 2, 3)
	if err != nil {
		return nil, err
	}
	lo, err := asInt(items[0])
	if err != nil {
		return nil, err
	}
	hi, err := asInt(items[1])
	if err != nil {
		return nil, err
	}
	r := &Range{Min: lo, Max: hi}
	if len(items) == 3 {
		if r.Step, err = asUint(items[2]); err != nil || r.Step == 0 {
			return nil, invalidf("range step must be positive")
		}
	}
	return r, nil
}

func decodeScale(md metadatum) (*RatingScale, error) {
	l, ok := md.(metaList)
	if !ok {
		n, err := asUint(md)
		return &RatingScale{Levels: n}, err
	}
	if len(l.Items) > 0 {
		if _, isText := l.Items[0].(lcommon.MetaText); isText {
			labels, _, err := decodeOptions(md)
			return &RatingScale{Labels: labels}, err
		}
	}
	grid, err := decodeRange(md)
	return &RatingScale{Grid: grid}, err
}

func decodeQuestion(md metadatum) (Question, error) {
	items, err := asList(md, 2, -1)
	if err != nil {
		return Question{}, err
	}
	tag, err := asUint(items[0])
	if err != nil {
		return Question{}, err
	}
	q := Question{Kind: QuestionKind(tag)}
	if q.Prompt, err = asChunkedText(items[1]); err != nil {
		return Question{}, err
	}
	// fixed is the number of mandatory elements; one optional flag may follow.
	fixed := map[QuestionKind]int{
		KindCustom: 3, KindSingleChoice: 3, KindMultiSelect: 5, KindRanking: 5,
		KindNumericRange: 3, KindPointsAllocation: 4, KindRating: 5,
	}[q.Kind]
	if fixed == 0 || len(items) < fixed || len(items) > fixed+1 {
		return Question{}, invalidf("question tag %d with %d elements", tag, len(items))
	}
	if q.Required, err = takeFlag(items, fixed); err != nil {
		return Question{}, err
	}
	switch q.Kind {
	case KindCustom:
		q.Anchor, err = decodeAnchor(items[2])
	case KindNumericRange:
		q.Range, err = decodeRange(items[2])
	case KindSingleChoice, KindMultiSelect, KindRanking, KindPointsAllocation, KindRating:
		q.Options, q.OptionCount, err = decodeOptions(items[2])
	}
	if err != nil {
		return Question{}, err
	}
	switch q.Kind {
	case KindMultiSelect, KindRanking:
		if q.Min, err = asUint(items[3]); err == nil {
			q.Max, err = asUint(items[4])
		}
	case KindPointsAllocation:
		q.Budget, err = asUint(items[3])
	case KindRating:
		if q.Scale, err = decodeScale(items[3]); err == nil {
			q.RequireAll, err = takeFlag(items, 4)
		}
	case KindCustom, KindSingleChoice, KindNumericRange:
		// No fields beyond the options or anchor read above.
	}
	if err != nil {
		return Question{}, err
	}
	return q, q.Validate()
}

func decodeResponse(md metadatum) (Response, error) {
	m, err := asKeyed(md)
	if err != nil {
		return Response{}, err
	}
	if err := requiredKeys(m, 5); err != nil {
		return Response{}, err
	}
	var r Response
	if r.Survey, err = decodeRef(m[1]); err != nil {
		return Response{}, err
	}
	role, err := asUint(m[2])
	if err != nil || Role(role) > RoleKeyholder {
		return Response{}, invalidf("response role")
	}
	r.Role = Role(role)
	if r.Credential, err = decodeCredential(m[3]); err != nil {
		return Response{}, err
	}
	if l, ok := m[4].(metaList); ok && len(l.Items) > 0 {
		if _, isList := l.Items[0].(metaList); isList {
			for _, item := range l.Items {
				a, err := decodeAnswer(item)
				if err != nil {
					return Response{}, err
				}
				r.Answers = append(r.Answers, a)
			}
		}
	}
	if r.Answers == nil {
		if r.Sealed, err = asChunkedBytes(m[4]); err != nil || len(r.Sealed) == 0 {
			return Response{}, invalidf("response answers are neither answer items nor a ciphertext")
		}
	}
	if a, ok := m[5]; ok {
		if r.Rationale, err = decodeAnchor(a); err != nil {
			return Response{}, err
		}
	}
	return r, nil
}

func decodeAnswer(md metadatum) (Answer, error) {
	items, err := asList(md, 3, 3)
	if err != nil {
		return Answer{}, err
	}
	tag, err := asUint(items[0])
	if err != nil {
		return Answer{}, err
	}
	a := Answer{Kind: QuestionKind(tag)}
	if a.Question, err = asUint(items[1]); err != nil {
		return Answer{}, err
	}
	v := items[2]
	switch a.Kind {
	case KindCustom:
		a.Custom = v
	case KindSingleChoice:
		a.Choice, err = asUint(v)
	case KindMultiSelect, KindRanking:
		a.Indices, err = decodeIndices(v)
	case KindNumericRange:
		a.Number, err = asInt(v)
	case KindPointsAllocation, KindRating:
		a.Pairs, err = decodePairs(v, a.Kind == KindPointsAllocation)
	default:
		err = invalidf("unknown answer tag %d", tag)
	}
	return a, err
}

func decodeIndices(md metadatum) ([]uint64, error) {
	items, err := asList(md, 0, -1)
	if err != nil {
		return nil, err
	}
	out := make([]uint64, 0, len(items))
	for _, item := range items {
		n, err := asUint(item)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func decodePairs(md metadatum, unsigned bool) ([]Pair, error) {
	items, err := asList(md, 1, -1)
	if err != nil {
		return nil, err
	}
	out := make([]Pair, 0, len(items))
	for _, item := range items {
		pair, err := asList(item, 2, 2)
		if err != nil {
			return nil, err
		}
		opt, err := asUint(pair[0])
		if err != nil {
			return nil, err
		}
		var val int64
		if unsigned {
			u, err := asUint(pair[1])
			if err != nil || u > 1<<62 {
				return nil, invalidf("points value")
			}
			val = int64(u) //nolint:gosec // bounded above
		} else if val, err = asInt(pair[1]); err != nil {
			return nil, err
		}
		out = append(out, Pair{Option: opt, Value: val})
	}
	return out, nil
}
