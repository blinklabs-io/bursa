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
	"math/big"
	"unicode/utf8"

	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

type (
	metadatum = lcommon.TransactionMetadatum
	metaList  = lcommon.MetaList
	metaMap   = lcommon.MetaMap
)

// Marshal encodes a payload to the CBOR value stored under label 17.
func Marshal(p Payload) ([]byte, error) {
	md, err := Encode(p)
	if err != nil {
		return nil, err
	}
	return cbor.Encode(md)
}

// Encode builds the label-17 metadatum for a payload. Integer-keyed maps are
// built in ascending key order, as CIP-179 requires; gouroboros also sorts a
// map's keys when it encodes one, and the golden tests pin the resulting bytes.
// The result can be handed to apollo's SetShelleyMetadata unchanged, since
// apollo passes a ready metadatum through.
func Encode(p Payload) (metadatum, error) {
	var batch []metadatum
	switch p.Kind {
	case KindDefinitions:
		if len(p.Responses)+len(p.Cancellations) > 0 {
			return nil, invalidf("definitions payload carries other batches")
		}
		for _, d := range p.Definitions {
			md, err := encodeDefinition(d)
			if err != nil {
				return nil, err
			}
			batch = append(batch, md)
		}
	case KindResponses:
		if len(p.Definitions)+len(p.Cancellations) > 0 {
			return nil, invalidf("responses payload carries other batches")
		}
		for _, r := range p.Responses {
			md, err := encodeResponse(r)
			if err != nil {
				return nil, err
			}
			batch = append(batch, md)
		}
	case KindCancellations:
		if len(p.Definitions)+len(p.Responses) > 0 {
			return nil, invalidf("cancellations payload carries other batches")
		}
		for _, r := range p.Cancellations {
			batch = append(batch, encodeRef(r))
		}
	default:
		return nil, invalidf("unknown payload kind %d", p.Kind)
	}
	if len(batch) == 0 {
		return nil, invalidf("empty payload")
	}
	return metaList{Items: []metadatum{mUint(uint64(p.Kind)), metaList{Items: batch}}}, nil
}

func mUint(n uint64) metadatum { return lcommon.MetaInt{Value: new(big.Int).SetUint64(n)} }
func mInt(n int64) metadatum   { return lcommon.MetaInt{Value: big.NewInt(n)} }
func mText(s string) metadatum { return lcommon.MetaText{Value: s} }
func mList(items ...metadatum) metadatum {
	return metaList{Items: items}
}

// field is one integer-keyed map entry.
type field struct {
	key   uint64
	value metadatum
}

// mMap builds an integer-keyed map; callers list fields in ascending key order.
func mMap(fields []field) metadatum {
	pairs := make([]lcommon.MetaPair, len(fields))
	for i, f := range fields {
		pairs[i] = lcommon.MetaPair{Key: mUint(f.key), Value: f.value}
	}
	return metaMap{Pairs: pairs}
}

// chunkedText is a single text when it fits the metadatum limit, otherwise an
// array of chunks that never split a UTF-8 sequence.
func chunkedText(s string) metadatum {
	if len(s) <= MaxChunk {
		return mText(s)
	}
	var items []metadatum
	for len(s) > 0 {
		n := min(MaxChunk, len(s))
		for n > 0 && n < len(s) && !utf8.RuneStart(s[n]) {
			n--
		}
		items = append(items, mText(s[:n]))
		s = s[n:]
	}
	return metaList{Items: items}
}

func chunkedBytes(b []byte) metadatum {
	if len(b) <= MaxChunk {
		return lcommon.MetaBytes{Value: b}
	}
	var items []metadatum
	for len(b) > 0 {
		n := min(MaxChunk, len(b))
		items = append(items, lcommon.MetaBytes{Value: b[:n]})
		b = b[n:]
	}
	return metaList{Items: items}
}

func encodeCredential(c Credential) metadatum {
	kind := uint64(0)
	if c.Script {
		kind = 1
	}
	return mList(mUint(kind), lcommon.MetaBytes{Value: c.Hash[:]})
}

func encodeRef(r Ref) metadatum {
	return mList(lcommon.MetaBytes{Value: r.TxID[:]}, mUint(r.Index))
}

func encodeAnchor(a Anchor) metadatum {
	return mList(chunkedText(a.URI), lcommon.MetaBytes{Value: a.Hash[:]})
}

func encodeFlag(b bool) metadatum {
	if b {
		return mUint(1)
	}
	return mUint(0)
}

func encodeDefinition(d Definition) (metadatum, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	roles := make([]metadatum, len(d.Roles))
	for i, r := range d.Roles {
		roles[i] = mUint(uint64(r))
	}
	mode := mList(mUint(0))
	if d.Mode.Sealed {
		mode = mList(mUint(1), lcommon.MetaBytes{Value: d.Mode.ChainHash[:]},
			mUint(d.Mode.Round), mUint(d.Mode.PaddingSize))
	}
	questions := make([]metadatum, len(d.Questions))
	for i, q := range d.Questions {
		questions[i] = encodeQuestion(q)
	}
	fields := []field{
		{0, mUint(SpecVersion)},
		{1, encodeCredential(d.Owner)},
		{2, chunkedText(d.Title)},
		{3, chunkedText(d.Description)},
		{4, mList(roles...)},
		{5, mUint(d.EndEpoch)},
		{6, mode},
		{7, mList(questions...)},
	}
	if d.Anchor != nil {
		fields = append(fields, field{8, encodeAnchor(*d.Anchor)})
	}
	return mMap(fields), nil
}

func encodeOptions(q Question) metadatum {
	if len(q.Options) == 0 {
		return mUint(q.OptionCount)
	}
	items := make([]metadatum, len(q.Options))
	for i, o := range q.Options {
		items[i] = mText(o)
	}
	return mList(items...)
}

func encodeRange(r Range) metadatum {
	items := []metadatum{mInt(r.Min), mInt(r.Max)}
	if r.Step > 0 {
		items = append(items, mUint(r.Step))
	}
	return mList(items...)
}

func encodeScale(s RatingScale) metadatum {
	switch {
	case s.Grid != nil:
		return encodeRange(*s.Grid)
	case len(s.Labels) > 0:
		items := make([]metadatum, len(s.Labels))
		for i, l := range s.Labels {
			items[i] = mText(l)
		}
		return mList(items...)
	default:
		return mUint(s.Levels)
	}
}

// encodeQuestion assumes q has been validated.
func encodeQuestion(q Question) metadatum {
	items := []metadatum{mUint(uint64(q.Kind)), chunkedText(q.Prompt)}
	switch q.Kind {
	case KindCustom:
		items = append(items, encodeAnchor(*q.Anchor))
	case KindSingleChoice:
		items = append(items, encodeOptions(q))
	case KindMultiSelect, KindRanking:
		items = append(items, encodeOptions(q), mUint(q.Min), mUint(q.Max))
	case KindNumericRange:
		items = append(items, encodeRange(*q.Range))
	case KindPointsAllocation:
		items = append(items, encodeOptions(q), mUint(q.Budget))
	case KindRating:
		items = append(items, encodeOptions(q), encodeScale(*q.Scale), encodeFlag(q.RequireAll))
	}
	if q.Required {
		items = append(items, mUint(1))
	}
	return mList(items...)
}

func encodeResponse(r Response) (metadatum, error) {
	if r.Role > RoleKeyholder {
		return nil, invalidf("role %d out of range", r.Role)
	}
	var answers metadatum
	switch {
	case len(r.Sealed) > 0 && len(r.Answers) > 0:
		return nil, invalidf("response carries both answers and a sealed ciphertext")
	case len(r.Sealed) > 0:
		answers = chunkedBytes(r.Sealed)
	case len(r.Answers) > 0:
		items := make([]metadatum, len(r.Answers))
		for i, a := range r.Answers {
			md, err := encodeAnswer(a)
			if err != nil {
				return nil, err
			}
			items[i] = md
		}
		answers = mList(items...)
	default:
		return nil, invalidf("response has no answers")
	}
	fields := []field{
		{0, mUint(SpecVersion)},
		{1, encodeRef(r.Survey)},
		{2, mUint(uint64(r.Role))},
		{3, encodeCredential(r.Credential)},
		{4, answers},
	}
	if r.Rationale != nil {
		fields = append(fields, field{5, encodeAnchor(*r.Rationale)})
	}
	return mMap(fields), nil
}

func encodeAnswer(a Answer) (metadatum, error) {
	head := []metadatum{mUint(uint64(a.Kind)), mUint(a.Question)}
	switch a.Kind {
	case KindCustom:
		if a.Custom == nil {
			return nil, invalidf("custom answer has no value")
		}
		return mList(append(head, a.Custom)...), nil
	case KindSingleChoice:
		return mList(append(head, mUint(a.Choice))...), nil
	case KindMultiSelect, KindRanking:
		idx := make([]metadatum, len(a.Indices))
		for i, v := range a.Indices {
			idx[i] = mUint(v)
		}
		return mList(append(head, mList(idx...))...), nil
	case KindNumericRange:
		return mList(append(head, mInt(a.Number))...), nil
	case KindPointsAllocation, KindRating:
		pairs := make([]metadatum, len(a.Pairs))
		for i, p := range a.Pairs {
			if a.Kind == KindPointsAllocation && p.Value < 0 {
				return nil, invalidf("negative points")
			}
			pairs[i] = mList(mUint(p.Option), mInt(p.Value))
		}
		return mList(append(head, mList(pairs...))...), nil
	}
	return nil, invalidf("unknown answer kind %d", a.Kind)
}
