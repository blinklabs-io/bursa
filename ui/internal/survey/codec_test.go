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
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// The expected bytes below are assembled from these helpers rather than from
// the codec, so they are an independent statement of the CIP-179 wire form.
func head(major byte, n int) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	default:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	}
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
func uintv(n int) []byte         { return head(0, n) }
func tstr(s string) []byte       { return cat(head(3, len(s)), []byte(s)) }
func bstr(b []byte) []byte       { return cat(head(2, len(b)), b) }
func arr(items ...[]byte) []byte { return cat(head(4, len(items)), cat(items...)) }
func mapv(pairs ...[]byte) []byte {
	return cat(head(5, len(pairs)/2), cat(pairs...))
}
func rep(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func cred(script bool, b byte) Credential {
	c := Credential{Script: script}
	copy(c.Hash[:], rep(b, 28))
	return c
}

func credCBOR(script bool, b byte) []byte {
	kind := 0
	if script {
		kind = 1
	}
	return arr(uintv(kind), bstr(rep(b, 28)))
}

func ref(b byte, idx uint64) Ref {
	r := Ref{Index: idx}
	copy(r.TxID[:], rep(b, 32))
	return r
}

func refCBOR(b byte, idx int) []byte { return arr(bstr(rep(b, 32)), uintv(idx)) }

func TestCancellationGolden(t *testing.T) {
	t.Parallel()
	// CIP-179 examples/cancellation.json
	want := arr(uintv(2), arr(refCBOR(0xef, 0)))
	p := Payload{Kind: KindCancellations, Cancellations: []Ref{ref(0xef, 0)}}

	got, err := Marshal(p)
	noErr(t, err)
	equal(t, want, got)

	back, err := Decode(want)
	noErr(t, err)
	equal(t, p, back)
}

func TestResponseGolden(t *testing.T) {
	t.Parallel()
	// CIP-179 examples/response-multi-select.json and the empty-selection
	// variant.
	for name, tc := range map[string]struct {
		answer     Answer
		answerCBOR []byte
	}{
		"multi-select": {
			Answer{Kind: KindMultiSelect, Question: 0, Indices: []uint64{1, 3}},
			arr(uintv(2), uintv(0), arr(uintv(1), uintv(3))),
		},
		"multi-select empty": {
			Answer{Kind: KindMultiSelect, Question: 0, Indices: []uint64{}},
			arr(uintv(2), uintv(0), arr()),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			want := arr(uintv(1), arr(mapv(
				uintv(0), uintv(5),
				uintv(1), refCBOR(0xef, 0),
				uintv(2), uintv(0),
				uintv(3), credCBOR(false, 0x22),
				uintv(4), arr(tc.answerCBOR),
			)))
			p := Payload{Kind: KindResponses, Responses: []Response{{
				Survey:     ref(0xef, 0),
				Role:       RoleDRep,
				Credential: cred(false, 0x22),
				Answers:    []Answer{tc.answer},
			}}}

			got, err := Marshal(p)
			noErr(t, err)
			equal(t, want, got)

			back, err := Decode(want)
			noErr(t, err)
			equal(t, p, back)
		})
	}
}

func TestDefinitionGolden(t *testing.T) {
	t.Parallel()
	// CIP-179 examples/survey-single-choice.json
	want := arr(uintv(0), arr(mapv(
		uintv(0), uintv(5),
		uintv(1), credCBOR(false, 0xcd),
		uintv(2), tstr("Dijkstra hard-fork CIP inclusion poll"),
		uintv(3), tstr("Signal support for including CIP-0136."),
		uintv(4), arr(uintv(3)),
		uintv(5), uintv(504),
		uintv(6), arr(uintv(0)),
		uintv(7), arr(arr(uintv(1), tstr("Should CIP-0136 be included?"),
			arr(tstr("YES"), tstr("NO"), tstr("ABSTAIN")))),
	)))
	p := Payload{Kind: KindDefinitions, Definitions: []Definition{{
		Owner:       cred(false, 0xcd),
		Title:       "Dijkstra hard-fork CIP inclusion poll",
		Description: "Signal support for including CIP-0136.",
		Roles:       []Role{RoleStakeholder},
		EndEpoch:    504,
		Questions: []Question{{
			Kind: KindSingleChoice, Prompt: "Should CIP-0136 be included?",
			Options: []string{"YES", "NO", "ABSTAIN"},
		}},
	}}}

	got, err := Marshal(p)
	noErr(t, err)
	equal(t, want, got)

	back, err := Decode(want)
	noErr(t, err)
	equal(t, p, back)
}

func TestDefinitionChunkedGolden(t *testing.T) {
	t.Parallel()
	// CIP-179 examples/survey-multi-select.json: chunked description and
	// prompt, min_selections 0.
	desc := "Select candidate CIPs for potential inclusion in the Dijkstra hard fork."
	prompt := "Which CIPs should be shortlisted for Dijkstra?"
	isTrue(t, len(desc) > MaxChunk)
	isTrue(t, len(prompt) <= MaxChunk)
	chunk0, chunk1 := desc[:MaxChunk], desc[MaxChunk:]

	want := arr(uintv(0), arr(mapv(
		uintv(0), uintv(5),
		uintv(1), credCBOR(false, 0xcd),
		uintv(2), tstr("Dijkstra hard-fork CIP shortlist"),
		uintv(3), arr(tstr(chunk0), tstr(chunk1)),
		uintv(4), arr(uintv(0)),
		uintv(5), uintv(504),
		uintv(6), arr(uintv(0)),
		uintv(7), arr(arr(uintv(2), tstr(prompt),
			arr(tstr("CIP-0108"), tstr("CIP-0119"), tstr("CIP-0136"), tstr("CIP-0149")),
			uintv(0), uintv(4))),
	)))
	p := Payload{Kind: KindDefinitions, Definitions: []Definition{{
		Owner:       cred(false, 0xcd),
		Title:       "Dijkstra hard-fork CIP shortlist",
		Description: desc,
		Roles:       []Role{RoleDRep},
		EndEpoch:    504,
		Questions: []Question{{
			Kind: KindMultiSelect, Prompt: prompt,
			Options: []string{"CIP-0108", "CIP-0119", "CIP-0136", "CIP-0149"},
			Min:     0, Max: 4,
		}},
	}}}

	got, err := Marshal(p)
	noErr(t, err)
	equal(t, want, got)

	back, err := Decode(want)
	noErr(t, err)
	equal(t, p, back)
}

func allQuestions() []Question {
	opts := []string{"a", "b", "c"}
	anchor := &Anchor{URI: "ipfs://schema"}
	copy(anchor.Hash[:], rep(0xaa, 32))
	return []Question{
		{Kind: KindCustom, Prompt: "custom", Anchor: anchor, Required: true},
		{Kind: KindSingleChoice, Prompt: "single", Options: opts},
		{Kind: KindMultiSelect, Prompt: "multi", Options: opts, Min: 1, Max: 2},
		{Kind: KindRanking, Prompt: "rank", Options: opts, Min: 1, Max: 3, Required: true},
		{Kind: KindNumericRange, Prompt: "num", Range: &Range{Min: -10, Max: 1000, Step: 5}},
		{Kind: KindPointsAllocation, Prompt: "points", Options: opts, Budget: 100},
		{
			Kind: KindRating, Prompt: "grid", Options: opts,
			Scale: &RatingScale{Grid: &Range{Min: 1, Max: 5}}, RequireAll: true,
		},
		{
			Kind: KindRating, Prompt: "labels", Options: opts,
			Scale: &RatingScale{Labels: []string{"bad", "ok", "good"}},
		},
		{Kind: KindRating, Prompt: "levels", OptionCount: 3, Scale: &RatingScale{Levels: 4}},
		{Kind: KindSingleChoice, Prompt: "counted", OptionCount: 4},
	}
}

func TestRoundTripAllQuestionTypes(t *testing.T) {
	t.Parallel()
	anchor := &Anchor{URI: "https://example.test/survey.json"}
	copy(anchor.Hash[:], rep(0xbb, 32))
	def := Definition{
		Owner:       cred(true, 0x01),
		Title:       "all types",
		Description: strings.Repeat("long description ", 20),
		Roles:       []Role{RoleDRep, RoleSPO, RoleCC, RoleStakeholder, RoleKeyholder},
		EndEpoch:    700,
		Mode:        SubmissionMode{Sealed: true, ChainHash: [32]byte{1, 2, 3}, Round: 99, PaddingSize: 512},
		Questions:   allQuestions(),
		Anchor:      anchor,
	}
	p := Payload{Kind: KindDefinitions, Definitions: []Definition{def, def}}

	raw, err := Marshal(p)
	noErr(t, err)
	back, err := Decode(raw)
	noErr(t, err)
	equal(t, p, back)
}

func TestRoundTripAllAnswerTypes(t *testing.T) {
	t.Parallel()
	custom := lcommon.MetaMap{Pairs: []lcommon.MetaPair{{
		Key:   lcommon.MetaText{Value: "k"},
		Value: lcommon.MetaInt{Value: big.NewInt(-7)},
	}}}
	rationale := &Anchor{URI: "ipfs://why"}
	copy(rationale.Hash[:], rep(0xcc, 32))
	p := Payload{Kind: KindResponses, Responses: []Response{{
		Survey:     ref(0x11, 3),
		Role:       RoleStakeholder,
		Credential: cred(true, 0x33),
		Rationale:  rationale,
		Answers: []Answer{
			{Kind: KindCustom, Question: 0, Custom: custom},
			{Kind: KindSingleChoice, Question: 1, Choice: 2},
			{Kind: KindMultiSelect, Question: 2, Indices: []uint64{0, 2}},
			{Kind: KindRanking, Question: 3, Indices: []uint64{2, 0, 1}},
			{Kind: KindNumericRange, Question: 4, Number: -325},
			{Kind: KindPointsAllocation, Question: 5, Pairs: []Pair{{0, 60}, {2, 40}}},
			{Kind: KindRating, Question: 6, Pairs: []Pair{{0, 1}, {1, -2}}},
		},
	}}}

	raw, err := Marshal(p)
	noErr(t, err)
	back, err := Decode(raw)
	noErr(t, err)

	// Custom is an interface value carrying decoder bookkeeping, so compare
	// its encoding and then the rest of the struct.
	isTrue(t, len(back.Responses) == 1)
	wantCustom, err := cbor.Encode(custom)
	noErr(t, err)
	equal(t, wantCustom, back.Responses[0].Answers[0].Custom.Cbor())
	back.Responses[0].Answers[0].Custom = nil
	p.Responses[0].Answers[0].Custom = nil
	equal(t, p, back)
}

func TestSealedResponseRoundTrip(t *testing.T) {
	t.Parallel()
	cipher := rep(0x5a, 150)
	p := Payload{Kind: KindResponses, Responses: []Response{{
		Survey: ref(0x11, 0), Role: RoleDRep, Credential: cred(false, 0x44), Sealed: cipher,
	}}}
	raw, err := Marshal(p)
	noErr(t, err)
	// 150 bytes are chunked into 64+64+22.
	want := arr(uintv(1), arr(mapv(
		uintv(0), uintv(5),
		uintv(1), refCBOR(0x11, 0),
		uintv(2), uintv(0),
		uintv(3), credCBOR(false, 0x44),
		uintv(4), arr(bstr(cipher[:64]), bstr(cipher[64:128]), bstr(cipher[128:])),
	)))
	equal(t, want, raw)
	back, err := Decode(raw)
	noErr(t, err)
	equal(t, p, back)
}

func TestChunkingNeverSplitsARune(t *testing.T) {
	t.Parallel()
	title := strings.Repeat("a", 63) + "é" + "tail"
	p := Payload{Kind: KindDefinitions, Definitions: []Definition{{
		Owner: cred(false, 1), Title: title, Roles: []Role{RoleDRep}, EndEpoch: 1,
		Questions: []Question{{Kind: KindSingleChoice, Prompt: "p", Options: []string{"a", "b"}}},
	}}}
	raw, err := Marshal(p)
	noErr(t, err)

	want := arr(uintv(0), arr(mapv(
		uintv(0), uintv(5),
		uintv(1), credCBOR(false, 1),
		uintv(2), arr(tstr(strings.Repeat("a", 63)), tstr("étail")),
		uintv(3), tstr(""),
		uintv(4), arr(uintv(0)),
		uintv(5), uintv(1),
		uintv(6), arr(uintv(0)),
		uintv(7), arr(arr(uintv(1), tstr("p"), arr(tstr("a"), tstr("b")))),
	)))
	equal(t, want, raw)
	back, err := Decode(raw)
	noErr(t, err)
	equal(t, title, back.Definitions[0].Title)
}

func TestDecodeToleratesForwardCompatibleForms(t *testing.T) {
	t.Parallel()
	// An unknown map key, a chunked form where a single string fits, an
	// explicit zero required flag, and an explicit zero "flag" all decode.
	raw := arr(uintv(0), arr(mapv(
		uintv(0), uintv(5),
		uintv(1), credCBOR(false, 0xcd),
		uintv(2), arr(tstr("ti"), tstr("tle")),
		uintv(3), tstr("d"),
		uintv(4), arr(uintv(3)),
		uintv(5), uintv(10),
		uintv(6), arr(uintv(0)),
		uintv(7), arr(arr(uintv(1), tstr("q"), arr(tstr("a"), tstr("b")), uintv(0)),
			arr(uintv(1), tstr("r"), arr(tstr("a"), tstr("b")), uintv(1))),
		uintv(42), tstr("future"),
	)))
	p, err := Decode(raw)
	noErr(t, err)
	d := p.Definitions[0]
	equal(t, "title", d.Title)
	isFalse(t, d.Questions[0].Required)
	isTrue(t, d.Questions[1].Required)
}

func TestDecodeRejectsMalformed(t *testing.T) {
	t.Parallel()
	good := func() [][]byte {
		return [][]byte{
			uintv(0), uintv(5),
			uintv(1), credCBOR(false, 0xcd),
			uintv(2), tstr("t"),
			uintv(3), tstr("d"),
			uintv(4), arr(uintv(3)),
			uintv(5), uintv(10),
			uintv(6), arr(uintv(0)),
			uintv(7), arr(arr(uintv(1), tstr("q"), arr(tstr("a"), tstr("b")))),
		}
	}
	def := func(mut func(kv [][]byte) [][]byte) []byte {
		return arr(uintv(0), arr(mapv(mut(good())...)))
	}
	resp := func(answers []byte, role int) []byte {
		return arr(uintv(1), arr(mapv(
			uintv(0), uintv(5), uintv(1), refCBOR(1, 0), uintv(2), uintv(role),
			uintv(3), credCBOR(false, 2), uintv(4), answers)))
	}
	sel := arr(arr(uintv(1), uintv(0), uintv(0)))

	cases := map[string][]byte{
		"empty":               {},
		"unknown payload tag": arr(uintv(9), arr()),
		"empty batch":         arr(uintv(0), arr()),
		"not a payload":       uintv(1),
		"version 4": def(func(kv [][]byte) [][]byte {
			kv[1] = uintv(4)
			return kv
		}),
		"missing owner": def(func(kv [][]byte) [][]byte { return append(kv[:2], kv[4:]...) }),
		"duplicate key": def(func(kv [][]byte) [][]byte { return append(kv, uintv(2), tstr("again")) }),
		"short owner hash": def(func(kv [][]byte) [][]byte {
			kv[3] = arr(uintv(0), bstr(rep(1, 27)))
			return kv
		}),
		"no roles": def(func(kv [][]byte) [][]byte {
			kv[9] = arr()
			return kv
		}),
		"role out of range": def(func(kv [][]byte) [][]byte {
			kv[9] = arr(uintv(5))
			return kv
		}),
		"one option": def(func(kv [][]byte) [][]byte {
			kv[15] = arr(arr(uintv(1), tstr("q"), arr(tstr("a"))))
			return kv
		}),
		"multi min above max": def(func(kv [][]byte) [][]byte {
			kv[15] = arr(arr(uintv(2), tstr("q"), arr(tstr("a"), tstr("b")), uintv(2), uintv(1)))
			return kv
		}),
		"unknown question tag": def(func(kv [][]byte) [][]byte {
			kv[15] = arr(arr(uintv(9), tstr("q")))
			return kv
		}),
		"no questions": def(func(kv [][]byte) [][]byte {
			kv[15] = arr()
			return kv
		}),
		"response role out of range": resp(sel, 7),
		"answer tag unknown":         resp(arr(arr(uintv(9), uintv(0), uintv(0))), 0),
		"empty answers":              resp(arr(), 0),
		"cancellation short txid":    arr(uintv(2), arr(arr(bstr(rep(1, 31)), uintv(0)))),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Decode(raw)
			isErr(t, err)
		})
	}
}

func TestEncodeRejectsInvalid(t *testing.T) {
	t.Parallel()
	base := func() Definition {
		return Definition{
			Owner: cred(false, 1), Title: "t", Roles: []Role{RoleDRep}, EndEpoch: 5,
			Questions: []Question{{Kind: KindSingleChoice, Prompt: "p", Options: []string{"a", "b"}}},
		}
	}
	for name, mut := range map[string]func(*Definition){
		"no questions":   func(d *Definition) { d.Questions = nil },
		"no roles":       func(d *Definition) { d.Roles = nil },
		"role range":     func(d *Definition) { d.Roles = []Role{9} },
		"one option":     func(d *Definition) { d.Questions[0].Options = []string{"a"} },
		"option too big": func(d *Definition) { d.Questions[0].Options = []string{strings.Repeat("x", 65), "b"} },
		"ranking min 0": func(d *Definition) {
			d.Questions[0] = Question{Kind: KindRanking, Prompt: "p", Options: []string{"a", "b"}, Min: 0, Max: 1}
		},
		"multi max over options": func(d *Definition) {
			d.Questions[0] = Question{Kind: KindMultiSelect, Prompt: "p", Options: []string{"a", "b"}, Max: 3}
		},
		"numeric min above max": func(d *Definition) {
			d.Questions[0] = Question{Kind: KindNumericRange, Prompt: "p", Range: &Range{Min: 5, Max: 1}}
		},
		"points no budget": func(d *Definition) {
			d.Questions[0] = Question{Kind: KindPointsAllocation, Prompt: "p", Options: []string{"a", "b"}}
		},
		"custom no anchor": func(d *Definition) { d.Questions[0] = Question{Kind: KindCustom, Prompt: "p"} },
		"rating no scale": func(d *Definition) {
			d.Questions[0] = Question{Kind: KindRating, Prompt: "p", Options: []string{"a", "b"}}
		},
		"sealed zero round": func(d *Definition) { d.Mode = SubmissionMode{Sealed: true, PaddingSize: 1} },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := base()
			mut(&d)
			_, err := Marshal(Payload{Kind: KindDefinitions, Definitions: []Definition{d}})
			isErr(t, err)
		})
	}

	t.Run("payload kind and batch disagree", func(t *testing.T) {
		t.Parallel()
		_, err := Marshal(Payload{Kind: KindResponses, Definitions: []Definition{base()}})
		isErr(t, err)
	})
}

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func isErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
}

func isTrue(t *testing.T, ok bool) {
	t.Helper()
	if !ok {
		t.Fatal("expected true")
	}
}

func isFalse(t *testing.T, ok bool) {
	t.Helper()
	isTrue(t, !ok)
}

func equal(t *testing.T, want, got any) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("mismatch\nwant %#v\n got %#v", want, got)
	}
}
