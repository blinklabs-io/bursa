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
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// testdata/cip179 holds the JSON examples published with CIP-179
// (CIP-0179/examples, CC-BY-4.0). Per its test-vector document, integer map
// keys are JSON object keys and byte strings are lowercase hex.

var hexBytes = regexp.MustCompile(`^(?:[0-9a-f]{56}|[0-9a-f]{64})$`)

// jsonMetadatum converts a decoded CIP-179 example into the metadatum it
// denotes. A string is bytes when it is a 28- or 32-byte lowercase hex value (a
// credential, transaction id or hash); no example carries text of that shape. An
// object key is an integer when it reads as one, as in the label-17 maps, and
// text otherwise, as in a custom answer.
func jsonMetadatum(t *testing.T, v any) lcommon.TransactionMetadatum {
	t.Helper()
	switch x := v.(type) {
	case float64:
		return lcommon.MetaInt{Value: big.NewInt(int64(x))}
	case string:
		if hexBytes.MatchString(x) {
			b, err := hex.DecodeString(x)
			noErr(t, err)
			return lcommon.MetaBytes{Value: b}
		}
		return lcommon.MetaText{Value: x}
	case []any:
		items := make([]lcommon.TransactionMetadatum, len(x))
		for i, item := range x {
			items[i] = jsonMetadatum(t, item)
		}
		return lcommon.MetaList{Items: items}
	case map[string]any:
		var pairs []lcommon.MetaPair
		for k, item := range x {
			var key lcommon.TransactionMetadatum = lcommon.MetaText{Value: k}
			if n, err := strconv.ParseUint(k, 10, 64); err == nil {
				key = lcommon.MetaInt{Value: new(big.Int).SetUint64(n)}
			}
			pairs = append(pairs, lcommon.MetaPair{Key: key, Value: jsonMetadatum(t, item)})
		}
		return lcommon.MetaMap{Pairs: pairs}
	}
	t.Fatalf("unsupported JSON value %T", v)
	return nil
}

// vectorCBOR reads an example and returns the CBOR of its label-17 value.
func vectorCBOR(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "cip179", name))
	noErr(t, err)
	var doc map[string]any
	noErr(t, json.Unmarshal(raw, &doc))
	label, ok := doc["17"]
	isTrue(t, ok)
	out, err := cbor.Encode(jsonMetadatum(t, label))
	noErr(t, err)
	return out
}

func decodeVector(t *testing.T, name string) Payload {
	t.Helper()
	p, err := Decode(vectorCBOR(t, name))
	noErr(t, err)
	return p
}

// Two examples split long text at word boundaries, which CIP-179 allows ("an
// array of <=64-byte strings concatenated"); this encoder always fills each
// chunk, so those two re-encode to equal values but different bytes.
var authorChunked = map[string]bool{
	"survey-multi-select.json":  true,
	"survey-custom-method.json": true,
}

func TestCIPExamplesRoundTrip(t *testing.T) {
	t.Parallel()
	names, err := filepath.Glob("testdata/cip179/*.json")
	noErr(t, err)
	var vectors []string
	for _, n := range names {
		if base := filepath.Base(n); base != "governance-action-anchor-survey-link.json" {
			vectors = append(vectors, base)
		}
	}
	// 7 definitions, 10 responses and 1 cancellation.
	equal(t, 18, len(vectors))

	for _, name := range vectors {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			want := vectorCBOR(t, name)
			p, err := Decode(want)
			noErr(t, err)
			got, err := Marshal(p)
			noErr(t, err)

			if authorChunked[name] {
				again, err := Decode(got)
				noErr(t, err)
				equal(t, p, again)
				return
			}
			equal(t, want, got)
		})
	}
}

func TestCIPDefinitionVectors(t *testing.T) {
	t.Parallel()

	single := decodeVector(t, "survey-single-choice.json").Definitions[0]
	equal(t, []Role{RoleStakeholder}, single.Roles)
	equal(t, uint64(504), single.EndEpoch)
	equal(t, Question{Kind: KindSingleChoice, Prompt: "Should CIP-0136 be included?", Options: []string{"YES", "NO", "ABSTAIN"}}, single.Questions[0])

	// Vector 2: min_selections 0 makes an empty selection a valid answer.
	multi := decodeVector(t, "survey-multi-select.json").Definitions[0]
	q := multi.Questions[0]
	equal(t, KindMultiSelect, q.Kind)
	equal(t, uint64(0), q.Min)
	equal(t, uint64(4), q.Max)
	equal(t, "Which CIPs should be shortlisted for Dijkstra?", q.Prompt)
	noErr(t, multi.CheckAnswers([]Answer{{Kind: KindMultiSelect, Question: 0, Indices: []uint64{}}}))

	// Vector 3: numeric range for DRep, SPO and CC.
	numeric := decodeVector(t, "survey-numeric-range.json").Definitions[0]
	equal(t, []Role{RoleDRep, RoleSPO, RoleCC}, numeric.Roles)
	equal(t, KindNumericRange, numeric.Questions[0].Kind)
	equal(t, &Range{Min: 10, Max: 1000, Step: 5}, numeric.Questions[0].Range)

	// Vector 4: a custom question anchored by URI (chunked) and hash.
	custom := decodeVector(t, "survey-custom-method.json").Definitions[0]
	cq := custom.Questions[0]
	equal(t, KindCustom, cq.Kind)
	isTrue(t, cq.Anchor != nil && len(cq.Anchor.URI) > MaxChunk)
	isTrue(t, custom.Anchor != nil)

	// Vectors 5 and 6: batches of questions in index order.
	same := decodeVector(t, "survey-multi-question-same-type.json").Definitions[0]
	equal(t, []QuestionKind{KindNumericRange, KindNumericRange}, kindsOf(same))
	mixed := decodeVector(t, "survey-multi-question-mixed-type.json").Definitions[0]
	equal(t, []QuestionKind{KindMultiSelect, KindSingleChoice, KindNumericRange}, kindsOf(mixed))

	// Vector 7: mixed eligibility, no weighting.
	shared := decodeVector(t, "survey-mixed-role-shared.json").Definitions[0]
	equal(t, []Role{RoleDRep, RoleSPO, RoleStakeholder}, shared.Roles)
}

func kindsOf(d Definition) []QuestionKind {
	var kinds []QuestionKind
	for _, q := range d.Questions {
		kinds = append(kinds, q.Kind)
	}
	return kinds
}

func TestCIPResponseVectors(t *testing.T) {
	t.Parallel()
	first := func(name string) Response { return decodeVector(t, name).Responses[0] }

	// Vectors 8-11, 13, 14: answer items per question type.
	equal(t, Answer{Kind: KindSingleChoice, Question: 0, Choice: 0}, first("response-single-choice.json").Answers[0])
	equal(t, Answer{Kind: KindMultiSelect, Question: 0, Indices: []uint64{1, 3}}, first("response-multi-select.json").Answers[0])
	empty := first("response-multi-select-empty.json").Answers[0]
	equal(t, KindMultiSelect, empty.Kind)
	isTrue(t, empty.Indices != nil && len(empty.Indices) == 0) // present and empty: "none selected", not an abstain
	equal(t, Answer{Kind: KindNumericRange, Question: 0, Number: 325}, first("response-numeric-range.json").Answers[0])

	var kinds []QuestionKind
	for _, a := range first("response-multi-question-mixed-type.json").Answers {
		kinds = append(kinds, a.Kind)
	}
	equal(t, []QuestionKind{KindMultiSelect, KindSingleChoice, KindNumericRange}, kinds)

	// Vector 12: a custom answer is an opaque metadatum.
	custom := first("response-custom-method.json").Answers[0]
	equal(t, KindCustom, custom.Kind)
	isTrue(t, custom.Custom != nil)

	// Each response checks out against the definition it targets.
	multi := decodeVector(t, "survey-multi-select.json").Definitions[0]
	noErr(t, multi.CheckAnswers(first("response-multi-select-empty.json").Answers))
	noErr(t, multi.CheckAnswers(first("response-multi-select.json").Answers))
	numeric := decodeVector(t, "survey-numeric-range.json").Definitions[0]
	noErr(t, numeric.CheckAnswers(first("response-numeric-range.json").Answers)) // 325 on [10, 1000] step 5
}

// The CIP's "latest valid response wins" behaviour vector: both responses share
// (survey_ref, role 3, credential 11..11); the older sits at (120100000, tx 2)
// and the latest at (120100005, tx 0), and the latest answer, [1, 0, 0], stands.
func TestCIPLatestValidResponseWinsVector(t *testing.T) {
	t.Parallel()
	def := decodeVector(t, "survey-single-choice.json").Definitions[0]
	older := decodeVector(t, "response-duplicate-older.json").Responses[0]
	latest := decodeVector(t, "response-duplicate-latest.json").Responses[0]
	equal(t, older.Survey, latest.Survey)
	equal(t, older.Credential, latest.Credential)
	equal(t, older.Role, latest.Role)

	tally := def.Aggregate([]Observed{
		{TxHash: "latest", Pos: Position{Height: 120100005, TxIndex: 0}, Epoch: 400, Response: latest},
		{TxHash: "older", Pos: Position{Height: 120100000, TxIndex: 2}, Epoch: 400, Response: older},
	})
	rt := roleTally(t, tally, RoleStakeholder)
	equal(t, uint64(1), rt.Responses)
	equal(t, latest.Answers, []Answer{{Kind: KindSingleChoice, Question: 0, Choice: 0}})
	equal(t, uint64(1), rt.Questions[0].Options[0].Count)
	equal(t, "superseded by a later response", reasons(tally)["older"])
}

func TestCIPCancellationVector(t *testing.T) {
	t.Parallel()
	p := decodeVector(t, "cancellation.json")
	equal(t, KindCancellations, p.Kind)
	equal(t, []Ref{ref(0xef, 0)}, p.Cancellations)
}

func TestCIPGovernanceAnchorLinkVector(t *testing.T) {
	t.Parallel()
	link, err := os.ReadFile(filepath.Join("testdata", "cip179", "governance-action-anchor-survey-link.json"))
	noErr(t, err)
	// The example is the cip179 object; it lives inside the CIP-108 body.
	doc := []byte(`{"body":{"title":"t","cip179":` + string(link) + `}}`)
	got, ok := ParseLink(doc)
	isTrue(t, ok)
	equal(t, ref(0xbb, 0), got)
}
