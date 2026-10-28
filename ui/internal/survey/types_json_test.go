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
	"math"
	"math/big"
	"testing"

	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

func TestRangeJSONPreservesInt64Values(t *testing.T) {
	rangeValue := Range{Min: math.MinInt64, Max: math.MaxInt64, Step: math.MaxUint64}
	raw, err := json.Marshal(rangeValue)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"min":"-9223372036854775808","max":"9223372036854775807","step":"18446744073709551615"}`
	if string(raw) != want {
		t.Fatalf("marshaled range = %s, want %s", raw, want)
	}
	var got Range
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got != rangeValue {
		t.Fatalf("round trip = %+v, want %+v", got, rangeValue)
	}
	if err := json.Unmarshal([]byte(`{"min":-9223372036854775808,"max":9223372036854775807,"step":18446744073709551615}`), &got); err != nil {
		t.Fatalf("numeric range input: %v", err)
	}
	if got != rangeValue {
		t.Fatalf("numeric input = %+v, want %+v", got, rangeValue)
	}
}

func TestAnswerJSONDecodesCustomMetadatumCBOR(t *testing.T) {
	var got Answer
	if err := json.Unmarshal([]byte(`{"kind":0,"question":2,"custom_cbor":"826178182a"}`), &got); err != nil {
		t.Fatal(err)
	}
	want := lcommon.MetaList{Items: []lcommon.TransactionMetadatum{
		lcommon.MetaText{Value: "x"},
		lcommon.MetaInt{Value: big.NewInt(42)},
	}}
	gotCBOR, err := cbor.Encode(got.Custom)
	if err != nil {
		t.Fatal(err)
	}
	wantCBOR, err := cbor.Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(gotCBOR) != hex.EncodeToString(wantCBOR) {
		t.Fatalf("custom metadatum = %x, want %x", gotCBOR, wantCBOR)
	}

	for _, raw := range []string{
		`{"kind":0,"question":0}`,
		`{"kind":0,"question":0,"custom_cbor":"zz"}`,
		`{"kind":0,"question":0,"custom_cbor":"ff"}`,
	} {
		if err := json.Unmarshal([]byte(raw), &got); err == nil {
			t.Fatalf("Unmarshal(%s) succeeded", raw)
		}
	}
}

func TestAnswerJSONAcceptsExactDecimalStrings(t *testing.T) {
	var got Answer
	if err := json.Unmarshal([]byte(`{"kind":4,"question":0,"number":"-9223372036854775808"}`), &got); err != nil {
		t.Fatal(err)
	}
	if got.Number != math.MinInt64 {
		t.Fatalf("answer number = %d, want %d", got.Number, int64(math.MinInt64))
	}
	if err := json.Unmarshal([]byte(`{"kind":6,"question":0,"pairs":[{"option":0,"value":"9223372036854775807"}]}`), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Pairs) != 1 || got.Pairs[0].Value != math.MaxInt64 {
		t.Fatalf("answer pairs = %+v, want max int64 value", got.Pairs)
	}
}
