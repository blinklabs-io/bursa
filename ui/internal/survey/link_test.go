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
	"testing"
)

func TestParseLink(t *testing.T) {
	t.Parallel()
	txid := strings.Repeat("ab", 32)
	doc := func(cip179 string) string {
		return `{"@context":{},"body":{"title":"t","cip179":` + cip179 + `}}`
	}
	valid := `{"specVersion":5,"kind":"survey-link","surveyTxId":"` + txid + `","surveyIndex":2}`

	for name, tc := range map[string]struct {
		doc  string
		want Ref
		ok   bool
	}{
		// CIP-179 examples/governance-action-anchor-survey-link.json shape.
		"valid":                {doc(valid), ref(0xab, 2), true},
		"txid compared as hex": {doc(`{"kind":"survey-link","surveyTxId":"` + strings.ToUpper(txid) + `","surveyIndex":0}`), ref(0xab, 0), true},
		"no cip179 object":     {`{"body":{"title":"t"}}`, Ref{}, false},
		"cip179 outside body":  {`{"cip179":` + valid + `}`, Ref{}, false},
		"wrong kind":           {doc(`{"kind":"other","surveyTxId":"` + txid + `","surveyIndex":0}`), Ref{}, false},
		"missing index":        {doc(`{"kind":"survey-link","surveyTxId":"` + txid + `"}`), Ref{}, false},
		"negative index":       {doc(`{"kind":"survey-link","surveyTxId":"` + txid + `","surveyIndex":-1}`), Ref{}, false},
		"fractional index":     {doc(`{"kind":"survey-link","surveyTxId":"` + txid + `","surveyIndex":1.5}`), Ref{}, false},
		"string index":         {doc(`{"kind":"survey-link","surveyTxId":"` + txid + `","surveyIndex":"0"}`), Ref{}, false},
		"short txid":           {doc(`{"kind":"survey-link","surveyTxId":"abcd","surveyIndex":0}`), Ref{}, false},
		"non-hex txid":         {doc(`{"kind":"survey-link","surveyTxId":"` + strings.Repeat("zz", 32) + `","surveyIndex":0}`), Ref{}, false},
		"cip179 not an object": {doc(`"x"`), Ref{}, false},
		"body not an object":   {`{"body":[]}`, Ref{}, false},
		"not json":             {`not json`, Ref{}, false},
		"empty":                {``, Ref{}, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, ok := ParseLink([]byte(tc.doc))
			if ok != tc.ok || got != tc.want {
				t.Fatalf("ParseLink = %+v, %v; want %+v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}
