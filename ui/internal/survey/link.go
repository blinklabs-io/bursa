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
	"strconv"
)

type linkDocument struct {
	Body struct {
		CIP179 *struct {
			Kind        string          `json:"kind"`
			SurveyTxID  string          `json:"surveyTxId"`
			SurveyIndex json.RawMessage `json:"surveyIndex"`
		} `json:"cip179"`
	} `json:"body"`
}

// ParseLink reads the CIP-179 survey link from a CIP-108 governance-action
// anchor document: the namespaced cip179 object inside the body. A missing or
// malformed link, including an index that is absent or not a non-negative
// integer, reports false rather than falling back to a default.
func ParseLink(doc []byte) (Ref, bool) {
	var d linkDocument
	if err := json.Unmarshal(doc, &d); err != nil || d.Body.CIP179 == nil {
		return Ref{}, false
	}
	l := d.Body.CIP179
	if l.Kind != "survey-link" {
		return Ref{}, false
	}
	txid, err := hex.DecodeString(l.SurveyTxID)
	if err != nil || len(txid) != 32 {
		return Ref{}, false
	}
	idx, err := strconv.ParseUint(string(l.SurveyIndex), 10, 64)
	if err != nil {
		return Ref{}, false
	}
	r := Ref{Index: idx}
	copy(r.TxID[:], txid)
	return r, true
}
