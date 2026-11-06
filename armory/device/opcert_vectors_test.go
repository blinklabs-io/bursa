// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package device

import (
	"encoding/json"
	"os"
	"testing"
)

// The vectors are shared with the root module's internal/signer/opcertrule,
// which copies nextOpCert because the root module cannot import this one.
type opCertVector struct {
	Name       string `json:"name"`
	Floor      uint64 `json:"floor"`
	FloorSet   bool   `json:"floor_set"`
	LastIssued uint64 `json:"last_issued"`
	Chain      uint64 `json:"chain"`
	Issue      uint64 `json:"issue"`
	NewFloor   uint64 `json:"new_floor"`
	Error      string `json:"error"`
}

func TestNextOpCertSharedVectors(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/opcert_vectors.json")
	if err != nil {
		t.Fatal(err)
	}

	var vectors []opCertVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}

	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()

			issue, floor, err := nextOpCert(
				v.Floor, v.FloorSet, v.LastIssued, v.Chain,
			)
			if v.Error != "" {
				if err == nil || err.Error() != v.Error {
					t.Fatalf("error = %v, want %q", err, v.Error)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if issue != v.Issue || floor != v.NewFloor {
				t.Fatalf(
					"got issue %d floor %d, want issue %d floor %d",
					issue, floor, v.Issue, v.NewFloor,
				)
			}
		})
	}
}
