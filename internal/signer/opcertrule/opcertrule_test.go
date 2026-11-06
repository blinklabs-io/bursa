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

package opcertrule

import (
	"encoding/json"
	"os"
	"testing"
)

// vectorFile is shared with the armory module's test of nextOpCert.
const vectorFile = "../../../armory/device/testdata/opcert_vectors.json"

type vector struct {
	Name       string `json:"name"`
	Floor      uint64 `json:"floor"`
	FloorSet   bool   `json:"floor_set"`
	LastIssued uint64 `json:"last_issued"`
	Chain      uint64 `json:"chain"`
	Issue      uint64 `json:"issue"`
	NewFloor   uint64 `json:"new_floor"`
	Error      string `json:"error"`
}

func TestNextSharedVectors(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatal(err)
	}

	var vectors []vector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}

	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()

			issue, floor, err := Next(
				v.Floor,
				v.FloorSet,
				v.LastIssued,
				v.Chain,
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

func TestNextErrorIdentity(t *testing.T) {
	t.Parallel()

	if _, _, err := Next(3, true, 5, 2); err != ErrBelowFloor {
		t.Fatalf("below floor: %v", err)
	}

	if _, _, err := Next(3, true, 5, 6); err != ErrAboveIssued {
		t.Fatalf("above issued: %v", err)
	}

	if _, _, err := Next(0, false, 0, ^uint64(0)); err != ErrOutOfRange {
		t.Fatalf("out of range: %v", err)
	}
}

func TestCheckPeriod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                         string
		issue, lastIssued, last, per uint64
		err                          error
	}{
		{"same period reissue", 5, 5, 100, 100, nil},
		{"higher period reissue", 5, 5, 100, 101, nil},
		{"lower period reissue", 5, 5, 100, 99, ErrKESBackdated},
		{"unknown recorded period", 5, 5, 0, 0, nil},
		{"new issue number at lower period", 6, 5, 100, 50, nil},
		{"older issue number is not recorded", 4, 5, 100, 50, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := CheckPeriod(tt.issue, tt.lastIssued, tt.last, tt.per)
			if err != tt.err {
				t.Fatalf("err = %v, want %v", err, tt.err)
			}
		})
	}
}
