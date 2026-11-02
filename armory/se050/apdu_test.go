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

package se050

import (
	"bytes"
	"testing"
)

func TestCommandEncoding(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		le   bool
		want []byte
	}{
		{"header only", nil, false, []byte{0x80, 0x04, 0x00, 0x28}},
		{"le only", nil, true, []byte{0x80, 0x04, 0x00, 0x28, 0x00}},
		{"data and le", []byte{0x01, 0x02}, true, []byte{0x80, 0x04, 0x00, 0x28, 0x02, 0x01, 0x02, 0x00}},
	} {
		got, err := command(0x80, 0x04, 0x00, 0x28, tc.data, tc.le)

		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}

		if !bytes.Equal(got, tc.want) {
			t.Fatalf("%s: % x, want % x", tc.name, got, tc.want)
		}
	}

	if _, err := command(0x80, 0, 0, 0, make([]byte, 256), false); err == nil {
		t.Fatal("oversized short APDU accepted")
	}
}

func TestTLVRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 0x7f, 0x80, 0xff, 0x100} {
		val := bytes.Repeat([]byte{0x5a}, n)
		b := appendTLV(nil, tag2, []byte{0x01})
		b = appendTLV(b, tag1, val)

		got, err := findTLV(b, tag1)

		if err != nil {
			t.Fatalf("len %d: %v", n, err)
		}

		if !bytes.Equal(got, val) {
			t.Fatalf("len %d: value mismatch", n)
		}
	}
}

func TestFindTLVTruncated(t *testing.T) {
	b := appendTLV(nil, tag1, []byte{1, 2, 3})

	for n := range len(b) {
		if _, err := findTLV(b[:n], tag1); err == nil {
			t.Fatalf("truncated TLV of %d bytes accepted", n)
		}
	}
}

func TestParseVersion(t *testing.T) {
	v, err := parseVersion([]byte{0x07, 0x02, 0x00, 0x3f, 0xff, 0x01, 0x0a})

	if err != nil {
		t.Fatal(err)
	}

	if v.Major != 7 || v.Minor != 2 || v.Config != 0x3fff || !v.EdDSA() || v.SecureBoxMinor != 0x0a {
		t.Fatalf("unexpected version %+v", v)
	}
}

func TestObjectIDEncoding(t *testing.T) {
	if got := objectID(0x7fff0201); !bytes.Equal(got, []byte{0x41, 0x04, 0x7f, 0xff, 0x02, 0x01}) {
		t.Fatalf("objectID = % x", got)
	}
}
