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

package nft

import (
	"encoding/json"
	"testing"
)

func TestParseImageCID(t *testing.T) {
	const v1 = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	const v0 = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ipfs scheme v0", "ipfs://" + v0, v0},
		{"ipfs scheme v1", "ipfs://" + v1, v1},
		{"ipfs double prefix", "ipfs://ipfs/" + v0, v0},
		{"bare cid", v0, v0},
		{"cid with path", "ipfs://" + v0 + "/image.png", v0},
		{"whitespace", "  ipfs://" + v0 + "  ", v0},
		{"empty", "", ""},
		{"http rejected", "https://example.com/x.png", ""},
		{"http plain rejected", "http://example.com/x.png", ""},
		{"data uri rejected", "data:image/png;base64,iVBOR", ""},
		{"garbage", "not-a-cid", ""},
		{"ipfs scheme but invalid cid", "ipfs://not-a-cid!", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseImageCID(tc.in); got != tc.want {
				t.Fatalf("parseImageCID(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseMetadata(t *testing.T) {
	const cid = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"

	t.Run("string image and description", func(t *testing.T) {
		raw, _ := json.Marshal(map[string]any{
			"name": "My NFT", "image": "ipfs://" + cid, "description": "a token",
		})
		md := parseMetadata(raw)
		if md.Name != "My NFT" || md.ImageCID != cid || md.Description != "a token" {
			t.Fatalf("unexpected: %+v", md)
		}
	})

	t.Run("array image chunks concatenate", func(t *testing.T) {
		raw, _ := json.Marshal(map[string]any{
			"name":  "Chunked",
			"image": []string{"ipfs://Qm", "YwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"},
		})
		md := parseMetadata(raw)
		if md.ImageCID != cid {
			t.Fatalf("array image CID = %q, want %q", md.ImageCID, cid)
		}
	})

	t.Run("array description concatenates", func(t *testing.T) {
		raw, _ := json.Marshal(map[string]any{
			"name": "X", "description": []string{"part one ", "part two"},
		})
		md := parseMetadata(raw)
		if md.Description != "part one part two" {
			t.Fatalf("description = %q", md.Description)
		}
	})

	t.Run("empty metadata", func(t *testing.T) {
		if md := parseMetadata(nil); md != (parsedMetadata{}) {
			t.Fatalf("nil metadata = %+v, want zero", md)
		}
	})

	t.Run("malformed json tolerated", func(t *testing.T) {
		if md := parseMetadata(json.RawMessage(`{not json`)); md != (parsedMetadata{}) {
			t.Fatalf("malformed metadata = %+v, want zero", md)
		}
	})

	t.Run("http image yields no CID", func(t *testing.T) {
		raw, _ := json.Marshal(map[string]any{"name": "Web", "image": "https://x/y.png"})
		md := parseMetadata(raw)
		if md.Name != "Web" || md.ImageCID != "" {
			t.Fatalf("http image: %+v, want name only, no CID", md)
		}
	})
}
