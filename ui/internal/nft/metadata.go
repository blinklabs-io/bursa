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
	"strings"

	gocid "github.com/ipfs/go-cid"
)

// ipfsSchemeCutPrefix removes an "ipfs://" prefix from s in a case-insensitive
// way (URI schemes are case-insensitive per RFC 3986). Returns (rest, true) if
// the prefix was found, otherwise ("", false).
func ipfsSchemeCutPrefix(s string) (string, bool) {
	const prefix = "ipfs://"
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return "", false
}

// onchainMetadata is the subset of CIP-25/CIP-68 token metadata the wallet
// reads. The `image` field may be a plain string ("ipfs://<cid>") or, for
// large/multi-part images, an array of string chunks that concatenate into one
// URI — so it is decoded as RawMessage and normalised by imageURI.
type onchainMetadata struct {
	Name        string          `json:"name"`
	Description json.RawMessage `json:"description"`
	Image       json.RawMessage `json:"image"`
}

// parsedMetadata is the wallet-facing view of an asset's on-chain metadata.
type parsedMetadata struct {
	Name        string
	Description string
	ImageCID    string // the IPFS CID extracted from image, or "" if none/unsupported
}

// parseMetadata interprets a raw on-chain-metadata JSON object (as returned by
// the node's GET /assets/{asset}). It tolerates absent or malformed metadata,
// returning a zero parsedMetadata rather than an error: an asset whose metadata
// the wallet cannot interpret simply has no displayable media.
func parseMetadata(raw json.RawMessage) parsedMetadata {
	if len(raw) == 0 {
		return parsedMetadata{}
	}
	var m onchainMetadata
	if err := json.Unmarshal(raw, &m); err != nil {
		return parsedMetadata{}
	}
	return parsedMetadata{
		Name:        m.Name,
		Description: joinStringOrArray(m.Description),
		ImageCID:    parseImageCID(joinStringOrArray(m.Image)),
	}
}

// joinStringOrArray normalises a CIP-25 field that is either a JSON string or a
// JSON array of strings (the chunking convention used to fit values into the
// 64-byte on-chain string limit) into a single string. Anything else yields "".
func joinStringOrArray(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var parts []string
	if err := json.Unmarshal(raw, &parts); err == nil {
		return strings.Join(parts, "")
	}
	return ""
}

// parseImageCID extracts an IPFS CID from a CIP-25/CIP-68 image URI. Only the
// ipfs:// scheme (and the bare-CID form) is supported in v1: the embedded boxo
// client fetches over the IPFS p2p network, so http(s):// and data: URIs are
// deliberately ignored — they would require an outbound HTTP connection, which
// the wallet's identity model forbids. Returns "" when no valid CID is found.
func parseImageCID(uri string) string {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return ""
	}
	// Strip an ipfs:// scheme and any "ipfs/" path prefix; tolerate the common
	// "ipfs://ipfs/<cid>" double form. Scheme matching is case-insensitive per
	// RFC 3986.
	s := uri
	if rest, ok := ipfsSchemeCutPrefix(s); ok {
		s = rest
	} else {
		lower := strings.ToLower(s)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "data:") {
			// Non-IPFS scheme: not fetchable over p2p, ignore.
			return ""
		}
	}
	s = strings.TrimPrefix(s, "ipfs/")
	// A CID may be followed by a path (cid/foo.png); keep only the CID segment.
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Validate it really is a CID — this also guarantees it is a safe filename
	// (CID alphabets are restricted alphanumerics, no path separators).
	if _, err := gocid.Decode(s); err != nil {
		return ""
	}
	return s
}
