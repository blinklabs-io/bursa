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

package wire

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
)

// MarshalFrame encodes the push as JSON identical to json.Marshal's output,
// bounded by max payload bytes,
// directly into a buffer the caller owns. encoding/json returns its working
// buffer to a process-wide pool without clearing it, which would leave the
// base64 signing key in memory that no caller can wipe.
func (k KeyPush) MarshalFrame(max int) ([]byte, error) {
	typ, err := json.Marshal(k.Type)
	if err != nil {
		return nil, err
	}
	// Size the buffer for the whole frame: if append outgrew it, the copy would
	// move the signing key to a new array and leave the old one unwiped.
	const fixedLen = len(
		`{"type":,"period":,"depth":,"kes_sign_key":,"kes_vkey":,"opcert":}`,
	)
	// Bounding every term first keeps the sum from overflowing, and rejects an
	// oversized push before the signing key is encoded at all.
	if len(typ) > max || len(k.KESSignKey) > max ||
		len(k.KESVKey) > max || len(k.OpCert) > max {
		return nil, ErrFrameTooLarge
	}
	size := fixedLen + len(typ) + uintLen(k.Period) + uintLen(k.Depth) +
		jsonBytesLen(
			k.KESSignKey,
		) + jsonBytesLen(k.KESVKey) + jsonBytesLen(k.OpCert)
	if size > max {
		return nil, ErrFrameTooLarge
	}
	buf := make([]byte, 0, size)
	buf = append(buf, `{"type":`...)
	buf = append(buf, typ...)
	buf = append(buf, `,"period":`...)
	buf = strconv.AppendUint(buf, k.Period, 10)
	buf = append(buf, `,"depth":`...)
	buf = strconv.AppendUint(buf, k.Depth, 10)
	buf = append(buf, `,"kes_sign_key":`...)
	buf = appendJSONBytes(buf, k.KESSignKey)
	buf = append(buf, `,"kes_vkey":`...)
	buf = appendJSONBytes(buf, k.KESVKey)
	buf = append(buf, `,"opcert":`...)
	buf = appendJSONBytes(buf, k.OpCert)
	return append(buf, '}'), nil
}

// uintLen is the length strconv.AppendUint appends for v in base 10.
func uintLen(v uint64) int {
	n := 1
	for v >= 10 {
		v /= 10
		n++
	}
	return n
}

// jsonBytesLen is the length appendJSONBytes appends for b.
func jsonBytesLen(b []byte) int {
	if b == nil {
		return len("null")
	}
	return 2 + base64.StdEncoding.EncodedLen(len(b))
}

// appendJSONBytes appends b as encoding/json encodes a []byte: null for nil,
// otherwise a quoted standard base64 string.
func appendJSONBytes(buf, b []byte) []byte {
	if b == nil {
		return append(buf, "null"...)
	}
	buf = append(buf, '"')
	buf = base64.StdEncoding.AppendEncode(buf, b)
	return append(buf, '"')
}

// FrameMarshaler is implemented by frames that carry secrets and must not be
// serialized through encoding/json's pooled buffers. MarshalFrame receives the
// caller's maximum payload length and returns an error wrapping ErrFrameTooLarge
// when the frame cannot fit.
type FrameMarshaler interface {
	MarshalFrame(max int) ([]byte, error)
}
