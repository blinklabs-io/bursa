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
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
)

var errMalformedRequest = errors.New("malformed request")

// secretHex is a hex string decoded to bytes, so key material can be zeroed:
// a Go string cannot be. It decodes from and marshals to the same hex string
// hosts send.
type secretHex []byte

// MarshalJSON encodes the key as its hex string, so the exported requests
// marshal to the JSON the device decodes.
func (h secretHex) MarshalJSON() ([]byte, error) {
	if h == nil {
		return []byte("null"), nil
	}

	b := make([]byte, hex.EncodedLen(len(h))+2)
	b[0] = '"'
	hex.Encode(b[1:], h)
	b[len(b)-1] = '"'

	return b, nil
}

// UnmarshalJSON decodes the string straight from the request bytes, without
// a string copy of the key. A hex digit sent as a \u escape is unescaped into
// a byte buffer that is zeroed after decoding. A key decoded earlier into h,
// as from a repeated or case-variant field name, is zeroed first.
func (h *secretHex) UnmarshalJSON(data []byte) error {
	clear(*h)
	*h = nil

	if bytes.Equal(data, []byte("null")) {
		return nil
	}

	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errMalformedKey
	}

	src := data[1 : len(data)-1]

	if bytes.IndexByte(src, '\\') >= 0 {
		un, err := unescapeHexDigits(src)
		defer clear(un)

		if err != nil {
			return err
		}

		src = un
	}

	dst := make([]byte, hex.DecodedLen(len(src)))

	if _, err := hex.Decode(dst, src); err != nil {
		clear(dst)
		return errMalformedKey
	}

	*h = dst

	return nil
}

// unescapeHexDigits returns the JSON string contents src with each \u escape
// of a hex digit replaced by the digit. Any other escape cannot be part of a
// hex key and is refused, as is an escape cut short.
func unescapeHexDigits(src []byte) ([]byte, error) {
	out := make([]byte, 0, len(src))

	for i := 0; i < len(src); i++ {
		if src[i] != '\\' {
			out = append(out, src[i])
			continue
		}

		// a hex digit is \u0030-\u0039, \u0041-\u0046 or \u0061-\u0066
		if i+6 > len(src) || src[i+1] != 'u' || src[i+2] != '0' || src[i+3] != '0' {
			return out, errMalformedKey
		}

		var c [1]byte

		_, err := hex.Decode(c[:], src[i+4:i+6])
		if err != nil || !isHexDigit(c[0]) {
			return out, errMalformedKey
		}

		out = append(out, c[0])
		clear(c[:])
		i += 5
	}

	return out, nil
}

func isHexDigit(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// secretRequest is a request that carries key material. Its body is read into
// one buffer that is zeroed after decoding, and its decoded key fields are
// cleared when the request is done.
type secretRequest interface {
	clearSecrets()
}

func (r *ColdRequest) clearSecrets()      { clear(r.SigningKey) }
func (r *ProvisionRequest) clearSecrets() { clear(r.OwnerSigningKey) }

func clearSecrets(req any) {
	if r, ok := req.(secretRequest); ok {
		r.clearSecrets()
	}
}

// ignored accepts any JSON value without keeping it.
type ignored struct{}

func (*ignored) UnmarshalJSON([]byte) error { return nil }

// decodeRequest decodes a bounded JSON request into req. Unknown fields and
// trailing data are refused, so a misspelled field is not ignored. A request
// that carries key material is read into a single buffer, zeroed before
// returning, so no copy of the key outlives the call in this process's
// buffers.
func decodeRequest(w http.ResponseWriter, r *http.Request, req any) error {
	if _, ok := req.(secretRequest); !ok {
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequest))
		dec.DisallowUnknownFields()

		if err := dec.Decode(req); err != nil || dec.Decode(&struct{}{}) != io.EOF {
			return errMalformedRequest
		}

		return nil
	}

	buf := make([]byte, maxRequest+1)
	defer clear(buf)

	// the buffer is one byte larger than the limit, so a body within it ends
	// the read short
	n, err := io.ReadFull(http.MaxBytesReader(w, r.Body, maxRequest), buf)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		return errMalformedRequest
	}

	body := buf[:n]

	if err = json.Unmarshal(body, req); err == nil {
		err = refuseUnknownFields(body, req)
	}

	if err != nil {
		clearSecrets(req)

		if errors.Is(err, errMalformedKey) {
			return errMalformedKey
		}

		return errMalformedRequest
	}

	return nil
}

// refuseUnknownFields fails when the JSON object body names a field req has
// no JSON name for, matching names as encoding/json does. The values are
// discarded unread, so key material is not copied.
func refuseUnknownFields(body []byte, req any) error {
	var keys map[string]ignored
	if err := json.Unmarshal(body, &keys); err != nil {
		return err
	}

	names := jsonNames(reflect.TypeOf(req).Elem(), nil)

	for key := range keys {
		if !slices.ContainsFunc(names, func(name string) bool { return strings.EqualFold(name, key) }) {
			return errMalformedRequest
		}
	}

	return nil
}

// jsonNames appends the JSON field names of struct type t to names, as
// encoding/json decodes them: the fields of an embedded struct without a
// JSON name are its own, an untagged field goes by its Go name, and
// unexported and "-" fields are not decoded.
func jsonNames(t reflect.Type, names []string) []string {
	for i := range t.NumField() {
		f := t.Field(i)

		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}

		name, _, _ := strings.Cut(tag, ",")

		if f.Anonymous && name == "" {
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}

			if ft.Kind() == reflect.Struct {
				names = jsonNames(ft, names)
				continue
			}
		}

		if !f.IsExported() {
			continue
		}

		if name == "" {
			name = f.Name
		}

		names = append(names, name)
	}

	return names
}

func coldResponse(id uint32, pub []byte) ColdResponse {
	h := keyHash(pub)

	return ColdResponse{
		ColdKeyID: id,
		PublicKey: hex.EncodeToString(pub),
		PoolID:    hex.EncodeToString(h[:]),
	}
}

// importCold stores the seed in cold key object id. An existing object
// holding the same key confirms an earlier import whose answer was lost.
func (s *Service) importCold(id uint32, seed []byte) (ColdResponse, error) {
	pub, err := s.importKey(id, seed)
	if errors.Is(err, errKeyExists) {
		return ColdResponse{}, errors.New("cold key object already exists with a different key")
	} else if err != nil {
		return ColdResponse{}, err
	}

	res := coldResponse(id, pub)
	s.logf("imported cold key %#08x pool %s", id, res.PoolID)

	return res, nil
}
