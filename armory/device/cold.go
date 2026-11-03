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

// Cold key origins, as reported in ColdResponse.
const (
	originGenerated = "generated"
	originImported  = "imported"
	// originUnknown is a cold key with no origin record, such as one
	// provisioned before origins were recorded.
	originUnknown = "unknown"
)

// The origin of each cold key is recorded at creation in a binary object at
// the cold key's object ID plus coldOriginOffset (0x20e50040-0x20e5004f),
// above the identity key, host key list and signing log head
// (0x20e50020-0x20e50022) and below the owner keys (0x20e50100). The SE050
// object origin attribute is not used: the driver in armory/se050 reads no
// object attributes.
const (
	coldOriginOffset uint32 = 0x30
	coldOriginFirst         = coldKeyFirst + coldOriginOffset
	coldOriginLast          = coldKeyLast + coldOriginOffset
)

func coldOriginID(id uint32) uint32 { return id + coldOriginOffset }

var errMalformedRequest = errors.New("malformed request")

// ColdInfoRequest asks for an existing cold key's public key, pool id and
// origin.
type ColdInfoRequest struct {
	HostAuth
	ColdKeyID uint32 `json:"cold_key_id"`
}

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

// writeOrigin records how the cold key id was made, and fails unless the
// record reads back as written.
func (s *Service) writeOrigin(id uint32, origin string) error {
	want := []byte(origin)

	err := s.chip.WriteBinary(coldOriginID(id), want)
	if err == nil {
		var got []byte

		if got, err = s.chip.ReadBinary(coldOriginID(id)); err == nil && !bytes.Equal(got, want) {
			err = errors.New("read back differs")
		}
	}

	if err != nil {
		s.logf("write origin %#08x: %v", coldOriginID(id), err)
		return errDevice
	}

	return nil
}

// readOrigin returns the recorded origin of the cold key id, originUnknown
// when none is recorded.
func (s *Service) readOrigin(id uint32) (string, error) {
	ok, err := s.chip.Exists(coldOriginID(id))
	if err != nil {
		s.logf("exist check %#08x: %v", coldOriginID(id), err)
		return "", errDevice
	}

	if !ok {
		return originUnknown, nil
	}

	b, err := s.chip.ReadBinary(coldOriginID(id))
	if err != nil {
		s.logf("read origin %#08x: %v", coldOriginID(id), err)
		return "", errDevice
	}

	switch o := string(b); o {
	case originGenerated, originImported:
		return o, nil
	}

	return originUnknown, nil
}

// discard deletes a key this request just created and could not describe, so
// the device never holds a cold key it cannot account for.
func (s *Service) discard(id uint32) {
	if err := s.chip.Delete(id); err != nil {
		s.logf("delete %#08x after a failed provision: %v", id, err)
	}
}

func coldResponse(id uint32, pub []byte, origin string) ColdResponse {
	h := keyHash(pub)

	return ColdResponse{
		ColdKeyID: id,
		PublicKey: hex.EncodeToString(pub),
		PoolID:    hex.EncodeToString(h[:]),
		Origin:    origin,
	}
}

// generateCold creates a cold key inside the chip and records that it was
// generated there. An existing object is never replaced.
//
// A generated cold key has NO backup. Its private key cannot leave the chip,
// so losing, wiping or breaking the device loses the pool: the pool id, its
// registration and its stake cannot be moved to another key. Import a key
// instead when the pool must survive the device.
func (s *Service) generateCold(id uint32) (ColdResponse, error) {
	ok, err := s.chip.Exists(id)
	if err != nil {
		s.logf("exist check %#08x: %v", id, err)
		return ColdResponse{}, errDevice
	}

	if ok {
		return ColdResponse{}, errors.New("cold key object already exists")
	}

	if err = s.chip.GenerateEd25519(id, false); err != nil {
		s.logf("generate %#08x: %v", id, err)

		// the object was absent above, so one present now is the key this
		// call generated and only its answer was lost
		ok, xerr := s.chip.Exists(id)
		if xerr != nil {
			// whatever is there now is this call's, so remove it rather
			// than leave a key with no origin that blocks a retry
			s.logf("exist check %#08x: %v", id, xerr)
			s.discard(id)

			return ColdResponse{}, errDevice
		}

		if !ok {
			return ColdResponse{}, errDevice
		}
	}

	pub, err := s.publicKey(id)
	if err == nil {
		err = s.writeOrigin(id, originGenerated)
	}

	if err != nil {
		s.discard(id)
		return ColdResponse{}, err
	}

	res := coldResponse(id, pub, originGenerated)
	s.logf("generated cold key %#08x pool %s: no backup exists, losing the device loses the pool", id, res.PoolID)

	return res, nil
}

// importCold stores the seed in cold key object id. An existing object
// holding the same key confirms an earlier import whose answer was lost. A
// key that matches the seed supplied was imported, whatever an earlier record
// says: a generated key's seed is not known to anyone.
func (s *Service) importCold(id uint32, seed []byte) (ColdResponse, error) {
	existed, err := s.chip.Exists(id)
	if err != nil {
		s.logf("exist check %#08x: %v", id, err)
		return ColdResponse{}, errDevice
	}

	pub, err := s.importKey(id, seed)
	if errors.Is(err, errKeyExists) {
		return ColdResponse{}, errors.New("cold key object already exists with a different key")
	} else if err != nil {
		return ColdResponse{}, err
	}

	if err = s.writeOrigin(id, originImported); err != nil {
		if !existed {
			s.discard(id)
		}

		return ColdResponse{}, err
	}

	res := coldResponse(id, pub, originImported)
	s.logf("imported cold key %#08x pool %s", id, res.PoolID)

	return res, nil
}

// coldInfo describes an existing cold key.
func (s *Service) coldInfo(req ColdInfoRequest) (ColdResponse, error) {
	if req.ColdKeyID < coldKeyFirst || req.ColdKeyID > coldKeyLast {
		return ColdResponse{}, errors.New("cold key id outside the cold key range")
	}

	ok, err := s.chip.Exists(req.ColdKeyID)
	if err != nil {
		s.logf("exist check %#08x: %v", req.ColdKeyID, err)
		return ColdResponse{}, errDevice
	}

	if !ok {
		return ColdResponse{}, errors.New("cold key not provisioned")
	}

	pub, err := s.publicKey(req.ColdKeyID)
	if err != nil {
		return ColdResponse{}, err
	}

	origin, err := s.readOrigin(req.ColdKeyID)
	if err != nil {
		return ColdResponse{}, err
	}

	return coldResponse(req.ColdKeyID, pub, origin), nil
}
