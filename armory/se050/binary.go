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
	"fmt"
)

const (
	p1Binary = 0x06

	p2Size   = 0x07
	p2Memory = 0x22

	memPersistent = 0x01

	resultFailure = 0x02

	// maxBinaryChunk keeps each read or write within a short APDU: object
	// ID (6), offset (4), file length (4) and data (3 + 224) TLVs total 241
	// of 255 data bytes. Records up to this size are written in one APDU.
	maxBinaryChunk = 0xe0
)

func u16(v int) []byte {
	return []byte{byte(v >> 8), byte(v)} //nolint:gosec // values passed are within uint16 range
}

func beUint(b []byte) (v uint64) {
	for _, c := range b {
		v = v<<8 | uint64(c)
	}

	return
}

// objectSize returns the size in bytes of a binary object.
func (se *SE050) objectSize(id uint32) (int, error) {
	res, err := se.call(insRead, p1Default, p2Size, objectID(id), true)
	if err != nil {
		return 0, err
	}

	if len(res) == 0 || len(res) > 8 {
		return 0, fmt.Errorf("se050: invalid size length %d", len(res))
	}

	return int(beUint(res)), nil //nolint:gosec // size reported by secure element is within int range on supported platforms
}

// WriteBinary stores data in a persistent binary object, creating it or
// replacing its contents. An existing object of a different size is deleted
// and recreated, as the SE050 fixes a binary object's length at creation.
func (se *SE050) WriteBinary(id uint32, data []byte) error {
	if len(data) == 0 || len(data) > 0xffff {
		return fmt.Errorf("se050: invalid binary length %d", len(data))
	}

	exists, err := se.Exists(id)
	if err != nil {
		return err
	}

	create := !exists

	if exists {
		size, err := se.objectSize(id)
		if err != nil {
			return err
		}

		if size != len(data) {
			if err = se.Delete(id); err != nil {
				return err
			}

			create = true
		}
	}

	for off := 0; off < len(data); off += maxBinaryChunk {
		chunk := data[off:min(off+maxBinaryChunk, len(data))]

		tlvs := objectID(id)
		tlvs = appendTLV(tlvs, tag2, u16(off))

		if create && off == 0 {
			tlvs = appendTLV(tlvs, tag3, u16(len(data)))
		}

		tlvs = appendTLV(tlvs, tag4, chunk)

		if _, err := se.call(insWrite, p1Binary, p2Default, tlvs, false); err != nil {
			return err
		}
	}

	return nil
}

// ReadBinary returns the contents of a binary object.
func (se *SE050) ReadBinary(id uint32) ([]byte, error) {
	size, err := se.objectSize(id)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 0, size)

	for off := 0; off < size; off += maxBinaryChunk {
		n := min(maxBinaryChunk, size-off)

		tlvs := objectID(id)
		tlvs = appendTLV(tlvs, tag2, u16(off))
		tlvs = appendTLV(tlvs, tag3, u16(n))

		chunk, err := se.call(insRead, p1Default, p2Default, tlvs, true)
		if err != nil {
			return nil, err
		}

		if len(chunk) != n {
			return nil, fmt.Errorf("se050: short read at offset %d", off)
		}

		data = append(data, chunk...)
	}

	return data, nil
}

// FreeMemory returns the available persistent memory in bytes, as reported
// by the applet.
func (se *SE050) FreeMemory() (uint16, error) {
	res, err := se.call(insMgmt, p1Default, p2Memory, appendTLV(nil, tag1, []byte{memPersistent}), true)
	if err != nil {
		return 0, err
	}

	if len(res) != 2 {
		return 0, fmt.Errorf("se050: invalid free memory length %d", len(res))
	}

	return be16(res), nil
}
