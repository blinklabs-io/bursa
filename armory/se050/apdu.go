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

// command encodes a short ISO 7816-4 command APDU. Extended length APDUs
// are not needed for Ed25519 operations and are not supported.
func command(cla, ins, p1, p2 byte, data []byte, le bool) ([]byte, error) {
	if len(data) > 0xff {
		return nil, fmt.Errorf("se050: command data too long (%d bytes)", len(data))
	}

	apdu := []byte{cla, ins, p1, p2}

	if len(data) > 0 {
		apdu = append(apdu, byte(len(data)))
		apdu = append(apdu, data...)
	}

	if le {
		// 0x00 requests up to 256 response bytes
		apdu = append(apdu, 0x00)
	}

	return apdu, nil
}

func appendTLV(b []byte, tag byte, val []byte) []byte {
	b = append(b, tag)

	switch n := len(val); {
	case n < 0x80:
		b = append(b, byte(n))
	case n <= 0xff:
		b = append(b, 0x81, byte(n))
	default:
		b = append(b, 0x82, byte(n>>8), byte(n))
	}

	return append(b, val...)
}

// findTLV returns the value of the first occurrence of tag.
func findTLV(b []byte, tag byte) ([]byte, error) {
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, fmt.Errorf("se050: truncated TLV")
		}

		t := b[0]
		n := int(b[1])
		b = b[2:]

		switch n {
		case 0x81:
			if len(b) < 1 {
				return nil, fmt.Errorf("se050: truncated TLV length")
			}

			n = int(b[0])
			b = b[1:]
		case 0x82:
			if len(b) < 2 {
				return nil, fmt.Errorf("se050: truncated TLV length")
			}

			n = int(be16(b))
			b = b[2:]
		default:
			if n >= 0x80 {
				return nil, fmt.Errorf("se050: unsupported TLV length encoding %#02x", n)
			}
		}

		if len(b) < n {
			return nil, fmt.Errorf("se050: truncated TLV value")
		}

		if t == tag {
			return b[:n], nil
		}

		b = b[n:]
	}

	return nil, fmt.Errorf("se050: tag %#02x not found", tag)
}
