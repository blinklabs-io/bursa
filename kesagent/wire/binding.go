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
	"crypto/sha256"
	"encoding/binary"
)

// AttestationBinding is the digest provider evidence must commit to. It binds
// a caller nonce to the active public KES state and the pool identity.
func AttestationBinding(
	nonce, coldVKey, kesVKey, opcert []byte,
	period uint64,
) []byte {
	h := sha256.New()
	h.Write([]byte(AttestedProtocolID))
	writeBindingField(h, nonce)
	writeBindingField(h, coldVKey)
	writeBindingField(h, kesVKey)
	writeBindingField(h, opcert)
	var p [8]byte
	binary.BigEndian.PutUint64(p[:], period)
	h.Write(p[:])
	return h.Sum(nil)
}

type bindingWriter interface{ Write([]byte) (int, error) }

func writeBindingField(w bindingWriter, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = w.Write(size[:])
	_, _ = w.Write(value)
}
