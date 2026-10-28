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
	"crypto/sha256"
	"strconv"
)

// Protocol is the attested-signer protocol version Bursa speaks.
const Protocol = "bursa-attested-signer/1"

// KeyInfo is one key in an inventory.
type KeyInfo struct {
	Role      string `json:"role"`
	PublicKey []byte `json:"public_key"`
}

// InventoryBinding is the digest the identity key signs for an inventory. It
// matches Bursa's backend.InventoryBinding: the protocol version, the
// caller's nonce, then each key's length-prefixed role and public key.
func InventoryBinding(nonce []byte, keys []KeyInfo) []byte {
	h := sha256.New()
	h.Write([]byte(Protocol))
	h.Write(nonce)

	for _, k := range keys {
		h.Write([]byte(strconv.Itoa(len(k.Role)) + ":" + k.Role))
		h.Write(k.PublicKey)
	}

	return h.Sum(nil)
}
