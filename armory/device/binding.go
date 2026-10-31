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

// ProtocolSummary is the sign request version that asks for the signing
// policy's summary in the reply, bound by the binding signature. Inventory
// stays at Protocol.
const ProtocolSummary = "bursa-attested-signer/2"

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

// ResponseBinding is the digest the selected key signs alongside the Cardano
// signature: each request field and the signature, length-prefixed, so a
// response cannot be paired with another nonce, profile or payload. An absent
// era is an empty field. For Protocol it matches Bursa's
// backend.AttestedResponseBinding. Under ProtocolSummary the summary is one
// more field, present even when empty. A version-1 reply carries no summary;
// a summary on one does not verify.
func ResponseBinding(req SignRequest, signature []byte, summary string) []byte {
	h := sha256.New()

	var era []byte
	if req.Era != nil {
		era = []byte(strconv.FormatUint(uint64(*req.Era), 10))
	}

	for _, field := range [][]byte{
		[]byte(req.Version),
		[]byte(req.Purpose),
		[]byte(req.KeyHash),
		[]byte(req.Role),
		req.Nonce,
		req.Payload,
		[]byte(req.Profile),
		era,
		signature,
	} {
		h.Write([]byte(strconv.Itoa(len(field)) + ":"))
		h.Write(field)
	}

	if req.Version == ProtocolSummary || summary != "" {
		h.Write([]byte(strconv.Itoa(len(summary)) + ":" + summary))
	}

	return h.Sum(nil)
}

// requestDomain separates host signatures over requests from every other
// signature the host key could make.
const requestDomain = "bursa-armory-request/1"

// RequestBinding is the digest a host key signs to authenticate a signing
// request: the domain string, then each request field and the challenge,
// length-prefixed as in ResponseBinding. An absent era is an empty field.
func RequestBinding(req SignRequest) []byte {
	h := sha256.New()

	var era []byte
	if req.Era != nil {
		era = []byte(strconv.FormatUint(uint64(*req.Era), 10))
	}

	for _, field := range [][]byte{
		[]byte(requestDomain),
		[]byte(req.Version),
		[]byte(req.Purpose),
		[]byte(req.KeyHash),
		[]byte(req.Role),
		req.Nonce,
		req.Payload,
		[]byte(req.Profile),
		era,
		req.Challenge,
	} {
		h.Write([]byte(strconv.Itoa(len(field)) + ":"))
		h.Write(field)
	}

	return h.Sum(nil)
}

// signLogDomain separates host signatures over signing log reads from every
// other signature the host key could make.
const signLogDomain = "bursa-armory-signlog-read/1"

// SignLogBinding is the digest a host key signs to authenticate a signing log
// read: the domain string, the first block, the block count and the
// challenge, length-prefixed as in RequestBinding.
func SignLogBinding(req SignLogRequest) []byte {
	h := sha256.New()

	for _, field := range [][]byte{
		[]byte(signLogDomain),
		[]byte(strconv.FormatUint(req.From, 10)),
		[]byte(strconv.FormatUint(uint64(req.Count), 10)),
		req.Challenge,
	} {
		h.Write([]byte(strconv.Itoa(len(field)) + ":"))
		h.Write(field)
	}

	return h.Sum(nil)
}
