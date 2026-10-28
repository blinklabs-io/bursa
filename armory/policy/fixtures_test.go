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

package policy

import (
	"bytes"

	"github.com/fxamacker/cbor/v2"
)

// Bodies are built as raw CBOR so malformed shapes (duplicate keys,
// indefinite maps, unknown keys) can be expressed alongside valid ones.

func fill(b byte) (h [28]byte) {
	copy(h[:], bytes.Repeat([]byte{b}, len(h)))
	return h
}

var (
	testKeys = Keys{Pool: fill(0xa1), Owner: fill(0xb2), Fee: fill(0xc3)}
	foreign  = fill(0xdd)
)

type body map[uint64]any

var enc, _ = cbor.CoreDetEncOptions().EncMode()

func encode(v any) []byte {
	b, err := enc.Marshal(v)
	if err != nil {
		panic(err)
	}

	return b
}

func (b body) cbor() []byte { return encode(map[uint64]any(b)) }

func (b body) with(key uint64, v any) body {
	n := body{}

	for k, v := range b {
		n[k] = v
	}

	n[key] = v

	return n
}

func (b body) without(key uint64) body {
	n := b.with(key, nil)
	delete(n, key)

	return n
}

func enterprise(net uint8, h [28]byte) []byte {
	return append([]byte{0x60 | net}, h[:]...)
}

func base(net uint8, pay, stake [28]byte) []byte {
	return append(append([]byte{0x00 | net}, pay[:]...), stake[:]...)
}

func output(addr []byte) []any { return []any{addr, uint64(5_000_000)} }

// baseBody spends one input back to the fee wallet on testnet.
func baseBody() body {
	return body{
		0: []any{[]any{make([]byte, 32), uint64(0)}},
		1: []any{output(enterprise(0, testKeys.Fee))},
		2: uint64(200_000),
	}
}

func keyCred(h [28]byte) []any { return []any{uint64(0), h[:]} }

func poolReg(operator [28]byte, owners ...[28]byte) []any {
	return poolRegFields(operator, nil, owners...)
}

func poolRegFields(operator [28]byte, leios []any, owners ...[28]byte) []any {
	ownerList := []any{}

	for _, o := range owners {
		ownerList = append(ownerList, o[:])
	}

	reward := append([]byte{0xe0}, foreign[:]...)
	cert := []any{uint64(3), operator[:], make([]byte, 32)}

	if leios != nil {
		cert = append(cert, leios)
	}

	return append(cert,
		uint64(500_000_000), uint64(170_000_000),
		cbor.Tag{Number: 30, Content: []uint64{1, 100}},
		reward, ownerList,
		[]any{[]any{uint64(1), uint64(3001), "relay.example"}},
		nil,
	)
}

func retire(pool [28]byte) []any { return []any{uint64(4), pool[:], uint64(900)} }

func stakeReg(h [28]byte) []any { return []any{uint64(0), keyCred(h)} }

func registration(h [28]byte) []any {
	return []any{uint64(7), keyCred(h), uint64(2_000_000)}
}

func delegation(h, pool [28]byte) []any {
	return []any{uint64(2), keyCred(h), pool[:]}
}

func regDeleg(h, pool [28]byte) []any {
	return []any{uint64(11), keyCred(h), pool[:], uint64(2_000_000)}
}

func certs(c ...[]any) []any {
	l := []any{}
	for _, x := range c {
		l = append(l, x)
	}

	return l
}

// votes encodes {[voterType, hash]: {[txid, 0]: [1, null]}} by hand since a
// Go map can't key on an array.
func votes(voterType uint64, h [28]byte) cbor.RawMessage {
	v := []byte{0xa1}
	v = append(v, encode([]any{voterType, h[:]})...)
	v = append(v, 0xa1)
	v = append(v, encode([]any{make([]byte, 32), uint64(0)})...)
	v = append(v, encode([]any{uint64(1), nil})...)

	return v
}

func leiosKey() []any {
	return []any{bytes.Repeat([]byte{1}, 96), bytes.Repeat([]byte{2}, 48)}
}

// duplicateFee re-encodes baseBody with key 2 appearing twice.
func duplicateFee() []byte {
	b := baseBody().cbor()
	if b[0] != 0xa3 {
		panic("unexpected map header")
	}

	b = append([]byte{0xa4}, b[1:]...)

	b = append(b, encode(uint64(2))...)

	return append(b, encode(uint64(1))...)
}

func indefiniteBody() []byte {
	b := baseBody().cbor()
	b = append([]byte{0xbf}, b[1:]...)

	return append(b, 0xff)
}
