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
	"bytes"
	"testing"
)

// scriptedSE answers each host I-block with the next queued response APDU,
// acknowledging chained blocks with R-blocks. It records every command APDU.
type scriptedSE struct {
	bus      *fakeBus
	commands [][]byte
	pending  []byte
	replies  [][]byte
	seq      byte // N(S) of the next SE I-block
}

func newScriptedSE(replies ...[]byte) (*scriptedSE, *SE050) {
	s := &scriptedSE{bus: &fakeBus{}, replies: replies}

	s.bus.onWrite = func(f []byte) {
		pcb := f[1]

		if pcb&iBlockMask != 0 {
			return
		}

		s.pending = append(s.pending, f[3:3+int(f[2])]...)

		if pcb&iBlockMore != 0 {
			next := (pcb>>6&1 ^ 1) << 4
			s.bus.reads = append(s.bus.reads, seFrame(rBlock|next, nil))
			return
		}

		s.commands = append(s.commands, s.pending)
		s.pending = nil

		reply := []byte{0x90, 0x00}

		if len(s.replies) > 0 {
			reply, s.replies = s.replies[0], s.replies[1:]
		}

		s.bus.reads = append(s.bus.reads, seFrame(s.seq<<6, reply))
		s.seq ^= 1
	}

	return s, &SE050{t1: newTestT1(s.bus)}
}

func ok(data ...[]byte) []byte {
	return append(bytes.Join(data, nil), 0x90, 0x00)
}

func TestWriteBinaryCreatesThenWritesChunks(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 300)

	// exist check: no; then two writes
	s, se := newScriptedSE(ok(appendTLV(nil, tag1, []byte{resultFailure})))

	if err := se.WriteBinary(0x20e50300, data); err != nil {
		t.Fatal(err)
	}

	if len(s.commands) != 3 {
		t.Fatalf("got %d APDUs, want exist check + 2 writes", len(s.commands))
	}

	first := s.commands[1]

	if !bytes.Equal(first[:4], []byte{claSE, insWrite, p1Binary, p2Default}) {
		t.Fatalf("first write header % x", first[:4])
	}

	if v, err := findTLV(first[5:], tag3); err != nil || !bytes.Equal(v, []byte{0x01, 0x2c}) {
		t.Fatalf("file length TLV = % x, %v", v, err)
	}

	second := s.commands[2]

	if _, err := findTLV(second[5:], tag3); err == nil {
		t.Fatal("file length must only be sent on create")
	}

	if v, _ := findTLV(second[5:], tag2); !bytes.Equal(v, []byte{0x00, maxBinaryChunk}) {
		t.Fatalf("second write offset % x", v)
	}
}

func TestWriteBinaryRecreatesOnSizeChange(t *testing.T) {
	s, se := newScriptedSE(
		ok(appendTLV(nil, tag1, []byte{resultSuccess})),           // exists
		ok(appendTLV(nil, tag1, []byte{0, 0, 0, 0, 0, 0, 0, 10})), // size 10
	)

	if err := se.WriteBinary(0x20e50300, make([]byte, 20)); err != nil {
		t.Fatal(err)
	}

	// exist, size, delete, create
	if len(s.commands) != 4 || s.commands[2][3] != p2DeleteObject {
		t.Fatalf("expected delete before recreate, got %d APDUs", len(s.commands))
	}
}

func TestReadBinaryChunks(t *testing.T) {
	part1 := bytes.Repeat([]byte{1}, maxBinaryChunk)
	part2 := bytes.Repeat([]byte{2}, 300-maxBinaryChunk)

	s, se := newScriptedSE(
		ok(appendTLV(nil, tag1, []byte{0, 0, 0, 0, 0, 0, 0x01, 0x2c})),
		ok(appendTLV(nil, tag1, part1)),
		ok(appendTLV(nil, tag1, part2)),
	)

	got, err := se.ReadBinary(0x20e50300)

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, append(part1, part2...)) {
		t.Fatal("reassembled data mismatch")
	}

	if off, _ := findTLV(s.commands[2][5:], tag2); !bytes.Equal(off, []byte{0x00, maxBinaryChunk}) {
		t.Fatalf("second read offset % x", off)
	}
}

func TestFreeMemoryParse(t *testing.T) {
	s, se := newScriptedSE(ok(appendTLV(nil, tag1, []byte{0x7a, 0x12})))

	n, err := se.FreeMemory()

	if err != nil {
		t.Fatal(err)
	}

	if n != 0x7a12 {
		t.Fatalf("free = %#x", n)
	}

	if !bytes.Equal(s.commands[0][:4], []byte{claSE, insMgmt, p1Default, p2Memory}) {
		t.Fatalf("header % x", s.commands[0][:4])
	}

	if v, _ := findTLV(s.commands[0][5:], tag1); !bytes.Equal(v, []byte{memPersistent}) {
		t.Fatalf("memory type % x", v)
	}
}
