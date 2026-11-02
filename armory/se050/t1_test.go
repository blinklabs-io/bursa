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
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// fakeBus replays queued SE frames and records host writes. An empty queue
// behaves like an address NACK.
type fakeBus struct {
	writes [][]byte
	reads  [][]byte
	cur    []byte

	// onWrite, when set, lets a test queue a reply to each host frame
	onWrite func(f []byte)
}

func (b *fakeBus) Write(buf []byte) error {
	b.writes = append(b.writes, bytes.Clone(buf))

	if b.onWrite != nil {
		b.onWrite(buf)
	}

	return nil
}

func (b *fakeBus) Read(n int) ([]byte, error) {
	if len(b.cur) == 0 {
		if len(b.reads) == 0 {
			return nil, errors.New("nack")
		}

		b.cur, b.reads = b.reads[0], b.reads[1:]
	}

	if len(b.cur) < n {
		return nil, errors.New("short read")
	}

	r := b.cur[:n]
	b.cur = b.cur[n:]

	return r, nil
}

func seFrame(pcb byte, data []byte) []byte {
	f := frame(pcb, data)
	f[0] = nadSEToHost
	crc := crc16(f[:len(f)-2])
	f[len(f)-2], f[len(f)-1] = byte(crc), byte(crc>>8)
	return f
}

func newTestT1(bus Bus) *T1 {
	t := NewT1(bus)
	t.sleep = func(time.Duration) {}
	t.bwt = 50 * time.Millisecond
	return t
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)

	if err != nil {
		t.Fatal(err)
	}

	return b
}

func TestCRC16X25CheckValue(t *testing.T) {
	// standard CRC catalogue check value for CRC-16/X-25
	if got := crc16([]byte("123456789")); got != 0x906e {
		t.Fatalf("crc16 = %#04x, want 0x906e", got)
	}
}

func TestFrameLayout(t *testing.T) {
	f := frame(sSoftResetRequest, nil)

	if !bytes.Equal(f[:3], []byte{0x5a, 0xcf, 0x00}) {
		t.Fatalf("header = % x", f[:3])
	}

	crc := crc16(f[:3])

	if f[3] != byte(crc) || f[4] != byte(crc>>8) {
		t.Fatalf("trailer = % x, want little-endian %#04x", f[3:], crc)
	}
}

const testATR = "00a0000003960403e800fe020b03e80801000000006400000a4a434f5034204154504f"

func TestParseATR(t *testing.T) {
	atr, err := parseATR(mustHex(t, testATR))

	if err != nil {
		t.Fatal(err)
	}

	if atr.BWT != time.Second || atr.IFSC != 0xfe || atr.MPOT != time.Millisecond ||
		atr.SEGT != 100*time.Microsecond || atr.WUT != 0 {
		t.Fatalf("unexpected ATR %+v", atr)
	}

	if string(atr.Historical) != "JCOP4 ATPO" {
		t.Fatalf("historical bytes = %q", atr.Historical)
	}
}

func TestParseATRTruncated(t *testing.T) {
	full := mustHex(t, testATR)

	for n := range len(full) {
		if _, err := parseATR(full[:n]); err == nil {
			t.Fatalf("parseATR accepted %d of %d bytes", n, len(full))
		}
	}
}

func TestSoftResetAppliesATRTimings(t *testing.T) {
	bus := &fakeBus{reads: [][]byte{seFrame(sSoftResetResponse, mustHex(t, testATR))}}
	t1 := newTestT1(bus)
	t1.sendSeq = 1

	if _, err := t1.SoftReset(); err != nil {
		t.Fatal(err)
	}

	if t1.sendSeq != 0 || t1.bwt != time.Second || t1.segt != 100*time.Microsecond {
		t.Fatalf("timings not applied: seq %d bwt %v segt %v", t1.sendSeq, t1.bwt, t1.segt)
	}
}

func TestTransceiveSingleBlock(t *testing.T) {
	bus := &fakeBus{reads: [][]byte{seFrame(0x00, []byte{0x90, 0x00})}}
	t1 := newTestT1(bus)

	res, err := t1.Transceive([]byte{0x80, 0x04, 0x00, 0x20, 0x00})

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(res, []byte{0x90, 0x00}) {
		t.Fatalf("response = % x", res)
	}

	if want := frame(0x00, []byte{0x80, 0x04, 0x00, 0x20, 0x00}); !bytes.Equal(bus.writes[0], want) {
		t.Fatalf("frame = % x, want % x", bus.writes[0], want)
	}

	if t1.sendSeq != 1 {
		t.Fatalf("send sequence not toggled")
	}
}

func TestTransceiveChainedCommand(t *testing.T) {
	apdu := bytes.Repeat([]byte{0xaa}, maxFrameData+10)
	bus := &fakeBus{}
	bus.onWrite = func(f []byte) {
		switch f[1] {
		case iBlockMore: // first chained block, seq 0
			bus.reads = append(bus.reads, seFrame(rBlock|rBlockSeq, nil))
		case iBlockSeq: // last block, seq 1
			bus.reads = append(bus.reads, seFrame(0x00, []byte{0x90, 0x00}))
		}
	}

	if _, err := newTestT1(bus).Transceive(apdu); err != nil {
		t.Fatal(err)
	}

	if len(bus.writes) != 2 || bus.writes[0][2] != maxFrameData || bus.writes[1][2] != 10 {
		t.Fatalf("unexpected chaining: %d frames", len(bus.writes))
	}
}

func TestTransceiveChainedResponse(t *testing.T) {
	bus := &fakeBus{}
	bus.onWrite = func(f []byte) {
		switch f[1] {
		case 0x00: // command
			bus.reads = append(bus.reads, seFrame(iBlockMore, []byte{0x01, 0x02}))
		case rBlock | rBlockSeq: // host requests block with seq 1
			bus.reads = append(bus.reads, seFrame(iBlockSeq, []byte{0x90, 0x00}))
		}
	}

	res, err := newTestT1(bus).Transceive([]byte{0x00})

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(res, []byte{0x01, 0x02, 0x90, 0x00}) {
		t.Fatalf("response = % x", res)
	}
}

func TestTransceiveAnswersWTX(t *testing.T) {
	bus := &fakeBus{reads: [][]byte{
		seFrame(sWTXRequest, []byte{0x02}),
		seFrame(0x00, []byte{0x90, 0x00}),
	}}

	if _, err := newTestT1(bus).Transceive([]byte{0x00}); err != nil {
		t.Fatal(err)
	}

	if want := frame(sWTXResponse, []byte{0x02}); !bytes.Equal(bus.writes[1], want) {
		t.Fatalf("WTX response = % x, want % x", bus.writes[1], want)
	}
}

func TestReadFrameRejectsBadCRC(t *testing.T) {
	f := seFrame(0x00, []byte{0x90, 0x00})
	f[len(f)-1] ^= 0xff

	if _, err := newTestT1(&fakeBus{reads: [][]byte{f}}).Transceive([]byte{0x00}); err == nil {
		t.Fatal("corrupted frame accepted")
	}
}

func TestReadFrameTimesOut(t *testing.T) {
	_, err := newTestT1(&fakeBus{}).Transceive([]byte{0x00})

	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
}

func corrupt(f []byte) []byte {
	f = bytes.Clone(f)
	f[len(f)-1] ^= 0xff

	return f
}

func TestTransceiveRetransmitsOnBadCRC(t *testing.T) {
	good := seFrame(0x00, []byte{0x90, 0x00})
	bus := &fakeBus{reads: [][]byte{corrupt(good), good}}

	res, err := newTestT1(bus).Transceive([]byte{0x00})

	if err != nil || !bytes.Equal(res, []byte{0x90, 0x00}) {
		t.Fatalf("res % x, err %v", res, err)
	}

	// R-block expecting SE sequence 0, CRC error
	if want := frame(rBlock|0x01, nil); len(bus.writes) != 2 || !bytes.Equal(bus.writes[1], want) {
		t.Fatalf("writes % x, want R(err) % x", bus.writes, want)
	}
}

func TestTransceiveResendsOnSERBlock(t *testing.T) {
	bus := &fakeBus{reads: [][]byte{
		seFrame(rBlock|0x01, nil), // SE got our block corrupted
		seFrame(0x00, []byte{0x90, 0x00}),
	}}

	if _, err := newTestT1(bus).Transceive([]byte{0x00}); err != nil {
		t.Fatal(err)
	}

	if len(bus.writes) != 2 || !bytes.Equal(bus.writes[0], bus.writes[1]) {
		t.Fatalf("I-block not retransmitted: % x", bus.writes)
	}
}

func TestTransceiveResyncAfterRetries(t *testing.T) {
	good := seFrame(0x00, []byte{0x90, 0x00})
	bad := corrupt(good)
	bus := &fakeBus{reads: [][]byte{bad, bad, bad, seFrame(sResyncResponse, nil), good}}
	t1 := newTestT1(bus)
	t1.sendSeq, t1.recvSeq = 1, 1

	// sequence 1 so the resent block after resync visibly restarts at 0
	bus.reads[4] = seFrame(0x00, []byte{0x90, 0x00})

	res, err := t1.Transceive([]byte{0x00})

	if err != nil || !bytes.Equal(res, []byte{0x90, 0x00}) {
		t.Fatalf("res % x, err %v", res, err)
	}

	// I(1), R(err), R(err), S(RESYNCH), I(0)
	if len(bus.writes) != 5 || !bytes.Equal(bus.writes[3], frame(sResyncRequest, nil)) || bus.writes[4][1] != 0x00 {
		t.Fatalf("writes % x", bus.writes)
	}

	if t1.sendSeq != 1 || t1.recvSeq != 1 {
		t.Fatalf("sequence after resync exchange: send %d recv %d", t1.sendSeq, t1.recvSeq)
	}
}

func TestSendSeqNotToggledWithoutAck(t *testing.T) {
	t1 := newTestT1(&fakeBus{})

	if _, err := t1.Transceive([]byte{0x00}); err == nil {
		t.Fatal("no reply accepted")
	}

	if t1.sendSeq != 0 {
		t.Fatal("send sequence toggled for an unacknowledged block")
	}
}

func TestTransceiveRejectsWrongSESequence(t *testing.T) {
	// an I-block with sequence 1 when 0 is expected is never accepted
	wrong := seFrame(iBlockSeq, []byte{0x90, 0x00})
	bus := &fakeBus{reads: [][]byte{wrong, wrong, wrong, seFrame(sResyncResponse, nil), seFrame(0x00, []byte{0x90, 0x00})}}

	if _, err := newTestT1(bus).Transceive([]byte{0x00}); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bus.writes[1], frame(rBlock|0x02, nil)) {
		t.Fatalf("expected R(other error), got % x", bus.writes[1])
	}
}

func TestReopenResetsAndSelects(t *testing.T) {
	version := []byte{3, 1, 1, 0x6f, 0xff, 1, 11, 0x90, 0x00}
	bus := &fakeBus{}
	se := &SE050{t1: newTestT1(bus)}
	se.t1.sendSeq, se.t1.recvSeq = 1, 1

	bus.reads = [][]byte{seFrame(sSoftResetResponse, mustHex(t, testATR)), seFrame(0x00, version)}

	if err := se.Reopen(); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bus.writes[0], frame(sSoftResetRequest, nil)) || bus.writes[1][1] != 0x00 {
		t.Fatalf("writes % x", bus.writes)
	}

	if !se.Version.EdDSA() || string(se.ATR.Historical) != "JCOP4 ATPO" {
		t.Fatalf("session not refreshed: %+v", se)
	}
}
