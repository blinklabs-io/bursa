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

// Package se050 drives an NXP SE050 secure element over I²C using the
// T=1 over I²C transport (NXP UM11225) and the SE05x APDU set (NXP AN12413).
//
// The package has no hardware dependencies: callers supply a Bus that
// performs plain I²C reads and writes to the SE050 target address.
package se050

import (
	"errors"
	"fmt"
	"time"
)

// Bus performs plain I²C transfers to the SE050 target. Neither method may
// send a register address: the SE050 rejects write-then-read transfers
// with a repeated start (UM11225 3.1.1.1).
type Bus interface {
	Write(buf []byte) error
	Read(n int) ([]byte, error)
}

const (
	nadHostToSE = 0x5a
	nadSEToHost = 0xa5

	maxFrameData = 0xfe

	iBlockMask = 0x9f
	iBlockSeq  = 0x40
	iBlockMore = 0x20

	rBlock     = 0x80
	rBlockMask = 0xec
	rBlockSeq  = 0x10
	rBlockErr  = 0x03

	sWTXRequest        = 0xc3
	sWTXResponse       = 0xe3
	sSoftResetRequest  = 0xcf
	sSoftResetResponse = 0xef
)

// ErrTimeout is returned when the SE050 does not answer within the block
// waiting time.
var ErrTimeout = errors.New("se050: block waiting time exceeded")

// ATR is the answer to reset returned by an interface soft reset.
type ATR struct {
	// BWT is the block waiting time.
	BWT time.Duration
	// IFSC is the maximum information field size of the SE.
	IFSC int
	// MPOT is the minimum polling time.
	MPOT time.Duration
	// SEGT is the guard time between frames.
	SEGT time.Duration
	// WUT is the wake-up time.
	WUT time.Duration
	// Historical holds the historical bytes.
	Historical []byte
}

// T1 implements the T=1 over I²C block transport.
type T1 struct {
	bus   Bus
	sleep func(time.Duration)

	sendSeq uint8

	bwt  time.Duration
	mpot time.Duration
	segt time.Duration
}

// NewT1 returns a transport with conservative timings, which an interface
// soft reset replaces with the values advertised in the ATR.
func NewT1(bus Bus) *T1 {
	return &T1{
		bus:   bus,
		sleep: time.Sleep,
		bwt:   time.Second,
		mpot:  time.Millisecond,
		segt:  10 * time.Microsecond,
	}
}

func crc16(data []byte) uint16 {
	// CRC-16/X-25: reflected polynomial 0x1021, init and final XOR 0xffff.
	crc := uint16(0xffff)

	for _, b := range data {
		crc ^= uint16(b)

		for range 8 {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0x8408
			} else {
				crc >>= 1
			}
		}
	}

	return ^crc
}

func frame(pcb byte, data []byte) []byte {
	f := make([]byte, 0, 3+len(data)+2)
	f = append(f, nadHostToSE, pcb, byte(len(data)))
	f = append(f, data...)
	crc := crc16(f)

	// the CRC is transmitted least significant byte first
	return append(f, byte(crc), byte(crc>>8))
}

// writeFrame retries until the SE050 accepts the frame, as it NACKs its
// address while busy or waking up.
func (t *T1) writeFrame(f []byte) (err error) {
	deadline := time.Now().Add(t.bwt)

	for {
		if err = t.bus.Write(f); err == nil {
			t.sleep(t.segt)
			return
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("se050: write failed, %w (last error: %v)", ErrTimeout, err)
		}

		t.sleep(t.mpot)
	}
}

// readFrame polls for a frame, answering waiting time extension requests
// transparently.
func (t *T1) readFrame() (pcb byte, data []byte, err error) {
	deadline := time.Now().Add(t.bwt)

	for {
		hdr, err := t.bus.Read(3)

		if err != nil {
			if time.Now().After(deadline) {
				return 0, nil, fmt.Errorf("se050: read failed, %w (last error: %v)", ErrTimeout, err)
			}

			t.sleep(t.mpot)
			continue
		}

		if hdr[0] != nadSEToHost {
			return 0, nil, fmt.Errorf("se050: invalid NAD %#02x", hdr[0])
		}

		pcb = hdr[1]
		n := int(hdr[2])

		if n > maxFrameData {
			return 0, nil, fmt.Errorf("se050: invalid frame length %d", n)
		}

		data = []byte{}

		if n > 0 {
			if data, err = t.bus.Read(n); err != nil {
				return 0, nil, err
			}
		}

		trailer, err := t.bus.Read(2)

		if err != nil {
			return 0, nil, err
		}

		crc := crc16(append(hdr, data...))

		if trailer[0] != byte(crc) || trailer[1] != byte(crc>>8) {
			return 0, nil, errors.New("se050: frame CRC mismatch")
		}

		if pcb == sWTXRequest {
			if len(data) != 1 {
				return 0, nil, errors.New("se050: invalid WTX request")
			}

			if err = t.writeFrame(frame(sWTXResponse, data)); err != nil {
				return 0, nil, err
			}

			deadline = time.Now().Add(t.bwt * time.Duration(data[0]))
			continue
		}

		return pcb, data, nil
	}
}

// SoftReset performs an interface soft reset, which resets sequence
// counters and returns the ATR.
func (t *T1) SoftReset() (atr *ATR, err error) {
	if err = t.writeFrame(frame(sSoftResetRequest, nil)); err != nil {
		return
	}

	pcb, data, err := t.readFrame()

	if err != nil {
		return
	}

	if pcb != sSoftResetResponse {
		return nil, fmt.Errorf("se050: unexpected soft reset response PCB %#02x", pcb)
	}

	if atr, err = parseATR(data); err != nil {
		return
	}

	t.sendSeq = 0

	// zero values would turn polling into a busy loop, keep the defaults
	if atr.BWT > 0 {
		t.bwt = atr.BWT
	}

	if atr.MPOT > 0 {
		t.mpot = atr.MPOT
	}

	t.segt = atr.SEGT

	return
}

func parseATR(b []byte) (*ATR, error) {
	errShort := errors.New("se050: truncated ATR")

	// protocol version (1), vendor ID (5), DLLP length (1)
	if len(b) < 7 {
		return nil, errShort
	}

	// data link layer parameters: BWT (2), IFSC (2)
	n := int(b[6])
	b = b[7:]

	if n < 4 || len(b) < n {
		return nil, errShort
	}

	atr := &ATR{
		BWT:  time.Duration(be16(b[0:])) * time.Millisecond,
		IFSC: int(be16(b[2:])),
	}
	b = b[n:]

	// physical layer ID (1), PLP length (1)
	if len(b) < 2 {
		return nil, errShort
	}

	// physical layer parameters: MCF (2), config (1), MPOT (1), RFU (3),
	// SEGT (2), WUT (2)
	n = int(b[1])
	b = b[2:]

	if n < 11 || len(b) < n {
		return nil, errShort
	}

	atr.MPOT = time.Duration(b[3]) * time.Millisecond
	atr.SEGT = time.Duration(be16(b[7:])) * time.Microsecond
	atr.WUT = time.Duration(be16(b[9:])) * time.Microsecond
	b = b[n:]

	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return nil, errShort
	}

	atr.Historical = append([]byte{}, b[1:1+int(b[0])]...)

	return atr, nil
}

func be16(b []byte) uint16 {
	return uint16(b[0])<<8 | uint16(b[1])
}

// Transceive sends a command APDU, chaining it across I-blocks when it
// exceeds the frame size, and returns the reassembled response APDU.
func (t *T1) Transceive(apdu []byte) (resp []byte, err error) {
	for off := 0; ; {
		n := min(len(apdu)-off, maxFrameData)
		last := off+n == len(apdu)

		pcb := t.sendSeq << 6

		if !last {
			pcb |= iBlockMore
		}

		if err = t.writeFrame(frame(pcb, apdu[off:off+n])); err != nil {
			return
		}

		t.sendSeq ^= 1
		off += n

		if last {
			break
		}

		// the SE acknowledges each chained block with an R-block
		rpcb, rdata, err := t.readFrame()

		if err != nil {
			return nil, err
		}

		if rpcb&rBlockMask != rBlock || len(rdata) != 0 {
			return nil, fmt.Errorf("se050: expected R-block, got PCB %#02x", rpcb)
		}

		if rpcb&rBlockErr != 0 {
			return nil, fmt.Errorf("se050: R-block error %d", rpcb&rBlockErr)
		}
	}

	for {
		pcb, data, err := t.readFrame()

		if err != nil {
			return nil, err
		}

		if pcb&iBlockMask != 0 {
			return nil, fmt.Errorf("se050: expected I-block, got PCB %#02x", pcb)
		}

		resp = append(resp, data...)

		if pcb&iBlockMore == 0 {
			return resp, nil
		}

		// acknowledge with the sequence number of the next expected block
		next := (pcb>>6&1 ^ 1) << 4

		if err = t.writeFrame(frame(rBlock|next, nil)); err != nil {
			return nil, err
		}
	}
}
