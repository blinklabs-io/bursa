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

	rErrCRC   = 0x01
	rErrOther = 0x02

	sResyncRequest     = 0xc0
	sResyncResponse    = 0xe0
	sWTXRequest        = 0xc3
	sWTXResponse       = 0xe3
	sSoftResetRequest  = 0xcf
	sSoftResetResponse = 0xef
)

// ErrTimeout is returned when the SE050 does not answer within the block
// waiting time.
var ErrTimeout = errors.New("se050: block waiting time exceeded")

// errCorrupt marks a received frame that failed NAD, length or CRC checks.
var errCorrupt = errors.New("se050: corrupted frame")

// errRetries is returned when a block exchange fails maxAttempts times.
var errRetries = errors.New("se050: block exchange failed after retries")

// maxAttempts bounds the replies tried for one block before resynchronising.
const maxAttempts = 3

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

	// sendSeq is N(S) of the next host I-block, recvSeq the N(S) expected
	// in the next SE I-block
	sendSeq uint8
	recvSeq uint8

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
			return 0, nil, fmt.Errorf("%w: invalid NAD %#02x", errCorrupt, hdr[0])
		}

		pcb = hdr[1]
		n := int(hdr[2])

		if n > maxFrameData {
			return 0, nil, fmt.Errorf("%w: invalid frame length %d", errCorrupt, n)
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
			return 0, nil, fmt.Errorf("%w: CRC mismatch", errCorrupt)
		}

		if pcb == sWTXRequest {
			if len(data) != 1 {
				return 0, nil, errors.New("se050: invalid WTX request")
			}

			if err = t.writeFrame(frame(sWTXResponse, data)); err != nil {
				return 0, nil, err
			}

			deadline = time.Now().Add(t.bwt * time.Duration(max(data[0], 1)))
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

	t.sendSeq, t.recvSeq = 0, 0

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

func isIBlock(pcb byte) bool { return pcb&0x80 == 0 }
func isRBlock(pcb byte) bool { return pcb&0xc0 == rBlock }

// exchange sends block f and returns the SE's reply. A corrupted reply, a
// timeout or an SE I-block out of sequence is answered with an R-block
// asking for a resend; an SE R-block refusing f resends f. After
// maxAttempts failed replies it returns errRetries.
func (t *T1) exchange(f []byte) (pcb byte, data []byte, err error) {
	if err = t.writeFrame(f); err != nil {
		return
	}

	for attempt := 1; ; attempt++ {
		pcb, data, err = t.readFrame()

		code := byte(0)

		switch {
		case errors.Is(err, errCorrupt):
			code = rErrCRC
		case errors.Is(err, ErrTimeout):
			code = rErrOther
		case err != nil:
			return
		case isIBlock(pcb) && pcb>>6&1 != t.recvSeq:
			code = rErrOther
		case isRBlock(pcb) && isIBlock(f[1]) && (pcb&rBlockErr != 0 || pcb>>4&1 == f[1]>>6&1):
			// the SE asks for f again
		default:
			return pcb, data, nil
		}

		if attempt == maxAttempts {
			return 0, nil, fmt.Errorf("%w: last error %v, PCB %#02x", errRetries, err, pcb)
		}

		if code == 0 {
			err = t.writeFrame(f)
		} else {
			err = t.writeFrame(frame(rBlock|t.recvSeq<<4|code, nil))
		}

		if err != nil {
			return 0, nil, err
		}
	}
}

// Resync resynchronises the T=1 link, resetting both sequence counters.
func (t *T1) Resync() error {
	if err := t.writeFrame(frame(sResyncRequest, nil)); err != nil {
		return err
	}

	pcb, _, err := t.readFrame()

	if err != nil {
		return err
	}

	if pcb != sResyncResponse {
		return fmt.Errorf("se050: unexpected resync response PCB %#02x", pcb)
	}

	t.sendSeq, t.recvSeq = 0, 0

	return nil
}

// Transceive sends a command APDU, chaining it across I-blocks when it
// exceeds the frame size, and returns the reassembled response APDU. When
// block retries are exhausted it resynchronises the link and sends the APDU
// once more.
func (t *T1) Transceive(apdu []byte) ([]byte, error) {
	resp, err := t.transceive(apdu)

	if !errors.Is(err, errRetries) {
		return resp, err
	}

	if err = t.Resync(); err != nil {
		return nil, err
	}

	return t.transceive(apdu)
}

func (t *T1) transceive(apdu []byte) (resp []byte, err error) {
	var (
		pcb  byte
		data []byte
	)

	for off := 0; ; {
		n := min(len(apdu)-off, maxFrameData)
		last := off+n == len(apdu)

		ipcb := t.sendSeq << 6

		if !last {
			ipcb |= iBlockMore
		}

		if pcb, data, err = t.exchange(frame(ipcb, apdu[off:off+n])); err != nil {
			return
		}

		off += n

		if last {
			break
		}

		// the SE acknowledges each chained block with an R-block naming
		// the next sequence number
		if !isRBlock(pcb) || pcb&rBlockErr != 0 || len(data) != 0 || pcb>>4&1 != t.sendSeq^1 {
			return nil, fmt.Errorf("se050: expected R-block acknowledgement, got PCB %#02x", pcb)
		}

		t.sendSeq ^= 1
	}

	if !isIBlock(pcb) {
		return nil, fmt.Errorf("se050: expected I-block, got PCB %#02x", pcb)
	}

	// the SE's I-block acknowledges the last host block
	t.sendSeq ^= 1

	for {
		t.recvSeq ^= 1
		resp = append(resp, data...)

		if pcb&iBlockMore == 0 {
			return resp, nil
		}

		if pcb, data, err = t.exchange(frame(rBlock|t.recvSeq<<4, nil)); err != nil {
			return nil, err
		}

		if !isIBlock(pcb) {
			return nil, fmt.Errorf("se050: expected I-block, got PCB %#02x", pcb)
		}
	}
}
