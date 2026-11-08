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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/blinklabs-io/bursa/internal/kesagent/securemem"
)

const (
	// MaxFrameLen caps a single frame payload to guard against abuse.
	MaxFrameLen = 1 << 20 // 1 MiB

	// FrameIOTimeout bounds a complete inbound or outbound frame. Inbound
	// timing includes idle time before the length header; outbound timing starts
	// immediately before the header write.
	FrameIOTimeout = 10 * time.Second
)

// DeadlineWriter is a writer with a write deadline, such as a net.Conn.
type DeadlineWriter interface {
	io.Writer
	SetWriteDeadline(time.Time) error
}

// WriteFrame writes a single length-prefixed JSON frame.
func WriteFrame(w DeadlineWriter, v any) (retErr error) {
	var payload []byte
	var err error
	if m, ok := v.(FrameMarshaler); ok {
		payload, err = m.MarshalFrame()
	} else {
		payload, err = json.Marshal(v)
	}
	if err != nil {
		return fmt.Errorf("kesagent: marshal frame: %w", err)
	}
	defer securemem.Wipe(payload)
	if len(payload) > MaxFrameLen {
		return fmt.Errorf("kesagent: frame too large (%d bytes)", len(payload))
	}
	if err := w.SetWriteDeadline(time.Now().Add(FrameIOTimeout)); err != nil {
		return fmt.Errorf("kesagent: set frame write deadline: %w", err)
	}
	defer func() {
		if err := w.SetWriteDeadline(time.Time{}); retErr == nil && err != nil {
			retErr = fmt.Errorf("kesagent: clear frame write deadline: %w", err)
		}
	}()
	var hdr [4]byte
	binary.BigEndian.PutUint32(
		hdr[:],
		uint32(len(payload)),
	) // #nosec G115 -- bounded by MaxFrameLen
	n, err := w.Write(hdr[:])
	if err != nil {
		return fmt.Errorf("kesagent: write frame header: %w", err)
	}
	if n != len(hdr) {
		return fmt.Errorf("kesagent: write frame header: %w", io.ErrShortWrite)
	}
	n, err = w.Write(payload)
	if err != nil {
		return fmt.Errorf("kesagent: write frame payload: %w", err)
	}
	if n != len(payload) {
		return fmt.Errorf("kesagent: write frame payload: %w", io.ErrShortWrite)
	}
	return nil
}

// DeadlineReader is a reader with a read deadline, such as a net.Conn.
type DeadlineReader interface {
	io.Reader
	SetReadDeadline(time.Time) error
}

// ReadFrame reads a single length-prefixed JSON frame into v.
func ReadFrame(r DeadlineReader, v any) (retErr error) {
	if err := r.SetReadDeadline(time.Now().Add(FrameIOTimeout)); err != nil {
		return fmt.Errorf("kesagent: set frame read deadline: %w", err)
	}
	defer func() {
		if err := r.SetReadDeadline(time.Time{}); retErr == nil && err != nil {
			retErr = fmt.Errorf("kesagent: clear frame read deadline: %w", err)
		}
	}()
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err // may be io.EOF; callers distinguish
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return errors.New("kesagent: zero-length frame")
	}
	if n > MaxFrameLen {
		return fmt.Errorf("kesagent: frame too large (%d bytes)", n)
	}
	// Grow the payload buffer as bytes actually arrive rather than
	// pre-allocating the full advertised length: a client that announces a
	// large frame (up to MaxFrameLen) but never sends the body then ties up
	// only what it actually delivered, not the whole advertised buffer.
	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, r, int64(n)); err != nil {
		return fmt.Errorf("kesagent: read frame payload: %w", err)
	}
	payload := buf.Bytes()
	if err := json.Unmarshal(payload, v); err != nil {
		return fmt.Errorf("kesagent: unmarshal frame: %w", err)
	}
	return nil
}
