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

	// Suggested per-message caps for callers of ReadFrameLimit and
	// WriteFrameLimit. They are advisory: the Limit functions enforce only the
	// max they are given, and the agent keeps MaxFrameLen.

	// MaxHelloFrameLen bounds the initial handshake frame.
	MaxHelloFrameLen = 4 << 10
	// MaxKeyPushFrameLen bounds a serve-key push.
	MaxKeyPushFrameLen = 8 << 10
	// MaxSignFrameLen bounds a sign-mode request or response.
	MaxSignFrameLen = 64 << 10
)

// DeadlineWriter is a writer with a write deadline, such as a net.Conn.
type DeadlineWriter interface {
	io.Writer
	SetWriteDeadline(time.Time) error
}

// WriteFrame writes a single length-prefixed JSON frame, bounding the write
// with FrameIOTimeout.
func WriteFrame(w DeadlineWriter, v any) (retErr error) {
	if err := w.SetWriteDeadline(time.Now().Add(FrameIOTimeout)); err != nil {
		return fmt.Errorf("kesagent: set frame write deadline: %w", err)
	}
	defer func() {
		if err := w.SetWriteDeadline(time.Time{}); retErr == nil && err != nil {
			retErr = fmt.Errorf("kesagent: clear frame write deadline: %w", err)
		}
	}()
	return WriteFrameLimit(w, MaxFrameLen, v)
}

// WriteFrameLimit writes a single length-prefixed JSON frame of at most max
// payload bytes (and never more than MaxFrameLen). It sets no deadline; the
// caller owns them. A short write is an error.
func WriteFrameLimit(w io.Writer, max int, v any) error {
	if max > MaxFrameLen {
		max = MaxFrameLen
	}
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
	if len(payload) > max {
		return fmt.Errorf("kesagent: frame too large (%d bytes)", len(payload))
	}
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

// ReadFrame reads a single length-prefixed JSON frame into v, bounding the
// whole read with FrameIOTimeout.
func ReadFrame(r DeadlineReader, v any) (retErr error) {
	if err := r.SetReadDeadline(time.Now().Add(FrameIOTimeout)); err != nil {
		return fmt.Errorf("kesagent: set frame read deadline: %w", err)
	}
	defer func() {
		if err := r.SetReadDeadline(time.Time{}); retErr == nil && err != nil {
			retErr = fmt.Errorf("kesagent: clear frame read deadline: %w", err)
		}
	}()
	return ReadFrameLimit(r, MaxFrameLen, nil, v)
}

// ReadFrameLimit reads a single length-prefixed JSON frame of at most max
// payload bytes (and never more than MaxFrameLen) into v. It sets no
// deadline; the caller owns them. bodyGuard, if non-nil, runs after the
// 4-byte header is read and before the body is read, so a caller can set a
// body deadline there; an error from it aborts the read. The body is read
// into one buffer of the exact advertised size, which is wiped before the
// function returns, so an inbound KeyPush leaves no key bytes behind.
func ReadFrameLimit(
	r io.Reader,
	max int,
	bodyGuard func() error,
	v any,
) error {
	if max > MaxFrameLen {
		max = MaxFrameLen
	}
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err // may be io.EOF; callers distinguish
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return errors.New("kesagent: zero-length frame")
	}
	if uint64(n) > uint64(max) {
		return fmt.Errorf("kesagent: frame too large (%d bytes)", n)
	}
	if bodyGuard != nil {
		if err := bodyGuard(); err != nil {
			return err
		}
	}
	payload := make([]byte, n)
	defer securemem.Wipe(payload)
	if _, err := io.ReadFull(r, payload); err != nil {
		return fmt.Errorf("kesagent: read frame payload: %w", err)
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return fmt.Errorf("kesagent: unmarshal frame: %w", err)
	}
	return nil
}
