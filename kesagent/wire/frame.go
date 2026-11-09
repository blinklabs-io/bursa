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

	"github.com/blinklabs-io/bursa/internal/kesagent/securemem"
)

const (
	// MaxFrameLen is the agent's cap on a single frame payload.
	MaxFrameLen = 1 << 20 // 1 MiB

	// MaxHelloFrameLen is a suggested cap for the handshake frame.
	MaxHelloFrameLen = 4 << 10
	// MaxKeyPushFrameLen is a suggested cap for a serve-key push.
	MaxKeyPushFrameLen = 8 << 10
	// MaxSignFrameLen is a suggested cap for a sign-mode request or response.
	MaxSignFrameLen = 64 << 10
)

var (
	// ErrFrameTooLarge is wrapped by errors for a frame whose length exceeds
	// the caller's maximum, on read or write.
	ErrFrameTooLarge = errors.New("kesagent: frame too large")
	// ErrFrameBodyIncomplete is wrapped, together with the underlying error,
	// when a frame header was read but the body could not be.
	ErrFrameBodyIncomplete = errors.New("kesagent: frame body incomplete")
)

// WriteFrameLimit writes a single length-prefixed JSON frame whose payload is
// at most max bytes. It sets no deadline; the caller owns them. A payload from
// a FrameMarshaler is wiped after the write.
func WriteFrameLimit(w io.Writer, max int, v any) error {
	var payload []byte
	var err error
	if m, ok := v.(FrameMarshaler); ok {
		payload, err = m.MarshalFrame(max)
	} else {
		payload, err = json.Marshal(v)
	}
	// Wipe before checking err: a FrameMarshaler may return a partial
	// payload together with an error.
	defer securemem.Wipe(payload)
	if err != nil {
		return fmt.Errorf("kesagent: marshal frame: %w", err)
	}
	if len(payload) > max || uint64(len(payload)) > 1<<32-1 {
		return fmt.Errorf("%w (%d bytes)", ErrFrameTooLarge, len(payload))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(
		hdr[:],
		uint32(len(payload)), // #nosec G115 -- checked above
	)
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

// ReadFrameLimit reads a single length-prefixed JSON frame of at most max
// payload bytes into v. It sets no deadline; the caller owns them. A header
// read error is returned unwrapped so callers can distinguish io.EOF. Once the
// header is read, a failure reading the body wraps ErrFrameBodyIncomplete and
// the underlying error. The body buffer is wiped before ReadFrameLimit
// returns.
func ReadFrameLimit(r io.Reader, max int, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err // may be io.EOF; callers distinguish
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return errors.New("kesagent: zero-length frame")
	}
	if int64(n) > int64(max) {
		return fmt.Errorf("%w (%d bytes)", ErrFrameTooLarge, n)
	}
	body, err := readFrameBody(r, int(n)) // #nosec G115 -- n <= max
	// The body of a KeyPush carries the base64 signing key; wipe it on
	// every exit. json.Unmarshal copies decoded fields into v.
	defer securemem.Wipe(body)
	if err != nil {
		return fmt.Errorf(
			"kesagent: read frame payload: %w: %w",
			ErrFrameBodyIncomplete,
			err,
		)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("kesagent: unmarshal frame: %w", err)
	}
	return nil
}

// frameBodyInitialCap is the first allocation for a frame body.
const frameBodyInitialCap = 512

// readFrameBody reads exactly n bytes from r. It grows its buffer as bytes
// actually arrive rather than pre-allocating the full advertised length, so a
// client that announces a large frame but never sends the body ties up only
// what it delivered. Each superseded buffer is wiped when it is replaced. On
// error the returned slice holds the bytes read so far, for the caller to
// wipe; a body that ends early returns io.EOF, as io.CopyN does.
func readFrameBody(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, 0, min(n, frameBodyInitialCap))
	for len(buf) < n {
		if len(buf) == cap(buf) {
			grown := make([]byte, len(buf), min(2*cap(buf), n))
			copy(grown, buf)
			securemem.Wipe(buf)
			buf = grown
		}
		m, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+m]
		if err != nil {
			if len(buf) == n {
				break
			}
			return buf, err
		}
	}
	return buf, nil
}
