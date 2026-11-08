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

package kesagent

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"
)

// deadlineRecorder serves a fixed byte stream and records every read
// deadline it is given, relative to when it was set.
type deadlineRecorder struct {
	r         *bytes.Reader
	deadlines []time.Duration
}

func (d *deadlineRecorder) Read(p []byte) (int, error) { return d.r.Read(p) }

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		d.deadlines = append(d.deadlines, 0)
		return nil
	}
	d.deadlines = append(d.deadlines, time.Until(t))
	return nil
}

func encodedFrame(t *testing.T, v any) []byte {
	t.Helper()
	payload, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload))) //nolint:gosec
	return append(hdr[:], payload...)
}

// within reports whether got is in (want-slack, want].
func within(got, want time.Duration) bool {
	return got <= want && got > want-time.Second
}

func TestReadFrameIdleBoundsHeaderAndBodySeparately(t *testing.T) {
	t.Parallel()
	frame := encodedFrame(t, SignRequest{Type: SignRequestTypePing})

	rec := &deadlineRecorder{r: bytes.NewReader(frame)}
	var req SignRequest
	if err := readFrameIdle(rec, &req, time.Minute); err != nil {
		t.Fatalf("readFrameIdle: %v", err)
	}
	if len(rec.deadlines) != 3 ||
		!within(rec.deadlines[0], time.Minute) ||
		!within(rec.deadlines[1], frameIOTimeout) ||
		rec.deadlines[2] != 0 {
		t.Fatalf(
			"deadlines = %v, want [~1m (header), ~%v (body), cleared]",
			rec.deadlines,
			frameIOTimeout,
		)
	}

	// Without an idle bound, one frameIOTimeout covers header and body, as
	// before.
	rec = &deadlineRecorder{r: bytes.NewReader(frame)}
	if err := readFrame(rec, &req); err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if len(rec.deadlines) != 2 ||
		!within(rec.deadlines[0], frameIOTimeout) ||
		rec.deadlines[1] != 0 {
		t.Fatalf(
			"deadlines = %v, want [~%v (frame), cleared]",
			rec.deadlines,
			frameIOTimeout,
		)
	}
}

func TestHandleSignAnswersPingWithoutTouchingState(t *testing.T) {
	t.Parallel()
	a, _, spec := newHeaderAgent(t)
	floorBefore, setBefore := a.guard.Floor()

	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleSign(context.Background(), server, attestedSignIdleTimeout)
		_ = server.Close()
	}()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	for range 2 {
		if err := writeFrame(
			client,
			SignRequest{Type: SignRequestTypePing},
		); err != nil {
			t.Fatalf("write ping: %v", err)
		}
		var pong Pong
		if err := readFrame(client, &pong); err != nil {
			t.Fatalf("read pong: %v", err)
		}
		if pong.Type != "pong" {
			t.Fatalf("reply type = %q, want pong", pong.Type)
		}
	}
	if floor, set := a.guard.Floor(); floor != floorBefore || set != setBefore {
		t.Fatalf(
			"ping moved the period floor: %d %v -> %d %v",
			floorBefore, setBefore, floor, set,
		)
	}

	// The session still signs after pings.
	if err := writeFrame(client, SignRequest{
		Type: "sign_request", Period: 5, Message: spec.encode(t),
	}); err != nil {
		t.Fatalf("write sign request: %v", err)
	}
	var resp SignResponse
	if err := readFrame(client, &resp); err != nil {
		t.Fatalf("read sign response: %v", err)
	}
	if resp.Error != "" || len(resp.Signature) == 0 {
		t.Fatalf("sign after ping: error %q, %d-byte signature",
			resp.Error, len(resp.Signature))
	}
	_ = client.Close()
	<-done
}
