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
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// deadlineTripwire fails the test if a deadline method is called.
type deadlineTripwire struct {
	io.Reader
	io.Writer
	t *testing.T
}

func (d deadlineTripwire) SetReadDeadline(time.Time) error {
	d.t.Error("SetReadDeadline called by a deadline-free function")
	return nil
}

func (d deadlineTripwire) SetWriteDeadline(time.Time) error {
	d.t.Error("SetWriteDeadline called by a deadline-free function")
	return nil
}

func goldenFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "frames", name+".hex"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLimitVariantsRoundTripGoldenFrames(t *testing.T) {
	t.Parallel()
	for _, tc := range goldenCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fixture := goldenFixture(t, tc.name)
			var out bytes.Buffer
			w := deadlineTripwire{Writer: &out, t: t}
			if err := WriteFrameLimit(w, MaxFrameLen, tc.value); err != nil {
				t.Fatalf("WriteFrameLimit: %v", err)
			}
			if !bytes.Equal(out.Bytes(), fixture) {
				t.Fatalf("frame differs\n got %x\nwant %x", out.Bytes(), fixture)
			}
			r := deadlineTripwire{Reader: bytes.NewReader(fixture), t: t}
			got := tc.fresh()
			if err := ReadFrameLimit(r, MaxFrameLen, nil, got); err != nil {
				t.Fatalf("ReadFrameLimit: %v", err)
			}
			if g, w := mustJSON(t, got), mustJSON(t, tc.value); g != w {
				t.Fatalf("decoded %s, want %s", g, w)
			}
		})
	}
}

// countingReader records how many bytes were read.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestReadFrameLimitRefusesOversizeBeforeBody(t *testing.T) {
	t.Parallel()
	fixture := goldenFixture(t, "sign_request")
	if len(fixture)-4 <= 16 {
		t.Fatal("fixture too small for the test")
	}
	guardCalled := false
	cr := &countingReader{r: bytes.NewReader(fixture)}
	var req SignRequest
	err := ReadFrameLimit(cr, 16, func() error {
		guardCalled = true
		return nil
	}, &req)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("err = %v, want frame too large", err)
	}
	if cr.n != 4 {
		t.Fatalf("read %d bytes, want only the 4-byte header", cr.n)
	}
	if guardCalled {
		t.Fatal("bodyGuard ran for a refused frame")
	}
	// The same frame passes with a sufficient limit.
	if err := ReadFrameLimit(bytes.NewReader(fixture), len(fixture)-4, nil, &req); err != nil {
		t.Fatalf("exact limit refused: %v", err)
	}
}

func TestWriteFrameLimitRefusesOversize(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	err := WriteFrameLimit(&out, 16, SignRequest{Type: "sign_request", Message: make([]byte, 64)})
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("err = %v, want frame too large", err)
	}
	if out.Len() != 0 {
		t.Fatalf("%d bytes written for a refused frame", out.Len())
	}
}

func TestReadFrameLimitBodyGuardRunsOnceAfterHeader(t *testing.T) {
	t.Parallel()
	fixture := goldenFixture(t, "hello_sign")
	cr := &countingReader{r: bytes.NewReader(fixture)}
	calls, readAtCall := 0, -1
	var hello Hello
	err := ReadFrameLimit(cr, MaxHelloFrameLen, func() error {
		calls++
		readAtCall = cr.n
		return nil
	}, &hello)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || readAtCall != 4 {
		t.Fatalf("guard calls = %d after %d bytes, want 1 after 4", calls, readAtCall)
	}

	guardErr := errors.New("guard refused")
	cr = &countingReader{r: bytes.NewReader(fixture)}
	err = ReadFrameLimit(cr, MaxHelloFrameLen, func() error { return guardErr }, &hello)
	if !errors.Is(err, guardErr) || cr.n != 4 {
		t.Fatalf("err = %v after %d bytes, want guard error before the body", err, cr.n)
	}
}

// capture records the payload slice json hands it.
type capture struct {
	seen []byte
	copy []byte
}

func (c *capture) UnmarshalJSON(b []byte) error {
	c.seen = b
	c.copy = append([]byte(nil), b...)
	return nil
}

func TestReadFrameLimitWipesBody(t *testing.T) {
	t.Parallel()
	fixture := goldenFixture(t, "key_push")
	var c capture
	if err := ReadFrameLimit(bytes.NewReader(fixture), MaxKeyPushFrameLen, nil, &c); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(c.copy, []byte("kes_sign_key")) {
		t.Fatalf("decoder saw %q, not the key push", c.copy)
	}
	if len(c.seen) != len(c.copy) {
		t.Fatalf("captured %d bytes, copied %d", len(c.seen), len(c.copy))
	}
	for i, b := range c.seen {
		if b != 0 {
			t.Fatalf("payload byte %d not wiped", i)
		}
	}
}

func TestWriteFrameLimitShortWrite(t *testing.T) {
	t.Parallel()
	for _, limit := range []int{2, 4 + 10} {
		w := &shortWriter{limit: limit}
		err := WriteFrameLimit(w, MaxFrameLen, Hello{Protocol: ProtocolID, Mode: ModeSign})
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("limit %d: err = %v, want short write", limit, err)
		}
	}
}

// shortWriter accepts at most limit bytes in total without reporting an error.
type shortWriter struct {
	limit, n int
}

func (s *shortWriter) Write(p []byte) (int, error) {
	room := s.limit - s.n
	if room > len(p) {
		room = len(p)
	}
	s.n += room
	return room, nil
}

func jsonString(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	s, err := jsonString(v)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
