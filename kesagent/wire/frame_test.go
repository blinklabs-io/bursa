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
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"
)

type retainingFrameWriter struct {
	writes     int
	header     []byte
	payload    []byte
	wire       []byte
	payloadErr error
}

func (w *retainingFrameWriter) SetWriteDeadline(time.Time) error {
	return nil
}

func (w *retainingFrameWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		w.header = append(w.header, p...)
		return len(p), nil
	}
	w.payload = p
	w.wire = append(w.wire, p...)
	if w.payloadErr != nil {
		return 0, w.payloadErr
	}
	return len(p), nil
}

func TestWriteFrameWipesKeyPushPayload(t *testing.T) {
	t.Parallel()
	errPayloadWrite := errors.New("payload write failed")
	for _, test := range []struct {
		name       string
		payloadErr error
	}{
		{name: "success"},
		{name: "payload error", payloadErr: errPayloadWrite},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			secret := bytes.Repeat([]byte{0x5a}, 64)
			writer := &retainingFrameWriter{payloadErr: test.payloadErr}
			t.Cleanup(func() {
				clear(secret)
				clear(writer.wire)
			})
			push := KeyPush{
				Type:       "key_push",
				Period:     42,
				Depth:      6,
				KESSignKey: secret,
				KESVKey:    bytes.Repeat([]byte{0x2a}, 32),
				OpCert:     []byte{0x81, 0x01},
			}

			err := WriteFrameLimit(writer, MaxFrameLen, push)
			if !errors.Is(err, test.payloadErr) {
				t.Fatalf(
					"WriteFrameLimit() error = %v, want %v",
					err,
					test.payloadErr,
				)
			}
			if len(writer.payload) == 0 {
				t.Fatal("writer did not retain the serialized payload")
			}
			if !bytes.Equal(writer.payload, make([]byte, len(writer.payload))) {
				t.Fatal(
					"serialized KeyPush payload retained secret-bearing bytes after write returned",
				)
			}

			if test.payloadErr == nil {
				if len(writer.header) != 4 {
					t.Fatalf(
						"frame header length = %d, want 4",
						len(writer.header),
					)
				}
				if got := binary.BigEndian.Uint32(writer.header); got != uint32(
					len(writer.wire),
				) {
					t.Fatalf(
						"frame payload length = %d, want %d",
						got,
						len(writer.wire),
					)
				}
				var decoded KeyPush
				if err := json.Unmarshal(writer.wire, &decoded); err != nil {
					t.Fatalf("unmarshal written payload: %v", err)
				}
				if !bytes.Equal(decoded.KESSignKey, secret) {
					t.Fatal("written KeyPush signing key changed")
				}
			}
		})
	}
}

func TestKeyPushMarshalFrameMatchesJSON(t *testing.T) {
	t.Parallel()
	for _, push := range []KeyPush{
		{Type: "key_push", Period: 42, Depth: 6, KESSignKey: []byte{1, 2, 3}, KESVKey: []byte{4}, OpCert: []byte{5}},
		{Type: "key_push"},
		{Type: "a\"b<\n", Period: 1<<64 - 1, Depth: 1<<64 - 1, KESSignKey: []byte{}, KESVKey: nil, OpCert: []byte{0xff, 0xfe}},
	} {
		want, err := json.Marshal(push)
		if err != nil {
			t.Fatal(err)
		}
		got, err := push.MarshalFrame(MaxFrameLen)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("MarshalFrame() = %s, want %s", got, want)
		}
		if cap(got) != len(got) {
			t.Fatalf(
				"MarshalFrame() cap = %d, len = %d: buffer was not sized exactly",
				cap(got),
				len(got),
			)
		}
	}
}

func TestKeyPushMarshalFrameExactLimit(t *testing.T) {
	t.Parallel()
	for _, v := range []uint64{0, 9, 10, 1<<64 - 1} {
		push := KeyPush{
			Type:       "key_push",
			Period:     v,
			Depth:      v,
			KESSignKey: []byte{1, 2, 3},
			KESVKey:    []byte{4},
			OpCert:     []byte{5},
		}
		want, err := json.Marshal(push)
		if err != nil {
			t.Fatal(err)
		}
		got, err := push.MarshalFrame(len(want))
		if err != nil {
			t.Fatalf("MarshalFrame(%d) with period %d: %v", len(want), v, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("MarshalFrame() = %s, want %s", got, want)
		}
		if _, err := push.MarshalFrame(len(want) - 1); !errors.Is(
			err,
			ErrFrameTooLarge,
		) {
			t.Fatalf(
				"MarshalFrame(%d) with period %d error = %v, want ErrFrameTooLarge",
				len(want)-1,
				v,
				err,
			)
		}
	}
}

// partialFrameMarshaler returns a payload together with an error and keeps a
// reference to it so the test can inspect it afterwards.
type partialFrameMarshaler struct{ payload []byte }

func (m *partialFrameMarshaler) MarshalFrame(int) ([]byte, error) {
	m.payload = bytes.Repeat([]byte{0x5a}, 64)
	return m.payload, errors.New("partial marshal")
}

func TestWriteFrameWipesPayloadOnMarshalError(t *testing.T) {
	t.Parallel()
	m := &partialFrameMarshaler{}
	writer := &discardFrameWriter{}
	if err := WriteFrameLimit(writer, MaxFrameLen, m); err == nil {
		t.Fatal("WriteFrameLimit() succeeded, want marshal error")
	}
	if writer.bytes != 0 {
		t.Fatalf("WriteFrameLimit() wrote %d bytes after marshal error", writer.bytes)
	}
	if !bytes.Equal(m.payload, make([]byte, len(m.payload))) {
		t.Fatal("partial payload retained bytes after WriteFrameLimit returned")
	}
}

// retainingFrameReader serves src in small chunks and keeps every buffer the
// reader under test passed to Read, so the test can check they were wiped.
type retainingFrameReader struct {
	src   []byte
	chunk int
	err   error
	bufs  [][]byte
}

func (r *retainingFrameReader) Read(p []byte) (int, error) {
	if len(r.src) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		return 0, io.EOF
	}
	r.bufs = append(r.bufs, p)
	n := copy(p[:min(len(p), r.chunk)], r.src)
	r.src = r.src[n:]
	return n, nil
}

func TestReadFrameLimitWipesBody(t *testing.T) {
	t.Parallel()
	push := KeyPush{
		Type:       "key_push",
		Period:     1234,
		Depth:      6,
		KESSignKey: bytes.Repeat([]byte{0x5c}, 608),
		KESVKey:    bytes.Repeat([]byte{0x2a}, 32),
		OpCert:     bytes.Repeat([]byte{0x3b}, 140),
	}
	payload, err := json.Marshal(push)
	if err != nil {
		t.Fatal(err)
	}
	frame := func(body []byte, declared int) []byte {
		out := binary.BigEndian.AppendUint32(nil, uint32(declared)) // #nosec G115 -- test sizes
		return append(out, body...)
	}
	errDeadline := errors.New("read deadline")
	for _, test := range []struct {
		name    string
		frame   []byte
		err     error
		wantErr bool
	}{
		{name: "success", frame: frame(payload, len(payload))},
		{
			name:    "unmarshal error",
			frame:   frame(append(bytes.Clone(payload), '}'), len(payload)+1),
			wantErr: true,
		},
		{
			name:    "body eof",
			frame:   frame(payload[:len(payload)-1], len(payload)),
			wantErr: true,
		},
		{
			name:    "body read error",
			frame:   frame(payload[:len(payload)-1], len(payload)),
			err:     errDeadline,
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			r := &retainingFrameReader{src: test.frame, chunk: 97, err: test.err}
			var got KeyPush
			err := ReadFrameLimit(r, MaxFrameLen, &got)
			if test.wantErr != (err != nil) {
				t.Fatalf("ReadFrameLimit() error = %v, wantErr %v", err, test.wantErr)
			}
			if test.err != nil && !errors.Is(err, test.err) {
				t.Fatalf("ReadFrameLimit() error = %v, want %v", err, test.err)
			}
			if !test.wantErr && !bytes.Equal(got.KESSignKey, push.KESSignKey) {
				t.Fatal("decoded KeyPush signing key changed")
			}
			// The first Read fills the header, which carries no key bytes.
			if len(r.bufs) < 3 {
				t.Fatalf("body read in %d calls, want growth across several", len(r.bufs))
			}
			for i, b := range r.bufs[1:] {
				if !bytes.Equal(b, make([]byte, len(b))) {
					t.Fatalf("body buffer %d retained bytes after ReadFrameLimit returned", i)
				}
			}
		})
	}
}

func TestKeyPushMarshalFrameRejectsOversizedPush(t *testing.T) {
	t.Parallel()
	big := make([]byte, MaxFrameLen)
	for _, push := range []KeyPush{
		{Type: strings.Repeat("t", MaxFrameLen+1)},
		{Type: "key_push", KESSignKey: big},
		{Type: "key_push", KESVKey: big},
		{Type: "key_push", OpCert: big},
	} {
		got, err := push.MarshalFrame(MaxFrameLen)
		if err == nil {
			t.Fatalf(
				"MarshalFrame() returned %d bytes, want frame-size error",
				len(got),
			)
		}
		if !errors.Is(err, ErrFrameTooLarge) {
			t.Fatalf("MarshalFrame() error = %v, want ErrFrameTooLarge", err)
		}
	}
}

// TestWriteFrameLeavesNoSigningKeyInHeap writes a KeyPush and then searches the
// process's writable memory for the base64 signing key, which json.Marshal
// would leave behind in its pooled encoder buffer.
func TestWriteFrameLeavesNoSigningKeyInHeap(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("scans /proc/self/mem")
	}
	secret := make([]byte, 96)
	for i := range secret {
		secret[i] = byte(0xa5 ^ i*7)
	}
	needle := base64.StdEncoding.AppendEncode(nil, secret)
	defer clear(needle)
	push := KeyPush{
		Type:       "key_push",
		KESSignKey: secret,
		KESVKey:    []byte{1},
		OpCert:     []byte{2},
	}
	clear(secret)
	secret = nil
	// Rebuild the key inside the push from the needle so the plain secret
	// is never kept elsewhere.
	push.KESSignKey = make([]byte, base64.StdEncoding.DecodedLen(len(needle)))
	if _, err := base64.StdEncoding.Decode(push.KESSignKey, needle); err != nil {
		t.Fatal(err)
	}
	defer clear(push.KESSignKey)

	writer := &discardFrameWriter{}
	if err := WriteFrameLimit(writer, MaxFrameLen, push); err != nil {
		t.Fatal(err)
	}
	if writer.bytes == 0 {
		t.Fatal("nothing written")
	}
	if n := countInHeap(t, needle, &needle[0]); n != 0 {
		t.Fatalf(
			"base64 signing key found %d time(s) in process memory after WriteFrameLimit",
			n,
		)
	}
}

type discardFrameWriter struct{ bytes int }

func (w *discardFrameWriter) SetWriteDeadline(time.Time) error { return nil }
func (w *discardFrameWriter) Write(p []byte) (int, error) {
	w.bytes += len(p)
	return len(p), nil
}

// countInHeap counts occurrences of needle in the process's writable
// mappings, ignoring the copy at self.
func countInHeap(t *testing.T, needle []byte, self *byte) int {
	t.Helper()
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Skipf("read maps: %v", err)
	}
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		t.Skipf("open mem: %v", err)
	}
	defer mem.Close()
	count := 0
	for _, line := range strings.Split(string(maps), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !strings.HasPrefix(f[1], "rw") {
			continue
		}
		if len(f) >= 6 && strings.HasPrefix(f[5], "[v") {
			continue
		}
		var lo, hi uint64
		if _, err := fmt.Sscanf(f[0], "%x-%x", &lo, &hi); err != nil {
			continue
		}
		const chunk = 1 << 20
		buf := make([]byte, chunk+len(needle))
		for off := lo; off < hi; off += chunk {
			n, _ := mem.ReadAt(buf[:min(uint64(len(buf)), hi-off)], int64(off))
			for i := 0; ; {
				j := bytes.Index(buf[i:n], needle)
				if j < 0 {
					break
				}
				addr := off + uint64(i+j)
				if addr != uint64(uintptr(unsafe.Pointer(self))) &&
					(addr < uint64(uintptr(unsafe.Pointer(&buf[0]))) || addr >= uint64(uintptr(unsafe.Pointer(&buf[0])))+uint64(len(buf))) {
					count++
				}
				i += j + 1
			}
		}
		clear(buf)
	}
	return count
}

// TestWriteFrameLeavesNoSigningKeyInHeapWithFullSizeFields uses production
// field sizes: a Sum6 signing key, a 32-byte verification key, and opcert
// CBOR. Fields that outgrow the frame buffer force append to copy the signing
// key into a new array and abandon the old one unwiped.
func TestWriteFrameLeavesNoSigningKeyInHeapWithFullSizeFields(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("scans /proc/self/mem")
	}
	push := KeyPush{
		Type:       "key_push",
		Period:     1234,
		Depth:      6,
		KESSignKey: make([]byte, 608),
		KESVKey:    bytes.Repeat([]byte{0x2a}, 32),
		OpCert:     bytes.Repeat([]byte{0x3b}, 140),
	}
	for i := range push.KESSignKey {
		push.KESSignKey[i] = byte(0x5c ^ i*13)
	}
	defer clear(push.KESSignKey)
	needle := base64.StdEncoding.AppendEncode(nil, push.KESSignKey)
	defer clear(needle)

	writer := &discardFrameWriter{}
	if err := WriteFrameLimit(writer, MaxFrameLen, push); err != nil {
		t.Fatal(err)
	}
	if n := countInHeap(t, needle, &needle[0]); n != 0 {
		t.Fatalf(
			"base64 signing key found %d time(s) in process memory after WriteFrameLimit",
			n,
		)
	}
}
