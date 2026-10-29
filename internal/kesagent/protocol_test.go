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
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
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

			err := writeFrame(writer, push)
			if !errors.Is(err, test.payloadErr) {
				t.Fatalf("writeFrame() error = %v, want %v", err, test.payloadErr)
			}
			if len(writer.payload) == 0 {
				t.Fatal("writer did not retain the serialized payload")
			}
			if !bytes.Equal(writer.payload, make([]byte, len(writer.payload))) {
				t.Fatal("serialized KeyPush payload retained secret-bearing bytes after write returned")
			}

			if test.payloadErr == nil {
				if len(writer.header) != 4 {
					t.Fatalf("frame header length = %d, want 4", len(writer.header))
				}
				if got := binary.BigEndian.Uint32(writer.header); got != uint32(len(writer.wire)) {
					t.Fatalf("frame payload length = %d, want %d", got, len(writer.wire))
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
		got, err := push.marshalFrame()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("marshalFrame() = %s, want %s", got, want)
		}
	}
}

func TestKeyPushMarshalFrameRejectsOversizedPush(t *testing.T) {
	t.Parallel()
	big := make([]byte, maxFrameLen)
	for _, push := range []KeyPush{
		{Type: strings.Repeat("t", maxFrameLen+1)},
		{Type: "key_push", KESSignKey: big},
		{Type: "key_push", KESVKey: big},
		{Type: "key_push", OpCert: big},
	} {
		if got, err := push.marshalFrame(); err == nil {
			t.Fatalf("marshalFrame() returned %d bytes, want frame-size error", len(got))
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
	push := KeyPush{Type: "key_push", KESSignKey: secret, KESVKey: []byte{1}, OpCert: []byte{2}}
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
	if err := writeFrame(writer, push); err != nil {
		t.Fatal(err)
	}
	if writer.bytes == 0 {
		t.Fatal("nothing written")
	}
	if n := countInHeap(t, needle, &needle[0]); n != 0 {
		t.Fatalf("base64 signing key found %d time(s) in process memory after writeFrame", n)
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
				if addr != uint64(uintptr(unsafe.Pointer(self))) && (addr < uint64(uintptr(unsafe.Pointer(&buf[0]))) || addr >= uint64(uintptr(unsafe.Pointer(&buf[0])))+uint64(len(buf))) {
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
	if err := writeFrame(writer, push); err != nil {
		t.Fatal(err)
	}
	if n := countInHeap(t, needle, &needle[0]); n != 0 {
		t.Fatalf("base64 signing key found %d time(s) in process memory after writeFrame", n)
	}
}
