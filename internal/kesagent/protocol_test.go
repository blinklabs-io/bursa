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
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"time"
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
