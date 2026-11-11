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
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var updateGolden = flag.Bool(
	"update-golden",
	false,
	"rewrite the golden frames under testdata/frames",
)

// fixed returns n deterministic bytes starting at seed.
func fixed(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return b
}

type goldenCase struct {
	name  string
	value any
	// fresh returns a pointer to a zero value of the value's type.
	fresh func() any
}

func goldenCases() []goldenCase {
	kesVKey := fixed(32, 0x20)
	opcert := fixed(40, 0x40)
	nonce := fixed(32, 0x01)
	return []goldenCase{
		{"hello_sign", Hello{Protocol: ProtocolID, Mode: ModeSign},
			func() any { return new(Hello) }},
		{"hello_serve_key", Hello{Protocol: ProtocolID, Mode: ModeServeKey},
			func() any { return new(Hello) }},
		{"hello_attested_sign", Hello{Protocol: AttestedProtocolID, Mode: ModeSign},
			func() any { return new(Hello) }},
		{"attestation_request", AttestationRequest{
			Type: "attestation_request", Protocol: AttestedProtocolID, Nonce: nonce,
		}, func() any { return new(AttestationRequest) }},
		{"attestation_request_selector", AttestationRequest{
			Type: "attestation_request", Protocol: AttestedProtocolID, Nonce: nonce,
			KESVKey: kesVKey, Profile: "pool-a",
		}, func() any { return new(AttestationRequest) }},
		{"attestation_response", AttestationResponse{
			Type: "attestation_response", Protocol: AttestedProtocolID,
			Nonce: nonce, Provider: "nitro",
			KESVKey: kesVKey, OpCert: opcert, Period: 812,
			Attestation: fixed(24, 0x80),
		}, func() any { return new(AttestationResponse) }},
		{"attestation_response_error", AttestationResponse{
			Type: "attestation_response", Protocol: AttestedProtocolID,
			Nonce: nonce, Provider: "nitro",
			Error: "kesagent: attestation failed",
		}, func() any { return new(AttestationResponse) }},
		{"sign_request", SignRequest{
			Type: "sign_request", Period: 812, Message: fixed(16, 0x90),
		}, func() any { return new(SignRequest) }},
		{"sign_response", SignResponse{
			Type: "sign_response", Period: 812, Signature: fixed(64, 0xa0),
		}, func() any { return new(SignResponse) }},
		{"sign_response_error", SignResponse{
			Type: "sign_response", Period: 812,
			Error: "kesagent: no active KES key installed",
		}, func() any { return new(SignResponse) }},
		{"key_push", KeyPush{
			Type: "key_push", Period: 812, Depth: 6,
			KESSignKey: fixed(48, 0xc0), KESVKey: kesVKey, OpCert: opcert,
		}, func() any { return new(KeyPush) }},
		{"command_gen_staged_key", Command{Command: CmdGenStagedKey},
			func() any { return new(Command) }},
		{"command_install_key", Command{Command: CmdInstallKey, OpCert: opcert},
			func() any { return new(Command) }},
		{"command_drop_key", Command{Command: CmdDropKey, Target: "staged"},
			func() any { return new(Command) }},
		{"command_info", Command{Command: CmdInfo},
			func() any { return new(Command) }},
		{"reply_kes_vkey", Reply{Ok: true, KESVKey: kesVKey},
			func() any { return new(Reply) }},
		{"reply_error", Reply{Ok: false, Error: "no staged key"},
			func() any { return new(Reply) }},
		{"reply_info", Reply{Ok: true, Info: &AgentInfo{
			Version: "test", Mode: ModeSign,
			HasActiveKey: true, ActivePeriod: 812, ActiveStart: 800,
			ActiveEnd: 850, ActiveKESVKey: kesVKey, ActiveIssueNumber: 3,
			ActiveOpCert: opcert, StagedKESVKey: fixed(32, 0x60),
			CurrentPeriod: 812, MonotonicFloor: 810, FloorInitialized: true,
		}}, func() any { return new(Reply) }},
	}
}

// TestGoldenFrames encodes each case and compares it byte for byte with the
// committed frame and payload, then decodes the committed frame and compares
// it with the original value.
func TestGoldenFrames(t *testing.T) {
	t.Parallel()
	for _, tc := range goldenCases() {
		t.Run(tc.name, func(t *testing.T) {
			var frame bytes.Buffer
			if err := WriteFrameLimit(&frame, MaxFrameLen, tc.value); err != nil {
				t.Fatalf("WriteFrameLimit: %v", err)
			}
			hexPath := filepath.Join("testdata", "frames", tc.name+".hex")
			jsonPath := filepath.Join("testdata", "frames", tc.name+".json")
			if *updateGolden {
				writeGolden(t, hexPath, hex.EncodeToString(frame.Bytes())+"\n")
				writeGolden(t, jsonPath, string(frame.Bytes()[4:])+"\n")
			}
			wantHex, err := os.ReadFile(hexPath)
			if err != nil {
				t.Fatal(err)
			}
			wantJSON, err := os.ReadFile(jsonPath)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(frame.Bytes()); got != strings.TrimSpace(string(wantHex)) {
				t.Fatalf("encoded frame = %s, want %s", got, wantHex)
			}
			if got := string(frame.Bytes()[4:]); got != strings.TrimSpace(string(wantJSON)) {
				t.Fatalf("encoded payload = %s, want %s", got, wantJSON)
			}
			raw, err := hex.DecodeString(strings.TrimSpace(string(wantHex)))
			if err != nil {
				t.Fatal(err)
			}
			got := tc.fresh()
			if err := ReadFrameLimit(bytes.NewReader(raw), MaxFrameLen, nil, got); err != nil {
				t.Fatalf("ReadFrameLimit: %v", err)
			}
			if !reflect.DeepEqual(reflect.ValueOf(got).Elem().Interface(), tc.value) {
				t.Fatalf("decoded = %+v, want %+v", got, tc.value)
			}
		})
	}
}

func writeGolden(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFrameLimitRejectsOversizedWrite(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	err := WriteFrameLimit(&buf, 8, Hello{Protocol: ProtocolID, Mode: ModeSign})
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("WriteFrameLimit() error = %v, want ErrFrameTooLarge", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("oversized write emitted %d bytes", buf.Len())
	}
	// A KeyPush is bounded by the same caller limit.
	err = WriteFrameLimit(&buf, 8, KeyPush{Type: "key_push"})
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("WriteFrameLimit(KeyPush) error = %v, want ErrFrameTooLarge", err)
	}
}

func TestFrameLimitRejectsOversizedRead(t *testing.T) {
	t.Parallel()
	var frame bytes.Buffer
	if err := WriteFrameLimit(&frame, MaxFrameLen, Hello{Protocol: ProtocolID, Mode: ModeSign}); err != nil {
		t.Fatal(err)
	}
	var h Hello
	err := ReadFrameLimit(&frame, 8, nil, &h)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ReadFrameLimit() error = %v, want ErrFrameTooLarge", err)
	}
	if errors.Is(err, ErrFrameBodyIncomplete) {
		t.Fatal("oversized header reported as incomplete body")
	}
}

func TestFrameLimitHeaderErrorsUnwrapped(t *testing.T) {
	t.Parallel()
	var h Hello
	if err := ReadFrameLimit(bytes.NewReader(nil), MaxFrameLen, nil, &h); err != io.EOF {
		t.Fatalf("empty read error = %v, want io.EOF", err)
	}
	if err := ReadFrameLimit(bytes.NewReader(make([]byte, 4)), MaxFrameLen, nil, &h); err == nil {
		t.Fatal("zero-length frame accepted")
	}
}

func TestReadFrameLimitBodyEOF(t *testing.T) {
	t.Parallel()
	// Header advertises 10 bytes; only 3 follow.
	raw := []byte{0, 0, 0, 10, '{', '}', ' '}
	var h Hello
	err := ReadFrameLimit(bytes.NewReader(raw), MaxFrameLen, nil, &h)
	if !errors.Is(err, ErrFrameBodyIncomplete) {
		t.Fatalf("error = %v, want ErrFrameBodyIncomplete", err)
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("error = %v, want underlying io.EOF", err)
	}
}

func TestReadFrameLimitBodyDeadline(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		// Header only; the body never arrives.
		_, _ = client.Write([]byte{0, 0, 0, 10})
	}()
	var h Hello
	// The caller owns the deadline: the package sets none.
	if err := server.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	err := ReadFrameLimit(server, MaxFrameLen, nil, &h)
	if !errors.Is(err, ErrFrameBodyIncomplete) {
		t.Fatalf("error = %v, want ErrFrameBodyIncomplete", err)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("error = %v, want os.ErrDeadlineExceeded", err)
	}
}
