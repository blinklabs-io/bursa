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
	"flag"
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

type bufConn struct{ bytes.Buffer }

func (*bufConn) SetWriteDeadline(time.Time) error { return nil }
func (*bufConn) SetReadDeadline(time.Time) error  { return nil }

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
		{"attestation_response_none", AttestationResponse{
			Type: "attestation_response", Protocol: AttestedProtocolID,
			Nonce: nonce, Provider: NoEvidenceProvider,
			KESVKey: kesVKey, OpCert: opcert, Period: 812,
		}, func() any { return new(AttestationResponse) }},
		{"attestation_response_evidence", AttestationResponse{
			Type: "attestation_response", Protocol: AttestedProtocolID,
			Nonce: nonce, Provider: "nitro",
			KESVKey: kesVKey, OpCert: opcert, Period: 812,
			Attestation: fixed(24, 0x80),
		}, func() any { return new(AttestationResponse) }},
		{"attestation_response_error", AttestationResponse{
			Type: "attestation_response", Protocol: AttestedProtocolID,
			Nonce: nonce, Provider: NoEvidenceProvider,
			Error: "kesagent: attestation failed",
		}, func() any { return new(AttestationResponse) }},
		{"sign_request", SignRequest{
			Type: "sign_request", Period: 812, Message: fixed(16, 0x90),
		}, func() any { return new(SignRequest) }},
		{"sign_request_profile", SignRequest{
			Type: "sign_request", Period: 812, Message: fixed(16, 0x90),
			Profile: "mainnet-pool",
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
		{"command_install_key", Command{
			Command: CmdInstallKey, OpCert: opcert, Profile: "mainnet-pool",
		}, func() any { return new(Command) }},
		{"command_drop_key", Command{Command: CmdDropKey, Target: "staged"},
			func() any { return new(Command) }},
		{"command_info", Command{Command: CmdInfo},
			func() any { return new(Command) }},
		{"reply_kes_vkey", Reply{Ok: true, KESVKey: kesVKey},
			func() any { return new(Reply) }},
		{"reply_error", Reply{Ok: false, Error: "no staged key"},
			func() any { return new(Reply) }},
		{"reply_info", Reply{Ok: true, Info: &AgentInfo{
			Version: "test", Mode: ModeSign, Profile: "mainnet-pool",
			HasActiveKey: true, ActivePeriod: 812, ActiveStart: 800,
			ActiveEnd: 861, ActiveKESVKey: kesVKey,
			ActiveIssueNumber: 3, ActiveOpCert: opcert,
			CurrentPeriod: 812, MonotonicFloor: 812, FloorInitialized: true,
		}}, func() any { return new(Reply) }},
	}
}

func TestGoldenFrames(t *testing.T) {
	t.Parallel()
	dir := filepath.Join("testdata", "frames")
	for _, tc := range goldenCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var conn bufConn
			if err := WriteFrame(&conn, tc.value); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}
			frame := conn.Bytes()
			hexPath := filepath.Join(dir, tc.name+".hex")
			jsonPath := filepath.Join(dir, tc.name+".json")
			wantJSON, err := json.MarshalIndent(tc.value, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			wantJSON = append(wantJSON, '\n')
			if *updateGolden {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(hexPath, []byte(hex.EncodeToString(frame)+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(jsonPath, wantJSON, 0o644); err != nil {
					t.Fatal(err)
				}
			}

			raw, err := os.ReadFile(hexPath)
			if err != nil {
				t.Fatal(err)
			}
			fixture, err := hex.DecodeString(strings.TrimSpace(string(raw)))
			if err != nil {
				t.Fatalf("fixture is not hex: %v", err)
			}
			if !bytes.Equal(frame, fixture) {
				t.Fatalf("encoded frame differs from fixture\n got %x\nwant %x", frame, fixture)
			}
			gotJSON, err := os.ReadFile(jsonPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotJSON, wantJSON) {
				t.Fatalf("json fixture differs\n got %s\nwant %s", gotJSON, wantJSON)
			}

			// Decode the fixture, not the freshly encoded bytes.
			in := bufConn{}
			in.Write(fixture)
			got := tc.fresh()
			if err := ReadFrame(&in, got); err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if in.Len() != 0 {
				t.Fatalf("%d bytes left after the frame", in.Len())
			}
			if !reflect.DeepEqual(reflect.ValueOf(got).Elem().Interface(), tc.value) {
				t.Fatalf("decoded %+v, want %+v", got, tc.value)
			}
		})
	}
}

func TestNoEvidenceAttestationResponseHasNoAttestationKey(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("testdata", "frames", "attestation_response_none.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["attestation"]; ok {
		t.Fatal("none-provider response carries an attestation key")
	}
}

// Decoding ignores unknown fields so a peer can add optional ones within the
// protocol version.
func TestReadFrameIgnoresUnknownFields(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"type":"attestation_request","protocol":"` +
		AttestedProtocolID + `","nonce":"AQ==","role":"sign","profile":"p"}`)
	var in bufConn
	in.Write([]byte{0, 0, 0, byte(len(payload))})
	in.Write(payload)
	var req AttestationRequest
	if err := ReadFrame(&in, &req); err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if req.Type != "attestation_request" || !bytes.Equal(req.Nonce, []byte{1}) {
		t.Fatalf("decoded %+v", req)
	}
}
