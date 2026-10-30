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
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blinklabs-io/gouroboros/kes"
)

type bindingAttester struct {
	err error
}

func (a bindingAttester) Evidence(
	_ context.Context,
	binding []byte,
) ([]byte, error) {
	if a.err != nil {
		return nil, a.err
	}
	return append([]byte(nil), binding...), nil
}

type bindingVerifier struct{}

func (bindingVerifier) Verify(
	_ context.Context,
	evidence, binding []byte,
) error {
	if !bytes.Equal(evidence, binding) {
		return errors.New("binding mismatch")
	}
	return nil
}

func TestAttestedServiceBindsStateAndSignsOnlyHeaders(t *testing.T) {
	t.Parallel()
	a, cold, spec := newHeaderAgent(t)
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	go func() {
		defer server.Close()
		a.serveAttestedConn(
			t.Context(),
			server,
			AttestedServiceConfig{
				Provider: "nitro",
				Attester: bindingAttester{},
			},
		)
	}()

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	var hello Hello
	if err := readFrame(client, &hello); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if hello.Protocol != AttestedProtocolID || hello.Mode != ModeSign {
		t.Fatalf("hello = %+v", hello)
	}
	req, err := NewAttestationRequest()
	if err != nil {
		t.Fatalf("NewAttestationRequest: %v", err)
	}
	if err := writeFrame(client, req); err != nil {
		t.Fatalf("write challenge: %v", err)
	}
	var attested AttestationResponse
	if err := readFrame(client, &attested); err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	if err := VerifyAttestation(t.Context(), req, attested, "nitro", cold.pub, attested.OpCert, bindingVerifier{}); err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}

	msg := spec.encode(t)
	if err := writeFrame(client, SignRequest{Type: "sign_request", Period: 5, Message: msg}); err != nil {
		t.Fatalf("write sign request: %v", err)
	}
	var signed SignResponse
	if err := readFrame(client, &signed); err != nil {
		t.Fatalf("read sign response: %v", err)
	}
	if signed.Error != "" ||
		!kes.VerifySignedKES(attested.KESVKey, 2, msg, signed.Signature) {
		t.Fatalf("header signature refused or invalid: %q", signed.Error)
	}

	if err := writeFrame(client, SignRequest{Type: "arbitrary", Period: 5, Message: msg}); err != nil {
		t.Fatalf("write wrong-type request: %v", err)
	}
	var refused SignResponse
	if err := readFrame(client, &refused); err != nil {
		t.Fatalf("read refusal: %v", err)
	}
	if refused.Error == "" || len(refused.Signature) != 0 {
		t.Fatal("non-header request type was signed")
	}
}

func TestAttestedServiceFailsClosedWhenProviderFails(t *testing.T) {
	t.Parallel()
	a, _, _ := newHeaderAgent(t)
	server, client := net.Pipe()
	go func() {
		a.serveAttestedConn(
			t.Context(),
			server,
			AttestedServiceConfig{
				Provider: "confidential-space",
				Attester: bindingAttester{
					err: errors.New("provider unavailable"),
				},
			},
		)
		// Let net.Pipe's peer clear its frame deadline after reading the refusal.
		// A real socket can clear a deadline after the peer half closes, while
		// net.Pipe reports the close immediately.
		time.Sleep(20 * time.Millisecond)
		_ = server.Close()
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	var hello Hello
	if err := readFrame(client, &hello); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	req, _ := NewAttestationRequest()
	if err := writeFrame(client, req); err != nil {
		t.Fatalf("write challenge: %v", err)
	}
	var resp AttestationResponse
	if err := readFrame(client, &resp); err != nil {
		t.Fatalf("read refusal: %v", err)
	}
	if resp.Error == "" || len(resp.Attestation) != 0 {
		t.Fatalf("provider failure response = %+v", resp)
	}
	var signResp SignResponse
	if err := readFrame(client, &signResp); !errors.Is(err, io.EOF) {
		t.Fatalf("connection remained usable after provider failure: %v", err)
	}
}

func TestAttestedServiceRejectsUnauthenticatedTransport(t *testing.T) {
	t.Parallel()
	a, _, _ := newHeaderAgent(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- a.ServeAttestedService(ctx, ln, AttestedServiceConfig{Provider: "nitro", Attester: bindingAttester{}})
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		cancel()
		t.Fatalf("dial: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var hello Hello
	if err := readFrame(conn, &hello); err == nil {
		t.Fatal("plain TCP peer received an attested-service hello")
	}
	_ = conn.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeAttestedService: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeAttestedService did not stop")
	}
}

func TestAttestedRestartCannotInstallBelowDurableFloor(t *testing.T) {
	t.Parallel()
	cold := newColdKey(t)
	guard := filepath.Join(t.TempDir(), "guard.json")
	newAgent := func(now time.Time) *Agent {
		a, err := New(Config{
			Mode: ModeSign, Depth: kes.CardanoKesDepth, SystemStart: epoch,
			SlotLength: time.Second, SlotsPerKESPeriod: 10, MaxKESEvolutions: 62,
			ColdVKey: cold.pub, EvolveInterval: time.Hour, GuardPath: guard,
		}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		a.now = func() time.Time { return now }
		return a
	}

	first := newAgent(atPeriod(5))
	vkey, _ := first.GenStagedKey()
	if _, err := first.InstallKey(makeOpCert(t, vkey, 1, 5, cold)); err != nil {
		t.Fatalf("first install: %v", err)
	}
	first.Close()

	restarted := newAgent(atPeriod(4))
	t.Cleanup(restarted.Close)
	rollbackVKey, _ := restarted.GenStagedKey()
	if _, err := restarted.InstallKey(makeOpCert(t, rollbackVKey, 2, 4, cold)); !errors.Is(
		err,
		ErrPeriodRollback,
	) {
		t.Fatalf("restart install error = %v, want ErrPeriodRollback", err)
	}
	if _, err := restarted.attestedKeyState(); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("restarted agent exposed state after rollback: %v", err)
	}
}

func TestVerifyAttestationRejectsReplayAndProviderMismatch(t *testing.T) {
	t.Parallel()
	coldPair := newColdKey(t)
	req, _ := NewAttestationRequest()
	cold := []byte(coldPair.pub)
	kesVKey := bytes.Repeat([]byte{2}, 32)
	opcert := makeOpCert(t, kesVKey, 1, 5, coldPair)
	resp := AttestationResponse{
		Type: "attestation_response", Protocol: AttestedProtocolID,
		Nonce: append([]byte(nil), req.Nonce...), Provider: "nitro",
		KESVKey: kesVKey, OpCert: opcert, Period: 7,
	}
	resp.Attestation = AttestationBinding(
		req.Nonce,
		cold,
		resp.KESVKey,
		resp.OpCert,
		resp.Period,
	)
	if err := VerifyAttestation(t.Context(), req, resp, "nitro", cold, opcert, bindingVerifier{}); err != nil {
		t.Fatalf("valid response: %v", err)
	}
	replayed, _ := NewAttestationRequest()
	if err := VerifyAttestation(t.Context(), replayed, resp, "nitro", cold, opcert, bindingVerifier{}); !errors.Is(
		err,
		ErrAttestation,
	) {
		t.Fatalf("replay error = %v", err)
	}
	if err := VerifyAttestation(t.Context(), req, resp, "confidential-space", cold, opcert, bindingVerifier{}); !errors.Is(
		err,
		ErrAttestation,
	) {
		t.Fatalf("provider mismatch error = %v", err)
	}
}

func TestHTTPAttesterRequiresEchoedBinding(t *testing.T) {
	t.Parallel()
	var mismatch atomic.Bool
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/v1/attest" {
				http.Error(w, "unexpected request", http.StatusNotFound)
				return
			}
			var req struct {
				Protocol string `json:"protocol"`
				Binding  []byte `json:"binding"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			if mismatch.Load() {
				req.Binding[0] ^= 0xff
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"protocol":    req.Protocol,
				"binding":     req.Binding,
				"attestation": req.Binding,
			})
		}),
	)
	defer server.Close()
	attester, err := NewHTTPAttester(server.URL)
	if err != nil {
		t.Fatalf("NewHTTPAttester: %v", err)
	}
	binding := bytes.Repeat([]byte{7}, 32)
	if evidence, err := attester.Evidence(t.Context(), binding); err != nil ||
		!bytes.Equal(evidence, binding) {
		t.Fatalf("valid evidence = %x, %v", evidence, err)
	}
	mismatch.Store(true)
	if _, err := attester.Evidence(t.Context(), binding); !errors.Is(
		err,
		ErrAttestation,
	) {
		t.Fatalf("binding mismatch error = %v", err)
	}
	if _, err := NewHTTPAttester("http://192.0.2.1/attest"); err == nil {
		t.Fatal("accepted cleartext non-loopback attester")
	}
}
