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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/gouroboros/kes"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestPeriodGuardFresh reports whether a guard opened without a prior record:
// a missing or empty guard file is fresh, a file with a record is not.
func TestPeriodGuardFresh(t *testing.T) {
	for _, tc := range []struct {
		name      string
		content   []byte // nil leaves the file absent
		wantFresh bool
	}{
		{name: "missing", content: nil, wantFresh: true},
		{name: "empty", content: []byte{}, wantFresh: true},
		{
			name:      "record",
			content:   []byte(`{"floor":3,"set":true}`),
			wantFresh: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "guard.json")
			if tc.content != nil {
				if err := os.WriteFile(path, tc.content, 0o600); err != nil {
					t.Fatalf("seed guard file: %v", err)
				}
			}
			g, err := NewPeriodGuard(path)
			if err != nil {
				t.Fatalf("NewPeriodGuard: %v", err)
			}
			t.Cleanup(g.Close)
			if got := g.Fresh(); got != tc.wantFresh {
				t.Fatalf("Fresh() = %v, want %v", got, tc.wantFresh)
			}
		})
	}
}

// signalAgentConfig is a sign-mode single-profile config on guardPath with
// the testAgent clock parameters.
func signalAgentConfig(cold coldKeyPair, guardPath string) Config {
	return Config{
		Mode:              ModeSign,
		Depth:             kes.CardanoKesDepth,
		SystemStart:       epoch,
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 10,
		MaxKESEvolutions:  62,
		ColdVKey:          cold.pub,
		EvolveInterval:    time.Hour,
		GuardPath:         guardPath,
		Version:           "test",
	}
}

// TestNewSignalsAFreshGuardFile starts an agent on a missing guard file and
// then restarts it on the file it wrote: the first start warns with the path
// and sets the fresh gauge, the restart does neither.
func TestNewSignalsAFreshGuardFile(t *testing.T) {
	cold := newColdKey(t)
	guardPath := filepath.Join(t.TempDir(), "guard.json")
	cfg := signalAgentConfig(cold, guardPath)
	for _, tc := range []struct {
		name      string
		wantFresh float64
		wantWarn  bool
	}{
		{name: "first start", wantFresh: 1, wantWarn: true},
		{name: "restart", wantFresh: 0, wantWarn: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			m := NewMetrics()
			a, err := New(cfg, logger, m)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer a.Close()
			a.now = func() time.Time { return atPeriod(5) }
			got := testutil.ToFloat64(
				m.guardFresh.WithLabelValues(DefaultProfileName),
			)
			if got != tc.wantFresh {
				t.Fatalf("guard fresh gauge = %v, want %v", got, tc.wantFresh)
			}
			warned := strings.Contains(logs.String(), "level=WARN") &&
				strings.Contains(logs.String(), guardPath)
			if warned != tc.wantWarn {
				t.Fatalf(
					"warning naming the guard path = %v, want %v (logs: %s)",
					warned,
					tc.wantWarn,
					logs.String(),
				)
			}
			// Leave a record behind for the restart.
			vkey, err := a.GenStagedKey()
			if err != nil {
				t.Fatalf("GenStagedKey: %v", err)
			}
			if _, err := a.InstallKey(makeOpCert(t, vkey, 1, 5, cold)); err != nil {
				t.Fatalf("InstallKey: %v", err)
			}
		})
	}
}

// TestSlotGuardRefusalsAreCounted counts each slot-guard refusal under its
// reason, and leaves the counter alone for a signed header and its retry.
func TestSlotGuardRefusalsAreCounted(t *testing.T) {
	cold := newColdKey(t)
	cfg := signalAgentConfig(cold, filepath.Join(t.TempDir(), "guard.json"))
	m := NewMetrics()
	a, err := New(cfg, nil, m)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	// Both reasons have a series from startup, so the first refusal is an
	// increase a rate or increase query can see.
	if n := testutil.CollectAndCount(m.slotGuardRefusals); n != 2 {
		t.Fatalf("refusal series at startup = %d, want 2", n)
	}
	a.now = func() time.Time { return atPeriod(5) }
	vkey, err := a.GenStagedKey()
	if err != nil {
		t.Fatalf("GenStagedKey: %v", err)
	}
	opcert := makeOpCert(t, vkey, 7, 3, cold)
	if _, err := a.InstallKey(opcert); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
	spec := headerSpec{
		slot:      52,
		issuer:    cold.pub,
		hotVkey:   vkey,
		sequence:  7,
		kesPeriod: 3,
		coldSig:   opCertColdSig(t, opcert),
	}
	other := spec
	other.blockNumber = 2
	older := spec
	older.slot = 51

	refusals := func(reason string) float64 {
		return testutil.ToFloat64(
			m.slotGuardRefusals.WithLabelValues(DefaultProfileName, reason),
		)
	}
	for _, tc := range []struct {
		name            string
		body            []byte
		wantErr         error
		wantEquivocated float64
		wantRolledBack  float64
	}{
		{name: "first header", body: spec.encode(t)},
		{name: "identical retry", body: spec.encode(t)},
		{
			name:            "other body for the slot",
			body:            other.encode(t),
			wantErr:         ErrSlotEquivocation,
			wantEquivocated: 1,
		},
		{
			name:            "older slot",
			body:            older.encode(t),
			wantErr:         ErrSlotRollback,
			wantEquivocated: 1,
			wantRolledBack:  1,
		},
	} {
		// The cases share one agent and run in order.
		_, err := a.SignHeader(5, tc.body)
		if !errors.Is(err, tc.wantErr) {
			t.Fatalf("%s: want %v, got %v", tc.name, tc.wantErr, err)
		}
		if got := refusals("equivocation"); got != tc.wantEquivocated {
			t.Fatalf(
				"%s: equivocation refusals = %v, want %v",
				tc.name,
				got,
				tc.wantEquivocated,
			)
		}
		if got := refusals("rollback"); got != tc.wantRolledBack {
			t.Fatalf(
				"%s: rollback refusals = %v, want %v",
				tc.name,
				got,
				tc.wantRolledBack,
			)
		}
	}
}

// TestSlotGuardRefusalsAreLogged writes one WARN line per slot-guard refusal
// with the profile, reason, slot, period and a hash of the refused header, and
// none for a signed header or its identical retry.
func TestSlotGuardRefusalsAreLogged(t *testing.T) {
	t.Parallel()
	cold := newColdKey(t)
	cfg := signalAgentConfig(cold, filepath.Join(t.TempDir(), "guard.json"))
	var logs bytes.Buffer
	a, err := New(cfg, slog.New(slog.NewJSONHandler(&logs, nil)), NewMetrics())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	a.now = func() time.Time { return atPeriod(5) }
	vkey, err := a.GenStagedKey()
	if err != nil {
		t.Fatalf("GenStagedKey: %v", err)
	}
	opcert := makeOpCert(t, vkey, 7, 3, cold)
	if _, err := a.InstallKey(opcert); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
	spec := headerSpec{
		slot:      52,
		issuer:    cold.pub,
		hotVkey:   vkey,
		sequence:  7,
		kesPeriod: 3,
		coldSig:   opCertColdSig(t, opcert),
	}
	other := spec
	other.blockNumber = 2
	older := spec
	older.slot = 51

	// refusalLines returns the guard refusal records written so far.
	refusalLines := func() []map[string]any {
		var out []map[string]any
		for _, line := range strings.Split(logs.String(), "\n") {
			if !strings.Contains(line, "slot guard refused") {
				continue
			}
			rec := map[string]any{}
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("log line %q: %v", line, err)
			}
			out = append(out, rec)
		}
		return out
	}
	hashOf := func(body []byte) string {
		sum := sha256.Sum256(body)
		return hex.EncodeToString(sum[:8])
	}
	for _, tc := range []struct {
		name       string
		body       []byte
		wantErr    error
		wantReason string
		wantSlot   float64
		wantLines  int
	}{
		{name: "first header", body: spec.encode(t)},
		{name: "identical retry", body: spec.encode(t)},
		{
			name:       "other body for the slot",
			body:       other.encode(t),
			wantErr:    ErrSlotEquivocation,
			wantReason: "equivocation",
			wantSlot:   52,
			wantLines:  1,
		},
		{
			name:       "older slot",
			body:       older.encode(t),
			wantErr:    ErrSlotRollback,
			wantReason: "rollback",
			wantSlot:   51,
			wantLines:  2,
		},
	} {
		// The cases share one agent and run in order.
		_, err := a.SignHeader(5, tc.body)
		if !errors.Is(err, tc.wantErr) {
			t.Fatalf("%s: want %v, got %v", tc.name, tc.wantErr, err)
		}
		lines := refusalLines()
		if len(lines) != tc.wantLines {
			t.Fatalf("%s: %d refusal log lines, want %d (logs: %s)",
				tc.name, len(lines), tc.wantLines, logs.String())
		}
		if tc.wantErr == nil {
			continue
		}
		rec := lines[len(lines)-1]
		if rec["level"] != "WARN" ||
			rec["profile"] != DefaultProfileName ||
			rec["remote"] != "local" ||
			rec["reason"] != tc.wantReason ||
			rec["slot"] != tc.wantSlot ||
			rec["kes_period"] != float64(5) ||
			rec["header_hash"] != hashOf(tc.body) {
			t.Fatalf("%s: unexpected refusal record: %v", tc.name, rec)
		}
	}
}

// peerConn is a connection that reports a fixed remote address and, like a
// *tls.Conn, a connection state carrying the verified client certificate.
type peerConn struct {
	net.Conn
	remote net.Addr
	state  tls.ConnectionState
}

func (c peerConn) RemoteAddr() net.Addr { return c.remote }

func (c peerConn) ConnectionState() tls.ConnectionState { return c.state }

// TestSlotGuardRefusalLogNamesTheClient serves two sign requests for one slot
// over a connection and checks the refusal line names the remote address and
// the client certificate, and that the accepted request logs nothing.
func TestSlotGuardRefusalLogNamesTheClient(t *testing.T) {
	t.Parallel()
	cold := newColdKey(t)
	cfg := signalAgentConfig(cold, filepath.Join(t.TempDir(), "guard.json"))
	var logs bytes.Buffer
	a, err := New(cfg, slog.New(slog.NewJSONHandler(&logs, nil)), NewMetrics())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	a.now = func() time.Time { return atPeriod(5) }
	vkey, err := a.GenStagedKey()
	if err != nil {
		t.Fatalf("GenStagedKey: %v", err)
	}
	opcert := makeOpCert(t, vkey, 7, 3, cold)
	if _, err := a.InstallKey(opcert); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
	spec := headerSpec{
		slot:      52,
		issuer:    cold.pub,
		hotVkey:   vkey,
		sequence:  7,
		kesPeriod: 3,
		coldSig:   opCertColdSig(t, opcert),
	}
	other := spec
	other.blockNumber = 2

	spki := []byte("test-spki")
	server, client := net.Pipe()
	defer client.Close()
	conn := peerConn{
		Conn:   server,
		remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 4242},
		state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
			Subject:                 pkix.Name{CommonName: "producer-1"},
			RawSubjectPublicKeyInfo: spki,
		}}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleSign(ctx, conn, nil)
	}()
	defer func() {
		cancel()
		_ = client.Close()
		<-done
	}()
	roundTrip := func(body []byte) SignResponse {
		if err := writeFrame(client, SignRequest{
			Type: "sign_request", Period: 5, Message: body,
		}); err != nil {
			t.Fatalf("write: %v", err)
		}
		var resp SignResponse
		if err := readFrame(client, &resp); err != nil {
			t.Fatalf("read: %v", err)
		}
		return resp
	}
	if resp := roundTrip(spec.encode(t)); resp.Error != "" {
		t.Fatalf("first header refused: %s", resp.Error)
	}
	if n := strings.Count(logs.String(), "slot guard refused"); n != 0 {
		t.Fatalf("accepted header logged %d refusals", n)
	}
	if resp := roundTrip(other.encode(t)); resp.Error == "" {
		t.Fatal("equivocating header was signed")
	}
	var rec map[string]any
	n := 0
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "slot guard refused") {
			n++
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("log line %q: %v", line, err)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d refusal lines, want 1 (logs: %s)", n, logs.String())
	}
	sum := sha256.Sum256(spki)
	if rec["remote"] != "192.0.2.7:4242" ||
		rec["client_cert_subject"] != "CN=producer-1" ||
		rec["client_cert_spki_sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("refusal record does not name the client: %v", rec)
	}
}
