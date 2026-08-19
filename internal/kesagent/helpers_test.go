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
	"crypto/ed25519"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger"
)

// epoch is a fixed genesis system start for deterministic period math.
var epoch = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// coldKeyPair is a generated pool cold key pair for tests.
type coldKeyPair struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newColdKey(t *testing.T) coldKeyPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate cold key: %v", err)
	}
	return coldKeyPair{pub: pub, priv: priv}
}

// testAgent builds an Agent with a fixed clock. slotLen is 1s and
// slotsPerKESPeriod is 10, so a KES period is 10s. clockAt sets now().
func testAgent(t *testing.T, mode string, cold coldKeyPair, depth uint64, clockAt time.Time) *Agent {
	t.Helper()
	cfg := Config{
		Mode:              mode,
		Depth:             depth,
		SystemStart:       epoch,
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 10,
		MaxKESEvolutions:  62,
		ColdVKey:          cold.pub,
		EvolveInterval:    time.Hour,
		GuardPath:         "", // in-memory guard
		Version:           "test",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := New(cfg, logger, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.now = func() time.Time { return clockAt }
	t.Cleanup(a.Close)
	return a
}

// atPeriod returns the wall-clock time at the start of the given KES period for
// the testAgent parameters (10s per period).
func atPeriod(p uint64) time.Time {
	return epoch.Add(time.Duration(p) * 10 * time.Second)
}

// makeOpCert builds a canonical node operational certificate CBOR envelope
// [[kes_vkey, issue, period, cold_sig], cold_vkey] signed by cold.
func makeOpCert(t *testing.T, kesVkey []byte, issue, period uint64, cold coldKeyPair) []byte {
	t.Helper()
	oc, err := ledger.CreateOpCert(kesVkey, issue, period, cold.priv)
	if err != nil {
		t.Fatalf("CreateOpCert: %v", err)
	}
	env := []any{
		[]any{oc.KesVkey, issue, period, oc.ColdSignature},
		[]byte(cold.pub),
	}
	b, err := cbor.Encode(env)
	if err != nil {
		t.Fatalf("encode opcert: %v", err)
	}
	return b
}

// tamperOpCertKESVkey re-encodes an opcert with a different inner KES vkey,
// leaving the cold vkey stamp and cold signature intact. The cold signature
// then no longer matches, so VerifyOpCertSignature fails.
func tamperOpCertKESVkey(t *testing.T, opcert, newVkey []byte) []byte {
	t.Helper()
	dec, err := decodeOpCert(opcert)
	if err != nil {
		t.Fatalf("decode for tamper: %v", err)
	}
	env := []any{
		[]any{newVkey, dec.issueNumber, dec.kesPeriod, dec.coldSig},
		dec.coldVkey,
	}
	b, err := cbor.Encode(env)
	if err != nil {
		t.Fatalf("encode tampered opcert: %v", err)
	}
	return b
}
