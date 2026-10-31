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

package device

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/armory/profile"
	"github.com/blinklabs-io/bursa/armory/signlog"
	"golang.org/x/crypto/blake2b"
)

// fakeLog records appends, noting how many signatures the chip had made
// when each arrived, and fails on demand.
type fakeLog struct {
	chip           *fakeChip
	records        []signlog.Record
	signsAtAppend  []int
	err            error
	head           signlog.Head
	appendsAttempt int
}

func (l *fakeLog) Append(rec signlog.Record) (signlog.Entry, error) {
	l.appendsAttempt++

	if l.err != nil {
		return signlog.Entry{}, l.err
	}

	l.records = append(l.records, rec)
	l.signsAtAppend = append(l.signsAtAppend, l.chip.signs)

	return signlog.Entry{Record: rec, Seq: uint64(len(l.records))}, nil
}

func (l *fakeLog) Head() signlog.Head { return l.head }

// loggedService is a provisioned service with a fake signing log installed.
func loggedService(t *testing.T) (*Service, *fakeChip, *fakeLog, ProvisionResponse) {
	t.Helper()

	s, chip := newTestService(t)
	resp := provisionTestProfile(t, s)
	l := &fakeLog{chip: chip}
	s.RequireSigningLog()
	s.SetSigningLog(l, nil)

	return s, chip, l, resp
}

func poolTxRequest(t *testing.T, chip *fakeChip, n byte) SignRequest {
	t.Helper()

	cold, _ := chip.PublicKeyEd25519(testColdID)

	return SignRequest{
		Purpose: "tx-body", KeyHash: hashHex(cold), Role: "pool", Nonce: nonce(n),
		Payload: certBody(retirement(keyHash(cold))), Profile: "otg@preview", Era: conwayEra(),
	}
}

func TestTxBodyIsLoggedBeforeSignature(t *testing.T) {
	t.Parallel()

	s, chip, l, _ := loggedService(t)
	req := poolTxRequest(t, chip, 1)

	r := sign(t, s, req)
	if r.Error != "" || len(r.Signature) == 0 {
		t.Fatalf("refused: %+v", r)
	}

	if len(l.records) != 1 {
		t.Fatalf("%d records, want 1", len(l.records))
	}

	hash := blake2b.Sum256(req.Payload)
	got := l.records[0]

	if got.Profile != "otg@preview" || got.Role != "pool" || got.Purpose != signlog.PurposeTxBody ||
		!bytes.Equal(got.BodyHash, hash[:]) || !strings.Contains(got.Summary, "retire") {
		t.Fatalf("record %+v", got)
	}

	// the record was appended before the chip made any signature
	if l.signsAtAppend[0] != 0 {
		t.Fatalf("chip had made %d signatures when the entry was appended", l.signsAtAppend[0])
	}
}

func TestOpCertIsLoggedBeforeSignature(t *testing.T) {
	t.Parallel()

	s, chip, l, _ := loggedService(t)
	cold, _ := chip.PublicKeyEd25519(testColdID)
	kes := bytes.Repeat([]byte{0x4b}, 32)

	r := sign(t, s, SignRequest{
		Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool",
		Nonce: nonce(1), Payload: opCertPayload(kes, 3, 1100), Profile: "otg@preview",
	})
	if r.Error != "" || r.IssueCounter == nil || *r.IssueCounter != 4 {
		t.Fatalf("response %+v", r)
	}

	if len(l.records) != 1 {
		t.Fatalf("%d records, want 1", len(l.records))
	}

	kesHash := blake2b.Sum256(kes)
	got := l.records[0]

	if got.Profile != "otg@preview" || got.Role != "pool" || got.Purpose != signlog.PurposeOpCertNext ||
		got.IssueCounter != 4 || got.KESPeriod != 1100 || !bytes.Equal(got.KESKeyHash, kesHash[:]) ||
		got.BodyHash != nil || !strings.Contains(got.Summary, "issue 4") {
		t.Fatalf("record %+v", got)
	}

	if l.signsAtAppend[0] != 0 {
		t.Fatalf("chip had made %d signatures when the entry was appended", l.signsAtAppend[0])
	}
}

// Any Append failure, including a full medium, refuses the request: no
// signature, no binding signature, no chip signing and no opcert floor move.
func TestAppendFailureRefusesSigning(t *testing.T) {
	t.Parallel()

	for name, appendErr := range map[string]error{
		"write failure": errors.New("sd write failed"),
		"full":          signlog.ErrFull,
		"head store":    signlog.ErrHeadStore,
	} {
		s, chip, l, _ := loggedService(t)
		l.err = appendErr
		cold, _ := chip.PublicKeyEd25519(testColdID)
		before := chip.signs

		reqs := map[string]SignRequest{
			"tx-body": poolTxRequest(t, chip, 1),
			"opcert": {
				Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool", Nonce: nonce(2),
				Payload: opCertPayload(bytes.Repeat([]byte{0x4b}, 32), 7, 1100), Profile: "otg@preview",
			},
		}

		for kind, req := range reqs {
			r := sign(t, s, req)

			if r.Error == "" || !strings.Contains(r.Error, "signing log") {
				t.Errorf("%s/%s: error %q does not name the signing log", name, kind, r.Error)
			}

			if r.Signature != nil || r.BindingSignature != nil || r.IssueCounter != nil {
				t.Errorf("%s/%s: released %+v", name, kind, r)
			}
		}

		if chip.signs != before {
			t.Errorf("%s: chip made %d signatures", name, chip.signs-before)
		}

		rec, _ := chip.ReadBinary(profile.Profile{Slot: 0}.RecordID())
		if p, _ := profile.Decode(rec); p.OpCertFloor != 3 {
			t.Errorf("%s: opcert floor moved to %d by a refused request", name, p.OpCertFloor)
		}

		if len(l.records) != 0 {
			t.Errorf("%s: %d records kept", name, len(l.records))
		}
	}
}

func TestFullLogErrorIsClear(t *testing.T) {
	t.Parallel()

	s, chip, l, _ := loggedService(t)
	l.err = signlog.ErrFull

	if r := sign(t, s, poolTxRequest(t, chip, 1)); !strings.Contains(r.Error, "full") {
		t.Fatalf("error %q", r.Error)
	}
}

// A required log that was never installed refuses signing with the reason,
// while inventory still works.
func TestRequiredLogMissingRefusesSigning(t *testing.T) {
	t.Parallel()

	s, chip := newTestService(t)
	provisionTestProfile(t, s)
	post(t, s, "/provision/identity", struct{}{})
	s.RequireSigningLog()

	r := sign(t, s, poolTxRequest(t, chip, 1))
	if r.Error == "" || r.Signature != nil || !strings.Contains(r.Error, "not open") {
		t.Fatalf("response %+v", r)
	}

	s.SigningLogFailed(errors.New("no SD card"))

	r = sign(t, s, poolTxRequest(t, chip, 2))
	if r.Signature != nil || !strings.Contains(r.Error, "no SD card") || !strings.Contains(r.Error, "signing log") {
		t.Fatalf("response %+v", r)
	}

	if chip.signs != 0 {
		t.Fatalf("chip made %d signatures", chip.signs)
	}

	code, body := post(t, s, "/v1/inventory", InventoryRequest{Nonce: nonce(3), Profile: "otg@preview"})
	if code != http.StatusOK {
		t.Fatalf("inventory: %d %s", code, body)
	}

	if code, _ = post(t, s, "/v1/challenge", struct{}{}); code != http.StatusOK {
		t.Fatalf("challenge: %d", code)
	}
}

// A refusal for want of a log does not use up the request nonce.
func TestLogRefusalKeepsNonce(t *testing.T) {
	t.Parallel()

	s, chip := newTestService(t)
	provisionTestProfile(t, s)
	s.RequireSigningLog()

	req := poolTxRequest(t, chip, 1)
	if r := sign(t, s, req); r.Error == "" {
		t.Fatal("signed without a log")
	}

	l := &fakeLog{chip: chip}
	s.SetSigningLog(l, nil)

	if r := sign(t, s, req); r.Error != "" || len(r.Signature) == 0 {
		t.Fatalf("retry refused: %+v", r)
	}
}

// Policy refusals never reach the log.
func TestPolicyRefusalIsNotLogged(t *testing.T) {
	t.Parallel()

	s, chip, l, _ := loggedService(t)
	req := poolTxRequest(t, chip, 1)
	req.Payload = certBody(retirement([28]byte{1}))

	if r := sign(t, s, req); r.Error == "" {
		t.Fatal("signed")
	}

	if l.appendsAttempt != 0 {
		t.Fatalf("%d appends for a refused request", l.appendsAttempt)
	}
}

// With the real writer: every release is on the medium and verifies, and a
// full medium refuses the next request.
func TestSigningThroughRealLog(t *testing.T) {
	t.Parallel()

	s, chip := newTestService(t)
	provisionTestProfile(t, s)

	pub, priv, _ := ed25519.GenerateKey(nil)
	id := signlog.NewKeySigner(priv)
	m := signlog.NewMemMedium(1 + 2*signlog.RecordBlocks)

	w, err := signlog.Open(m, signlog.NewMemHeadStore(signlog.Head{}), id)
	if err != nil {
		t.Fatal(err)
	}

	s.RequireSigningLog()
	s.SetSigningLog(w, m)

	cold, _ := chip.PublicKeyEd25519(testColdID)

	for n, req := range []SignRequest{
		poolTxRequest(t, chip, 1),
		{
			Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool", Nonce: nonce(2),
			Payload: opCertPayload(bytes.Repeat([]byte{0x4b}, 32), 3, 1100), Profile: "otg@preview",
		},
	} {
		if r := sign(t, s, req); r.Error != "" || len(r.Signature) == 0 {
			t.Fatalf("request %d refused: %+v", n, r)
		}
	}

	log, err := signlog.Verify(m, pub)
	if err != nil || len(log.Entries) != 2 {
		t.Fatalf("verify: %v", err)
	}

	if log.Entries[0].Purpose != signlog.PurposeTxBody || log.Entries[1].Purpose != signlog.PurposeOpCertNext {
		t.Fatalf("entries %+v", log.Entries)
	}

	signs := chip.signs
	if r := sign(t, s, poolTxRequest(t, chip, 3)); r.Error == "" || r.Signature != nil || !strings.Contains(r.Error, "full") {
		t.Fatalf("full medium: %+v", r)
	}

	if chip.signs != signs {
		t.Fatal("chip signed for a request the full log refused")
	}
}
