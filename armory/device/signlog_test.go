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
	"sync"
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

func (l *fakeLog) Check() error { return l.err }

func (l *fakeLog) Last() (signlog.Entry, bool) {
	if len(l.records) == 0 {
		return signlog.Entry{}, false
	}

	return signlog.Entry{Record: l.records[len(l.records)-1], Seq: uint64(len(l.records))}, true
}

func (l *fakeLog) LastOpCert(profile string, cold []byte) (issue, period uint64, ok bool) {
	for i := len(l.records) - 1; i >= 0; i-- {
		if r := l.records[i]; r.Profile == profile && r.Purpose == signlog.PurposeOpCertNext &&
			(len(r.ColdKeyHash) == 0 || bytes.Equal(r.ColdKeyHash, cold)) {
			return r.IssueCounter, r.KESPeriod, true
		}
	}

	return 0, 0, false
}

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

// An opcert-next whose updated record would not fit in RecordSize is refused
// before the log entry, so the log never records an opcert that was not issued.
func TestOpCertNextRecordTooLargeNotLogged(t *testing.T) {
	t.Parallel()

	s, chip, l, _ := loggedService(t)
	cold, _ := chip.PublicKeyEd25519(testColdID)
	rec, _ := chip.ReadBinary(profile.Profile{Slot: 0}.RecordID())
	signs := chip.signs

	// a 20-digit floor and a 20-digit issued counter overflow the record
	r := sign(t, s, SignRequest{
		Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool", Nonce: nonce(1),
		Payload: opCertPayload(bytes.Repeat([]byte{0x4b}, 32), ^uint64(0)-1, 1100), Profile: "otg@preview",
	})

	if r.Error == "" || r.Signature != nil || r.IssueCounter != nil {
		t.Fatalf("released %+v", r)
	}

	if l.appendsAttempt != 0 || chip.signs != signs {
		t.Fatalf("%d log appends and %d signatures for a refused opcert", l.appendsAttempt, chip.signs-signs)
	}

	if after, _ := chip.ReadBinary(profile.Profile{Slot: 0}.RecordID()); !bytes.Equal(after, rec) {
		t.Fatalf("refusal changed the record: %q", after)
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

func TestRecordRaw(t *testing.T) {
	t.Parallel()

	s, chip, l, _ := loggedService(t)
	msg := []byte("raw message")

	if err := s.RecordRaw(msg); err != nil {
		t.Fatal(err)
	}

	hash := blake2b.Sum256(msg)

	if len(l.records) != 1 || l.records[0].Purpose != signlog.PurposeRaw || !bytes.Equal(l.records[0].BodyHash, hash[:]) ||
		!strings.Contains(l.records[0].Summary, "unfiltered testnet signing") || l.signsAtAppend[0] != chip.signs {
		t.Fatalf("records %+v", l.records)
	}

	l.err = signlog.ErrFull
	if err := s.RecordRaw(msg); err == nil || !strings.Contains(err.Error(), "full") {
		t.Fatalf("append failure: %v", err)
	}

	// a required log that is not installed refuses
	s2, _ := newTestService(t)
	s2.RequireSigningLog()

	if err := s2.RecordRaw(msg); err == nil || !strings.Contains(err.Error(), "signing log") {
		t.Fatalf("no log: %v", err)
	}
}

// An exact repeat of the last issued opcert-next (same counter, KES key and
// period) is signed again without a new log record, so repeating a request
// cannot fill the card. A different KES key at the same counter is a
// supported rotation and is logged.
func TestOpCertNextRepeatIsNotLogged(t *testing.T) {
	t.Parallel()

	s, chip := newTestService(t)
	provisionTestProfile(t, s)

	pub, priv, _ := ed25519.GenerateKey(nil)
	id := signlog.NewKeySigner(priv)
	m := signlog.NewMemMedium(1 + 3*signlog.RecordBlocks)
	hs := signlog.NewMemHeadStore(signlog.Head{})

	w, err := signlog.Open(m, hs, id)
	if err != nil {
		t.Fatal(err)
	}

	s.RequireSigningLog()
	s.SetSigningLog(w, m)

	cold, _ := chip.PublicKeyEd25519(testColdID)
	kesA := bytes.Repeat([]byte{0x4b}, 32)
	kesB := bytes.Repeat([]byte{0x4c}, 32)
	n := byte(0)

	issue := func(svc *Service, kes []byte, chain, period uint64) SignResponse {
		t.Helper()

		n++

		return sign(t, svc, SignRequest{
			Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool", Nonce: nonce(n),
			Payload: opCertPayload(kes, chain, period), Profile: "otg@preview",
		})
	}

	first := issue(s, kesA, 3, 1100)
	if first.Error != "" || len(first.Signature) == 0 {
		t.Fatalf("first: %+v", first)
	}

	for range 5 {
		r := issue(s, kesA, 3, 1100)
		if r.Error != "" || !bytes.Equal(r.Signature, first.Signature) || r.IssueCounter == nil || *r.IssueCounter != 4 {
			t.Fatalf("repeat: %+v", r)
		}
	}

	if got := w.Head().Seq; got != 1 {
		t.Fatalf("head at entry %d after 5 repeats, want 1", got)
	}

	// a restart reopens the log and reloads the profile; the repeat is still
	// recognised
	w2, err := signlog.Open(m, hs, id)
	if err != nil {
		t.Fatal(err)
	}

	s2 := New(&sync.Mutex{}, t.Logf)
	if err = s2.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	s2.RequireSigningLog()
	s2.SetSigningLog(w2, m)

	if r := issue(s2, kesA, 3, 1100); r.Error != "" || !bytes.Equal(r.Signature, first.Signature) {
		t.Fatalf("repeat after restart: %+v", r)
	}

	if got := w2.Head().Seq; got != 1 {
		t.Fatalf("head at entry %d after a repeat across a restart, want 1", got)
	}

	// a different period, or a different KES key at the same counter, is not
	// a repeat
	if r := issue(s2, kesA, 3, 1101); r.Error != "" || r.IssueCounter == nil || *r.IssueCounter != 4 {
		t.Fatalf("new period: %+v", r)
	}

	if r := issue(s2, kesB, 3, 1101); r.Error != "" || r.IssueCounter == nil || *r.IssueCounter != 4 {
		t.Fatalf("new KES key: %+v", r)
	}

	if got := w2.Head().Seq; got != 3 {
		t.Fatalf("head at entry %d, want 3", got)
	}

	log, err := signlog.Verify(m, pub)
	if err != nil || len(log.Entries) != 3 {
		t.Fatalf("verify: %v, %d entries", err, len(log.Entries))
	}
}

// failHeads is a head store whose Store fails on demand.
type failHeads struct {
	*signlog.MemHeadStore
	fail bool
}

func (h *failHeads) Store(head signlog.Head) error {
	if h.fail {
		return errors.New("injected head store failure")
	}

	return h.MemHeadStore.Store(head)
}

// A reissue whose head update failed was refused, so a retry of it is not a
// repeat: the signature is released only once the head store holds an entry
// for it.
func TestOpCertNextRetryAfterHeadFailureIsLogged(t *testing.T) {
	t.Parallel()

	s, chip := newTestService(t)
	provisionTestProfile(t, s)

	_, priv, _ := ed25519.GenerateKey(nil)
	m := signlog.NewMemMedium(1 + 8*signlog.RecordBlocks)
	hs := &failHeads{MemHeadStore: signlog.NewMemHeadStore(signlog.Head{})}

	w, err := signlog.Open(m, hs, signlog.NewKeySigner(priv))
	if err != nil {
		t.Fatal(err)
	}

	s.RequireSigningLog()
	s.SetSigningLog(w, m)

	cold, _ := chip.PublicKeyEd25519(testColdID)
	n := byte(0)

	issue := func(kes []byte) SignResponse {
		t.Helper()

		n++

		return sign(t, s, SignRequest{
			Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool", Nonce: nonce(n),
			Payload: opCertPayload(kes, 3, 1100), Profile: "otg@preview",
		})
	}

	if r := issue(bytes.Repeat([]byte{0x4b}, 32)); r.Error != "" {
		t.Fatalf("first: %+v", r)
	}

	kesB := bytes.Repeat([]byte{0x4c}, 32)
	hs.fail = true

	if r := issue(kesB); r.Error == "" || len(r.Signature) != 0 {
		t.Fatalf("reissue with a failed head update: %+v", r)
	}

	hs.fail = false

	r := issue(kesB)
	if r.Error != "" || len(r.Signature) == 0 {
		t.Fatalf("retry: %+v", r)
	}

	if head, _ := hs.Load(); head.Seq < 2 {
		t.Fatalf("signature released with the head store at entry %d", head.Seq)
	}
}

// removableMedium is a log medium whose card can be pulled.
type removableMedium struct {
	*signlog.MemMedium
	removed bool
}

func (m *removableMedium) ReadBlocks(lba uint64, p []byte) error {
	if m.removed {
		return errors.New("no card")
	}

	return m.MemMedium.ReadBlocks(lba, p)
}

// A repeat of the last opcert-next is refused, as an append would be, when
// the card is removed, replaced or no longer matches the stored head.
func TestOpCertNextRepeatChecksLog(t *testing.T) {
	t.Parallel()

	for name, breakLog := range map[string]func(*removableMedium, *signlog.MemHeadStore){
		"card removed": func(m *removableMedium, _ *signlog.MemHeadStore) { m.removed = true },
		"card replaced": func(m *removableMedium, _ *signlog.MemHeadStore) {
			_ = m.WriteBlocks(1, make([]byte, signlog.RecordSize))
		},
		"head moved": func(_ *removableMedium, hs *signlog.MemHeadStore) {
			_ = hs.Store(signlog.Head{Seq: 1, Hash: [signlog.HashSize]byte{1}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s, chip := newTestService(t)
			provisionTestProfile(t, s)

			_, priv, _ := ed25519.GenerateKey(nil)
			m := &removableMedium{MemMedium: signlog.NewMemMedium(1 + 3*signlog.RecordBlocks)}
			hs := signlog.NewMemHeadStore(signlog.Head{})

			w, err := signlog.Open(m, hs, signlog.NewKeySigner(priv))
			if err != nil {
				t.Fatal(err)
			}

			s.RequireSigningLog()
			s.SetSigningLog(w, m)

			cold, _ := chip.PublicKeyEd25519(testColdID)
			req := func(n byte) SignRequest {
				return SignRequest{
					Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool", Nonce: nonce(n),
					Payload: opCertPayload(bytes.Repeat([]byte{0x4b}, 32), 3, 1100), Profile: "otg@preview",
				}
			}

			if r := sign(t, s, req(1)); r.Error != "" || len(r.Signature) == 0 {
				t.Fatalf("first: %+v", r)
			}

			breakLog(m, hs)
			before := chip.signs

			r := sign(t, s, req(2))
			if r.Error == "" || !strings.Contains(r.Error, "signing log") {
				t.Fatalf("repeat: error %q does not name the signing log", r.Error)
			}

			if r.Signature != nil || r.IssueCounter != nil {
				t.Fatalf("repeat released %+v", r)
			}

			if chip.signs != before {
				t.Fatalf("chip made %d signatures", chip.signs-before)
			}
		})
	}
}

// A full card still answers a repeat of its latest entry, which writes
// nothing, and refuses a new opcert.
func TestOpCertNextRepeatOnFullLog(t *testing.T) {
	t.Parallel()

	s, chip := newTestService(t)
	provisionTestProfile(t, s)

	_, priv, _ := ed25519.GenerateKey(nil)
	m := signlog.NewMemMedium(1 + signlog.RecordBlocks)

	w, err := signlog.Open(m, signlog.NewMemHeadStore(signlog.Head{}), signlog.NewKeySigner(priv))
	if err != nil {
		t.Fatal(err)
	}

	s.RequireSigningLog()
	s.SetSigningLog(w, m)

	cold, _ := chip.PublicKeyEd25519(testColdID)
	req := func(n byte, period uint64) SignRequest {
		return SignRequest{
			Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool", Nonce: nonce(n),
			Payload: opCertPayload(bytes.Repeat([]byte{0x4b}, 32), 3, period), Profile: "otg@preview",
		}
	}

	first := sign(t, s, req(1, 1100))
	if first.Error != "" || len(first.Signature) == 0 {
		t.Fatalf("first: %+v", first)
	}

	if r := sign(t, s, req(2, 1100)); r.Error != "" || !bytes.Equal(r.Signature, first.Signature) {
		t.Fatalf("repeat on a full log: %+v", r)
	}

	if r := sign(t, s, req(3, 1101)); !strings.Contains(r.Error, "full") || r.Signature != nil {
		t.Fatalf("new opcert on a full log: %+v", r)
	}
}

// A reissue of the last issued counter may not take a KES period below the
// one the log holds for it; a new counter, or an equal or later period, may.
func TestOpCertNextRefusesBackdatedReissue(t *testing.T) {
	t.Parallel()

	s, chip := newTestService(t)
	provisionTestProfile(t, s)

	_, priv, _ := ed25519.GenerateKey(nil)
	id := signlog.NewKeySigner(priv)
	m := signlog.NewMemMedium(1 + 8*signlog.RecordBlocks)
	hs := signlog.NewMemHeadStore(signlog.Head{})

	w, err := signlog.Open(m, hs, id)
	if err != nil {
		t.Fatal(err)
	}

	s.RequireSigningLog()
	s.SetSigningLog(w, m)

	cold, _ := chip.PublicKeyEd25519(testColdID)
	kesA := bytes.Repeat([]byte{0x4b}, 32)
	kesB := bytes.Repeat([]byte{0x4c}, 32)
	n := byte(0)

	issue := func(svc *Service, kes []byte, chain, period uint64) SignResponse {
		t.Helper()

		n++

		return sign(t, svc, SignRequest{
			Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool", Nonce: nonce(n),
			Payload: opCertPayload(kes, chain, period), Profile: "otg@preview",
		})
	}

	if r := issue(s, kesA, 3, 1100); r.Error != "" {
		t.Fatalf("first: %+v", r)
	}

	if r := issue(s, kesB, 3, 1099); r.Error != errKESBackdated.Error() || len(r.Signature) != 0 {
		t.Fatalf("backdated reissue: %+v", r)
	}

	if r := issue(s, kesB, 3, 1100); r.Error != "" {
		t.Fatalf("reissue at the same period: %+v", r)
	}

	// a restart rebuilds the bound from the log
	w2, err := signlog.Open(m, hs, id)
	if err != nil {
		t.Fatal(err)
	}

	s2 := New(&sync.Mutex{}, t.Logf)
	if err = s2.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	s2.RequireSigningLog()
	s2.SetSigningLog(w2, m)

	if r := issue(s2, kesA, 3, 1050); r.Error != errKESBackdated.Error() {
		t.Fatalf("backdated reissue after restart: %+v", r)
	}

	// the next counter is not a reissue
	if r := issue(s2, kesA, 4, 1050); r.Error != "" || r.IssueCounter == nil || *r.IssueCounter != 5 {
		t.Fatalf("next counter: %+v", r)
	}

	if got := w2.Head().Seq; got != 3 {
		t.Fatalf("head at entry %d, want 3: a refusal is not logged", got)
	}
}

// A request whose profile write failed after its log entry leaves the log
// ahead of the profile record; a retry of that counter at an older KES period
// is still refused.
func TestOpCertNextBackdatedAfterProfileWriteFailure(t *testing.T) {
	t.Parallel()

	s, chip := newTestService(t)
	provisionTestProfile(t, s)

	_, priv, _ := ed25519.GenerateKey(nil)
	m := signlog.NewMemMedium(1 + 8*signlog.RecordBlocks)

	w, err := signlog.Open(m, signlog.NewMemHeadStore(signlog.Head{}), signlog.NewKeySigner(priv))
	if err != nil {
		t.Fatal(err)
	}

	s.RequireSigningLog()
	s.SetSigningLog(w, m)

	cold, _ := chip.PublicKeyEd25519(testColdID)
	issue := func(n byte, period uint64) SignResponse {
		t.Helper()

		return sign(t, s, SignRequest{
			Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool", Nonce: nonce(n),
			Payload: opCertPayload(bytes.Repeat([]byte{n}, 32), 3, period), Profile: "otg@preview",
		})
	}

	chip.failWrite = true
	if r := issue(1, 1100); r.Error == "" || len(r.Signature) != 0 {
		t.Fatalf("signed although the profile write failed: %+v", r)
	}

	chip.failWrite = false
	if r := issue(2, 1099); r.Error != errKESBackdated.Error() || len(r.Signature) != 0 {
		t.Fatalf("backdated retry after a failed profile write: %+v", r)
	}
}

// A profile name reprovisioned with another cold key does not inherit the
// KES period the log holds for the old key; the same cold key keeps it, a
// profile of another name does not share it, and an entry that records no
// cold key (a version 1 medium) binds every cold key of its profile.
func TestOpCertNextBackdatedFloorIsPerColdKey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		profile string
		cold    func(real []byte) []byte
		want    string
	}{
		{"same name, same cold key", "otg@preview", func(real []byte) []byte { return real }, errKESBackdated.Error()},
		{"same name, another cold key", "otg@preview", func([]byte) []byte { return bytes.Repeat([]byte{0x77}, 28) }, ""},
		{"other profile, same cold key", "otg@other", func(real []byte) []byte { return real }, ""},
		{"same name, entry without a cold key", "otg@preview", func([]byte) []byte { return nil }, errKESBackdated.Error()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, chip := newTestService(t)
			provisionTestProfile(t, s)

			cold, _ := chip.PublicKeyEd25519(testColdID)
			realHash := keyHash(cold)

			l := &fakeLog{chip: chip}
			l.records = append(l.records, signlog.Record{
				Profile: tc.profile, Role: "pool", Purpose: signlog.PurposeOpCertNext,
				IssueCounter: 4, KESPeriod: 1100, KESKeyHash: bytes.Repeat([]byte{1}, 32),
				ColdKeyHash: tc.cold(realHash[:]),
			})

			s.RequireSigningLog()
			s.SetSigningLog(l, nil)

			r := sign(t, s, SignRequest{
				Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool", Nonce: nonce(1),
				Payload: opCertPayload(bytes.Repeat([]byte{2}, 32), 3, 1000), Profile: "otg@preview",
			})
			if r.Error != tc.want {
				t.Fatalf("error %q, want %q", r.Error, tc.want)
			}

			if tc.want == "" {
				got := l.records[len(l.records)-1]
				if !bytes.Equal(got.ColdKeyHash, realHash[:]) {
					t.Fatalf("logged cold hash %x, want %x", got.ColdKeyHash, realHash)
				}
			}
		})
	}
}
