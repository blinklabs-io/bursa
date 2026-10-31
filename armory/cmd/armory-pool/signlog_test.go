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

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/armory/device"
	devprofile "github.com/blinklabs-io/bursa/armory/profile"
	"github.com/blinklabs-io/bursa/armory/signlog"
	"github.com/blinklabs-io/bursa/armory/signlog/chipstore"
)

// logRig is a rig whose device signs into a log on an in-memory card, with
// the log's identity the chip's identity key as on the device.
type logRig struct {
	*rig
	medium *signlog.MemMedium
	svc    *device.Service
	w      *signlog.Writer
}

func newLogRig(t *testing.T, slots uint64) *logRig {
	t.Helper()

	chip := &fakeChip{keys: map[uint32]ed25519.PrivateKey{}, bins: map[uint32][]byte{}}
	svc := device.New(&sync.Mutex{}, t.Logf)

	if err := svc.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(svc.Handler())
	t.Cleanup(srv.Close)

	var id device.IdentityResponse

	devicePost(t, srv, "/provision/identity", struct{}{}, &id)

	var cold device.ColdResponse

	devicePost(t, srv, "/provision/cold", device.ColdRequest{
		ColdKeyID: coldID, SigningKey: "5820" + strings.Repeat("42", 32),
	}, &cold)

	chain := uint64(3)

	var prov device.ProvisionResponse

	devicePost(t, srv, "/provision/profile", device.ProvisionRequest{
		Name: profile, Slot: 0, ColdKeyID: coldID, ChainCounter: &chain, RewardAccount: testReward,
	}, &prov)

	ident, err := chipstore.NewIdentity(chip, devprofile.IdentityKeyID)
	if err != nil {
		t.Fatal(err)
	}

	m := signlog.NewMemMedium(1 + slots*signlog.RecordBlocks)

	w, err := signlog.Open(m, chipstore.NewHeadStore(chip, devprofile.SignLogHeadID), ident)
	if err != nil {
		t.Fatal(err)
	}

	svc.RequireSigningLog()
	svc.SetSigningLog(w, m)

	pool, _ := hex.DecodeString(cold.PublicKey)

	return &logRig{
		rig: &rig{
			s:        &session{c: newClient(srv.URL, ""), identity: id.PublicKey, profile: profile},
			identity: id.PublicKey, pool: pool, owner: prov.OwnerPublicKey, srv: srv,
		},
		medium: m, svc: svc, w: w,
	}
}

func (r *logRig) witnessN(t *testing.T, n int) {
	t.Helper()

	dir := t.TempDir()
	txFile := txEnvelope(t, dir, conwayBody(retirement(hash224(r.pool))))

	for i := range n {
		if err := r.s.witness("pool", txFile, filepath.Join(dir, "w"), io.Discard); err != nil {
			t.Fatalf("witness %d: %v", i, err)
		}
	}
}

func (r *logRig) args(extra ...string) []string {
	return append([]string{"-signer", r.srv.URL, "-source", "", "-identity", hex.EncodeToString(r.identity)}, extra...)
}

func TestSignLogFetchesAndVerifies(t *testing.T) {
	t.Parallel()

	r := newLogRig(t, 8)
	r.witnessN(t, 2)

	var out bytes.Buffer
	if err := run(r.args("signlog"), &out); err != nil {
		t.Fatalf("signlog: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "1 tx-body "+profile+" pool body=") ||
		!strings.HasPrefix(lines[1], "2 tx-body ") || !strings.HasPrefix(lines[2], "ok: 2 entries, head 2 ") {
		t.Fatalf("output:\n%s", out.String())
	}

	// pinning the printed head passes; any other head fails
	head := strings.Fields(lines[2])
	pin := []string{"signlog", "-head-seq", "2", "-head-hash", head[len(head)-1]}

	if err := run(r.args(pin...), &bytes.Buffer{}); err != nil {
		t.Fatalf("pinned head refused: %v", err)
	}

	pin[2] = "1"
	if err := run(r.args(pin...), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "expected 1") {
		t.Fatalf("stale pin: %v", err)
	}

	if err := run(r.args("signlog", "-head-seq", "2"), &bytes.Buffer{}); err == nil {
		t.Fatal("a head number without a hash accepted")
	}

	if err := run(r.args("signlog", "-head-seq", "-5"), &bytes.Buffer{}); err == nil {
		t.Fatal("a negative head number accepted")
	}

	// a positional token stops flag parsing; the pin after it must not vanish
	pin = []string{"signlog", "unexpected", "-head-seq", "1", "-head-hash", head[len(head)-1]}
	if err := run(r.args(pin...), &bytes.Buffer{}); err == nil {
		t.Fatal("a head pin after a positional argument was ignored")
	}
}

// A log longer than one read is fetched in several and still verifies.
func TestSignLogFetchesInChunks(t *testing.T) {
	t.Parallel()

	slots := uint64(device.MaxLogBlocks/signlog.RecordBlocks + 10)
	r := newLogRig(t, slots+2)
	r.witnessN(t, int(slots))

	var out bytes.Buffer
	if err := run(r.args("signlog"), &out); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out.String(), "ok: "+itoa(slots)+" entries") {
		t.Fatalf("tail of output: %s", out.String()[max(0, out.Len()-120):])
	}

	if 1+slots*signlog.RecordBlocks <= device.MaxLogBlocks {
		t.Fatal("log fits one read; the chunk loop was not exercised")
	}
}

func itoa(n uint64) string { b, _ := json.Marshal(n); return string(b) }

func TestSignLogRefusesTamperedCard(t *testing.T) {
	t.Parallel()

	r := newLogRig(t, 8)
	r.witnessN(t, 2)

	blk := make([]byte, signlog.BlockSize)
	if err := r.medium.ReadBlocks(1, blk); err != nil {
		t.Fatal(err)
	}

	blk[20] ^= 1

	if err := r.medium.WriteBlocks(1, blk); err != nil {
		t.Fatal(err)
	}

	if err := run(r.args("signlog"), &bytes.Buffer{}); err == nil {
		t.Fatal("tampered log verified")
	}
}

func TestSignLogRefusesOtherIdentity(t *testing.T) {
	t.Parallel()

	r := newLogRig(t, 8)
	r.witnessN(t, 1)

	other, _, _ := ed25519.GenerateKey(nil)

	err := run([]string{"-signer", r.srv.URL, "-source", "", "-identity", hex.EncodeToString(other), "signlog"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "different device identity") {
		t.Fatalf("got %v", err)
	}
}

func TestSignLogHostKeyAuth(t *testing.T) {
	t.Parallel()

	r := newLogRig(t, 8)
	r.witnessN(t, 1)

	dir := t.TempDir()
	hostFile := filepath.Join(dir, "host.skey")

	var out bytes.Buffer
	if err := run([]string{"host-key", "-out", hostFile}, &out); err != nil {
		t.Fatal(err)
	}

	var keys device.HostKeyResponse

	devicePost(t, r.srv, "/provision/host-key", json.RawMessage(out.Bytes()), &keys)

	if err := run(r.args("signlog"), &bytes.Buffer{}); err == nil {
		t.Fatal("log served to an unauthenticated host once a host key is registered")
	}

	out.Reset()

	if err := run(r.args("-host-key", hostFile, "signlog"), &out); err != nil || !strings.Contains(out.String(), "ok: 1 entries") {
		t.Fatalf("authenticated: %v\n%s", err, out.String())
	}
}

// staleHead reports the head one entry behind the log, as a device that does
// not match its own medium would.
type staleHead struct{ *signlog.Writer }

func (s staleHead) Head() signlog.Head {
	h := s.Writer.Head()
	h.Seq--

	return h
}

// hugeHead reports a head beyond any log the device formats.
type hugeHead struct{ *signlog.Writer }

func (hugeHead) Head() signlog.Head { return signlog.Head{Seq: signlog.DefaultMaxEntries + 1} }

// TestSignLogBoundsTheRead checks the host does not let the head a device
// reports set how much it reads.
func TestSignLogBoundsTheRead(t *testing.T) {
	t.Parallel()

	r := newLogRig(t, 8)
	r.witnessN(t, 1)
	r.svc.SetSigningLog(hugeHead{r.w}, r.medium)

	if err := run(r.args("signlog"), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("got %v", err)
	}
}

func TestSignLogRefusesHeadThatDiffersFromLog(t *testing.T) {
	t.Parallel()

	r := newLogRig(t, 8)
	r.witnessN(t, 2)
	r.svc.SetSigningLog(staleHead{r.w}, r.medium)

	if err := run(r.args("signlog"), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "device reports") {
		t.Fatalf("got %v", err)
	}
}
