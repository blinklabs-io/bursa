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
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/armory/signlog"
)

// logRig is a service signing into a real log on an in-memory card.
type logRig struct {
	s    *Service
	chip *fakeChip
	w    *signlog.Writer
	m    *signlog.MemMedium
	pub  ed25519.PublicKey
}

func newLogRig(t *testing.T, slots uint64) *logRig {
	t.Helper()

	s, chip := newTestService(t)
	provisionTestProfile(t, s)

	pub, priv, _ := ed25519.GenerateKey(nil)
	m := signlog.NewMemMedium(1 + slots*signlog.RecordBlocks)

	w, err := signlog.Open(m, signlog.NewMemHeadStore(signlog.Head{}), signlog.NewKeySigner(priv))
	if err != nil {
		t.Fatal(err)
	}

	s.RequireSigningLog()
	s.SetSigningLog(w, m)

	return &logRig{s: s, chip: chip, w: w, m: m, pub: pub}
}

func (r *logRig) signN(t *testing.T, n int) {
	t.Helper()

	for i := range n {
		if resp := sign(t, r.s, poolTxRequest(t, r.chip, byte(100+i))); resp.Error != "" {
			t.Fatalf("sign %d: %s", i, resp.Error)
		}
	}
}

func readLog(t *testing.T, s *Service, req SignLogRequest) (int, SignLogResponse, string) {
	t.Helper()

	code, body := post(t, s, "/v1/signlog", req)

	var resp SignLogResponse
	if code == http.StatusOK {
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatal(err)
		}
	}

	return code, resp, string(body)
}

func authLogRead(req SignLogRequest, k ed25519.PrivateKey, ch []byte) SignLogRequest {
	req.Challenge = ch
	req.HostKey = hostPub(k)
	req.HostSignature = ed25519.Sign(k, SignLogBinding(req))

	return req
}

// The blocks the endpoint serves, with its head, are what a host verifies.
func TestSignLogReadBackVerifies(t *testing.T) {
	t.Parallel()

	r := newLogRig(t, 8)
	r.signN(t, 3)

	var prefix []byte

	var head SignLogResponse

	want := uint32(1 + 3*signlog.RecordBlocks)
	for from := uint32(0); from < want; from += 5 {
		count := min(5, want-from)

		code, resp, body := readLog(t, r.s, SignLogRequest{From: uint64(from), Count: count})
		if code != http.StatusOK {
			t.Fatalf("read %d+%d: %d %s", from, count, code, body)
		}

		if resp.From != uint64(from) || len(resp.Blocks) != int(count)*signlog.BlockSize {
			t.Fatalf("response from %d with %d bytes", resp.From, len(resp.Blocks))
		}

		prefix, head = append(prefix, resp.Blocks...), resp
	}

	if head.NumBlocks != r.m.NumBlocks() {
		t.Fatalf("num_blocks %d, want %d", head.NumBlocks, r.m.NumBlocks())
	}

	m, err := signlog.NewSparseMedium(head.NumBlocks, prefix)
	if err != nil {
		t.Fatal(err)
	}

	log, err := signlog.Verify(m, r.pub)
	if err != nil || len(log.Entries) != 3 {
		t.Fatalf("verify: %v", err)
	}

	got := log.Head()
	if head.HeadSeq != got.Seq || !bytes.Equal(head.HeadHash, got.Hash[:]) {
		t.Fatalf("served head %d %x, log head %d %x", head.HeadSeq, head.HeadHash, got.Seq, got.Hash)
	}

	// the entries are the ones the sign path logged
	if log.Entries[0].Purpose != signlog.PurposeTxBody || log.Entries[0].Profile != "otg@preview" {
		t.Fatalf("entry %+v", log.Entries[0])
	}
}

func TestSignLogReadRefusals(t *testing.T) {
	t.Parallel()

	// larger than MaxLogBlocks, so the per-read bound is the rule that refuses
	r := newLogRig(t, 40)
	n := r.m.NumBlocks()

	if n <= MaxLogBlocks+1 {
		t.Fatalf("medium of %d blocks does not isolate the read bound", n)
	}

	for name, req := range map[string]SignLogRequest{
		"too many blocks": {From: 0, Count: MaxLogBlocks + 1},
		"past the end":    {From: n - 1, Count: 2},
		"from past end":   {From: n + 1, Count: 0},
		"overflow":        {From: ^uint64(0), Count: 1},
	} {
		if code, _, _ := readLog(t, r.s, req); code == http.StatusOK {
			t.Errorf("%s: served", name)
		}
	}

	// the head alone, with no blocks
	if code, resp, body := readLog(t, r.s, SignLogRequest{}); code != http.StatusOK || len(resp.Blocks) != 0 || resp.NumBlocks != n {
		t.Fatalf("head only: %d %s", code, body)
	}
}

func TestSignLogReadWithoutLog(t *testing.T) {
	t.Parallel()

	s, _ := newTestService(t)
	s.RequireSigningLog()
	s.SigningLogFailed(errNoCardForTest)

	code, _, body := readLog(t, s, SignLogRequest{})
	if code == http.StatusOK || !strings.Contains(body, "signing log unavailable") || !strings.Contains(body, "no SD card") {
		t.Fatalf("%d %s", code, body)
	}

	// no log at all, none required
	s2, _ := newTestService(t)
	if code, _, body = readLog(t, s2, SignLogRequest{}); code == http.StatusOK {
		t.Fatalf("served without a log: %s", body)
	}
}

var errNoCardForTest = errors.New("no SD card")

// With a host key registered the read needs the same authentication a
// signing request does, and the signature covers the range asked for.
func TestSignLogReadHostAuth(t *testing.T) {
	t.Parallel()

	r := newLogRig(t, 4)
	registerHostKey(t, r.s, hostPub(testHostKey))

	req := SignLogRequest{From: 0, Count: 1}

	if code, _, _ := readLog(t, r.s, req); code == http.StatusOK {
		t.Fatal("unauthenticated read served")
	}

	ch := challenge(t, r.s)

	if code, _, body := readLog(t, r.s, authLogRead(req, testHostKey, ch)); code != http.StatusOK {
		t.Fatalf("authenticated read: %d %s", code, body)
	}

	// the challenge is single use
	again := authLogRead(req, testHostKey, ch)
	if code, _, _ := readLog(t, r.s, again); code == http.StatusOK {
		t.Fatal("replayed challenge served")
	}

	// a signature for another range does not carry over
	ch = challenge(t, r.s)
	forged := authLogRead(SignLogRequest{From: 0, Count: 1}, testHostKey, ch)
	forged.Count = 2

	if code, _, _ := readLog(t, r.s, forged); code == http.StatusOK {
		t.Fatal("read served with a signature over another range")
	}

	// a signing request signature cannot be replayed as a read
	ch = challenge(t, r.s)
	sreq := SignRequest{Version: Protocol, Challenge: ch}
	other := SignLogRequest{Challenge: ch, HostKey: hostPub(testHostKey), HostSignature: ed25519.Sign(testHostKey, RequestBinding(sreq))}

	if code, _, _ := readLog(t, r.s, other); code == http.StatusOK {
		t.Fatal("read served with a signing-request signature")
	}
}

// A mainnet-style build refuses reads until a host key is registered.
func TestSignLogReadRequiresHostAuthWhenRequired(t *testing.T) {
	t.Parallel()

	r := newLogRig(t, 4)
	r.s.RequireHostAuth()

	if code, _, body := readLog(t, r.s, SignLogRequest{}); code == http.StatusOK || !strings.Contains(body, "host authentication") {
		t.Fatalf("%d %s", code, body)
	}
}

func TestSigningHandlerServesSignLog(t *testing.T) {
	t.Parallel()

	s, _ := newTestService(t)

	if code := serve(s.SigningHandler(), "/v1/signlog", "{}"); code == http.StatusNotFound {
		t.Error("signing handler does not serve /v1/signlog")
	}

	if code := serve(s.ProvisioningHandler(), "/v1/signlog", "{}"); code != http.StatusNotFound {
		t.Errorf("provisioning handler serves /v1/signlog: %d", code)
	}
}

// Reads stop at the slot after the head: the rest of the card holds no entry
// and is not served.
func TestSignLogReadStopsAfterNextSlot(t *testing.T) {
	t.Parallel()

	r := newLogRig(t, 8)
	r.signN(t, 2)

	end := uint64(1 + 3*signlog.RecordBlocks)

	if code, _, body := readLog(t, r.s, SignLogRequest{From: 0, Count: uint32(end)}); code != http.StatusOK {
		t.Fatalf("used blocks and the next slot: %d %s", code, body)
	}

	for name, req := range map[string]SignLogRequest{
		"one block beyond": {From: 0, Count: uint32(end) + 1},
		"later slot":       {From: end, Count: 1},
		"last block":       {From: r.m.NumBlocks() - 1, Count: 1},
	} {
		if code, _, _ := readLog(t, r.s, req); code == http.StatusOK {
			t.Errorf("%s: served", name)
		}
	}

	// the head alone is still served from any position inside the bound
	if code, _, body := readLog(t, r.s, SignLogRequest{From: end}); code != http.StatusOK {
		t.Fatalf("head only at the bound: %d %s", code, body)
	}
}
