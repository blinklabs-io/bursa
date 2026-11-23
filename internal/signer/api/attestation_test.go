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

package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/kesagent"
	"github.com/blinklabs-io/bursa/internal/signer"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/kesagent/wire"
)

// attestFixture is a signer server whose caller "alice" holds one cold key,
// with agentA pinned for it and no kes_vkeys listed unless listed is set.
type attestFixture struct {
	srv    *Server
	hash   backend.KeyHash
	agentA *ecdsa.PrivateKey
	agentB *ecdsa.PrivateKey
}

func newAttestFixture(
	t *testing.T,
	pinProfile string,
	listed ...[32]byte,
) attestFixture {
	t.Helper()
	agentA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The cold key hash is only known once the server exists, so build the
	// server with a placeholder ACL first, as TestHandleSignOpCert_ACLDenied
	// does, then swap in the real one.
	srv, h, _ := newOpCertServer(t, []string{"opcert"}, NewCallerACL(nil))
	spki, err := marshalSPKI(agentA)
	if err != nil {
		t.Fatal(err)
	}
	grant := signer.CallerGrant{
		Keys: []backend.KeyHash{h},
		KESAgents: map[backend.KeyHash][]signer.KESAgentPin{
			h: {{SPKISHA256: sha256.Sum256(spki), Profile: pinProfile}},
		},
	}
	if len(listed) > 0 {
		grant.OpCerts = map[backend.KeyHash][][32]byte{h: listed}
	}
	srv.acl = NewCallerACL(map[string]signer.CallerGrant{"alice": grant})
	return attestFixture{srv: srv, hash: h, agentA: agentA, agentB: agentB}
}

func marshalSPKI(k *ecdsa.PrivateKey) ([]byte, error) {
	att, err := wire.SignStagedKey(k, "x", make([]byte, 32), make([]byte, 28))
	if err != nil {
		return nil, err
	}
	return att.SPKI, nil
}

func (f attestFixture) attest(
	t *testing.T,
	by *ecdsa.PrivateKey,
	profile string,
	kesVKey []byte,
	cold backend.KeyHash,
) *wire.StagedKeyAttestation {
	t.Helper()
	att, err := wire.SignStagedKey(by, profile, kesVKey, cold[:])
	if err != nil {
		t.Fatal(err)
	}
	return att
}

func (f attestFixture) post(
	t *testing.T,
	kesVKey []byte,
	att *wire.StagedKeyAttestation,
) (int, string) {
	t.Helper()
	body, err := json.Marshal(SignRequest{
		Type:        "opcert",
		Key:         f.hash.String(),
		KesVkey:     hex.EncodeToString(kesVKey),
		KesPeriod:   42,
		Attestation: att,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := withCaller(
		httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body)),
		"alice",
	)
	rr := httptest.NewRecorder()
	f.srv.handleSign(rr, req)
	return rr.Code, rr.Body.String()
}

func TestHandleSignOpCertAttestation(t *testing.T) {
	t.Parallel()
	vkey := bytes.Repeat([]byte{0x5A}, 32)
	otherVKey := bytes.Repeat([]byte{0x5B}, 32)
	const (
		notGranted = "caller is not authorized for this opcert"
		refused    = "opcert attestation refused: "
	)
	otherCold := backend.KeyHash{0xEE}

	cases := []struct {
		name       string
		pinProfile string
		listed     [][32]byte
		build      func(t *testing.T, f attestFixture) *wire.StagedKeyAttestation
		wantCode   int
		wantBody   string
	}{
		{
			name: "attested key from the pinned agent is issued",
			build: func(t *testing.T, f attestFixture) *wire.StagedKeyAttestation {
				return f.attest(t, f.agentA, "pool-a", vkey, f.hash)
			},
			wantCode: http.StatusOK,
		},
		{
			name:       "profile pin matches",
			pinProfile: "pool-a",
			build: func(t *testing.T, f attestFixture) *wire.StagedKeyAttestation {
				return f.attest(t, f.agentA, "pool-a", vkey, f.hash)
			},
			wantCode: http.StatusOK,
		},
		{
			name: "self-generated key without attestation is refused",
			build: func(*testing.T, attestFixture) *wire.StagedKeyAttestation {
				return nil
			},
			wantCode: http.StatusForbidden,
			wantBody: notGranted,
		},
		{
			name: "attestation from an unpinned agent is refused",
			build: func(t *testing.T, f attestFixture) *wire.StagedKeyAttestation {
				return f.attest(t, f.agentB, "pool-a", vkey, f.hash)
			},
			wantCode: http.StatusForbidden,
			wantBody: refused + ErrAttestationAgentUntrusted.Error(),
		},
		{
			name: "attestation over a different vkey is refused",
			build: func(t *testing.T, f attestFixture) *wire.StagedKeyAttestation {
				return f.attest(t, f.agentA, "pool-a", otherVKey, f.hash)
			},
			wantCode: http.StatusForbidden,
			wantBody: refused + ErrAttestationKESKey.Error(),
		},
		{
			name: "attestation for a different pool is refused",
			build: func(t *testing.T, f attestFixture) *wire.StagedKeyAttestation {
				return f.attest(t, f.agentA, "pool-a", vkey, otherCold)
			},
			wantCode: http.StatusForbidden,
			wantBody: refused + ErrAttestationColdKey.Error(),
		},
		{
			name:       "attestation for a different profile is refused",
			pinProfile: "pool-a",
			build: func(t *testing.T, f attestFixture) *wire.StagedKeyAttestation {
				return f.attest(t, f.agentA, "pool-b", vkey, f.hash)
			},
			wantCode: http.StatusForbidden,
			wantBody: refused + ErrAttestationProfile.Error(),
		},
		{
			name: "tampered signature is refused",
			build: func(t *testing.T, f attestFixture) *wire.StagedKeyAttestation {
				att := f.attest(t, f.agentA, "pool-a", vkey, f.hash)
				att.Signature[len(att.Signature)-1] ^= 0x01
				return att
			},
			wantCode: http.StatusForbidden,
			wantBody: refused + wire.ErrStagedKeyAttestationSignature.Error(),
		},
		{
			name: "vkey rewritten after signing is refused",
			build: func(t *testing.T, f attestFixture) *wire.StagedKeyAttestation {
				att := f.attest(t, f.agentA, "pool-a", otherVKey, f.hash)
				att.KESVKey = vkey
				return att
			},
			wantCode: http.StatusForbidden,
			wantBody: refused + wire.ErrStagedKeyAttestationSignature.Error(),
		},
		{
			name: "empty attestation is malformed, not absent",
			build: func(*testing.T, attestFixture) *wire.StagedKeyAttestation {
				return &wire.StagedKeyAttestation{}
			},
			wantCode: http.StatusForbidden,
			wantBody: refused + wire.ErrStagedKeyAttestationMalformed.Error(),
		},
		{
			name:   "listed vkey is issued without attestation",
			listed: [][32]byte{[32]byte(vkey)},
			build: func(*testing.T, attestFixture) *wire.StagedKeyAttestation {
				return nil
			},
			wantCode: http.StatusOK,
		},
		{
			name:   "listed vkey with a bad attestation is refused",
			listed: [][32]byte{[32]byte(vkey)},
			build: func(t *testing.T, f attestFixture) *wire.StagedKeyAttestation {
				return f.attest(t, f.agentB, "pool-a", vkey, f.hash)
			},
			wantCode: http.StatusForbidden,
			wantBody: refused + ErrAttestationAgentUntrusted.Error(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newAttestFixture(t, tc.pinProfile, tc.listed...)
			code, body := f.post(t, vkey, tc.build(t, f))
			if code != tc.wantCode {
				t.Fatalf("status = %d (%s), want %d", code, body, tc.wantCode)
			}
			if tc.wantBody != "" && !strings.Contains(body, tc.wantBody) {
				t.Fatalf("body %q does not contain %q", body, tc.wantBody)
			}
		})
	}
}

// A valid attestation does not help a caller that does not hold the cold key.
func TestAuthorizeAttestedOpCertRequiresColdKeyGrant(t *testing.T) {
	t.Parallel()
	f := newAttestFixture(t, "")
	vkey := bytes.Repeat([]byte{0x5A}, 32)
	att := f.attest(t, f.agentA, "pool-a", vkey, f.hash)
	for _, caller := range []string{"bob", ""} {
		err := f.srv.acl.AuthorizeAttestedOpCert(caller, f.hash, vkey, att)
		if !errors.Is(err, ErrOpCertNotGranted) {
			t.Fatalf("caller %q: err = %v, want ErrOpCertNotGranted", caller, err)
		}
	}
	var nilACL *CallerACL
	if err := nilACL.AuthorizeAttestedOpCert("alice", f.hash, vkey, att); !errors.Is(err, ErrOpCertNotGranted) {
		t.Fatalf("nil ACL: err = %v", err)
	}
	other := backend.KeyHash{0x77}
	if err := f.srv.acl.AuthorizeAttestedOpCert("alice", other, vkey, att); !errors.Is(err, ErrOpCertNotGranted) {
		t.Fatalf("ungranted cold key: err = %v", err)
	}
}

// A reply the agent really produces, served over its control socket, is
// admitted by the signer through the same verifier.
func TestAgentStagedKeyAttestationAdmittedBySigner(t *testing.T) {
	t.Parallel()
	coldPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "kes")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	agent, err := kesagent.New(kesagent.Config{
		Mode:              kesagent.ModeServeKey,
		SystemStart:       time.Now().Add(-time.Hour),
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 129600,
		MaxKESEvolutions:  62,
		ColdVKey:          coldPub,
		GuardPath:         filepath.Join(dir, "guard.json"),
		EvolveInterval:    time.Hour,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("kesagent.New: %v", err)
	}
	t.Cleanup(agent.Close)
	sock := filepath.Join(dir, "c.sock")
	ln, err := kesagent.ListenUnix(sock, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = agent.ServeControl(ctx, ln) }()

	gen := func() kesagent.Reply {
		reply, err := kesagent.ControlRequest(
			ctx, sock, kesagent.Command{Command: kesagent.CmdGenStagedKey},
		)
		if err != nil || !reply.Ok {
			t.Fatalf("gen-staged-key: %+v, %v", reply, err)
		}
		return reply
	}
	if gen().StagedKeyAttestation != nil {
		t.Fatal("an agent with no identity key must not attest")
	}
	agent.SetStagedKeyIdentity(identity)
	reply := gen()
	if reply.StagedKeyAttestation == nil {
		t.Fatal("agent with an identity key returned no attestation")
	}

	coldHash := backend.HashPublicKey(coldPub)
	spki := reply.StagedKeyAttestation.SPKISHA256()
	acl := NewCallerACL(map[string]signer.CallerGrant{
		"alice": {
			Keys: []backend.KeyHash{coldHash},
			KESAgents: map[backend.KeyHash][]signer.KESAgentPin{
				coldHash: {{SPKISHA256: spki, Profile: kesagent.DefaultProfileName}},
			},
		},
	})
	if err := acl.AuthorizeAttestedOpCert(
		"alice", coldHash, reply.KESVKey, reply.StagedKeyAttestation,
	); err != nil {
		t.Fatalf("agent's own attestation refused: %v", err)
	}
	// The key the agent staged first was replaced; its attestation is for
	// a vkey that is no longer the one being certified.
	if err := acl.AuthorizeAttestedOpCert(
		"alice", coldHash, bytes.Repeat([]byte{1}, 32), reply.StagedKeyAttestation,
	); !errors.Is(err, ErrAttestationKESKey) {
		t.Fatalf("err = %v, want ErrAttestationKESKey", err)
	}
}
