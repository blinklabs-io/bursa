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
	"errors"
	"net"
	"testing"
	"time"
)

type fp = [sha256.Size]byte

// remoteControlRig is an attested listener over TLS with one agent behind it.
type remoteControlRig struct {
	f    *tlsFixture
	a    *Agent
	addr string
	done chan error
}

func serveRemote(
	t *testing.T,
	f *tlsFixture,
	a *Agent,
	signers ...fp,
) *remoteControlRig {
	t.Helper()
	ln := f.listen(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- a.ServeAttestedService(ctx, ln, AttestedServiceConfig{
			Provider:          NoEvidenceProvider,
			AllowedClientSPKI: signers,
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("ServeAttestedService did not stop")
		}
	})
	return &remoteControlRig{f: f, a: a, addr: ln.Addr().String(), done: done}
}

// open dials as client and returns the connection and the Hello it received.
func (r *remoteControlRig) open(
	t *testing.T,
	client tls.Certificate,
) (*tls.Conn, Hello) {
	t.Helper()
	select {
	case err := <-r.done:
		t.Fatalf("ServeAttestedService stopped: %v", err)
	default:
	}
	conn := r.f.dial(t, r.addr, client)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var hello Hello
	if err := readFrame(conn, &hello); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	return conn, hello
}

// challenge sends an attestation request declaring role and
// returns the request and response.
func challenge(
	t *testing.T,
	conn net.Conn,
	role, profile string,
) (AttestationRequest, AttestationResponse) {
	t.Helper()
	req, err := NewAttestationRequest()
	if err != nil {
		t.Fatal(err)
	}
	req.Role = role
	req.Profile = profile
	if err := writeFrame(conn, req); err != nil {
		t.Fatalf("write challenge: %v", err)
	}
	var resp AttestationResponse
	if err := readFrame(conn, &resp); err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	return req, resp
}

// attest runs the challenge exchange declaring role ("" is sign) and verifies
// the response against cold.
func attest(
	t *testing.T,
	conn net.Conn,
	role, profile string,
	cold coldKeyPair,
) {
	t.Helper()
	req, resp := challenge(t, conn, role, profile)
	if resp.Error != "" {
		t.Fatalf("attestation error: %s", resp.Error)
	}
	wantRole := role
	if wantRole == "" {
		wantRole = ModeSign
	}
	if resp.Role != wantRole {
		t.Fatalf("response role = %q, want %q", resp.Role, wantRole)
	}
	if err := VerifyAttestation(
		t.Context(), req, resp, NoEvidenceProvider, cold.pub, resp.OpCert, nil,
	); err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}
}

func rpc(t *testing.T, conn net.Conn, cmd Command) Reply {
	t.Helper()
	if err := writeFrame(conn, cmd); err != nil {
		t.Fatalf("write %s: %v", cmd.Command, err)
	}
	var reply Reply
	if err := readFrame(conn, &reply); err != nil {
		t.Fatalf("read %s reply: %v", cmd.Command, err)
	}
	return reply
}

func requireRefused(t *testing.T, what string, reply Reply) {
	t.Helper()
	if reply.Ok || reply.Error == "" {
		t.Fatalf("%s was not refused: %+v", what, reply)
	}
}

// singleControlAgent is a one-profile agent with an installed key whose
// control list is controllers.
func singleControlAgent(
	t *testing.T,
	controllers ...fp,
) (*Agent, coldKeyPair) {
	t.Helper()
	cold := newColdKey(t)
	pc := profileOn(t, networkA, "pool", cold)
	pc.ControlClientSPKI = controllers
	a := newMultiAgent(t, pc)
	install(t, a, "pool", cold, 3, 52, 5)
	return a, cold
}

func TestRemoteControlStagesAndInstalls(t *testing.T) {
	t.Parallel()
	f := newTLSFixture(t)
	ctrl, ctrlFP := f.client(t, "controller")
	a, cold := singleControlAgent(t, ctrlFP)
	rig := serveRemote(t, f, a)

	conn, hello := rig.open(t, ctrl)
	if hello.Protocol != AttestedProtocolID || hello.Mode != ModeControl {
		t.Fatalf("hello = %+v, want %s mode %s", hello, AttestedProtocolID, ModeControl)
	}
	attest(t, conn, ModeControl, "", cold)

	staged := rpc(t, conn, Command{Command: CmdGenStagedKey})
	if !staged.Ok || len(staged.KESVKey) != 32 {
		t.Fatalf("gen-staged-key: %+v", staged)
	}
	opcert := makeOpCert(t, staged.KESVKey, 2, 4, cold)
	installed := rpc(t, conn, Command{Command: CmdInstallKey, OpCert: opcert})
	if !installed.Ok {
		t.Fatalf("install-key: %s", installed.Error)
	}
	info := rpc(t, conn, Command{Command: CmdInfo})
	if !info.Ok || info.Info == nil ||
		info.Info.ActiveIssueNumber != 2 ||
		!bytes.Equal(info.Info.ActiveKESVKey, staged.KESVKey) ||
		!bytes.Equal(info.Info.ActiveOpCert, opcert) {
		t.Fatalf("info does not reflect the installed key: %+v", info.Info)
	}
}

func TestRemoteControlServesDropKeyAndRefusesUnknownCommands(t *testing.T) {
	t.Parallel()
	f := newTLSFixture(t)
	ctrl, ctrlFP := f.client(t, "controller")
	a, cold := singleControlAgent(t, ctrlFP)
	rig := serveRemote(t, f, a)
	conn, hello := rig.open(t, ctrl)
	if hello.Mode != ModeControl {
		t.Fatalf("hello mode = %q, want %q", hello.Mode, ModeControl)
	}
	attest(t, conn, ModeControl, "", cold)

	staged := rpc(t, conn, Command{Command: CmdGenStagedKey})
	if !staged.Ok {
		t.Fatalf("gen-staged-key: %s", staged.Error)
	}
	reply := rpc(t, conn, Command{Command: CmdDropKey, Target: "staged"})
	if !reply.Ok || reply.Info == nil || reply.Info.StagedKESVKey != nil {
		t.Fatalf("drop-key: %+v", reply)
	}
	if !reply.Info.HasActiveKey {
		t.Fatal("dropping the staged key dropped the active key")
	}
	requireRefused(t, "unknown command", rpc(t, conn, Command{Command: "wipe"}))
}

func TestRemoteControlRefusesProfileNotPermitted(t *testing.T) {
	t.Parallel()
	f := newTLSFixture(t)
	ctrlA, fpA := f.client(t, "controller-a")
	coldA, coldB := newColdKey(t), newColdKey(t)
	pa := profileOn(t, networkA, "pool-a", coldA)
	pa.ControlClientSPKI = []fp{fpA}
	pb := profileOn(t, networkB, "pool-b", coldB)
	a := newMultiAgent(t, pa, pb)
	install(t, a, "pool-a", coldA, 3, 52, 5)
	before := install(t, a, "pool-b", coldB, 0, 25, 1)
	rig := serveRemote(t, f, a)
	conn, _ := rig.open(t, ctrlA)
	attest(t, conn, ModeControl, "pool-a", coldA)

	for _, cmd := range []Command{
		{Command: CmdGenStagedKey, Profile: "pool-b"},
		{Command: CmdInstallKey, Profile: "pool-b", OpCert: makeOpCert(t, before.vkey, 2, 0, coldB)},
		{Command: CmdInfo, Profile: "pool-b"},
		{Command: CmdGenStagedKey}, // two profiles: must name one
		{Command: CmdInfo},
		{Command: CmdGenStagedKey, Profile: "no-such-pool"},
	} {
		requireRefused(t, cmd.Command+" for "+cmd.Profile, rpc(t, conn, cmd))
	}
	infoB := a.profileInfo(named(t, a, "pool-b"))
	if infoB.StagedKESVKey != nil ||
		!bytes.Equal(infoB.ActiveKESVKey, before.vkey) ||
		infoB.ActiveIssueNumber != 1 {
		t.Fatalf("pool-b changed: %+v", infoB)
	}
	if reply := rpc(t, conn, Command{Command: CmdGenStagedKey, Profile: "pool-a"}); !reply.Ok {
		t.Fatalf("permitted profile refused: %s", reply.Error)
	}
}

func TestRemoteControlAndSignSessionsAreIsolated(t *testing.T) {
	t.Parallel()
	f := newTLSFixture(t)
	ctrl, ctrlFP := f.client(t, "controller")
	signer, signerFP := f.client(t, "signer")
	a, cold := singleControlAgent(t, ctrlFP)
	rig := serveRemote(t, f, a, signerFP)

	sconn, shello := rig.open(t, signer)
	if shello.Mode != ModeSign {
		t.Fatalf("signer hello mode = %q, want %q", shello.Mode, ModeSign)
	}
	attest(t, sconn, "", "", cold)
	var signReply struct {
		Ok        bool   `json:"ok"`
		Error     string `json:"error"`
		KESVKey   []byte `json:"kes_vkey"`
		Signature []byte `json:"signature"`
	}
	if err := writeFrame(sconn, Command{Command: CmdGenStagedKey}); err != nil {
		t.Fatal(err)
	}
	if err := readFrame(sconn, &signReply); err != nil {
		t.Fatalf("read reply to control frame on a sign session: %v", err)
	}
	if signReply.Ok || len(signReply.KESVKey) != 0 || signReply.Error == "" {
		t.Fatalf("sign session ran a control command: %+v", signReply)
	}
	if got := a.profileInfo(named(t, a, "pool")).StagedKESVKey; got != nil {
		t.Fatal("a sign session staged a key")
	}

	cconn, chello := rig.open(t, ctrl)
	if chello.Mode != ModeControl {
		t.Fatalf("controller hello mode = %q, want %q", chello.Mode, ModeControl)
	}
	attest(t, cconn, ModeControl, "", cold)
	signReply.Signature = nil
	if err := writeFrame(cconn, SignRequest{Type: "sign_request", Period: 5, Message: []byte{0x80}}); err != nil {
		t.Fatal(err)
	}
	if err := readFrame(cconn, &signReply); err != nil {
		t.Fatalf("read reply to sign frame on a control session: %v", err)
	}
	if signReply.Ok || len(signReply.Signature) != 0 || signReply.Error == "" {
		t.Fatalf("control session signed: %+v", signReply)
	}
}

func TestRemoteOneCertInBothListsOpensEitherRole(t *testing.T) {
	t.Parallel()
	f := newTLSFixture(t)
	both, bothFP := f.client(t, "both")
	a, cold := singleControlAgent(t, bothFP)
	rig := serveRemote(t, f, a, bothFP)

	sconn, shello := rig.open(t, both)
	if shello.Protocol != AttestedProtocolID {
		t.Fatalf("hello = %+v", shello)
	}
	attest(t, sconn, "", "", cold) // no role declared: sign
	if err := writeFrame(sconn, SignRequest{Type: "sign_request", Period: 5, Message: []byte{0x80}}); err != nil {
		t.Fatal(err)
	}
	var signed SignResponse
	if err := readFrame(sconn, &signed); err != nil {
		t.Fatalf("read sign response: %v", err)
	}
	if signed.Type != "sign_response" {
		t.Fatalf("sign session answered %+v", signed)
	}

	cconn, _ := rig.open(t, both)
	attest(t, cconn, ModeControl, "", cold)
	if reply := rpc(t, cconn, Command{Command: CmdGenStagedKey}); !reply.Ok {
		t.Fatalf("control session refused: %s", reply.Error)
	}
}

func TestRemoteRoleMustBeListedAndKnown(t *testing.T) {
	t.Parallel()
	f := newTLSFixture(t)
	ctrl, ctrlFP := f.client(t, "controller")
	signer, signerFP := f.client(t, "signer")
	a, _ := singleControlAgent(t, ctrlFP)
	rig := serveRemote(t, f, a, signerFP)

	for _, tc := range []struct {
		name   string
		client tls.Certificate
		role   string
	}{
		{"sign-only client declares control", signer, ModeControl},
		{"control-only client declares sign", ctrl, ""},
		{"unknown role", signer, "admin"},
	} {
		conn, _ := rig.open(t, tc.client)
		_, resp := challenge(t, conn, tc.role, "")
		if resp.Error == "" || len(resp.OpCert) != 0 {
			t.Fatalf("%s: admitted: %+v", tc.name, resp)
		}
	}
}

func TestAttestedServiceUnlistedClientRefusedBeforeHelloWithControl(t *testing.T) {
	t.Parallel()
	f := newTLSFixture(t)
	_, ctrlFP := f.client(t, "controller")
	_, signerFP := f.client(t, "signer")
	stranger, _ := f.client(t, "stranger")
	a, _ := singleControlAgent(t, ctrlFP)
	rig := serveRemote(t, f, a, signerFP)

	conn := f.dial(t, rig.addr, stranger)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hello Hello
	err := readFrame(conn, &hello)
	if err == nil {
		t.Fatalf("unlisted client received hello %+v", hello)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("unlisted client was not closed: %v", err)
	}
}

func TestRemoteControlAnyClientOverPlaintext(t *testing.T) {
	t.Parallel()
	coldA, coldB := newColdKey(t), newColdKey(t)
	pa := profileOn(t, networkA, "pool-a", coldA)
	pa.ControlAnyClient = true
	pb := profileOn(t, networkB, "pool-b", coldB)
	a := newMultiAgent(t, pa, pb)
	install(t, a, "pool-a", coldA, 3, 52, 5)
	install(t, a, "pool-b", coldB, 0, 25, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- a.ServeAttestedService(ctx, ln, AttestedServiceConfig{
			Provider:  NoEvidenceProvider,
			Plaintext: true,
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("ServeAttestedService did not stop")
		}
	})
	dial := func() net.Conn {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		var hello Hello
		if err := readFrame(conn, &hello); err != nil {
			t.Fatalf("read hello: %v", err)
		}
		return conn
	}

	conn := dial()
	req, err := NewAttestationRequest()
	if err != nil {
		t.Fatal(err)
	}
	req.Role = ModeControl
	req.Profile = "pool-a"
	if err := writeFrame(conn, req); err != nil {
		t.Fatal(err)
	}
	var resp AttestationResponse
	if err := readFrame(conn, &resp); err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	if resp.Error != "" || resp.Role != ModeControl {
		t.Fatalf("control over plaintext not admitted: %+v", resp)
	}
	staged := rpc(t, conn, Command{Command: CmdGenStagedKey, Profile: "pool-a"})
	if !staged.Ok || len(staged.KESVKey) != 32 {
		t.Fatalf("gen-staged-key: %+v", staged)
	}
	opcert := makeOpCert(t, staged.KESVKey, 2, 4, coldA)
	if reply := rpc(t, conn, Command{Command: CmdInstallKey, Profile: "pool-a", OpCert: opcert}); !reply.Ok {
		t.Fatalf("install-key: %s", reply.Error)
	}
	info := rpc(t, conn, Command{Command: CmdInfo, Profile: "pool-a"})
	if !info.Ok || info.Info == nil || info.Info.ActiveIssueNumber != 2 ||
		!bytes.Equal(info.Info.ActiveOpCert, opcert) {
		t.Fatalf("info does not reflect the installed key: %+v", info.Info)
	}
	// The option is per profile.
	requireRefused(t, "gen-staged-key on a profile without the option",
		rpc(t, conn, Command{Command: CmdGenStagedKey, Profile: "pool-b"}))

	// Without the option no client may declare the control role.
	solo := newMultiAgent(t, profileOn(t, networkA, "solo", coldA))
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(t.Context())
	done2 := make(chan error, 1)
	go func() {
		done2 <- solo.ServeAttestedService(ctx2, ln2, AttestedServiceConfig{
			Provider: NoEvidenceProvider, Plaintext: true,
		})
	}()
	t.Cleanup(func() { cancel2(); <-done2 })
	c2, err := net.DialTimeout("tcp", ln2.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c2.Close() })
	_ = c2.SetDeadline(time.Now().Add(5 * time.Second))
	var h Hello
	if err := readFrame(c2, &h); err != nil {
		t.Fatal(err)
	}
	_, refused := challenge(t, c2, ModeControl, "")
	if refused.Error == "" || len(refused.OpCert) != 0 {
		t.Fatalf("control admitted without control_any_client or a list: %+v", refused)
	}
}
