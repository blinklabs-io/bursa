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
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type spki = [sha256.Size]byte

// countingAttester counts Evidence calls so a test can show a refused client
// never reached evidence production.
type countingAttester struct{ calls atomic.Int64 }

func (c *countingAttester) Evidence(context.Context, []byte) ([]byte, error) {
	c.calls.Add(1)
	return []byte("evidence"), nil
}

// controlPKI issues the server and client certificates for a control rig.
// It exists apart from the listener because an agent's control list needs a
// client's key before the agent, and so the listener, can be built.
type controlPKI struct {
	t          *testing.T
	ca         *x509.Certificate
	caKey      *ecdsa.PrivateKey
	serverCert tls.Certificate
}

func newControlPKI(t *testing.T) *controlPKI {
	t.Helper()
	ca, caKey, _ := tlsTestCert(t, nil, nil, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "test ca"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	})
	_, _, serverCert := tlsTestCert(t, ca, caKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "server"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return &controlPKI{t: t, ca: ca, caKey: caKey, serverCert: serverCert}
}

// client issues a client certificate and returns it with its pinned key.
func (p *controlPKI) client(name string) (tls.Certificate, spki) {
	p.t.Helper()
	leaf, _, cert := tlsTestCert(p.t, p.ca, p.caKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: name},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return cert, sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
}

// controlRig is an attested TLS listener that verifies client certificates.
type controlRig struct {
	addr     string
	attester *countingAttester
}

func (p *controlPKI) serve(t *testing.T, a *Agent) *controlRig {
	t.Helper()
	rig := &controlRig{attester: &countingAttester{}}
	rig.addr = p.listen(t, a, rig.attester)
	return rig
}

// listen serves a on a verifying TLS listener with attester and returns its
// address.
func (p *controlPKI) listen(t *testing.T, a *Agent, attester Attester) string {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(p.ca)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{p.serverCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveAttested(t, a, ln, AttestedServiceConfig{
		Provider: "fake",
		Attester: attester,
	})
	return ln.Addr().String()
}

// open dials with client and returns the connection after the hello.
func (r *controlRig) open(t *testing.T, client tls.Certificate) *tls.Conn {
	t.Helper()
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second}, "tcp", r.addr,
		&tls.Config{
			MinVersion:         tls.VersionTLS13,
			Certificates:       []tls.Certificate{client},
			InsecureSkipVerify: true, //nolint:gosec // test server uses a throwaway CA
		},
	)
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var hello Hello
	if err := readFrame(conn, &hello); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if hello.Protocol != AttestedProtocolID || hello.Mode != ModeSign {
		t.Fatalf("hello = %+v", hello)
	}
	return conn
}

// challenge sends an attestation request declaring role and profile.
func challenge(
	t *testing.T,
	conn net.Conn,
	role, profile string,
) AttestationResponse {
	t.Helper()
	req, err := NewAttestationRequest()
	if err != nil {
		t.Fatal(err)
	}
	req.Role, req.Profile = role, profile
	if err := writeFrame(conn, req); err != nil {
		t.Fatalf("write challenge: %v", err)
	}
	var resp AttestationResponse
	if err := readFrame(conn, &resp); err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	return resp
}

func admit(t *testing.T, conn net.Conn, role, profile string) {
	t.Helper()
	resp := challenge(t, conn, role, profile)
	want := role
	if want == "" {
		want = RoleSign
	}
	if resp.Error != "" || resp.Role != want || len(resp.Attestation) == 0 {
		t.Fatalf("admission as %q: %+v", role, resp)
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

func requireRefused(t *testing.T, what, wantErr string, reply Reply) {
	t.Helper()
	if reply.Ok || !strings.Contains(reply.Error, wantErr) ||
		len(reply.KESVKey) != 0 || len(reply.Profiles) != 0 {
		t.Fatalf("%s: want refusal containing %q, got %+v", what, wantErr, reply)
	}
}

func hasStaged(p *profile) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.staged != nil
}

func activeVKey(t *testing.T, a *Agent, name string) []byte {
	t.Helper()
	reply := a.dispatch(t.Context(), Command{Command: CmdInfo, Profile: name})
	if !reply.Ok || reply.Info == nil {
		t.Fatalf("info %s: %+v", name, reply)
	}
	return reply.Info.ActiveKESVKey
}

// poolWithControl is a one-profile agent with an installed key whose control
// list is controllers.
func poolWithControl(
	t *testing.T,
	controllers ...spki,
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
	pki := newControlPKI(t)
	ctrl, ctrlFP := pki.client("controller")
	a, cold := poolWithControl(t, ctrlFP)
	rig := pki.serve(t, a)

	conn := rig.open(t, ctrl)
	admit(t, conn, RoleControl, "")
	staged := rpc(t, conn, Command{Command: CmdGenStagedKey})
	if !staged.Ok || len(staged.KESVKey) != 32 {
		t.Fatalf("gen-staged-key: %+v", staged)
	}
	opcert := makeOpCert(t, staged.KESVKey, 2, 4, cold)
	if r := rpc(t, conn, Command{Command: CmdInstallKey, OpCert: opcert}); !r.Ok {
		t.Fatalf("install-key: %s", r.Error)
	}
	info := rpc(t, conn, Command{Command: CmdInfo})
	if !info.Ok || info.Info == nil || info.Info.ActiveIssueNumber != 2 ||
		!bytes.Equal(info.Info.ActiveKESVKey, staged.KESVKey) ||
		!bytes.Equal(info.Info.ActiveOpCert, opcert) {
		t.Fatalf("info does not reflect the installed key: %+v", info.Info)
	}
}

func TestRemoteControlRefusesClientNotListed(t *testing.T) {
	t.Parallel()
	pki := newControlPKI(t)
	_, ctrlFP := pki.client("controller")
	stranger, _ := pki.client("stranger") // valid certificate, not pinned
	a, _ := poolWithControl(t, ctrlFP)
	rig := pki.serve(t, a)
	before := activeVKey(t, a, "pool")

	conn := rig.open(t, stranger)
	resp := challenge(t, conn, RoleControl, "")
	if resp.Error != ErrRoleNotPermitted.Error() ||
		len(resp.KESVKey) != 0 || len(resp.OpCert) != 0 ||
		len(resp.Attestation) != 0 || resp.Role != "" {
		t.Fatalf("unlisted client admitted or told state: %+v", resp)
	}
	if n := rig.attester.calls.Load(); n != 0 {
		t.Fatalf("evidence produced %d times for a refused client", n)
	}
	// An unlisted client learns nothing about profiles either: an unknown
	// profile name gets the same refusal, not a profile error.
	probe := rig.open(t, stranger)
	if got := challenge(t, probe, RoleControl, "no-such-pool"); got.Error != ErrRoleNotPermitted.Error() {
		t.Fatalf("unlisted client asking for an unknown profile: %+v", got)
	}
	// The session ends: a command gets no reply.
	_ = writeFrame(conn, Command{Command: CmdGenStagedKey})
	var reply Reply
	if err := readFrame(conn, &reply); err == nil {
		t.Fatalf("refused client was served: %+v", reply)
	}
	if hasStaged(sole(t, a)) || !bytes.Equal(activeVKey(t, a, "pool"), before) {
		t.Fatal("refused client changed key state")
	}
}

func TestRemoteControlRefusesUnknownRole(t *testing.T) {
	t.Parallel()
	pki := newControlPKI(t)
	ctrl, ctrlFP := pki.client("controller")
	a, _ := poolWithControl(t, ctrlFP)
	rig := pki.serve(t, a)

	conn := rig.open(t, ctrl)
	resp := challenge(t, conn, "admin", "")
	if resp.Error != ErrRoleNotPermitted.Error() || len(resp.OpCert) != 0 ||
		rig.attester.calls.Load() != 0 {
		t.Fatalf("unknown role: %+v", resp)
	}
}

func TestRemoteSignOnlyClientCannotRunControlCommands(t *testing.T) {
	t.Parallel()
	pki := newControlPKI(t)
	_, ctrlFP := pki.client("controller")
	signer, signerFP := pki.client("signer")
	a, _ := poolWithControl(t, ctrlFP)
	sole(t, a).cfg.SignClientSPKI = []spki{signerFP}
	rig := pki.serve(t, a)

	conn := rig.open(t, signer)
	admit(t, conn, "", "")
	for _, name := range []string{CmdGenStagedKey, CmdInstallKey, CmdDropKey, CmdInfo} {
		if err := writeFrame(conn, Command{Command: name}); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		var resp SignResponse
		if err := readFrame(conn, &resp); err != nil {
			t.Fatalf("read %s reply: %v", name, err)
		}
		// The sign handler answers: a control handler would reply with a
		// Reply frame and a control error instead.
		if resp.Type != "sign_response" ||
			!strings.Contains(resp.Error, "invalid sign request type") ||
			len(resp.Signature) != 0 {
			t.Fatalf("%s on a sign session: %+v", name, resp)
		}
	}
	if hasStaged(sole(t, a)) {
		t.Fatal("sign session staged a key")
	}
	if !sole(t, a).hasActiveVKey(activeVKey(t, a, "pool")) {
		t.Fatal("sign session changed the active key")
	}
}

func TestRemoteSigningStaysWithinListedProfiles(t *testing.T) {
	t.Parallel()
	pki := newControlPKI(t)
	signer, signerFP := pki.client("pool-a signer")
	shared, sharedFP := pki.client("shared signer")
	controller, controllerFP := pki.client("controller")
	stranger, _ := pki.client("unlisted signer")
	coldA, coldB := newColdKey(t), newColdKey(t)
	pcA := profileOn(t, networkA, "pool-a", coldA)
	pcA.SignClientSPKI = []spki{signerFP, sharedFP}
	pcA.ControlClientSPKI = []spki{controllerFP}
	pcB := profileOn(t, networkB, "pool-b", coldB)
	pcB.SignClientSPKI = []spki{sharedFP}
	a := newMultiAgent(t, pcA, pcB)
	install(t, a, "pool-a", coldA, 3, 52, 5)
	install(t, a, "pool-b", coldB, 0, 25, 1)
	rig := pki.serve(t, a)

	denied := rig.open(t, signer)
	resp := challenge(t, denied, RoleSign, "pool-b")
	if resp.Error != ErrRoleNotPermitted.Error() || len(resp.OpCert) != 0 ||
		len(resp.KESVKey) != 0 || len(resp.Attestation) != 0 || resp.Role != "" {
		t.Fatalf("profile-scoped signer admitted to another profile: %+v", resp)
	}
	if n := rig.attester.calls.Load(); n != 0 {
		t.Fatalf("evidence produced %d times for a refused signer", n)
	}
	unlisted := rig.open(t, stranger)
	if got := challenge(t, unlisted, RoleSign, "pool-a"); got.Error != ErrRoleNotPermitted.Error() || len(got.OpCert) != 0 {
		t.Fatalf("CA-valid unlisted signer admitted: %+v", got)
	}

	controlOnly := rig.open(t, controller)
	if got := challenge(t, controlOnly, RoleSign, "pool-a"); got.Error != ErrRoleNotPermitted.Error() || len(got.OpCert) != 0 {
		t.Fatalf("control authority implied signing authority: %+v", got)
	}

	admit(t, rig.open(t, signer), RoleSign, "pool-a")
	admit(t, rig.open(t, shared), RoleSign, "pool-a")
	admit(t, rig.open(t, shared), RoleSign, "pool-b")
}

func TestRemoteControlSessionRefusesSignFrames(t *testing.T) {
	t.Parallel()
	pki := newControlPKI(t)
	ctrl, ctrlFP := pki.client("controller")
	a, _ := poolWithControl(t, ctrlFP)
	rig := pki.serve(t, a)

	conn := rig.open(t, ctrl)
	admit(t, conn, RoleControl, "")
	if err := writeFrame(conn, SignRequest{
		Type: "sign_request", Period: 5, Message: []byte{0x80},
	}); err != nil {
		t.Fatalf("write sign request: %v", err)
	}
	var reply Reply
	if err := readFrame(conn, &reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	requireRefused(t, "sign frame on a control session", "unknown command", reply)
}

func TestRemoteControlRefusesDropKey(t *testing.T) {
	t.Parallel()
	pki := newControlPKI(t)
	ctrl, ctrlFP := pki.client("controller")
	a, _ := poolWithControl(t, ctrlFP)
	rig := pki.serve(t, a)
	active := activeVKey(t, a, "pool")

	conn := rig.open(t, ctrl)
	admit(t, conn, RoleControl, "")
	for _, target := range []string{"active", "staged"} {
		reply := rpc(t, conn, Command{Command: CmdDropKey, Target: target})
		requireRefused(t, "drop-key "+target, "drop-key is not served", reply)
	}
	if !bytes.Equal(activeVKey(t, a, "pool"), active) {
		t.Fatal("drop-key over remote control changed the active key")
	}
}

func TestRemoteControlStaysWithinListedProfiles(t *testing.T) {
	t.Parallel()
	pki := newControlPKI(t)
	ctrl, ctrlFP := pki.client("controller")
	coldA, coldB := newColdKey(t), newColdKey(t)
	pcA := profileOn(t, networkA, "pool-a", coldA)
	pcA.ControlClientSPKI = []spki{ctrlFP}
	pcB := profileOn(t, networkB, "pool-b", coldB) // controller not listed
	a := newMultiAgent(t, pcA, pcB)
	install(t, a, "pool-a", coldA, 3, 52, 5)
	pb := install(t, a, "pool-b", coldB, 0, 25, 1)
	rig := pki.serve(t, a)

	// A session cannot be admitted for a profile it is not listed on.
	denied := rig.open(t, ctrl)
	resp := challenge(t, denied, RoleControl, "pool-b")
	if resp.Error != ErrRoleNotPermitted.Error() || len(resp.OpCert) != 0 ||
		rig.attester.calls.Load() != 0 {
		t.Fatalf("admitted for an unlisted profile: %+v", resp)
	}

	conn := rig.open(t, ctrl)
	admit(t, conn, RoleControl, "pool-a")
	for _, cmd := range []Command{
		{Command: CmdGenStagedKey, Profile: "pool-b"},
		{Command: CmdInstallKey, Profile: "pool-b", OpCert: makeOpCert(t, pb.vkey, 9, 0, coldB)},
		{Command: CmdInfo, Profile: "pool-b"},
	} {
		requireRefused(t, cmd.Command+" on pool-b", "not permitted to control", rpc(t, conn, cmd))
	}
	// info without a profile on a multi-profile agent must not list every
	// pool, listed or not.
	requireRefused(t, "info without a profile", "profile", rpc(t, conn, Command{Command: CmdInfo}))
	if hasStaged(named(t, a, "pool-b")) ||
		!bytes.Equal(activeVKey(t, a, "pool-b"), pb.vkey) {
		t.Fatal("control session changed an unlisted profile")
	}
	// The listed profile still works on the same session.
	if r := rpc(t, conn, Command{Command: CmdGenStagedKey, Profile: "pool-a"}); !r.Ok {
		t.Fatalf("gen-staged-key on the listed profile: %+v", r)
	}
}

func TestServeAttestedServiceRefusesControlWithoutClientCertVerification(t *testing.T) {
	t.Parallel()
	for name, cfg := range map[string]AttestedServiceConfig{
		"plaintext":     {Plaintext: true},
		"cert optional": {ClientCertOptional: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a, _ := poolWithControl(t, spki{1})
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			cfg.Provider = NoEvidenceProvider
			// A bounded context turns a missing refusal into a failure
			// instead of a hang.
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			err = a.ServeAttestedService(ctx, ln, cfg)
			if !errors.Is(err, ErrClientAuthorizationNeedsClientCert) {
				t.Fatalf("err = %v, want ErrClientAuthorizationNeedsClientCert", err)
			}
		})
	}
}

// A control client learns nothing about profiles outside its list: a key or
// name that resolves outside the list, an unlisted profile with no key and an
// unknown name all get the same refusal, before any evidence.
func TestRemoteControlRefusalHidesOtherProfiles(t *testing.T) {
	t.Parallel()
	pki := newControlPKI(t)
	ctrl, ctrlFP := pki.client("controller")
	coldA, coldB, coldC := newColdKey(t), newColdKey(t), newColdKey(t)
	pcA := profileOn(t, networkA, "pool-a", coldA)
	pcA.ControlClientSPKI = []spki{ctrlFP}
	pcB := profileOn(t, networkB, "pool-b", coldB)
	pcC := profileOn(t, networkA, "pool-c", coldC) // never gets a key
	a := newMultiAgent(t, pcA, pcB, pcC)
	install(t, a, "pool-a", coldA, 3, 52, 5)
	pb := install(t, a, "pool-b", coldB, 0, 25, 1)
	rig := pki.serve(t, a)

	for _, tc := range []struct {
		what    string
		profile string
		kesVKey []byte
	}{
		{"listed name with another profile's key", "pool-a", pb.vkey},
		{"another profile's key alone", "", pb.vkey},
		{"unlisted profile with no key", "pool-c", nil},
		{"unknown profile", "no-such-pool", nil},
	} {
		conn := rig.open(t, ctrl)
		req, err := NewAttestationRequest()
		if err != nil {
			t.Fatal(err)
		}
		req.Role, req.Profile, req.KESVKey = RoleControl, tc.profile, tc.kesVKey
		if err := writeFrame(conn, req); err != nil {
			t.Fatalf("%s: write: %v", tc.what, err)
		}
		var resp AttestationResponse
		if err := readFrame(conn, &resp); err != nil {
			t.Fatalf("%s: read: %v", tc.what, err)
		}
		if resp.Error != ErrRoleNotPermitted.Error() || len(resp.OpCert) != 0 ||
			len(resp.KESVKey) != 0 {
			t.Errorf("%s: response %q, want %q with no key state",
				tc.what, resp.Error, ErrRoleNotPermitted.Error())
		}
	}
	if n := rig.attester.calls.Load(); n != 0 {
		t.Fatalf("evidence produced %d time(s) for refused control requests", n)
	}
}
