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
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/gouroboros/kes"
)

// keylessPool is a one-profile agent with no installed key, as after a restart
// without a shared key store. controllers may open control sessions and
// signers may open sign sessions.
func keylessPool(
	t *testing.T,
	controllers, signers []spki,
) (*Agent, coldKeyPair) {
	t.Helper()
	cold := newColdKey(t)
	pc := profileOn(t, networkA, "pool", cold)
	pc.ControlClientSPKI = controllers
	pc.SignClientSPKI = signers
	return newMultiAgent(t, pc), cold
}

func TestRemoteControlAdmitsKeylessProfileAndReportsNoKey(t *testing.T) {
	t.Parallel()
	pki := newControlPKI(t)
	ctrl, ctrlFP := pki.client("controller")
	a, _ := keylessPool(t, []spki{ctrlFP}, nil)
	rig := pki.serve(t, a)

	conn := rig.open(t, ctrl)
	resp := challenge(t, conn, RoleControl, "")
	if resp.Error != "" || resp.Role != RoleControl ||
		len(resp.Attestation) == 0 {
		t.Fatalf("keyless control admission refused: %+v", resp)
	}
	if len(resp.KESVKey) != 0 || len(resp.OpCert) != 0 || resp.Period != 0 {
		t.Fatalf("keyless admission carried key state: %+v", resp)
	}
	info := rpc(t, conn, Command{Command: CmdInfo})
	if !info.Ok || info.Info == nil || info.Info.HasActiveKey ||
		len(info.Info.ActiveKESVKey) != 0 || len(info.Info.ActiveOpCert) != 0 ||
		len(info.Info.StagedKESVKey) != 0 {
		t.Fatalf("info on a keyless profile: %+v", info)
	}
	staged := rpc(t, conn, Command{Command: CmdGenStagedKey})
	if !staged.Ok {
		t.Fatalf("gen-staged-key: %+v", staged)
	}
	info = rpc(t, conn, Command{Command: CmdInfo})
	if !info.Ok || info.Info.HasActiveKey ||
		!bytes.Equal(info.Info.StagedKESVKey, staged.KESVKey) {
		t.Fatalf("info after staging: %+v", info.Info)
	}
}

func TestRemoteControlKeylessEvidenceBindsKeylessState(t *testing.T) {
	t.Parallel()
	pki := newControlPKI(t)
	ctrl, ctrlFP := pki.client("controller")
	a, cold := keylessPool(t, []spki{ctrlFP}, nil)
	rig := &controlRig{addr: pki.listen(t, a, bindingAttester{})}

	resp := challenge(t, rig.open(t, ctrl), RoleControl, "")
	if resp.Error != "" || resp.Role != RoleControl {
		t.Fatalf("keyless control admission refused: %+v", resp)
	}
	want := AttestationBinding(resp.Nonce, cold.pub, nil, nil, 0)
	if !bytes.Equal(resp.Attestation, want) {
		t.Fatal("keyless evidence does not commit to the keyless state")
	}
}

func TestRemoteControlKeylessInstallKeepsDurableFloor(t *testing.T) {
	t.Parallel()
	pki := newControlPKI(t)
	ctrl, ctrlFP := pki.client("controller")
	cold := newColdKey(t)
	pc := profileOn(t, networkA, "pool", cold)
	pc.ControlClientSPKI = []spki{ctrlFP}

	// A key installed at period 7 leaves a durable floor of 7. The restarted
	// agent holds no key and its clock reads period 5.
	first := newMultiAgent(t, pc)
	first.now = func() time.Time { return atPeriod(7) }
	vkey, err := first.GenStagedKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.InstallKey(makeOpCert(t, vkey, 1, 7, cold)); err != nil {
		t.Fatalf("first install: %v", err)
	}
	first.Close()
	restarted := newMultiAgent(t, pc)
	rig := pki.serve(t, restarted)

	conn := rig.open(t, ctrl)
	admit(t, conn, RoleControl, "")
	staged := rpc(t, conn, Command{Command: CmdGenStagedKey})
	if !staged.Ok {
		t.Fatalf("gen-staged-key: %+v", staged)
	}
	r := rpc(t, conn, Command{
		Command: CmdInstallKey,
		OpCert:  makeOpCert(t, staged.KESVKey, 2, 4, cold),
	})
	if r.Ok || !strings.Contains(r.Error, ErrPeriodRollback.Error()) {
		t.Fatalf("install below the durable floor: %+v", r)
	}
	if sole(t, restarted).hasActiveVKey(staged.KESVKey) {
		t.Fatal("an install below the floor activated a key")
	}
}

func TestRemoteControlBootstrapsKeylessProfileThenSigns(t *testing.T) {
	t.Parallel()
	pki := newControlPKI(t)
	ctrl, ctrlFP := pki.client("controller")
	signer, signerFP := pki.client("signer")
	a, cold := keylessPool(t, []spki{ctrlFP}, []spki{signerFP})
	rig := pki.serve(t, a)

	conn := rig.open(t, ctrl)
	admit(t, conn, RoleControl, "")
	staged := rpc(t, conn, Command{Command: CmdGenStagedKey})
	if !staged.Ok || len(staged.KESVKey) != 32 {
		t.Fatalf("gen-staged-key: %+v", staged)
	}

	// The opcert must still be cold-signed, commit to the staged key and
	// respect the KES period: none of these checks depends on a prior key.
	other := newColdKey(t)
	for name, opcert := range map[string][]byte{
		"signed by another cold key": makeOpCert(t, staged.KESVKey, 2, 4, other),
		"committing to another key":  makeOpCert(t, bytes.Repeat([]byte{9}, 32), 2, 4, cold),
		"starting after the current": makeOpCert(t, staged.KESVKey, 2, 6, cold),
	} {
		if r := rpc(t, conn, Command{Command: CmdInstallKey, OpCert: opcert}); r.Ok {
			t.Fatalf("install-key accepted an opcert %s", name)
		}
	}
	if sole(t, a).hasActiveVKey(staged.KESVKey) {
		t.Fatal("a refused opcert installed a key")
	}

	opcert := makeOpCert(t, staged.KESVKey, 2, 4, cold)
	if r := rpc(t, conn, Command{Command: CmdInstallKey, OpCert: opcert}); !r.Ok {
		t.Fatalf("install-key: %s", r.Error)
	}
	info := rpc(t, conn, Command{Command: CmdInfo})
	if !info.Ok || !info.Info.HasActiveKey ||
		!bytes.Equal(info.Info.ActiveKESVKey, staged.KESVKey) {
		t.Fatalf("info after install: %+v", info.Info)
	}

	// The same control authority now attests a keyed profile.
	again := challenge(t, rig.open(t, ctrl), RoleControl, "")
	if again.Error != "" || !bytes.Equal(again.KESVKey, staged.KESVKey) ||
		!bytes.Equal(again.OpCert, opcert) {
		t.Fatalf("control admission after install: %+v", again)
	}

	sconn := rig.open(t, signer)
	admit(t, sconn, RoleSign, "")
	spec := headerSpec{
		slot:      52,
		issuer:    cold.pub,
		hotVkey:   staged.KESVKey,
		sequence:  2,
		kesPeriod: 4,
		coldSig:   opCertColdSig(t, opcert),
	}
	msg := spec.encode(t)
	if err := writeFrame(sconn, SignRequest{
		Type: "sign_request", Period: 5, Message: msg,
	}); err != nil {
		t.Fatalf("write sign request: %v", err)
	}
	var signed SignResponse
	if err := readFrame(sconn, &signed); err != nil {
		t.Fatalf("read sign response: %v", err)
	}
	if signed.Error != "" ||
		!kes.VerifySignedKES(staged.KESVKey, 5-4, msg, signed.Signature) {
		t.Fatalf("sign after bootstrap: %+v", signed)
	}
}

func TestRemoteSignRefusesKeylessProfile(t *testing.T) {
	t.Parallel()
	pki := newControlPKI(t)
	ctrl, ctrlFP := pki.client("controller")
	signer, signerFP := pki.client("signer")
	a, _ := keylessPool(t, []spki{ctrlFP}, []spki{signerFP})
	rig := pki.serve(t, a)

	resp := challenge(t, rig.open(t, signer), RoleSign, "")
	if resp.Error != ErrNoActiveKey.Error() || len(resp.KESVKey) != 0 ||
		len(resp.OpCert) != 0 || len(resp.Attestation) != 0 || resp.Role != "" {
		t.Fatalf("sign admission on a keyless profile: %+v", resp)
	}
	resp = challenge(t, rig.open(t, signer), RoleSign, "pool")
	if resp.Error != ErrNoActiveKey.Error() || resp.Role != "" {
		t.Fatalf("named sign admission on a keyless profile: %+v", resp)
	}
	// Control authority does not imply signing authority on a keyless
	// profile either.
	resp = challenge(t, rig.open(t, ctrl), RoleSign, "")
	if resp.Error != ErrRoleNotPermitted.Error() || resp.Role != "" {
		t.Fatalf("control client admitted to sign: %+v", resp)
	}
	if n := rig.attester.calls.Load(); n != 0 {
		t.Fatalf("evidence produced %d times for refused sign sessions", n)
	}
}

func TestRemoteControlKeylessRefusesUnlistedClient(t *testing.T) {
	t.Parallel()
	pki := newControlPKI(t)
	_, ctrlFP := pki.client("controller")
	stranger, _ := pki.client("stranger")
	a, _ := keylessPool(t, []spki{ctrlFP}, nil)
	rig := pki.serve(t, a)

	resp := challenge(t, rig.open(t, stranger), RoleControl, "")
	if resp.Error != ErrRoleNotPermitted.Error() || len(resp.KESVKey) != 0 ||
		len(resp.OpCert) != 0 || len(resp.Attestation) != 0 || resp.Role != "" {
		t.Fatalf("unlisted client on a keyless profile: %+v", resp)
	}
	if n := rig.attester.calls.Load(); n != 0 {
		t.Fatalf("evidence produced %d times for a refused client", n)
	}
	if hasStaged(sole(t, a)) {
		t.Fatal("refused client changed key state")
	}
}

func TestRemoteControlKeylessRefusesDropKey(t *testing.T) {
	t.Parallel()
	pki := newControlPKI(t)
	ctrl, ctrlFP := pki.client("controller")
	a, _ := keylessPool(t, []spki{ctrlFP}, nil)
	rig := pki.serve(t, a)

	conn := rig.open(t, ctrl)
	admit(t, conn, RoleControl, "")
	staged := rpc(t, conn, Command{Command: CmdGenStagedKey})
	if !staged.Ok {
		t.Fatalf("gen-staged-key: %+v", staged)
	}
	for _, target := range []string{"active", "staged", "all"} {
		reply := rpc(t, conn, Command{Command: CmdDropKey, Target: target})
		requireRefused(t, "drop-key "+target, "drop-key is not served", reply)
	}
	if !hasStaged(sole(t, a)) {
		t.Fatal("drop-key over remote control dropped the staged key")
	}
}

func TestRemoteControlKeylessSelectsByNameNotByKey(t *testing.T) {
	t.Parallel()
	pki := newControlPKI(t)
	ctrl, ctrlFP := pki.client("controller")
	coldA, coldB := newColdKey(t), newColdKey(t)
	pcA := profileOn(t, networkA, "pool-a", coldA)
	pcA.ControlClientSPKI = []spki{ctrlFP}
	pcB := profileOn(t, networkB, "pool-b", coldB)
	pcB.ControlClientSPKI = []spki{ctrlFP}
	a := newMultiAgent(t, pcA, pcB)
	rig := pki.serve(t, a)

	// Neither profile has a key, so a kes_vkey selects nothing.
	conn := rig.open(t, ctrl)
	req, err := NewAttestationRequest()
	if err != nil {
		t.Fatal(err)
	}
	req.Role, req.KESVKey = RoleControl, bytes.Repeat([]byte{4}, 32)
	if err := writeFrame(conn, req); err != nil {
		t.Fatal(err)
	}
	var resp AttestationResponse
	if err := readFrame(conn, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != ErrRoleNotPermitted.Error() || resp.Role != "" {
		t.Fatalf("selection by kes_vkey on keyless profiles: %+v", resp)
	}
	// Several profiles and no selector stays ambiguous.
	if got := challenge(t, rig.open(t, ctrl), RoleControl, ""); got.Error != ErrAmbiguousProfile.Error() {
		t.Fatalf("no selector across two profiles: %+v", got)
	}
	// A name selects a keyless profile.
	if got := challenge(t, rig.open(t, ctrl), RoleControl, "pool-b"); got.Error != "" ||
		got.Role != RoleControl || len(got.KESVKey) != 0 {
		t.Fatalf("selection by name: %+v", got)
	}
}

func TestKeylessBindingIsNotAKeyedBinding(t *testing.T) {
	t.Parallel()
	coldPair := newColdKey(t)
	cold := []byte(coldPair.pub)
	req, _ := NewAttestationRequest()
	kesVKey := bytes.Repeat([]byte{2}, 32)
	opcert := makeOpCert(t, kesVKey, 1, 5, coldPair)

	keyless := AttestationBinding(req.Nonce, cold, nil, nil, 0)
	for name, keyed := range map[string][]byte{
		"key without opcert":    AttestationBinding(req.Nonce, cold, kesVKey, nil, 0),
		"opcert without key":    AttestationBinding(req.Nonce, cold, nil, opcert, 0),
		"key and opcert":        AttestationBinding(req.Nonce, cold, kesVKey, opcert, 0),
		"key and opcert period": AttestationBinding(req.Nonce, cold, kesVKey, opcert, 7),
	} {
		if bytes.Equal(keyless, keyed) {
			t.Fatalf("keyless binding equals the binding of %s", name)
		}
	}
	// The nonce and cold key stay bound.
	if bytes.Equal(keyless, AttestationBinding(req.Nonce, []byte("other"), nil, nil, 0)) {
		t.Fatal("keyless binding does not commit to the cold key")
	}

	// A keyless response never passes the keyed verifier, however the
	// evidence is formed.
	resp := AttestationResponse{
		Type: "attestation_response", Protocol: AttestedProtocolID,
		Nonce: append([]byte(nil), req.Nonce...), Provider: "nitro",
		Attestation: keyless,
	}
	if err := VerifyAttestation(t.Context(), req, resp, "nitro", cold, opcert, bindingVerifier{}); !errors.Is(err, ErrAttestation) {
		t.Fatalf("keyless response verified as keyed: %v", err)
	}
	if err := VerifyAttestation(t.Context(), req, resp, "nitro", cold, nil, bindingVerifier{}); !errors.Is(err, ErrAttestation) {
		t.Fatalf("keyless response verified with no expected opcert: %v", err)
	}
}

func TestKeylessControlStateIsRefusedForSigning(t *testing.T) {
	t.Parallel()
	a, _ := keylessPool(t, nil, nil)
	p := sole(t, a)
	if _, err := p.attestedKeyState(); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("sign key state of a keyless profile: %v", err)
	}
}
