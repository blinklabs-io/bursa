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
	"net"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/gouroboros/kes"
)

// attestWith serves one attested connection with provider none, sends an
// attestation request carrying the selector, and returns the response and the
// open client connection.
func attestWith(
	t *testing.T,
	a *Agent,
	profile string,
	kesVKey []byte,
) (AttestationResponse, net.Conn) {
	t.Helper()
	server, client := tcpConnPair(t)
	go func() {
		a.serveAttestedConn(
			t.Context(),
			server,
			AttestedServiceConfig{Provider: NoEvidenceProvider},
		)
		_ = server.Close()
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	var hello Hello
	if err := readFrame(client, &hello); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	req, err := NewAttestationRequest()
	if err != nil {
		t.Fatalf("NewAttestationRequest: %v", err)
	}
	req.Profile, req.KESVKey = profile, kesVKey
	if err := writeFrame(client, req); err != nil {
		t.Fatalf("write challenge: %v", err)
	}
	var resp AttestationResponse
	if err := readFrame(client, &resp); err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	return resp, client
}

func twoAttestedProfiles(
	t *testing.T,
) (*Agent, installedProfile, installedProfile) {
	t.Helper()
	coldA, coldB := newColdKey(t), newColdKey(t)
	a := newMultiAgent(t,
		profileOn(t, networkA, "pool-a", coldA),
		profileOn(t, networkB, "pool-b", coldB),
	)
	pa := install(t, a, "pool-a", coldA, 3, 52, 5)
	pb := install(t, a, "pool-b", coldB, 0, 25, 1)
	return a, pa, pb
}

func opcertOf(t *testing.T, a *Agent, name string) []byte {
	t.Helper()
	p, err := a.profileByName(name)
	if err != nil {
		t.Fatalf("profileByName(%s): %v", name, err)
	}
	st, err := p.attestedKeyState()
	if err != nil {
		t.Fatalf("attestedKeyState(%s): %v", name, err)
	}
	return st.opcert
}

func TestAttestedAdmissionSelectsProfileByKESVKey(t *testing.T) {
	t.Parallel()
	a, pa, pb := twoAttestedProfiles(t)
	for _, tc := range []struct {
		name string
		p    installedProfile
	}{{"pool-a", pa}, {"pool-b", pb}} {
		resp, _ := attestWith(t, a, "", tc.p.vkey)
		if resp.Error != "" {
			t.Fatalf("%s: error %q", tc.name, resp.Error)
		}
		if !bytes.Equal(resp.KESVKey, tc.p.vkey) ||
			!bytes.Equal(resp.OpCert, opcertOf(t, a, tc.name)) {
			t.Fatalf("%s: response carries another profile's key state", tc.name)
		}
	}
}

func TestAttestedAdmissionSelectsProfileByName(t *testing.T) {
	t.Parallel()
	a, _, pb := twoAttestedProfiles(t)
	resp, _ := attestWith(t, a, "pool-b", nil)
	if resp.Error != "" || !bytes.Equal(resp.KESVKey, pb.vkey) ||
		!bytes.Equal(resp.OpCert, opcertOf(t, a, "pool-b")) {
		t.Fatalf("name alone: %+v", resp)
	}
}

func TestAttestedAdmissionRefusesNameThatMismatchesKESVKey(t *testing.T) {
	t.Parallel()
	a, pa, _ := twoAttestedProfiles(t)
	resp, _ := attestWith(t, a, "pool-b", pa.vkey)
	if !strings.Contains(resp.Error, ErrProfileMismatch.Error()) ||
		len(resp.KESVKey) != 0 {
		t.Fatalf("mismatched name and kes_vkey: %+v", resp)
	}
}

// TestAttestedAdmissionRefusesKeyRotatedAfterSelection covers a rotation
// between selection, which reads the routing snapshot, and the key state read
// under the profile lock: the response must not attest another key than the
// requested kes_vkey.
func TestAttestedAdmissionRefusesKeyRotatedAfterSelection(t *testing.T) {
	t.Parallel()
	a, _, _ := twoAttestedProfiles(t)
	p, err := a.profileByName("pool-a")
	if err != nil {
		t.Fatalf("profileByName: %v", err)
	}
	stale := bytes.Repeat([]byte{0x01}, 32)
	p.activeVKey.Store(&stale)
	resp, _ := attestWith(t, a, "", stale)
	if !strings.Contains(resp.Error, ErrUnknownProfile.Error()) ||
		len(resp.KESVKey) != 0 {
		t.Fatalf("attested a key other than the requested kes_vkey: %+v", resp)
	}
}

func TestAttestedAdmissionWithoutSelectorIsAmbiguousForTwoProfiles(t *testing.T) {
	t.Parallel()
	a, _, _ := twoAttestedProfiles(t)
	resp, _ := attestWith(t, a, "", nil)
	if !strings.Contains(resp.Error, ErrAmbiguousProfile.Error()) ||
		len(resp.KESVKey) != 0 {
		t.Fatalf("no selector with two profiles: %+v", resp)
	}
}

func TestAttestedAdmissionWithoutSelectorUsesTheSoleProfile(t *testing.T) {
	t.Parallel()
	a, _, _ := newHeaderAgent(t)
	resp, _ := attestWith(t, a, "", nil)
	if resp.Error != "" || len(resp.KESVKey) != 32 {
		t.Fatalf("sole profile: %+v", resp)
	}
}

// signOver sends a sign request for header on an admitted session and returns
// the response.
func signOver(t *testing.T, client net.Conn, ip installedProfile) SignResponse {
	t.Helper()
	if err := writeFrame(client, SignRequest{
		Type:    "sign_request",
		Period:  ip.period,
		Message: ip.header.encode(t),
	}); err != nil {
		t.Fatalf("write sign request: %v", err)
	}
	var signed SignResponse
	if err := readFrame(client, &signed); err != nil {
		t.Fatalf("read sign response: %v", err)
	}
	return signed
}

func TestAttestedSessionIsBoundToItsAdmittedProfile(t *testing.T) {
	t.Parallel()
	a, pa, pb := twoAttestedProfiles(t)
	resp, client := attestWith(t, a, "", pa.vkey)
	if resp.Error != "" || !bytes.Equal(resp.KESVKey, pa.vkey) {
		t.Fatalf("admission for pool-a: %+v", resp)
	}
	other := signOver(t, client, pb)
	if !strings.Contains(other.Error, ErrProfileMismatch.Error()) ||
		len(other.Signature) != 0 {
		t.Fatalf("session admitted for pool-a signed a pool-b header: %+v", other)
	}
	own := signOver(t, client, pa)
	if own.Error != "" ||
		!kes.VerifySignedKES(pa.vkey, pa.period-pa.header.kesPeriod, pa.header.encode(t), own.Signature) {
		t.Fatalf("session admitted for pool-a refused its own header: %+v", own)
	}
}
