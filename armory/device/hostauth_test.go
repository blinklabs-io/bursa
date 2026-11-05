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
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

var testHostKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x48}, 32))

var testHostKey2 = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x49}, 32))

func hostPub(k ed25519.PrivateKey) []byte { return []byte(k.Public().(ed25519.PublicKey)) }

func registerHostKey(t *testing.T, s *Service, pub []byte) {
	t.Helper()

	if code, body := post(t, s, "/provision/host-key", HostKeyRequest{PublicKey: pub}); code != http.StatusOK {
		t.Fatalf("register host key: %d %s", code, body)
	}
}

func challenge(t *testing.T, s *Service) []byte {
	t.Helper()

	code, body := post(t, s, "/v1/challenge", struct{}{})
	if code != http.StatusOK {
		t.Fatalf("challenge: %d %s", code, body)
	}

	var resp ChallengeResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}

	if resp.Version != Protocol || len(resp.Challenge) != challengeSize {
		t.Fatalf("challenge response %+v", resp)
	}

	return resp.Challenge
}

// opcertRequest is a request every check but host authentication accepts.
func opcertRequest(t *testing.T, s *Service, chip *fakeChip, n byte) SignRequest {
	t.Helper()

	cold, _ := chip.PublicKeyEd25519(testColdID)

	return SignRequest{
		Version: Protocol, Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool",
		Nonce: nonce(n), Payload: opCertPayload(bytes.Repeat([]byte{0x4b}, 32), 3, 1100), Profile: "otg@preview",
	}
}

func authenticate(req SignRequest, k ed25519.PrivateKey, ch []byte) SignRequest {
	req.Challenge = ch
	req.HostKey = hostPub(k)
	req.HostSignature = ed25519.Sign(k, RequestBinding(req))

	return req
}

func postSign(t *testing.T, s *Service, req SignRequest) SignResponse {
	t.Helper()

	code, body := post(t, s, "/v1/sign", req)
	if code != http.StatusOK {
		t.Fatalf("sign: %d %s", code, body)
	}

	var resp SignResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}

	return resp
}

func newHostAuthService(t *testing.T) (*Service, *fakeChip) {
	t.Helper()

	s, chip := newTestService(t)
	provisionTestProfile(t, s)
	registerHostKey(t, s, hostPub(testHostKey))

	return s, chip
}

func TestHostAuthSigns(t *testing.T) {
	s, chip := newHostAuthService(t)

	r := postSign(t, s, authenticate(opcertRequest(t, s, chip, 1), testHostKey, challenge(t, s)))
	if r.Error != "" || len(r.Signature) == 0 {
		t.Fatalf("authenticated request refused: %+v", r)
	}
}

func TestHostAuthRefusals(t *testing.T) {
	_, other, _ := ed25519.GenerateKey(nil)
	era := uint(6)

	// each case starts from a valid authenticated request and breaks one thing
	cases := map[string]func(t *testing.T, s *Service, req SignRequest, ch []byte) SignRequest{
		"no host fields": func(_ *testing.T, _ *Service, req SignRequest, _ []byte) SignRequest { return req },
		"unregistered key": func(_ *testing.T, _ *Service, req SignRequest, ch []byte) SignRequest {
			return authenticate(req, other, ch)
		},
		"bad signature": func(_ *testing.T, _ *Service, req SignRequest, ch []byte) SignRequest {
			req = authenticate(req, testHostKey, ch)
			req.HostSignature[0] ^= 1
			return req
		},
		"unknown challenge": func(_ *testing.T, _ *Service, req SignRequest, _ []byte) SignRequest {
			return authenticate(req, testHostKey, bytes.Repeat([]byte{1}, challengeSize))
		},
		"expired challenge": func(_ *testing.T, s *Service, req SignRequest, ch []byte) SignRequest {
			s.now = func() time.Time { return time.Now().Add(challengeTTL) }
			return authenticate(req, testHostKey, ch)
		},
		"future-dated challenge": func(_ *testing.T, s *Service, req SignRequest, ch []byte) SignRequest {
			s.now = func() time.Time { return time.Now().Add(-time.Second) }
			return authenticate(req, testHostKey, ch)
		},
	}

	// a signature over one field's value does not cover another value
	for name, change := range map[string]func(*SignRequest){
		"purpose":   func(r *SignRequest) { r.Purpose = "tx-body" },
		"key_hash":  func(r *SignRequest) { r.KeyHash = strings.Repeat("00", 28) },
		"role":      func(r *SignRequest) { r.Role = "stake" },
		"nonce":     func(r *SignRequest) { r.Nonce = nonce(9) },
		"payload":   func(r *SignRequest) { r.Payload = append([]byte(nil), r.Payload[:47]...) },
		"profile":   func(r *SignRequest) { r.Profile = "other@preview" },
		"era":       func(r *SignRequest) { r.Era = &era },
		"challenge": func(r *SignRequest) { r.Challenge = bytes.Repeat([]byte{2}, challengeSize) },
	} {
		cases["signature over another "+name] = func(_ *testing.T, _ *Service, req SignRequest, ch []byte) SignRequest {
			req = authenticate(req, testHostKey, ch)
			change(&req)
			return req
		}
	}

	for name, breakReq := range cases {
		t.Run(name, func(t *testing.T) {
			s, chip := newHostAuthService(t)
			req := breakReq(t, s, opcertRequest(t, s, chip, 1), challenge(t, s))
			before := chip.signs

			r := postSign(t, s, req)
			if r.Error == "" || len(r.Signature) != 0 || len(r.BindingSignature) != 0 {
				t.Fatalf("signed: %+v", r)
			}

			if chip.signs != before {
				t.Fatal("chip signed for a refused request")
			}
		})
	}
}

func TestHostAuthChallengeIsSingleUse(t *testing.T) {
	s, chip := newHostAuthService(t)
	ch := challenge(t, s)

	if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, 1), testHostKey, ch)); r.Error != "" {
		t.Fatalf("first use refused: %+v", r)
	}

	if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, 2), testHostKey, ch)); r.Error == "" {
		t.Fatal("challenge reused")
	}
}

func TestHostAuthForgeryKeepsChallenge(t *testing.T) {
	s, chip := newHostAuthService(t)
	_, other, _ := ed25519.GenerateKey(nil)
	ch := challenge(t, s)

	forged := authenticate(opcertRequest(t, s, chip, 1), testHostKey, ch)
	forged.HostSignature = ed25519.Sign(other, RequestBinding(forged))

	if r := postSign(t, s, forged); r.Error == "" {
		t.Fatal("forged request signed")
	}

	if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, 2), testHostKey, ch)); r.Error != "" {
		t.Fatalf("forged request consumed the real challenge: %+v", r)
	}
}

func TestHostAuthNoKeyRegistered(t *testing.T) {
	s, chip := newTestService(t)
	provisionTestProfile(t, s)

	if r := postSign(t, s, opcertRequest(t, s, chip, 1)); r.Error != "" {
		t.Fatalf("unauthenticated request refused with no host key registered: %+v", r)
	}

	s.RequireHostAuth()

	if r := postSign(t, s, opcertRequest(t, s, chip, 2)); r.Error == "" {
		t.Fatal("unauthenticated request signed when host authentication is required")
	}
}

func TestHostKeyProvisioning(t *testing.T) {
	s, chip := newTestService(t)
	keys := make([][]byte, maxHostKeys+1)

	for i := range keys {
		keys[i] = hostPub(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(0x60 + i)}, 32)))
	}

	// the first key is added unsigned, the others are signed by it
	registerHostKey(t, s, keys[0])

	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x60}, 32))

	for _, k := range keys[1:maxHostKeys] {
		if code, body := postAs(t, s.ProvisioningHandler(), "/provision/host-key", HostKeyRequest{PublicKey: k}, signer); code != http.StatusOK {
			t.Fatalf("register host key: %d %s", code, body)
		}
	}

	// a duplicate is not an error
	if code, body := postAs(t, s.ProvisioningHandler(), "/provision/host-key", HostKeyRequest{PublicKey: keys[0]}, signer); code != http.StatusOK {
		t.Fatalf("duplicate host key: %d %s", code, body)
	}

	stored := string(chip.bins[hostKeysID])

	for name, req := range map[string]struct {
		path string
		key  []byte
	}{
		"fifth key":      {"/provision/host-key", keys[maxHostKeys]},
		"short key":      {"/provision/host-key", keys[0][:31]},
		"all-zero key":   {"/provision/host-key", make([]byte, 32)},
		"revoke unknown": {"/provision/host-key/revoke", keys[maxHostKeys]},
	} {
		if code, _ := postAs(t, s.ProvisioningHandler(), req.path, HostKeyRequest{PublicKey: req.key}, signer); code == http.StatusOK {
			t.Errorf("%s accepted", name)
		}
	}

	if string(chip.bins[hostKeysID]) != stored {
		t.Fatal("host key list written on a refused request")
	}

	if code, body := postAs(t, s.ProvisioningHandler(), "/provision/host-key/revoke", HostKeyRequest{PublicKey: keys[1]}, signer); code != http.StatusOK {
		t.Fatalf("revoke: %d %s", code, body)
	}

	// a fresh service reads the same list from the chip
	s2 := New(&sync.Mutex{}, t.Logf)
	if err := s2.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	if got, want := len(s2.hostKeys), maxHostKeys-1; got != want {
		t.Fatalf("reloaded %d host keys, want %d", got, want)
	}

	for _, k := range s2.hostKeys {
		if bytes.Equal(k, keys[1]) {
			t.Fatal("revoked key reloaded")
		}
	}
}

func TestHostKeysUnreadableRefusesSigning(t *testing.T) {
	s, chip := newTestService(t)
	provisionTestProfile(t, s)

	// the profile is provisioned first: provisioning is refused over an
	// unreadable list
	chip.bins[hostKeysID] = []byte("torn")

	s = New(&sync.Mutex{}, t.Logf)
	if err := s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	if r := postSign(t, s, opcertRequest(t, s, chip, 1)); r.Error == "" {
		t.Fatal("signed while the host key list is unreadable")
	}
}

// TestRequestBindingVector pins the request binding bytes, which Bursa's
// signer computes too.
func TestRequestBindingVector(t *testing.T) {
	era := uint(6)
	req := SignRequest{
		Version: Protocol, Purpose: "opcert-next", KeyHash: strings.Repeat("ab", 28), Role: "pool",
		Nonce: bytes.Repeat([]byte{1}, 32), Payload: bytes.Repeat([]byte{2}, 48), Profile: "otg@preview",
		Era: &era, Challenge: bytes.Repeat([]byte{3}, 32),
	}

	if got := hex.EncodeToString(RequestBinding(req)); got != requestBindingVector {
		t.Fatalf("RequestBinding = %s", got)
	}
}

// requestBindingVector was computed independently of RequestBinding.
const requestBindingVector = "a398cde575f763d683168b38b24f539dc61fe9235f2140f36321c92ee0d944d0"

// TestHostKeyWriteFailureRefusesSigning checks a host key write that fails or
// does not read back leaves signing refused, as a reboot would find the list.
func TestHostKeyWriteFailureRefusesSigning(t *testing.T) {
	other := hostPub(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x49}, 32)))

	for name, fail := range map[string]func(*fakeChip){
		"write error": func(c *fakeChip) { c.failWrite = true },
		"torn write":  func(c *fakeChip) { c.tornWrite = true },
	} {
		t.Run(name, func(t *testing.T) {
			s, chip := newHostAuthService(t)
			fail(chip)

			if code, _ := postAs(t, s.ProvisioningHandler(), "/provision/host-key", HostKeyRequest{PublicKey: other}, testHostKey); code == http.StatusOK {
				t.Fatal("failed host key write reported success")
			}

			chip.failWrite, chip.tornWrite = false, false

			if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, 1), testHostKey, challenge(t, s))); r.Error == "" {
				t.Fatal("signed after a failed host key write")
			}

			// the list is unknown, so no key can sign for a write; the device
			// wipe, confirmed by the identity key alone, is the way out
			if code, _ := postAs(t, s.ProvisioningHandler(), "/provision/host-key", HostKeyRequest{PublicKey: hostPub(testHostKey)}, testHostKey); code == http.StatusOK {
				t.Fatal("host key list rewritten while the stored list is unknown")
			}

			if code, body := rawPost(s.WipeHandler(), "/wipe/device", []byte(`{"identity_public_key":""}`)); code != http.StatusOK {
				t.Fatalf("device wipe: %d %s", code, body)
			}

			registerHostKey(t, s, hostPub(testHostKey))

			if code, body := postAs(t, s.ProvisioningHandler(), "/provision/identity", IdentityRequest{}, testHostKey); code != http.StatusOK {
				t.Fatalf("not recovered by the wipe and a good write: %d %s", code, body)
			}
		})
	}
}

// TestRevokeLastHostKeyRefused checks the last host key cannot be revoked:
// an emptied list reads as the bootstrap state, which accepts unsigned
// provisioning and key enrollment. Only a device wipe returns to it.
func TestRevokeLastHostKeyRefused(t *testing.T) {
	t.Parallel()

	s, chip := newHostAuthService(t)

	code, body := postAs(t, s.ProvisioningHandler(), "/provision/host-key/revoke", HostKeyRequest{PublicKey: hostPub(testHostKey)}, testHostKey)
	if code == http.StatusOK || !strings.Contains(string(body), errLastHostKey.Error()) {
		t.Errorf("revoking the last host key: %d %s", code, body)
	}

	if _, ok := chip.bins[hostKeysID]; !ok {
		t.Error("host key list deleted by a refused revoke")
	}

	// each unsigned request is valid apart from its missing signature, so
	// only host authentication refuses it
	if r := postSign(t, s, opcertRequest(t, s, chip, 1)); !strings.Contains(r.Error, errHostKeyUnknown.Error()) {
		t.Errorf("unauthenticated sign after revoking the last host key: %+v", r)
	}

	if code, body := post(t, s, "/provision/floor", FloorRequest{Profile: "otg@preview", ChainCounter: 9}); code == http.StatusOK || !strings.Contains(string(body), errHostKeyUnknown.Error()) {
		t.Errorf("unsigned provisioning after revoking the last host key: %d %s", code, body)
	}

	// last, as an accepted enrollment would refill the list
	if code, body := post(t, s, "/provision/host-key", HostKeyRequest{PublicKey: hostPub(testHostKey2)}); code == http.StatusOK || !strings.Contains(string(body), errHostKeyUnknown.Error()) {
		t.Errorf("unsigned host key after revoking the last host key: %d %s", code, body)
	}

	// a restart reads the same list
	s2 := New(&sync.Mutex{}, t.Logf)
	if err := s2.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	if len(s2.hostKeys) != 1 || !bytes.Equal(s2.hostKeys[0], hostPub(testHostKey)) || s2.hostKeysBad {
		t.Fatalf("reloaded keys %x bad %v", s2.hostKeys, s2.hostKeysBad)
	}
}

// TestRevokeNonLastHostKey checks a key still revokes while another remains,
// and that a device wipe, not a revoke, returns to the bootstrap state.
func TestRevokeNonLastHostKey(t *testing.T) {
	t.Parallel()

	s, chip := newHostAuthService(t)

	code, body := postAs(t, s.ProvisioningHandler(), "/provision/host-key", HostKeyRequest{PublicKey: hostPub(testHostKey2)}, testHostKey)
	if code != http.StatusOK {
		t.Fatalf("add second key: %d %s", code, body)
	}

	if code, body := postAs(t, s.ProvisioningHandler(), "/provision/host-key/revoke", HostKeyRequest{PublicKey: hostPub(testHostKey)}, testHostKey2); code != http.StatusOK {
		t.Fatalf("revoke with another key left: %d %s", code, body)
	}

	if code, body := postAs(t, s.ProvisioningHandler(), "/provision/host-key/revoke", HostKeyRequest{PublicKey: hostPub(testHostKey2)}, testHostKey2); code == http.StatusOK || !strings.Contains(string(body), errLastHostKey.Error()) {
		t.Fatalf("revoking the last key: %d %s", code, body)
	}

	if r := postSign(t, s, opcertRequest(t, s, chip, 1)); !strings.Contains(r.Error, errHostKeyUnknown.Error()) {
		t.Fatalf("unauthenticated sign with a host key left: %+v", r)
	}

	if code, body := rawPost(s.WipeHandler(), "/wipe/device", []byte(`{"identity_public_key":""}`)); code != http.StatusOK {
		t.Fatalf("device wipe: %d %s", code, body)
	}

	if _, ok := chip.bins[hostKeysID]; ok {
		t.Fatal("wipe left the host key list")
	}

	registerHostKey(t, s, hostPub(testHostKey))
}

// TestWriteHostKeysEmptyDeleteFailureRefusesSigning checks a failed delete of
// an emptied list leaves the stored list unknown.
func TestWriteHostKeysEmptyDeleteFailureRefusesSigning(t *testing.T) {
	t.Parallel()

	s, chip := newHostAuthService(t)
	chip.failDelete = true

	if _, err := s.writeHostKeys(nil); err == nil {
		t.Fatal("failed delete reported success")
	}

	if r := postSign(t, s, opcertRequest(t, s, chip, 1)); r.Error == "" {
		t.Fatal("signed unauthenticated after a failed delete")
	}
}

// TestHostKeysAllZeroRefusesSigning checks a present list with no key is
// refused: revoking the last key deletes the object, so an all-zero object
// is not a valid empty list.
func TestHostKeysAllZeroRefusesSigning(t *testing.T) {
	s, chip := newTestService(t)
	provisionTestProfile(t, s)

	// the profile is provisioned first: provisioning is refused over an
	// unreadable list
	chip.bins[hostKeysID] = make([]byte, hostKeysLen)

	s = New(&sync.Mutex{}, t.Logf)
	if err := s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	if r := postSign(t, s, opcertRequest(t, s, chip, 1)); r.Error == "" {
		t.Fatal("signed unauthenticated with an all-zero host key list present")
	}

	// registering a key is refused over a list nothing can sign for; the
	// device wipe resets it
	if code, _ := post(t, s, "/provision/host-key", HostKeyRequest{PublicKey: hostPub(testHostKey)}); code == http.StatusOK {
		t.Fatal("host key registered over an all-zero list")
	}

	if code, body := rawPost(s.WipeHandler(), "/wipe/device", []byte(`{"identity_public_key":""}`)); code != http.StatusOK {
		t.Fatalf("device wipe: %d %s", code, body)
	}

	registerHostKey(t, s, hostPub(testHostKey))
}

// TestMainnetRequiresHostAuth checks a mainnet build refuses to sign until a
// host key is registered, and signs once one authenticates the request.
func TestMainnetRequiresHostAuth(t *testing.T) {
	s := newChainService(t, "prime-mainnet", "pool@prime-mainnet")
	chip := s.chip.(*fakeChip)
	cold, _ := chip.PublicKeyEd25519(0x20e50011)
	req := func(n byte) SignRequest {
		return SignRequest{
			Version: Protocol, Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool",
			Nonce: nonce(n), Payload: opCertPayload(bytes.Repeat([]byte{0x4b}, 32), 0, 1100), Profile: "pool@prime-mainnet",
		}
	}

	if r := postSign(t, s, req(1)); r.Error == "" || len(r.Signature) != 0 {
		t.Fatalf("mainnet build signed with no host key registered: %+v", r)
	}

	registerHostKey(t, s, hostPub(testHostKey))

	if r := postSign(t, s, authenticate(req(2), testHostKey, challenge(t, s))); r.Error != "" {
		t.Fatalf("authenticated request refused on a mainnet build: %+v", r)
	}
}

// TestResponseBindingSummaryVector pins the response binding bytes, which
// Bursa's signer computes too (backend TestAttestedSummaryBindingVector). The
// digests were computed independently of ResponseBinding.
func TestResponseBindingSummaryVector(t *testing.T) {
	t.Parallel()

	era := uint(6)
	req := SignRequest{
		Version: ProtocolSummary, Purpose: "tx-body", KeyHash: strings.Repeat("ab", 28), Role: "pool",
		Nonce: bytes.Repeat([]byte{1}, 32), Payload: bytes.Repeat([]byte{2}, 48), Profile: "otg@preview", Era: &era,
	}
	sig := bytes.Repeat([]byte{4}, 64)

	if got := hex.EncodeToString(ResponseBinding(req, sig, "pledge 1")); got != "b60325204c042b454e43758b76753047c7a7cc94329a4dfe6c0bc671b34d4c45" {
		t.Fatalf("summary binding = %s", got)
	}

	if got := hex.EncodeToString(ResponseBinding(req, sig, "")); got != "3c3c52985f23d4b5f9be422dac4cb8a6ebf96062e8bfb8e82324833b05fb8599" {
		t.Fatalf("empty summary binding = %s", got)
	}

	req.Version = Protocol

	if got := hex.EncodeToString(ResponseBinding(req, sig, "")); got != "f32cdc04026da1b47e82bc0af6c5b39b2aa53fe265bc595e7d0ff5fbd057e70b" {
		t.Fatalf("version 1 binding = %s", got)
	}
}

// A flood of unauthenticated challenge requests between the host's fetch and
// its sign must not invalidate the held challenge, however large it is.
func TestChallengeFloodKeepsHeldChallenge(t *testing.T) {
	t.Parallel()

	s, chip := newHostAuthService(t)
	held := challenge(t, s)

	for range 1000 {
		challenge(t, s)
	}

	if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, 1), testHostKey, held)); r.Error != "" {
		t.Fatalf("held challenge refused after flood: %s", r.Error)
	}
}

// A challenge works once: replaying it, even after the flood, is refused.
func TestChallengeReplayRefused(t *testing.T) {
	t.Parallel()

	s, chip := newHostAuthService(t)
	held := challenge(t, s)

	if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, 1), testHostKey, held)); r.Error != "" {
		t.Fatalf("first use refused: %s", r.Error)
	}

	if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, 2), testHostKey, held)); r.Error == "" {
		t.Fatal("used challenge accepted again")
	}
}

// A challenge the device did not issue is refused even when it carries a
// plausible issue time, and so is an issued one with its time altered.
func TestChallengeForgedRefused(t *testing.T) {
	t.Parallel()

	s, chip := newHostAuthService(t)
	held := challenge(t, s)

	forged := bytes.Clone(held)
	forged[0] ^= 1 // alters the embedded issue time, not the MAC

	other := bytes.Clone(held)
	other[challengeSize-1] ^= 1 // alters the MAC

	for name, ch := range map[string][]byte{"altered time": forged, "altered mac": other} {
		if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, 1), testHostKey, ch)); r.Error == "" {
			t.Fatalf("%s: forged challenge accepted", name)
		}
	}

	// the genuine challenge was not burned by the forgeries
	if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, 1), testHostKey, held)); r.Error != "" {
		t.Fatalf("genuine challenge refused after forgeries: %s", r.Error)
	}
}

// A challenge from another boot (another MAC key) is refused.
func TestChallengeFromOtherBootRefused(t *testing.T) {
	t.Parallel()

	s, chip := newHostAuthService(t)
	old := challenge(t, s)

	s.challengeKey = bytes.Repeat([]byte{7}, 32)

	if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, 1), testHostKey, old)); r.Error == "" {
		t.Fatal("challenge issued under another key accepted")
	}
}

// Used challenges are remembered only until they would expire anyway, so the
// used set cannot grow without bound.
func TestChallengeUsedSetAgesOut(t *testing.T) {
	t.Parallel()

	s, chip := newHostAuthService(t)
	now := time.Now()
	s.now = func() time.Time { return now }

	for i := range 20 {
		held := challenge(t, s)

		if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, byte(i+1)), testHostKey, held)); r.Error != "" {
			t.Fatalf("sign %d refused: %s", i, r.Error)
		}

		now = now.Add(challengeTTL)
	}

	if len(s.usedChallenges) > 1 {
		t.Fatalf("used set holds %d entries after expiry", len(s.usedChallenges))
	}
}

// A challenge request drops used entries that have expired, so a burst of
// signatures is not held until the next authenticated sign.
func TestChallengeRequestPurgesExpiredUsed(t *testing.T) {
	t.Parallel()

	s, chip := newHostAuthService(t)
	now := time.Now()
	s.now = func() time.Time { return now }

	for i := range 5 {
		if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, byte(i+1)), testHostKey, challenge(t, s))); r.Error != "" {
			t.Fatalf("sign %d refused: %s", i, r.Error)
		}
	}

	now = now.Add(challengeTTL)
	challenge(t, s)

	if len(s.usedChallenges) != 0 {
		t.Fatalf("used set holds %d entries after expiry", len(s.usedChallenges))
	}
}

// Challenges used out of issue order stay burned until they expire: when the
// older one expires, the newer one is still refused on replay.
func TestChallengeOutOfOrderReplayRefused(t *testing.T) {
	t.Parallel()

	s, chip := newHostAuthService(t)
	t0 := time.Now()
	now := t0
	s.now = func() time.Time { return now }

	older := challenge(t, s)
	now = t0.Add(50 * time.Second)
	newer := challenge(t, s)

	if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, 1), testHostKey, newer)); r.Error != "" {
		t.Fatalf("newer refused: %s", r.Error)
	}

	now = t0.Add(55 * time.Second)

	if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, 2), testHostKey, older)); r.Error != "" {
		t.Fatalf("older refused: %s", r.Error)
	}

	now = t0.Add(challengeTTL + 5*time.Second)

	if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, 3), testHostKey, newer)); !strings.Contains(r.Error, "challenge") {
		t.Fatalf("replayed newer challenge: %+v", r)
	}

	// control: a fresh challenge at the same time signs
	if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, 4), testHostKey, challenge(t, s))); r.Error != "" {
		t.Fatalf("fresh challenge refused: %s", r.Error)
	}
}
