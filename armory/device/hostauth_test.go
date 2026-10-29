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
)

var testHostKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x48}, 32))

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
		"evicted challenge": func(t *testing.T, s *Service, req SignRequest, ch []byte) SignRequest {
			for range maxChallenges {
				challenge(t, s)
			}
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

	for _, k := range keys[:maxHostKeys] {
		registerHostKey(t, s, k)
	}

	registerHostKey(t, s, keys[0]) // a duplicate is not an error

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
		if code, _ := post(t, s, req.path, HostKeyRequest{PublicKey: req.key}); code == http.StatusOK {
			t.Errorf("%s accepted", name)
		}
	}

	if string(chip.bins[hostKeysID]) != stored {
		t.Fatal("host key list written on a refused request")
	}

	if code, body := post(t, s, "/provision/host-key/revoke", HostKeyRequest{PublicKey: keys[1]}); code != http.StatusOK {
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
	chip := newFakeChip()
	chip.bins[hostKeysID] = []byte("torn")

	s := New(&sync.Mutex{}, t.Logf)
	if err := s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	provisionTestProfile(t, s)

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

			if code, _ := post(t, s, "/provision/host-key", HostKeyRequest{PublicKey: other}); code == http.StatusOK {
				t.Fatal("failed host key write reported success")
			}

			chip.failWrite, chip.tornWrite = false, false

			if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, 1), testHostKey, challenge(t, s))); r.Error == "" {
				t.Fatal("signed after a failed host key write")
			}

			// writing the list again recovers
			registerHostKey(t, s, hostPub(testHostKey))

			if r := postSign(t, s, authenticate(opcertRequest(t, s, chip, 2), testHostKey, challenge(t, s))); r.Error != "" {
				t.Fatalf("not recovered by a good write: %+v", r)
			}
		})
	}
}
