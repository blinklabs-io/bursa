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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/armory/profile"
	"github.com/blinklabs-io/gouroboros/ledger"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"
)

const testColdID uint32 = 0x20e50010

// testReward is the testnet reward address pinned in the test profile.
var testReward = "e0" + strings.Repeat("ee", 28)

// fakeChip is a software SE050: keys and binary objects by object ID.
type fakeChip struct {
	keys map[uint32]ed25519.PrivateKey
	bins map[uint32][]byte

	failWrite  bool
	failExists bool
}

func newFakeChip() *fakeChip {
	c := &fakeChip{keys: map[uint32]ed25519.PrivateKey{}, bins: map[uint32][]byte{}}
	c.keys[testColdID] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))

	return c
}

func (c *fakeChip) Exists(id uint32) (bool, error) {
	if c.failExists {
		return false, errors.New("i2c failure")
	}

	_, k := c.keys[id]
	_, b := c.bins[id]

	return k || b, nil
}

func (c *fakeChip) GenerateEd25519(id uint32, _ bool) error {
	if ok, _ := c.Exists(id); ok {
		return errors.New("object exists")
	}

	_, priv, _ := ed25519.GenerateKey(nil)
	c.keys[id] = priv

	return nil
}

func (c *fakeChip) PublicKeyEd25519(id uint32) (ed25519.PublicKey, error) {
	k, ok := c.keys[id]

	if !ok {
		return nil, errors.New("no key")
	}

	return k.Public().(ed25519.PublicKey), nil
}

func (c *fakeChip) SignEd25519(id uint32, msg []byte) ([]byte, error) {
	k, ok := c.keys[id]

	if !ok {
		return nil, errors.New("no key")
	}

	return ed25519.Sign(k, msg), nil
}

func (c *fakeChip) WriteBinary(id uint32, data []byte) error {
	if c.failWrite {
		return errors.New("i2c failure")
	}

	c.bins[id] = bytes.Clone(data)
	return nil
}

func (c *fakeChip) ReadBinary(id uint32) ([]byte, error) {
	b, ok := c.bins[id]

	if !ok {
		return nil, errors.New("no object")
	}

	return bytes.Clone(b), nil
}

func newTestService(t *testing.T) (*Service, *fakeChip) {
	t.Helper()

	chip := newFakeChip()
	s := New(&sync.Mutex{}, t.Logf)

	if err := s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	return s, chip
}

func post(t *testing.T, s *Service, path string, req any) (int, []byte) {
	t.Helper()

	b, err := json.Marshal(req)

	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b)))

	return w.Code, w.Body.Bytes()
}

func provisionTestProfile(t *testing.T, s *Service) ProvisionResponse {
	t.Helper()

	chain := uint64(3)
	code, body := post(t, s, "/provision/profile", ProvisionRequest{
		Name: "otg@preview", Slot: 0, ColdKeyID: testColdID, ChainCounter: &chain,
		RewardAccount: testReward,
	})

	if code != http.StatusOK {
		t.Fatalf("provision: %d %s", code, body)
	}

	var resp ProvisionResponse

	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}

	return resp
}

func hashHex(pub []byte) string {
	h := keyHash(pub)
	return hex.EncodeToString(h[:])
}

func nonce(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func sign(t *testing.T, s *Service, req SignRequest) SignResponse {
	t.Helper()

	req.Version = Protocol

	code, body := post(t, s, "/v1/sign", req)

	if code != http.StatusOK {
		t.Fatalf("sign: %d %s", code, body)
	}

	var resp SignResponse

	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(resp.Nonce, req.Nonce) || resp.Version != Protocol {
		t.Fatalf("response does not echo version and nonce: %+v", resp)
	}

	return resp
}

func TestProvisionProfile(t *testing.T) {
	s, chip := newTestService(t)
	resp := provisionTestProfile(t, s)

	p := profile.Profile{Slot: 0}

	for _, id := range []uint32{p.OwnerKeyID(), p.RecordID()} {
		if ok, _ := chip.Exists(id); !ok {
			t.Fatalf("object %#08x not created", id)
		}
	}

	owner, _ := chip.PublicKeyEd25519(p.OwnerKeyID())

	if !bytes.Equal(resp.OwnerPublicKey, owner) {
		t.Fatal("response owner key differs from chip")
	}

	rec, _ := chip.ReadBinary(p.RecordID())
	got, err := profile.Decode(rec)

	if err != nil || !got.FloorSet || got.OpCertFloor != 3 || got.ColdKeyID != testColdID || got.RewardAccount != testReward {
		t.Fatalf("record %+v, %v", got, err)
	}

	for name, req := range map[string]ProvisionRequest{
		"same slot":     {Name: "other", Slot: 0, ColdKeyID: testColdID},
		"same name":     {Name: "otg@preview", Slot: 1, ColdKeyID: 0x20e50011},
		"same cold key": {Name: "other", Slot: 1, ColdKeyID: testColdID},
		"no cold key":   {Name: "other", Slot: 1, ColdKeyID: 0x20e50011},
		"bad cold id":   {Name: "other", Slot: 1, ColdKeyID: 0x20e50300},
		"bad reward":    {Name: "other", Slot: 1, ColdKeyID: 0x20e50011, RewardAccount: "e1" + strings.Repeat("ee", 28)},
	} {
		if code, _ := post(t, s, "/provision/profile", req); code == http.StatusOK {
			t.Errorf("%s: provisioned", name)
		}
	}
}

func TestProvisionProfileKeepsExistingKeys(t *testing.T) {
	s, chip := newTestService(t)
	p := profile.Profile{Slot: 0}

	// a key left by an interrupted provisioning is reused, never replaced
	_ = chip.GenerateEd25519(p.OwnerKeyID(), false)
	before, _ := chip.PublicKeyEd25519(p.OwnerKeyID())

	resp := provisionTestProfile(t, s)

	if !bytes.Equal(resp.OwnerPublicKey, before) {
		t.Fatal("existing owner key replaced")
	}
}

func TestProvisionIdentity(t *testing.T) {
	s, chip := newTestService(t)

	code, first := post(t, s, "/provision/identity", struct{}{})

	if code != http.StatusOK {
		t.Fatalf("%d %s", code, first)
	}

	_, second := post(t, s, "/provision/identity", struct{}{})

	if !bytes.Equal(first, second) {
		t.Fatal("identity key changed on second call")
	}

	pub, _ := chip.PublicKeyEd25519(profile.IdentityKeyID)

	var resp IdentityResponse

	if err := json.Unmarshal(first, &resp); err != nil || !bytes.Equal(resp.PublicKey, pub) {
		t.Fatalf("identity response %s", first)
	}
}

func TestInventory(t *testing.T) {
	s, chip := newTestService(t)
	provisionTestProfile(t, s)
	post(t, s, "/provision/identity", struct{}{})

	code, body := post(t, s, "/v1/inventory", InventoryRequest{Nonce: nonce(1), Profile: "otg@preview"})

	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}

	var inv Inventory

	if err := json.Unmarshal(body, &inv); err != nil {
		t.Fatal(err)
	}

	if inv.Version != Protocol || len(inv.Keys) != 2 {
		t.Fatalf("inventory %+v", inv)
	}

	p := profile.Profile{Slot: 0, ColdKeyID: testColdID}

	for i, want := range []struct {
		role string
		id   uint32
	}{{"pool", p.ColdKeyID}, {"stake", p.OwnerKeyID()}} {
		pub, _ := chip.PublicKeyEd25519(want.id)

		if inv.Keys[i].Role != want.role || !bytes.Equal(inv.Keys[i].PublicKey, pub) {
			t.Fatalf("key %d = %+v, want %s", i, inv.Keys[i], want.role)
		}
	}

	identity, _ := chip.PublicKeyEd25519(profile.IdentityKeyID)

	if !ed25519.Verify(identity, InventoryBinding(nonce(1), inv.Keys), inv.Attestation) {
		t.Fatal("attestation does not verify under the identity key")
	}

	if ed25519.Verify(identity, InventoryBinding(nonce(2), inv.Keys), inv.Attestation) {
		t.Fatal("attestation verifies for another nonce")
	}

	if code, _ := post(t, s, "/v1/inventory", InventoryRequest{Nonce: nonce(1), Profile: "nope"}); code == http.StatusOK {
		t.Fatal("inventory for unknown profile")
	}
}

func TestInventoryNeedsIdentity(t *testing.T) {
	s, _ := newTestService(t)
	provisionTestProfile(t, s)

	if code, _ := post(t, s, "/v1/inventory", InventoryRequest{Nonce: nonce(1), Profile: "otg@preview"}); code == http.StatusOK {
		t.Fatal("inventory without an identity key")
	}
}

// certBody is a testnet body paid by an off-device wallet that carries certs.
func certBody(certs ...[]any) []byte {
	payer := append([]byte{0x60}, bytes.Repeat([]byte{0xc3}, 28)...)

	b, err := cbor.Marshal(map[uint64]any{
		0: []any{[]any{make([]byte, 32), uint64(0)}},
		1: []any{[]any{payer, uint64(5_000_000)}},
		2: uint64(200_000),
		4: certs,
	})

	if err != nil {
		panic(err)
	}

	return b
}

func retirement(pool [28]byte) []any { return []any{uint64(4), pool[:], uint64(900)} }

func regDeleg(owner, pool [28]byte) []any {
	return []any{uint64(11), []any{uint64(0), owner[:]}, pool[:], uint64(2_000_000)}
}

func TestSignTxBody(t *testing.T) {
	s, chip := newTestService(t)
	resp := provisionTestProfile(t, s)
	cold, _ := chip.PublicKeyEd25519(testColdID)
	pool, owner := keyHash(cold), keyHash(resp.OwnerPublicKey)

	for _, c := range []struct {
		role string
		pub  []byte
		body []byte
	}{
		{"pool", cold, certBody(retirement(pool))},
		{"stake", resp.OwnerPublicKey, certBody(regDeleg(owner, pool))},
	} {
		r := sign(t, s, SignRequest{
			Purpose: "tx-body", KeyHash: hashHex(c.pub), Role: c.role,
			Nonce: []byte(c.role), Payload: c.body, Profile: "otg@preview", Era: conwayEra(),
		})

		if r.Error != "" {
			t.Fatalf("%s refused: %s", c.role, r.Error)
		}

		hash := blake2b.Sum256(c.body)

		if !ed25519.Verify(c.pub, hash[:], r.Signature) {
			t.Fatalf("%s signature is not over blake2b-256(body)", c.role)
		}
	}

	body := certBody(retirement(pool))
	hash := blake2b.Sum256(body)

	for name, req := range map[string]SignRequest{
		"policy refuses": {Purpose: "tx-body", KeyHash: hashHex(cold), Role: "pool",
			Payload: certBody(retirement([28]byte{1})), Era: conwayEra()},
		"key hash of another role": {Purpose: "tx-body", KeyHash: hashHex(cold), Role: "stake",
			Payload: body, Era: conwayEra()},
		"payment role": {Purpose: "tx-body", KeyHash: hashHex(cold), Role: "payment",
			Payload: body, Era: conwayEra()},
		"no era":  {Purpose: "tx-body", KeyHash: hashHex(cold), Role: "pool", Payload: body},
		"tx-hash": {Purpose: "tx-hash", KeyHash: hashHex(cold), Role: "pool", Payload: hash[:]},
		"opcert":  {Purpose: "opcert", KeyHash: hashHex(cold), Role: "pool", Payload: make([]byte, 48)},
		"cip8":    {Purpose: "cip8", KeyHash: hashHex(cold), Role: "pool", Payload: []byte{1}},
	} {
		req.Profile = "otg@preview"
		req.Nonce = []byte(name)

		if r := sign(t, s, req); r.Error == "" || r.Signature != nil {
			t.Errorf("%s: signed", name)
		}
	}
}

func TestRewardAccountChange(t *testing.T) {
	s, chip := newTestService(t)
	provisionTestProfile(t, s)
	next := "e0" + strings.Repeat("dd", 28)

	if code, body := post(t, s, "/provision/reward", RewardRequest{Profile: "otg@preview", RewardAccount: next}); code != http.StatusOK {
		t.Fatalf("change: %d %s", code, body)
	}

	rec, _ := chip.ReadBinary(profile.Profile{Slot: 0}.RecordID())

	if p, _ := profile.Decode(rec); p.RewardAccount != next || p.OpCertFloor != 3 {
		t.Fatalf("record after change: %+v", p)
	}

	if s.profiles["otg@preview"].RewardAccount != next {
		t.Fatal("cached profile not updated")
	}

	for name, req := range map[string]RewardRequest{
		"mainnet on testnet profile": {Profile: "otg@preview", RewardAccount: "e1" + strings.Repeat("dd", 28)},
		"unknown profile":            {Profile: "nope", RewardAccount: next},
		"empty":                      {Profile: "otg@preview"},
	} {
		if code, _ := post(t, s, "/provision/reward", req); code == http.StatusOK {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSignRefusesReplayedNonce(t *testing.T) {
	s, chip := newTestService(t)
	provisionTestProfile(t, s)
	cold, _ := chip.PublicKeyEd25519(testColdID)
	req := SignRequest{
		Purpose: "tx-body", KeyHash: hashHex(cold), Role: "pool",
		Nonce: nonce(9), Payload: certBody(retirement(keyHash(cold))),
		Profile: "otg@preview", Era: conwayEra(),
	}

	if r := sign(t, s, req); r.Error != "" {
		t.Fatalf("first: %s", r.Error)
	}

	if r := sign(t, s, req); r.Error == "" {
		t.Fatal("replayed nonce signed")
	}
}

func TestNonceRingEvicts(t *testing.T) {
	var r nonceRing

	for i := range nonceRingSize + 1 {
		if !r.add([]byte{byte(i), byte(i >> 8)}) {
			t.Fatalf("nonce %d refused", i)
		}
	}

	if !r.add([]byte{0, 0}) {
		t.Fatal("oldest nonce still remembered after the ring wrapped")
	}

	last := nonceRingSize

	if r.add([]byte{byte(last), byte(last >> 8)}) {
		t.Fatal("recent nonce accepted twice")
	}
}

func opCertPayload(kes []byte, chain, period uint64) []byte {
	p := bytes.Clone(kes)
	p = binary.BigEndian.AppendUint64(p, chain)

	return binary.BigEndian.AppendUint64(p, period)
}

func TestOpCertNext(t *testing.T) {
	s, chip := newTestService(t)
	owner := provisionTestProfile(t, s).OwnerPublicKey

	cold, _ := chip.PublicKeyEd25519(testColdID)
	kes := bytes.Repeat([]byte{0x4b}, 32)

	r := sign(t, s, SignRequest{
		Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool",
		Nonce: nonce(1), Payload: opCertPayload(kes, 3, 1100), Profile: "otg@preview",
	})

	if r.Error != "" || r.IssueCounter == nil || *r.IssueCounter != 4 {
		t.Fatalf("response %+v", r)
	}

	if !ed25519.Verify(cold, opCertPayload(kes, 4, 1100), r.Signature) {
		t.Fatal("signature is not over kes_vkey || issue || period")
	}

	r = sign(t, s, SignRequest{
		Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool",
		Nonce: nonce(2), Payload: opCertPayload(kes, 5, 1100), Profile: "otg@preview",
	})

	if r.Error != "" || *r.IssueCounter != 6 {
		t.Fatalf("response %+v", r)
	}

	rec, _ := chip.ReadBinary(profile.Profile{Slot: 0}.RecordID())

	if p, _ := profile.Decode(rec); p.OpCertFloor != 5 {
		t.Fatalf("floor not persisted: %+v", p)
	}

	for name, req := range map[string]SignRequest{
		"below floor":  {Role: "pool", KeyHash: hashHex(cold), Payload: opCertPayload(kes, 4, 1100)},
		"short":        {Role: "pool", KeyHash: hashHex(cold), Payload: make([]byte, 40)},
		"non-pool key": {Role: "stake", KeyHash: hashHex(owner), Payload: opCertPayload(kes, 5, 1100)},
	} {
		req.Purpose = "opcert-next"
		req.Profile = "otg@preview"
		req.Nonce = []byte(name)

		if r := sign(t, s, req); r.Error == "" {
			t.Errorf("%s: signed", name)
		}
	}
}

func TestRequestBodyLimit(t *testing.T) {
	s, _ := newTestService(t)
	big := `{"nonce":"` + strings.Repeat("A", maxRequest) + `"}`

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/inventory", strings.NewReader(big)))

	if w.Code == http.StatusOK {
		t.Fatal("oversized request accepted")
	}
}

func TestNoChip(t *testing.T) {
	s := New(&sync.Mutex{}, t.Logf)

	if code, _ := post(t, s, "/v1/inventory", InventoryRequest{Nonce: nonce(1), Profile: "x"}); code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", code)
	}
}

func TestSetChipSkipsUnreadableRecord(t *testing.T) {
	chip := newFakeChip()
	good := profile.Profile{Name: "good", Slot: 1, ColdKeyID: 0x20e50011}
	rec, _ := profile.Encode(good)
	chip.bins[good.RecordID()] = rec
	chip.bins[profile.Profile{Slot: 0}.RecordID()] = []byte("{torn")
	chip.keys[0x20e50011] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	_ = chip.GenerateEd25519(good.OwnerKeyID(), false)
	_ = chip.GenerateEd25519(profile.IdentityKeyID, false)

	s := New(&sync.Mutex{}, t.Logf)

	if err := s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	if code, body := post(t, s, "/v1/inventory", InventoryRequest{Nonce: nonce(1), Profile: "good"}); code != http.StatusOK {
		t.Fatalf("readable profile not served: %d %s", code, body)
	}

	// the unreadable record may hold any cold key, so the cold key guard
	// cannot be checked until it is repaired
	if code, _ := post(t, s, "/provision/profile", ProvisionRequest{Name: "new", Slot: 2, ColdKeyID: testColdID}); code == http.StatusOK {
		t.Fatal("provisioned while a record is unreadable")
	}
}

func TestFloorReset(t *testing.T) {
	s, chip := newTestService(t)
	provisionTestProfile(t, s)

	cold, _ := chip.PublicKeyEd25519(testColdID)
	kes := bytes.Repeat([]byte{0x4b}, 32)
	req := func(n byte, chain uint64) SignRequest {
		return SignRequest{
			Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool",
			Nonce: nonce(n), Payload: opCertPayload(kes, chain, 1100), Profile: "otg@preview",
		}
	}

	if r := sign(t, s, req(1, 9)); r.Error != "" {
		t.Fatal(r.Error)
	}

	if r := sign(t, s, req(2, 4)); r.Error == "" {
		t.Fatal("chain below floor signed")
	}

	if code, body := post(t, s, "/provision/floor", FloorRequest{Profile: "otg@preview", ChainCounter: 4}); code != http.StatusOK {
		t.Fatalf("floor reset: %d %s", code, body)
	}

	r := sign(t, s, req(3, 4))

	if r.Error != "" || *r.IssueCounter != 5 {
		t.Fatalf("after reset: %+v", r)
	}

	rec, _ := chip.ReadBinary(profile.Profile{Slot: 0}.RecordID())

	if p, _ := profile.Decode(rec); p.OpCertFloor != 4 {
		t.Fatalf("reset floor not persisted: %+v", p)
	}

	if code, _ := post(t, s, "/provision/floor", FloorRequest{Profile: "nope", ChainCounter: 1}); code == http.StatusOK {
		t.Fatal("floor reset for unknown profile")
	}
}

func TestOpCertNextFloorWriteFailure(t *testing.T) {
	s, chip := newTestService(t)
	provisionTestProfile(t, s)
	chip.failWrite = true

	cold, _ := chip.PublicKeyEd25519(testColdID)
	r := sign(t, s, SignRequest{
		Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool",
		Nonce: nonce(1), Payload: opCertPayload(make([]byte, 32), 7, 1100), Profile: "otg@preview",
	})

	if r.Error == "" || r.Signature != nil {
		t.Fatalf("signed without persisting the floor: %+v", r)
	}

	if s.profiles["otg@preview"].OpCertFloor != 3 {
		t.Fatal("cached floor raised although the write failed")
	}
}

func TestChipErrorsReportedAsDeviceErrors(t *testing.T) {
	s, chip := newTestService(t)
	chip.failExists = true

	code, body := post(t, s, "/provision/profile", ProvisionRequest{Name: "x", Slot: 3, ColdKeyID: testColdID})

	if code == http.StatusOK || !strings.Contains(string(body), "device error") {
		t.Fatalf("got %d %q, want a device error", code, body)
	}
}

func conwayEra() *uint {
	era := uint(ledger.TxTypeConway)
	return &era
}

// TestResponseBindingMatchesBursa checks ResponseBinding against vectors from
// Bursa's backend.AttestedResponseBinding, with and without an era.
func TestResponseBindingMatchesBursa(t *testing.T) {
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i)
	}

	era := uint(6)
	req := SignRequest{
		Version: Protocol, Purpose: "tx-body", KeyHash: "ab12", Role: "pool",
		Nonce: []byte{1, 2, 3}, Payload: []byte{0xa0, 0xff}, Profile: "otg@preview", Era: &era,
	}

	if got := hex.EncodeToString(ResponseBinding(req, sig)); got != "0c01c305ffe8ff31572a4a84655dff50ab2e79354ce185b2f55166451b21e74e" {
		t.Errorf("with era: %s", got)
	}

	req.Era, req.Purpose = nil, "opcert-next"

	if got := hex.EncodeToString(ResponseBinding(req, sig)); got != "c7bb01b9f9a9ddcc251b13cda8f4c25f2913c290157b39d8565543992fd63e93" {
		t.Errorf("without era: %s", got)
	}
}

// TestSignResponseBindsRequest checks every signature comes with a binding
// signature from the same key over the complete request, so a proxy cannot
// pair a response with another nonce or profile.
func TestSignResponseBindsRequest(t *testing.T) {
	s, chip := newTestService(t)
	provisionTestProfile(t, s)
	cold, _ := chip.PublicKeyEd25519(testColdID)
	pool := keyHash(cold)

	for _, req := range []SignRequest{
		{Purpose: "tx-body", KeyHash: hashHex(cold), Role: "pool", Nonce: nonce(1),
			Payload: certBody(retirement(pool)), Profile: "otg@preview", Era: conwayEra()},
		{Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool", Nonce: nonce(2),
			Payload: opCertPayload(bytes.Repeat([]byte{0x4b}, 32), 3, 1100), Profile: "otg@preview"},
	} {
		r := sign(t, s, req)
		if r.Error != "" {
			t.Fatalf("%s refused: %s", req.Purpose, r.Error)
		}

		req.Version = Protocol

		if !ed25519.Verify(cold, ResponseBinding(req, r.Signature), r.BindingSignature) {
			t.Fatalf("%s: binding signature does not cover the request", req.Purpose)
		}

		other := req
		other.Profile = "other@preview"

		if ed25519.Verify(cold, ResponseBinding(other, r.Signature), r.BindingSignature) {
			t.Errorf("%s: binding signature accepts another profile", req.Purpose)
		}

		other = req
		other.Nonce = nonce(9)

		if ed25519.Verify(cold, ResponseBinding(other, r.Signature), r.BindingSignature) {
			t.Errorf("%s: binding signature accepts another nonce", req.Purpose)
		}
	}

	r := sign(t, s, SignRequest{
		Purpose: "tx-body", KeyHash: hashHex(cold), Role: "pool", Nonce: nonce(3),
		Payload: certBody(retirement([28]byte{1})), Profile: "otg@preview", Era: conwayEra(),
	})

	if r.Error == "" || r.BindingSignature != nil {
		t.Fatalf("refusal carries a binding signature: %+v", r)
	}
}
