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

// Package device serves Bursa's attested-signer protocol from keys held in
// the SE050. Every signature is checked against a profile's signing policy,
// and the device computes what it signs: a body hash from the body bytes, or
// an opcert from the on-chain counter.
package device

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"github.com/blinklabs-io/bursa/armory/policy"
	"github.com/blinklabs-io/bursa/armory/profile"
	"golang.org/x/crypto/blake2b"
)

const (
	// maxRequest bounds request bodies: the JSON and base64 of a maximum
	// size transaction body.
	maxRequest = 64 << 10
	// maxTxBody is the Conway maximum transaction size.
	maxTxBody = 16384
	// maxNonce bounds request nonces; Bursa sends 32 bytes.
	maxNonce = 64
	// opCertSignableSize is kes_vkey (32) + counter (8) + KES period (8).
	opCertSignableSize = 48

	coldKeyFirst uint32 = 0x20e50010
	coldKeyLast  uint32 = 0x20e5001f
)

var (
	errNoChip      = errors.New("SE050 not available")
	errDevice      = errors.New("device error")
	errUnknown     = errors.New("unknown profile")
	errUnsupported = errors.New("device signs only tx-body and opcert-next")
)

// Chip is the SE050 subset the service uses.
type Chip interface {
	Exists(id uint32) (bool, error)
	GenerateEd25519(id uint32, transient bool) error
	PublicKeyEd25519(id uint32) (ed25519.PublicKey, error)
	SignEd25519(id uint32, msg []byte) ([]byte, error)
	WriteBinary(id uint32, data []byte) error
	ReadBinary(id uint32) ([]byte, error)
}

// InventoryRequest asks for a profile's keys.
type InventoryRequest struct {
	Nonce   []byte `json:"nonce"`
	Profile string `json:"profile"`
}

// Inventory lists a profile's keys, attested by the identity key.
type Inventory struct {
	Version     string    `json:"version"`
	Keys        []KeyInfo `json:"keys"`
	Attestation []byte    `json:"attestation"`
}

// SignRequest is Bursa's AttestedRequest with the profile and era fields.
type SignRequest struct {
	Version string `json:"version"`
	Purpose string `json:"purpose"`
	KeyHash string `json:"key_hash"`
	Role    string `json:"role"`
	Nonce   []byte `json:"nonce"`
	Payload []byte `json:"payload"`
	Profile string `json:"profile"`
	Era     uint   `json:"era,omitempty"`
}

// SignResponse is Bursa's AttestedResponse with the opcert-next counter.
type SignResponse struct {
	Version      string  `json:"version"`
	Nonce        []byte  `json:"nonce"`
	Signature    []byte  `json:"signature,omitempty"`
	IssueCounter *uint64 `json:"issue_counter,omitempty"`
	Error        string  `json:"error,omitempty"`
}

// ProvisionRequest creates a profile. ChainCounter, when set, is the pool's
// current on-chain opcert counter and initialises the floor.
type ProvisionRequest struct {
	Name         string  `json:"name"`
	NetworkID    uint8   `json:"network_id"`
	Slot         uint8   `json:"slot"`
	ColdKeyID    uint32  `json:"cold_key_id"`
	ChainCounter *uint64 `json:"chain_counter,omitempty"`
	// RewardAccount is the hex reward address pool registrations must name.
	RewardAccount string `json:"reward_account,omitempty"`
}

// ProvisionResponse returns the profile's generated owner key.
type ProvisionResponse struct {
	OwnerPublicKey []byte `json:"owner_public_key"`
	OwnerKeyHash   string `json:"owner_key_hash"`
}

// RewardRequest changes the reward account a profile's pool registrations
// must name.
type RewardRequest struct {
	Profile       string `json:"profile"`
	RewardAccount string `json:"reward_account"`
}

// RewardResponse confirms the stored reward account.
type RewardResponse struct {
	Profile       string `json:"profile"`
	RewardAccount string `json:"reward_account"`
}

// FloorRequest resets a profile's opcert floor to the pool's current
// on-chain counter, for example after a rollback or a host that reported a
// counter too high.
type FloorRequest struct {
	Profile      string `json:"profile"`
	ChainCounter uint64 `json:"chain_counter"`
}

// FloorResponse confirms the stored floor.
type FloorResponse struct {
	Profile     string `json:"profile"`
	OpCertFloor uint64 `json:"opcert_floor"`
}

// IdentityResponse returns the identity public key for pinning in Bursa.
type IdentityResponse struct {
	PublicKey []byte `json:"public_key"`
}

// Service holds the chip session and profile cache. Every chip access holds
// mu, which the caller shares with anything else using the session.
type Service struct {
	mu       sync.Locker
	logf     func(format string, args ...any)
	chip     Chip
	profiles map[string]profile.Profile
	nonces   nonceRing
	// badSlots hold records that could not be read; provisioning stays
	// refused while any exist, as one of them may own any cold key
	badSlots map[uint8]bool
}

// New returns a service with no chip; it answers 503 until SetChip.
func New(mu sync.Locker, logf func(format string, args ...any)) *Service {
	return &Service{mu: mu, logf: logf, profiles: map[string]profile.Profile{}}
}

// SetChip loads every profile record from chip and starts serving. An
// unreadable record is logged and skipped so the other profiles stay usable.
func (s *Service) SetChip(chip Chip) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	profiles := map[string]profile.Profile{}
	bad := map[uint8]bool{}

	for slot := uint8(0); slot <= profile.MaxSlot; slot++ {
		id := profile.Profile{Slot: slot}.RecordID()

		if ok, err := chip.Exists(id); err != nil {
			return err
		} else if !ok {
			continue
		}

		b, err := chip.ReadBinary(id)

		if err != nil {
			s.logf("profile slot %d: unreadable: %v", slot, err)
			bad[slot] = true
			continue
		}

		p, err := profile.Decode(b)

		if err != nil {
			s.logf("profile slot %d: invalid record: %v", slot, err)
			bad[slot] = true
			continue
		}

		profiles[p.Name] = p
		s.logf("profile %q slot %d floor %d (set %v)", p.Name, p.Slot, p.OpCertFloor, p.FloorSet)
	}

	s.chip = chip
	s.profiles = profiles
	s.badSlots = bad

	return nil
}

// Handler returns the HTTP endpoints.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/inventory", handle(s, s.inventory))
	mux.HandleFunc("POST /v1/sign", handle(s, s.sign))
	mux.HandleFunc("POST /provision/profile", handle(s, s.provisionProfile))
	mux.HandleFunc("POST /provision/floor", handle(s, s.resetFloor))
	mux.HandleFunc("POST /provision/reward", handle(s, s.setReward))
	mux.HandleFunc("POST /provision/identity", handle(s, func(struct{}) (IdentityResponse, error) {
		return s.provisionIdentity()
	}))

	return mux
}

// handle decodes a bounded JSON request, runs fn holding the chip lock and
// writes its JSON result. Errors returned by fn go to the client as text.
func handle[Req, Resp any](s *Service, fn func(Req) (Resp, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req Req

		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequest)).Decode(&req); err != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}

		s.mu.Lock()
		defer s.mu.Unlock()

		if s.chip == nil {
			http.Error(w, errNoChip.Error(), http.StatusServiceUnavailable)
			return
		}

		resp, err := fn(req)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func keyHash(pub []byte) [28]byte {
	h, _ := blake2b.New(28, nil)
	h.Write(pub)

	var out [28]byte
	copy(out[:], h.Sum(nil))

	return out
}

// publicKey reads a key, mapping chip errors to errDevice after logging.
func (s *Service) publicKey(id uint32) (ed25519.PublicKey, error) {
	pub, err := s.chip.PublicKeyEd25519(id)

	if err != nil {
		s.logf("read public key %#08x: %v", id, err)
		return nil, errDevice
	}

	return pub, nil
}

type profileKeys struct {
	cold, owner ed25519.PublicKey
}

func (s *Service) keys(p profile.Profile) (k profileKeys, err error) {
	if k.cold, err = s.publicKey(p.ColdKeyID); err != nil {
		return
	}

	k.owner, err = s.publicKey(p.OwnerKeyID())

	return
}

func (s *Service) inventory(req InventoryRequest) (Inventory, error) {
	if len(req.Nonce) == 0 || len(req.Nonce) > maxNonce {
		return Inventory{}, errors.New("invalid nonce")
	}

	p, ok := s.profiles[req.Profile]

	if !ok {
		return Inventory{}, errUnknown
	}

	if ok, err := s.chip.Exists(profile.IdentityKeyID); err != nil {
		s.logf("exist check identity: %v", err)
		return Inventory{}, errDevice
	} else if !ok {
		return Inventory{}, errors.New("identity key not provisioned")
	}

	k, err := s.keys(p)

	if err != nil {
		return Inventory{}, err
	}

	inv := Inventory{
		Version: Protocol,
		Keys: []KeyInfo{
			{Role: "pool", PublicKey: k.cold},
			{Role: "stake", PublicKey: k.owner},
		},
	}

	if inv.Attestation, err = s.chip.SignEd25519(profile.IdentityKeyID, InventoryBinding(req.Nonce, inv.Keys)); err != nil {
		s.logf("attest: %v", err)
		return Inventory{}, errDevice
	}

	return inv, nil
}

// sign answers every well-formed request with a SignResponse; refusals are
// carried in its Error field so the nonce is still echoed.
func (s *Service) sign(req SignRequest) (SignResponse, error) {
	resp := SignResponse{Version: Protocol, Nonce: req.Nonce}

	sig, issue, err := s.signRequest(req)

	if err != nil {
		s.logf("sign %q %q %q: refused: %v", clip(req.Purpose), clip(req.Role), clip(req.Profile), err)
		resp.Error = err.Error()

		return resp, nil
	}

	resp.Signature = sig
	resp.IssueCounter = issue

	return resp, nil
}

func (s *Service) signRequest(req SignRequest) ([]byte, *uint64, error) {
	if req.Version != Protocol {
		return nil, nil, errors.New("unsupported protocol version")
	}

	if len(req.Nonce) == 0 || len(req.Nonce) > maxNonce {
		return nil, nil, errors.New("invalid nonce")
	}

	if !s.nonces.add(req.Nonce) {
		return nil, nil, errors.New("nonce replayed")
	}

	p, ok := s.profiles[req.Profile]

	if !ok {
		return nil, nil, errUnknown
	}

	k, err := s.keys(p)

	if err != nil {
		return nil, nil, err
	}

	var (
		role policy.Role
		id   uint32
		pub  ed25519.PublicKey
	)

	switch req.Role {
	case "pool":
		role, id, pub = policy.RoleCold, p.ColdKeyID, k.cold
	case "stake":
		role, id, pub = policy.RoleOwner, p.OwnerKeyID(), k.owner
	default:
		return nil, nil, errors.New("unknown role")
	}

	h := keyHash(pub)

	if want, err := hex.DecodeString(req.KeyHash); err != nil || !bytes.Equal(want, h[:]) {
		return nil, nil, errors.New("key hash does not match the profile key for this role")
	}

	switch req.Purpose {
	case "tx-body":
		return s.signTxBody(p, k, role, id, req)
	case "opcert-next":
		if role != policy.RoleCold {
			return nil, nil, errors.New("opcert-next requires the pool key")
		}

		return s.signOpCertNext(p, req.Payload)
	}

	return nil, nil, errUnsupported
}

func (s *Service) signTxBody(p profile.Profile, k profileKeys, role policy.Role, id uint32, req SignRequest) ([]byte, *uint64, error) {
	if len(req.Payload) == 0 || len(req.Payload) > maxTxBody {
		return nil, nil, errors.New("invalid body size")
	}

	keys := policy.Keys{Pool: keyHash(k.cold), Owner: keyHash(k.owner)}

	d, err := policy.Evaluate(p, keys, role, req.Era, req.Payload)

	if err != nil {
		return nil, nil, err
	}

	sig, err := s.chip.SignEd25519(id, d.BodyHash[:])

	if err != nil {
		s.logf("sign: %v", err)
		return nil, nil, errDevice
	}

	s.logf("tx-body %q %s body %x: %s", p.Name, req.Role, d.BodyHash, d.Summary)

	return sig, nil, nil
}

func (s *Service) signOpCertNext(p profile.Profile, payload []byte) ([]byte, *uint64, error) {
	if len(payload) != opCertSignableSize {
		return nil, nil, errors.New("opcert-next payload must be 48 bytes")
	}

	chain := binary.BigEndian.Uint64(payload[32:40])

	issue, floor, err := nextOpCert(p.OpCertFloor, p.FloorSet, chain)

	if err != nil {
		return nil, nil, err
	}

	// the floor is persisted before any signature leaves the device
	if !p.FloorSet || floor != p.OpCertFloor {
		p.FloorSet, p.OpCertFloor = true, floor

		if err = s.writeProfile(p); err != nil {
			return nil, nil, err
		}
	}

	signable := bytes.Clone(payload)
	binary.BigEndian.PutUint64(signable[32:40], issue)

	sig, err := s.chip.SignEd25519(p.ColdKeyID, signable)

	if err != nil {
		s.logf("sign: %v", err)
		return nil, nil, errDevice
	}

	s.logf("opcert-next %q chain %d issue %d period %d", p.Name, chain, issue, binary.BigEndian.Uint64(payload[40:]))

	return sig, &issue, nil
}

func (s *Service) writeProfile(p profile.Profile) error {
	b, err := profile.Encode(p)

	if err != nil {
		return err
	}

	if err = s.chip.WriteBinary(p.RecordID(), b); err != nil {
		s.logf("write profile %q: %v", p.Name, err)
		return errDevice
	}

	s.profiles[p.Name] = p

	return nil
}

// ensureKey generates a persistent key at id unless one is already there:
// a key is never overwritten.
func (s *Service) ensureKey(id uint32) (ed25519.PublicKey, error) {
	ok, err := s.chip.Exists(id)

	if err != nil {
		s.logf("exist check %#08x: %v", id, err)
		return nil, errDevice
	}

	if !ok {
		if err = s.chip.GenerateEd25519(id, false); err != nil {
			s.logf("generate %#08x: %v", id, err)
			return nil, errDevice
		}
	}

	return s.publicKey(id)
}

func (s *Service) provisionProfile(req ProvisionRequest) (ProvisionResponse, error) {
	p := profile.Profile{
		Name:          req.Name,
		NetworkID:     req.NetworkID,
		Slot:          req.Slot,
		ColdKeyID:     req.ColdKeyID,
		RewardAccount: req.RewardAccount,
	}

	if req.ChainCounter != nil {
		p.FloorSet, p.OpCertFloor = true, *req.ChainCounter
	}

	if _, err := profile.Encode(p); err != nil {
		return ProvisionResponse{}, err
	}

	if len(s.badSlots) > 0 {
		return ProvisionResponse{}, errors.New("a profile record is unreadable; provisioning is refused until it is repaired")
	}

	if p.ColdKeyID < coldKeyFirst || p.ColdKeyID > coldKeyLast {
		return ProvisionResponse{}, errors.New("cold key id outside the cold key range")
	}

	for _, other := range s.profiles {
		switch {
		case other.Name == p.Name:
			return ProvisionResponse{}, errors.New("profile name in use")
		case other.Slot == p.Slot:
			return ProvisionResponse{}, errors.New("slot in use")
		case other.ColdKeyID == p.ColdKeyID:
			// a second profile on one cold key could re-register the pool
			// with a different owner
			return ProvisionResponse{}, errors.New("cold key already belongs to a profile")
		}
	}

	if ok, err := s.chip.Exists(p.RecordID()); err != nil {
		s.logf("exist check %#08x: %v", p.RecordID(), err)
		return ProvisionResponse{}, errDevice
	} else if ok {
		return ProvisionResponse{}, errors.New("slot in use")
	}

	if ok, err := s.chip.Exists(p.ColdKeyID); err != nil {
		s.logf("exist check %#08x: %v", p.ColdKeyID, err)
		return ProvisionResponse{}, errDevice
	} else if !ok {
		return ProvisionResponse{}, errors.New("cold key not provisioned")
	}

	owner, err := s.ensureKey(p.OwnerKeyID())

	if err != nil {
		return ProvisionResponse{}, err
	}

	if err = s.writeProfile(p); err != nil {
		return ProvisionResponse{}, err
	}

	ownerHash := keyHash(owner)
	s.logf("provisioned profile %q slot %d", p.Name, p.Slot)

	return ProvisionResponse{
		OwnerPublicKey: owner,
		OwnerKeyHash:   hex.EncodeToString(ownerHash[:]),
	}, nil
}

// resetFloor sets the floor to the reported on-chain counter, lower or
// higher. A floor set too low only lets the device issue a counter the chain
// rejects, so this needs no more trust than opcert-next itself.
func (s *Service) resetFloor(req FloorRequest) (FloorResponse, error) {
	p, ok := s.profiles[req.Profile]

	if !ok {
		return FloorResponse{}, errUnknown
	}

	p.FloorSet, p.OpCertFloor = true, req.ChainCounter

	if err := s.writeProfile(p); err != nil {
		return FloorResponse{}, err
	}

	s.logf("floor reset %q to %d", p.Name, p.OpCertFloor)

	return FloorResponse{Profile: p.Name, OpCertFloor: p.OpCertFloor}, nil
}

// setReward changes the reward account pool registrations must name. It is a
// deliberate provisioning action, so the account cannot be changed from inside
// a transaction.
func (s *Service) setReward(req RewardRequest) (RewardResponse, error) {
	p, ok := s.profiles[req.Profile]

	if !ok {
		return RewardResponse{}, errUnknown
	}

	if req.RewardAccount == "" {
		return RewardResponse{}, errors.New("reward account required")
	}

	p.RewardAccount = req.RewardAccount

	if _, err := profile.Encode(p); err != nil {
		return RewardResponse{}, err
	}

	if err := s.writeProfile(p); err != nil {
		return RewardResponse{}, err
	}

	s.logf("reward account %q set to %s", p.Name, p.RewardAccount)

	return RewardResponse{Profile: p.Name, RewardAccount: p.RewardAccount}, nil
}

// clip bounds host-supplied strings before they reach the report.
func clip(v string) string {
	if len(v) > 64 {
		return v[:64] + "..."
	}

	return v
}

func (s *Service) provisionIdentity() (IdentityResponse, error) {
	pub, err := s.ensureKey(profile.IdentityKeyID)

	if err != nil {
		return IdentityResponse{}, err
	}

	return IdentityResponse{PublicKey: pub}, nil
}
