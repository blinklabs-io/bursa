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
	"fmt"
	"io"
	"net/http"
	"strings"
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
	ImportEd25519(id uint32, seed []byte, transient bool) error
	PublicKeyEd25519(id uint32) (ed25519.PublicKey, error)
	SignEd25519(id uint32, msg []byte) ([]byte, error)
	WriteBinary(id uint32, data []byte) error
	ReadBinary(id uint32) ([]byte, error)
	Delete(id uint32) error
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
	Era     *uint  `json:"era,omitempty"`
	// Challenge, HostKey and HostSignature authenticate the request: the
	// host key signs RequestBinding over the request and a challenge from
	// /v1/challenge.
	Challenge     []byte `json:"challenge,omitempty"`
	HostKey       []byte `json:"host_key,omitempty"`
	HostSignature []byte `json:"host_signature,omitempty"`
}

// SignResponse is Bursa's AttestedResponse with the opcert-next counter.
// BindingSignature is the selected key's signature over ResponseBinding.
type SignResponse struct {
	Version          string  `json:"version"`
	Nonce            []byte  `json:"nonce"`
	Signature        []byte  `json:"signature,omitempty"`
	BindingSignature []byte  `json:"binding_signature,omitempty"`
	IssueCounter     *uint64 `json:"issue_counter,omitempty"`
	// Summary describes a signed transaction body, as the signing policy saw
	// it. It is covered by BindingSignature.
	Summary string `json:"summary,omitempty"`
	Error   string `json:"error,omitempty"`
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
	// OwnerSigningKey is the cborHex of the owner's Ed25519 signing key.
	// When empty the owner key is generated in the chip.
	OwnerSigningKey string `json:"owner_signing_key,omitempty"`
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

// ColdRequest imports a cold signing key into a chosen cold key object.
// SigningKey is the hex cborHex of a StakePoolSigningKey_ed25519: 5820
// followed by the 32-byte seed.
type ColdRequest struct {
	ColdKeyID  uint32 `json:"cold_key_id"`
	SigningKey string `json:"signing_key"`
}

// ColdResponse returns the imported key's public key and pool id, both hex.
type ColdResponse struct {
	ColdKeyID uint32 `json:"cold_key_id"`
	PublicKey string `json:"public_key"`
	PoolID    string `json:"pool_id"`
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
	// hostKeys authenticate signing requests; hostKeysBad refuses signing
	// while the stored list is unreadable
	hostKeys        [][]byte
	hostKeysBad     bool
	requireHostAuth bool
	challenges      [][]byte
	// network, when fixed, is the only network id whose profiles this
	// build provisions and serves; chain, when set, is the only profile name
	// suffix ("name@chain") it accepts
	network      uint8
	networkFixed bool
	chain        string
}

// New returns a service with no chip; it answers 503 until SetChip.
func New(mu sync.Locker, logf func(format string, args ...any)) *Service {
	return &Service{mu: mu, logf: logf, profiles: map[string]profile.Profile{}}
}

// SetNetwork fixes the network id this build serves and, when chain is not
// empty, the chain label every profile name must end with ("name@chain").
// The device cannot tell chains that share a network id apart, so the label
// keeps one chain's profiles per device. Profiles for another network or
// chain are refused at provisioning, inventory, signing, floor reset and
// reward changes. Call it before SetChip.
func (s *Service) SetNetwork(id uint8, chain string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.network, s.networkFixed, s.chain = id, true, chain
}

// serves reports why this build does not serve a profile on network id
// with name, or nil if it does.
func (s *Service) serves(network uint8, name string) error {
	if !s.networkFixed {
		return nil
	}

	if network != s.network {
		return fmt.Errorf("profile %q is for network %d; this build serves network %d", name, network, s.network)
	}

	if s.chain != "" {
		if i := strings.LastIndexByte(name, '@'); i < 0 || name[i+1:] != s.chain {
			return fmt.Errorf("profile %q is not for chain %s, the only chain this build serves", name, s.chain)
		}
	}

	return nil
}

// profileFor returns the named profile if this build serves its network and
// chain.
func (s *Service) profileFor(name string) (profile.Profile, error) {
	p, ok := s.profiles[name]

	if !ok {
		return profile.Profile{}, errUnknown
	}

	if err := s.serves(p.NetworkID, name); err != nil {
		return profile.Profile{}, err
	}

	return p, nil
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

		if err := s.serves(p.NetworkID, p.Name); err != nil {
			s.logf("not served by this build: %v", err)
		}
	}

	if err := s.loadHostKeys(chip); err != nil {
		return err
	}

	s.chip = chip
	s.profiles = profiles
	s.badSlots = bad

	return nil
}

// Handler returns every endpoint, signing and provisioning.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	s.signingRoutes(mux)
	s.provisioningRoutes(mux)

	return mux
}

// SigningHandler serves only inventory and signing. The signing firmware
// serves this alone, so a process on the host cannot change a profile, the
// opcert floor or the key objects.
func (s *Service) SigningHandler() http.Handler {
	mux := http.NewServeMux()
	s.signingRoutes(mux)

	return mux
}

// ProvisioningHandler serves only the provisioning endpoints, for the
// provisioning firmware.
func (s *Service) ProvisioningHandler() http.Handler {
	mux := http.NewServeMux()
	s.provisioningRoutes(mux)

	return mux
}

func (s *Service) signingRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/inventory", handle(s, s.inventory))
	mux.HandleFunc("POST /v1/challenge", handle(s, s.challenge))
	mux.HandleFunc("POST /v1/sign", handle(s, s.sign))
}

func (s *Service) provisioningRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /provision/profile", handle(s, s.provisionProfile))
	mux.HandleFunc("POST /provision/floor", handle(s, s.resetFloor))
	mux.HandleFunc("POST /provision/reward", handle(s, s.setReward))
	mux.HandleFunc("POST /provision/cold", handle(s, s.provisionCold))
	mux.HandleFunc("POST /provision/host-key", handle(s, s.addHostKey))
	mux.HandleFunc("POST /provision/host-key/revoke", handle(s, s.revokeHostKey))
	mux.HandleFunc("POST /provision/identity", handle(s, func(struct{}) (IdentityResponse, error) {
		return s.provisionIdentity()
	}))
}

// handle decodes a bounded JSON request, runs fn holding the chip lock and
// writes its JSON result. Errors returned by fn go to the client as text.
func handle[Req, Resp any](s *Service, fn func(Req) (Resp, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req Req

		// unknown fields are refused, so a misspelled field is not ignored
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequest))
		dec.DisallowUnknownFields()

		if err := dec.Decode(&req); err != nil || dec.Decode(&struct{}{}) != io.EOF {
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

	p, err := s.profileFor(req.Profile)
	if err != nil {
		return Inventory{}, err
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
// carried in its Error field so the nonce is still echoed. A signature is
// returned only with the same key's signature over the complete request.
func (s *Service) sign(req SignRequest) (SignResponse, error) {
	resp := SignResponse{Version: Protocol, Nonce: req.Nonce}

	var out signed

	err := s.authenticate(req)
	if err == nil {
		out, err = s.signRequest(req)
	}

	if err == nil {
		resp.BindingSignature, err = s.chip.SignEd25519(out.id, ResponseBinding(req, out.sig, out.summary))
		if err != nil {
			s.logf("sign binding: %v", err)
			err = errDevice
		}
	}

	if err != nil {
		s.logf("sign %q %q %q: refused: %v", clip(req.Purpose), clip(req.Role), clip(req.Profile), err)
		resp.Error = err.Error()

		return resp, nil
	}

	resp.Signature = out.sig
	resp.IssueCounter = out.issue
	resp.Summary = out.summary

	return resp, nil
}

// signed is what signRequest produced: the selected key's object ID, its
// signature, the opcert issue counter and the transaction body summary.
type signed struct {
	id      uint32
	sig     []byte
	issue   *uint64
	summary string
}

// signRequest returns the selected key's object ID with its signature.
func (s *Service) signRequest(req SignRequest) (signed, error) {
	if req.Version != Protocol {
		return signed{}, errors.New("unsupported protocol version")
	}

	if len(req.Nonce) == 0 || len(req.Nonce) > maxNonce {
		return signed{}, errors.New("invalid nonce")
	}

	if !s.nonces.add(req.Nonce) {
		return signed{}, errors.New("nonce replayed")
	}

	p, err := s.profileFor(req.Profile)
	if err != nil {
		return signed{}, err
	}

	k, err := s.keys(p)
	if err != nil {
		return signed{}, err
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
		return signed{}, errors.New("unknown role")
	}

	h := keyHash(pub)

	if want, err := hex.DecodeString(req.KeyHash); err != nil || !bytes.Equal(want, h[:]) {
		return signed{}, errors.New("key hash does not match the profile key for this role")
	}

	switch req.Purpose {
	case "tx-body":
		sig, summary, err := s.signTxBody(p, k, role, id, req)
		return signed{id: id, sig: sig, summary: summary}, err
	case "opcert-next":
		if role != policy.RoleCold {
			return signed{}, errors.New("opcert-next requires the pool key")
		}

		sig, issue, err := s.signOpCertNext(p, req.Payload)
		return signed{id: id, sig: sig, issue: issue}, err
	}

	return signed{}, errUnsupported
}

func (s *Service) signTxBody(p profile.Profile, k profileKeys, role policy.Role, id uint32, req SignRequest) ([]byte, string, error) {
	if len(req.Payload) == 0 || len(req.Payload) > maxTxBody {
		return nil, "", errors.New("invalid body size")
	}

	if req.Era == nil {
		return nil, "", errors.New("tx-body requires an era")
	}

	keys := policy.Keys{Pool: keyHash(k.cold), Owner: keyHash(k.owner)}

	d, err := policy.Evaluate(p, keys, role, *req.Era, req.Payload)
	if err != nil {
		return nil, "", err
	}

	sig, err := s.chip.SignEd25519(id, d.BodyHash[:])
	if err != nil {
		s.logf("sign: %v", err)
		return nil, "", errDevice
	}

	s.logf("tx-body %q %s body %x: %s", p.Name, req.Role, d.BodyHash, d.Summary)

	return sig, d.Summary, nil
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
	if err := s.serves(req.NetworkID, req.Name); err != nil {
		return ProvisionResponse{}, err
	}

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

	var ownerSeed []byte

	if req.OwnerSigningKey != "" {
		key, err := parseSigningKey(req.OwnerSigningKey)
		defer clear(key)

		if err != nil {
			return ProvisionResponse{}, err
		}

		ownerSeed = key[len(coldKeyCBORPrefix):]
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

	var (
		owner ed25519.PublicKey
		err   error
	)

	if ownerSeed != nil {
		owner, err = s.importKey(p.OwnerKeyID(), ownerSeed)
		if errors.Is(err, errKeyExists) {
			return ProvisionResponse{}, errors.New("owner key object already exists with a different key")
		}
	} else {
		owner, err = s.ensureKey(p.OwnerKeyID())
	}

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
	p, err := s.profileFor(req.Profile)
	if err != nil {
		return FloorResponse{}, err
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
	p, err := s.profileFor(req.Profile)
	if err != nil {
		return RewardResponse{}, err
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

// coldKeyCBORPrefix heads a cardano-cli Ed25519 signing key: a CBOR byte
// string of length 32.
var coldKeyCBORPrefix = []byte{0x58, 0x20}

var errMalformedKey = errors.New("malformed signing key: expected cborHex of a 32-byte Ed25519 signing key")

var errKeyExists = errors.New("key object already exists with a different key")

// parseSigningKey decodes the cborHex of a 32-byte Ed25519 signing key. The
// caller clears the returned bytes.
func parseSigningKey(cborHex string) ([]byte, error) {
	key, err := hex.DecodeString(cborHex)
	if err != nil || len(key) != len(coldKeyCBORPrefix)+ed25519.SeedSize || !bytes.HasPrefix(key, coldKeyCBORPrefix) {
		clear(key)
		return nil, errMalformedKey
	}

	return key, nil
}

// importKey stores the key of seed in object id. An existing object is never
// written: holding this same key, it confirms an earlier import whose answer
// was lost, and holding another key it is errKeyExists.
func (s *Service) importKey(id uint32, seed []byte) (ed25519.PublicKey, error) {
	want := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	exists, err := s.chip.Exists(id)
	if err != nil {
		s.logf("exist check %#08x: %v", id, err)
		return nil, errDevice
	}

	if !exists {
		if err = s.chip.ImportEd25519(id, seed, false); err != nil {
			s.logf("import %#08x: %v", id, err)

			// the chip may have stored the key before its reply was lost
			if ok, xerr := s.chip.Exists(id); xerr != nil || !ok {
				return nil, errDevice
			}
		}
	}

	pub, err := s.publicKey(id)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(pub, want) {
		if exists {
			return nil, errKeyExists
		}

		s.logf("import %#08x: chip public key does not match the seed", id)

		return nil, errDevice
	}

	return pub, nil
}

// provisionCold imports a cold signing key into a free cold key object. The
// seed is never logged or echoed, and an existing object is never replaced.
func (s *Service) provisionCold(req ColdRequest) (ColdResponse, error) {
	if req.ColdKeyID < coldKeyFirst || req.ColdKeyID > coldKeyLast {
		return ColdResponse{}, errors.New("cold key id outside the cold key range")
	}

	key, err := parseSigningKey(req.SigningKey)
	defer clear(key)

	if err != nil {
		return ColdResponse{}, err
	}

	pub, err := s.importKey(req.ColdKeyID, key[len(coldKeyCBORPrefix):])
	if errors.Is(err, errKeyExists) {
		return ColdResponse{}, errors.New("cold key object already exists with a different key")
	} else if err != nil {
		return ColdResponse{}, err
	}

	h := keyHash(pub)
	s.logf("imported cold key %#08x pool %x", req.ColdKeyID, h)

	return ColdResponse{
		ColdKeyID: req.ColdKeyID,
		PublicKey: hex.EncodeToString(pub),
		PoolID:    hex.EncodeToString(h[:]),
	}, nil
}

func (s *Service) provisionIdentity() (IdentityResponse, error) {
	pub, err := s.ensureKey(profile.IdentityKeyID)
	if err != nil {
		return IdentityResponse{}, err
	}

	return IdentityResponse{PublicKey: pub}, nil
}
