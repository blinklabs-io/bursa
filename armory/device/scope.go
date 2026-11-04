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
	"errors"
	"fmt"
	"strings"
)

// Scope is one network and chain an image serves. Testnets share network id 0
// and an empty chain; mainnet chains share network id 1 and are told apart by
// the label their profile names end with ("name@<chain>").
type Scope struct {
	Network uint8
	Chain   string
}

// ScopeTestnet is the scope of every network-0 profile.
var ScopeTestnet = Scope{}

// Name is the label of a scope in requests: "testnet" for network 0, the
// chain label otherwise.
func (sc Scope) Name() string {
	if sc.Network == 0 {
		return "testnet"
	}

	return sc.Chain
}

// MultiScopes is the scope set of a multi image: every testnet, the Cardano
// mainnet and the Prime mainnet.
func MultiScopes() []Scope {
	return []Scope{
		ScopeTestnet,
		{Network: 1, Chain: "cardano-mainnet"},
		{Network: 1, Chain: "prime-mainnet"},
	}
}

// SetScopes makes the service a multi image serving scopes. A profile is
// served when its scope is in the set, and every request, including those of
// testnet profiles, needs a host key of the scope it acts on. Call it before
// SetChip, instead of SetNetwork.
func (s *Service) SetScopes(scopes []Scope) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.scopes = append([]Scope(nil), scopes...)
	s.networkFixed, s.requireHostAuth = true, true
	s.logf("multi image: signing and every request require a host key of the scope acted on")
}

// AllowFirstHostKey lets the provisioning image of a multi service take the
// first host key of a scope unsigned. Signing and wipe images never call it.
func (s *Service) AllowFirstHostKey() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.firstHostKeyOpen = true
}

func (s *Service) multi() bool { return len(s.scopes) > 0 }

// scopeOf returns the scope of a profile named name on network id, or why
// this build does not serve it.
func (s *Service) scopeOf(network uint8, name string) (Scope, error) {
	if network == 0 {
		if s.inScope(ScopeTestnet) {
			return ScopeTestnet, nil
		}

		return Scope{}, fmt.Errorf("profile %q is for network 0; this build serves %s", name, s.scopeNames())
	}

	if i := strings.LastIndexByte(name, '@'); i >= 0 {
		if sc := (Scope{Network: network, Chain: name[i+1:]}); s.inScope(sc) {
			return sc, nil
		}
	}

	return Scope{}, fmt.Errorf("profile %q is not for a scope this build serves (%s)", name, s.scopeNames())
}

func (s *Service) inScope(sc Scope) bool {
	for _, have := range s.scopes {
		if have == sc {
			return true
		}
	}

	return false
}

func (s *Service) scopeNames() string {
	names := make([]string, len(s.scopes))
	for i, sc := range s.scopes {
		names[i] = sc.Name()
	}

	return strings.Join(names, ", ")
}

var (
	errScopeMismatch = errors.New("host key is not of the scope of this profile")
	errDeviceWide    = errors.New("this request is device-wide: it needs a host key of a mainnet scope")
	errCrossScope    = errors.New("key already belongs to a profile of another scope")
	errFirstKey      = errors.New("an unsigned host key is accepted only by the provisioning image, for a scope of the image that has no host key")
	errKeyOtherScope = errors.New("host key is already registered for another scope")
	errScopeNeeded   = errors.New("a host key request names the scope it is for")
	// errAddScopeMismatch refuses a host key add signed by a key of another
	// scope than the one the request names
	errAddScopeMismatch = errors.New("host key is not of the scope it adds a key for")
)

// caller is who an admin request has been authenticated as, for the handler
// that runs after authorizeAdmin.
type caller struct {
	// known is set when a host key of scope authenticated the request
	known bool
	scope Scope
	// unsigned is the first host key of scope, accepted without a signature
	unsigned bool
}

// imageScope is the one scope a single-scope image serves.
func (s *Service) imageScope() Scope {
	return Scope{Network: s.network, Chain: s.chain}
}

// entryScope returns the scope of a stored host key when this multi image
// serves it. A legacy key carries no scope and counts as testnet: the
// devices holding them are testnet devices.
func (s *Service) entryScope(e hostEntry) (Scope, bool) {
	if e.kind == scopeLegacy {
		return ScopeTestnet, s.inScope(ScopeTestnet)
	}

	for _, sc := range s.scopes {
		if sc.Network == e.network && chainTag(sc.Chain) == e.chain {
			return sc, true
		}
	}

	return Scope{}, false
}

// hostKeyScope returns the scope key is registered for.
func (s *Service) hostKeyScope(key []byte) (Scope, bool) {
	for _, e := range s.hostEntries {
		if bytes.Equal(e.key, key) {
			return s.entryScope(e)
		}
	}

	return Scope{}, false
}

// scopeHasKey reports whether a host key is registered for sc.
func (s *Service) scopeHasKey(sc Scope) bool {
	for _, e := range s.hostEntries {
		if got, ok := s.entryScope(e); ok && got == sc {
			return true
		}
	}

	return false
}

// parseScope returns the scope of this multi image named name.
func (s *Service) parseScope(name string) (Scope, error) {
	if name == "" {
		return Scope{}, errScopeNeeded
	}

	for _, sc := range s.scopes {
		if sc.Name() == name {
			return sc, nil
		}
	}

	return Scope{}, fmt.Errorf("%w (scope %q is not one of %s)", errFirstKey, name, s.scopeNames())
}

// listedKeys returns the host keys a response lists. A single-scope image
// lists the keys it trusts. A multi image lists the keys of the caller's
// scope; a key of a mainnet scope, which may act device-wide, sees them all.
func (s *Service) listedKeys() [][]byte {
	keys := make([][]byte, 0, len(s.hostEntries))

	for _, e := range s.hostEntries {
		if s.trusts(e) && s.callerSees(e) {
			keys = append(keys, e.key)
		}
	}

	return keys
}

// callerSees reports whether the caller may list e. Every key is visible to a
// single-scope image; a multi image shows a caller the keys of its own scope,
// and a key of a mainnet scope, which may act device-wide, all of them. The
// first key of a scope, added unsigned, is no authority over other scopes.
func (s *Service) callerSees(e hostEntry) bool {
	if !s.multi() {
		return true
	}

	sc, _ := s.entryScope(e)

	if !s.caller.known {
		return false
	}

	return s.caller.scope == sc || (!s.caller.unsigned && s.caller.scope.Network == 1)
}

// authorizeMulti authenticates an admin request of a multi image.
func (s *Service) authorizeMulti(route string, req hostAuthed) error {
	a := req.hostAuth()

	// the first key of a scope is the only unsigned request
	if route == RouteProvisionHostKey && s.firstHostKeyOpen &&
		len(a.HostKey) == 0 && len(a.HostSignature) == 0 && len(a.Challenge) == 0 {
		hk, _ := req.(*HostKeyRequest)

		sc, err := s.parseScope(hk.Scope)
		if err != nil {
			return err
		}

		if s.scopeHasKey(sc) {
			return fmt.Errorf("%w (%s already has a host key)", errFirstKey, sc.Name())
		}

		s.caller = caller{known: true, scope: sc, unsigned: true}

		return nil
	}

	canonical, err := canonicalRequest(req)
	if err != nil {
		s.logf("canonical request: %v", err)
		return errDevice
	}

	sc, err := s.authenticateHostScope(a.HostKey, a.HostSignature, a.Challenge, AdminBinding(route, canonical, a.Challenge))
	if err != nil {
		return err
	}

	if err = s.authorizeScope(req, sc); err != nil {
		return err
	}

	s.caller = caller{known: true, scope: sc}

	return nil
}

// profileScope returns the scope of the stored profile name.
func (s *Service) profileScope(name string) (Scope, error) {
	p, ok := s.profiles[name]
	if !ok {
		return Scope{}, errUnknown
	}

	return s.scopeOf(p.NetworkID, p.Name)
}

// authorizeScope checks that a host key of scope sc may make req: a request
// that targets a profile needs a key of that profile's scope, and a
// device-wide one a key of a mainnet scope. Cold keys belong to no profile
// yet and are checked against the profiles of other scopes when imported.
func (s *Service) authorizeScope(req hostAuthed, sc Scope) error {
	var (
		target Scope
		err    error
	)

	switch r := req.(type) {
	case *ProvisionRequest:
		target, err = s.scopeOf(r.NetworkID, r.Name)
	case *FloorRequest:
		target, err = s.profileScope(r.Profile)
	case *RewardRequest:
		target, err = s.profileScope(r.Profile)
	case *PinsRequest:
		target, err = s.profileScope(r.Profile)
	case *WipeProfileRequest:
		target, err = s.profileScope(r.Profile)
	case *IdentityRequest, *WipeSignLogRequest:
		return s.needDeviceWide(sc)
	default:
		// cold keys, and host keys, which name their own scope
		return nil
	}

	if err != nil {
		return err
	}

	if target != sc {
		return errScopeMismatch
	}

	return nil
}

// needDeviceWide refuses a key that may not act device-wide. While the image
// serves a mainnet scope, only a key of a mainnet scope may.
func (s *Service) needDeviceWide(sc Scope) error {
	if sc.Network == 1 {
		return nil
	}

	for _, have := range s.scopes {
		if have.Network == 1 {
			return errDeviceWide
		}
	}

	return nil
}

// addHostKeyMulti registers a host key for the scope the request names. The
// key that signs the request must be of the same scope, so a scope's first
// key can only come from the provisioning image.
func (s *Service) addHostKeyMulti(req HostKeyRequest) (HostKeyResponse, error) {
	if !s.caller.known {
		return HostKeyResponse{}, errHostAuthMissing
	}

	sc, err := s.parseScope(req.Scope)
	if err != nil {
		return HostKeyResponse{}, err
	}

	if s.caller.scope != sc {
		return HostKeyResponse{}, errAddScopeMismatch
	}

	for _, e := range s.hostEntries {
		if !bytes.Equal(e.key, req.PublicKey) {
			continue
		}

		if got, _ := s.entryScope(e); got != sc {
			return HostKeyResponse{}, errKeyOtherScope
		}

		return HostKeyResponse{HostKeys: s.listedKeys()}, nil
	}

	if len(s.hostEntries) >= maxHostKeys {
		return HostKeyResponse{}, errors.New("host key list is full; revoke a key first")
	}

	return s.writeHostKeys(append(append([]hostEntry(nil), s.hostEntries...),
		hostEntry{key: bytes.Clone(req.PublicKey), kind: scopeImage, network: sc.Network, chain: chainTag(sc.Chain)}))
}

// revokeHostKeyMulti removes a host key. A key revokes keys of its own
// scope; a key of a mainnet scope also revokes the keys of other scopes.
func (s *Service) revokeHostKeyMulti(req HostKeyRequest) (HostKeyResponse, error) {
	if !s.caller.known {
		return HostKeyResponse{}, errHostAuthMissing
	}

	entries := []hostEntry{}
	found := false

	for _, e := range s.hostEntries {
		sc, ok := s.entryScope(e)

		if !ok || !bytes.Equal(e.key, req.PublicKey) {
			entries = append(entries, e)
			continue
		}

		if sc != s.caller.scope && s.caller.scope.Network != 1 {
			return HostKeyResponse{}, errDeviceWide
		}

		found = true
	}

	if !found {
		return HostKeyResponse{}, errHostKeyUnknown
	}

	return s.writeHostKeys(entries)
}

// keyScopeConflict refuses pub, or a cold key slot, that belongs to a profile
// of a scope other than sc. A cold key object no profile names carries no
// scope until a profile takes it, and is checked then.
func (s *Service) keyScopeConflict(sc Scope, slot uint32, pub ed25519.PublicKey) error {
	for _, other := range s.profiles {
		if got, err := s.scopeOf(other.NetworkID, other.Name); err == nil && got == sc {
			continue
		}

		if slot != 0 && other.ColdKeyID == slot {
			return errCrossScope
		}

		if pub == nil {
			continue
		}

		for _, id := range []uint32{other.ColdKeyID, other.OwnerKeyID()} {
			if ok, err := s.chip.Exists(id); err != nil || !ok {
				continue
			}

			if have, err := s.chip.PublicKeyEd25519(id); err == nil && bytes.Equal(have, pub) {
				return errCrossScope
			}
		}
	}

	return nil
}

// coldSlotKey returns the public key held in cold key object id, nil when
// none is or id is not a cold key object.
func (s *Service) coldSlotKey(id uint32) ed25519.PublicKey {
	if id < coldKeyFirst || id > coldKeyLast {
		return nil
	}

	if ok, err := s.chip.Exists(id); err != nil || !ok {
		return nil
	}

	pub, err := s.chip.PublicKeyEd25519(id)
	if err != nil {
		return nil
	}

	return pub
}

// seedPublic returns the public key of an Ed25519 seed.
func seedPublic(seed []byte) ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}

// authenticateInventory authenticates an inventory request of a multi image
// with a host key of the scope of the profile asked for. An unknown profile
// is refused by the caller once the key is known to be authentic.
func (s *Service) authenticateInventory(req InventoryRequest) error {
	sc, err := s.authenticateHostScope(req.HostKey, req.HostSignature, req.Challenge, InventoryRequestBinding(req))
	if err != nil {
		return err
	}

	if target, err := s.profileScope(req.Profile); err == nil && target != sc {
		return errScopeMismatch
	}

	return nil
}
