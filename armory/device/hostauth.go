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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// hostKeysID holds the registered host public keys: maxHostKeys slots, an
// all-zero key marking one unused. The fixed size means a rewrite never
// deletes and recreates the object.
const hostKeysID uint32 = 0x20e50021

const (
	maxHostKeys = 4
	// hostKeysLen is the size of the unscoped list older images wrote. The
	// current list has hostEntrySize bytes per slot, so the size tells the
	// formats apart.
	hostKeysLen = maxHostKeys * ed25519.PublicKeySize

	// A scoped slot is the key, a scope kind, the network id and the first
	// bytes of the SHA-256 of the chain label (zero without a label).
	chainTagSize  = 8
	hostEntrySize = ed25519.PublicKeySize + 2 + chainTagSize
	hostListSize  = maxHostKeys * hostEntrySize

	scopeLegacy byte = 0 // written by an image that did not scope keys
	scopeImage  byte = 1 // trusted by images of one network and chain

	// challengeSize is the wire size of a challenge: 8 bytes of issue time
	// (Unix nanoseconds, big endian), 8 random bytes and a 16-byte MAC over
	// both under a key generated at boot.
	challengeSize = 32
	challengeTime = 8
	challengeBody = 16
	// challengeTTL is how long an issued challenge stays valid.
	challengeTTL = 60 * time.Second
)

// ChallengeResponse carries a one-time challenge for an authenticated
// signing request.
type ChallengeResponse struct {
	Version   string `json:"version"`
	Challenge []byte `json:"challenge"`
}

// HostKeyRequest adds or revokes a host public key.
type HostKeyRequest struct {
	HostAuth
	PublicKey []byte `json:"public_key"`
	// Scope names the scope a key is added for in a multi image: "testnet"
	// or a chain label such as "prime-mainnet". It is part of the signed
	// request. A single-scope image takes it empty or naming its own scope.
	Scope string `json:"scope,omitempty"`
}

// HostKeyResponse lists the registered host public keys.
type HostKeyResponse struct {
	HostKeys [][]byte `json:"host_keys"`
}

var (
	errHostKeyUnknown  = errors.New("host key not registered")
	errHostKeysBad     = errors.New("host key list unreadable; wipe the device to reset it")
	errHostAuthMissing = errors.New("signing requires host authentication")
)

// RequireHostAuth refuses every signing request that is not authenticated
// by a registered host key, including while none is registered.
func (s *Service) RequireHostAuth() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.requireHostAuth = true
}

// hostEntry is one stored host key with the scope it was registered for.
type hostEntry struct {
	key     []byte
	kind    byte
	network uint8
	chain   [chainTagSize]byte
}

func chainTag(chain string) (tag [chainTagSize]byte) {
	if chain != "" {
		sum := sha256.Sum256([]byte(chain))
		copy(tag[:], sum[:])
	}

	return tag
}

// scopeEntry is the entry for key registered by this build.
func (s *Service) scopeEntry(key []byte) hostEntry {
	return hostEntry{key: bytes.Clone(key), kind: scopeImage, network: s.network, chain: chainTag(s.chain)}
}

// trusts reports whether this build trusts, lists and may revoke e. A build
// serves the keys of its own network and chain. Legacy keys carry no scope
// and are served by every build but a mainnet one: the only devices holding
// them are testnet devices, and a mainnet build cannot tell which network
// they were registered for.
func (s *Service) trusts(e hostEntry) bool {
	if s.multi() {
		_, ok := s.entryScope(e)
		return ok
	}

	if e.kind == scopeLegacy {
		return !s.networkFixed || s.network != 1
	}

	return e.network == s.network && e.chain == chainTag(s.chain)
}

// setHostEntries stores entries and derives the keys this build serves.
func (s *Service) setHostEntries(entries []hostEntry) {
	s.hostEntries, s.hostKeys = entries, nil

	for _, e := range entries {
		if s.trusts(e) {
			s.hostKeys = append(s.hostKeys, e.key)
		}
	}
}

// loadHostKeys reads the host key list from chip. A missing object means no
// host key is registered; an unreadable one refuses signing and every
// authenticated provisioning and wipe request until a restart reads a valid
// list or a device wipe resets it.
func (s *Service) loadHostKeys(chip Chip) error {
	s.setHostEntries(nil)
	s.hostKeysBad = false

	ok, err := chip.Exists(hostKeysID)
	if err != nil || !ok {
		return err
	}

	b, err := chip.ReadBinary(hostKeysID)
	if err != nil || (len(b) != hostKeysLen && len(b) != hostListSize) {
		s.logf("host key list: unreadable (%d bytes, %v)", len(b), err)
		s.hostKeysBad = true

		return nil
	}

	zero := make([]byte, ed25519.PublicKeySize)
	size := ed25519.PublicKeySize

	if len(b) == hostListSize {
		size = hostEntrySize
	}

	var entries []hostEntry

	for i := 0; i < len(b); i += size {
		k := b[i : i+ed25519.PublicKeySize]
		e := hostEntry{key: bytes.Clone(k), kind: scopeLegacy}

		// the scope kind is checked in every slot, used or not, so a list in
		// an unknown format is refused
		if size == hostEntrySize {
			meta := b[i+ed25519.PublicKeySize : i+size]
			if meta[0] != scopeLegacy && meta[0] != scopeImage {
				s.logf("host key list: unknown scope %d", meta[0])
				s.hostKeysBad = true

				return nil
			}

			e.kind, e.network = meta[0], meta[1]
			copy(e.chain[:], meta[2:])
		}

		if bytes.Equal(k, zero) {
			continue
		}

		entries = append(entries, e)
	}

	s.setHostEntries(entries)

	for _, k := range s.hostKeys {
		s.logf("host key %x", keyHash(k))
	}

	// revoking the last key deletes the object, so a present list with no
	// key is not a valid empty list
	if len(entries) == 0 {
		s.logf("host key list: present but empty")
		s.hostKeysBad = true
	}

	return nil
}

// clock returns the current time, from the test hook when set.
func (s *Service) clock() time.Time {
	if s.now != nil {
		return s.now()
	}

	return time.Now()
}

// challengeMAC returns the MAC of a challenge body under the boot key.
func (s *Service) challengeMAC(body []byte) []byte {
	m := hmac.New(sha256.New, s.challengeKey)
	m.Write(body)

	return m.Sum(nil)[:challengeSize-challengeBody]
}

// challenge issues a one-time challenge. It is stateless: the challenge
// carries its issue time and a MAC under a key generated at boot, so no
// number of unauthenticated requests can evict or exhaust a challenge the
// host holds. Challenges expire after challengeTTL. Each request also forgets
// used challenges that have expired.
func (s *Service) challenge(struct{}) (ChallengeResponse, error) {
	if len(s.challengeKey) == 0 {
		k := make([]byte, 32)

		if _, err := rand.Read(k); err != nil {
			s.logf("challenge key: %v", err)
			return ChallengeResponse{}, errDevice
		}

		s.challengeKey = k
	}

	c := make([]byte, challengeSize)

	if _, err := rand.Read(c[challengeTime:challengeBody]); err != nil {
		s.logf("challenge: %v", err)
		return ChallengeResponse{}, errDevice
	}

	now := s.clock()
	s.purgeUsed(now)

	binary.BigEndian.PutUint64(c, uint64(now.UnixNano())) //nolint:gosec // post-epoch time
	copy(c[challengeBody:], s.challengeMAC(c[:challengeBody]))

	return ChallengeResponse{Version: Protocol, Challenge: c}, nil
}

// takeChallenge burns challenge ch: it must carry this boot's MAC, be younger
// than challengeTTL and not issued in the future, and not be used already.
// The used set grows only through calls made after a host signature verified,
// and drops entries once they would be refused as expired anyway.
func (s *Service) takeChallenge(ch []byte) error {
	errBad := errors.New("unknown or used challenge")

	if len(ch) != challengeSize || len(s.challengeKey) == 0 ||
		!hmac.Equal(ch[challengeBody:], s.challengeMAC(ch[:challengeBody])) {
		return errBad
	}

	now := s.clock()
	issued := time.Unix(0, int64(binary.BigEndian.Uint64(ch))) //nolint:gosec // bounded by MAC

	if age := now.Sub(issued); age < 0 || age >= challengeTTL {
		return errBad
	}

	s.purgeUsed(now)

	var key [challengeSize]byte

	copy(key[:], ch)

	if _, used := s.usedChallenges[key]; used {
		return errBad
	}

	if s.usedChallenges == nil {
		s.usedChallenges = map[[challengeSize]byte]struct{}{}
	}

	s.usedChallenges[key] = struct{}{}
	s.usedOrder = append(s.usedOrder, usedChallenge{expires: now.Add(challengeTTL), key: key})

	return nil
}

// usedChallenge is a burned challenge and when it may be forgotten.
type usedChallenge struct {
	expires time.Time
	key     [challengeSize]byte
}

// purgeUsed forgets used challenges that have expired. The queue is in use
// order and each entry expires challengeTTL after its use, never before its
// issue time plus challengeTTL, so the front expires first and the purge
// visits only the entries it drops.
func (s *Service) purgeUsed(now time.Time) {
	n := 0

	for n < len(s.usedOrder) && !now.Before(s.usedOrder[n].expires) {
		delete(s.usedChallenges, s.usedOrder[n].key)
		n++
	}

	if n == len(s.usedOrder) {
		s.usedOrder = nil
	} else {
		s.usedOrder = s.usedOrder[n:]
	}
}

// authenticate checks a signing request against the registered host keys:
// the key is registered, its signature covers the request and challenge, and
// the challenge is outstanding. The challenge is burned only after the
// signature verifies, so a forged request cannot use up a real one.
func (s *Service) authenticate(req SignRequest) error {
	_, err := s.authenticateHostScope(req.HostKey, req.HostSignature, req.Challenge, RequestBinding(req), func(sc Scope) error {
		if !s.multi() {
			return nil
		}

		// the key is authentic; in a multi image it must also be of the
		// scope of the profile it signs for. An unknown profile is refused
		// later as ever.
		if p, ok := s.profiles[req.Profile]; ok {
			if target, err := s.scopeOf(p.NetworkID, p.Name); err == nil && target != sc {
				return errScopeMismatch
			}
		}

		return nil
	})

	return err
}

// authenticateHost checks that hostKey is registered, that sig is its
// signature over binding, and that challenge is outstanding, burning it. With
// no host key registered for any network or chain it refuses when host
// authentication is required and accepts otherwise.
func (s *Service) authenticateHost(hostKey, sig, challenge, binding []byte) error {
	_, err := s.authenticateHostScope(hostKey, sig, challenge, binding, nil)

	return err
}

// authenticateHostScope is authenticateHost returning the scope of the key
// that authenticated the request: its registered scope in a multi image, the
// image's scope otherwise. authorize, when set, refuses a scope that may not
// make the request; it runs after the signature verifies and before the
// challenge is burned, so only an authorized request uses one up. A request
// accepted because no host key exists returns the image scope and no error.
func (s *Service) authenticateHostScope(hostKey, sig, challenge, binding []byte, authorize func(Scope) error) (Scope, error) {
	if s.hostKeysBad {
		return Scope{}, errHostKeysBad
	}

	if len(s.hostKeys) == 0 {
		if s.requireHostAuth {
			return Scope{}, errHostAuthMissing
		}

		// a key of another network or chain still means the device
		// refuses unauthenticated requests
		if len(s.hostEntries) == 0 {
			return s.imageScope(), nil
		}
	}

	registered := false

	for _, k := range s.hostKeys {
		if bytes.Equal(k, hostKey) {
			registered = true
			break
		}
	}

	if !registered {
		return Scope{}, errHostKeyUnknown
	}

	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(hostKey, binding, sig) {
		return Scope{}, errors.New("host signature does not verify")
	}

	candidates := []Scope{s.imageScope()}

	if s.multi() {
		if candidates = s.hostKeyScopes(hostKey); len(candidates) == 0 {
			return Scope{}, errHostKeyUnknown
		}
	}

	// a key registered for several scopes acts under the first that allows
	// the request; the refusal reported is the first scope's
	sc := candidates[0]

	if authorize != nil {
		var refusal error

		for _, c := range candidates {
			err := authorize(c)
			if err == nil {
				sc, refusal = c, nil
				break
			}

			if refusal == nil {
				refusal = err
			}
		}

		if refusal != nil {
			return Scope{}, refusal
		}
	}

	if err := s.takeChallenge(challenge); err != nil {
		return Scope{}, err
	}

	return sc, nil
}

func validHostKey(k []byte) error {
	if len(k) != ed25519.PublicKeySize || bytes.Equal(k, make([]byte, ed25519.PublicKeySize)) {
		return errors.New("host key must be a 32-byte Ed25519 public key")
	}

	return nil
}

// addHostKey registers a host key for this build's network and chain.
// Registering a key twice is not an error. The slots are shared by every
// network, so keys of other scopes count toward the limit.
func (s *Service) addHostKey(req HostKeyRequest) (HostKeyResponse, error) {
	if err := validHostKey(req.PublicKey); err != nil {
		return HostKeyResponse{}, err
	}

	if s.multi() {
		return s.addHostKeyMulti(req)
	}

	if req.Scope != "" && req.Scope != s.imageScope().Name() {
		return HostKeyResponse{}, fmt.Errorf("this image serves the scope %s, not %q", s.imageScope().Name(), req.Scope)
	}

	for _, k := range s.hostKeys {
		if bytes.Equal(k, req.PublicKey) {
			return HostKeyResponse{HostKeys: s.hostKeys}, nil
		}
	}

	if len(s.hostEntries) >= maxHostKeys {
		return HostKeyResponse{}, errors.New("host key list is full; revoke a key first")
	}

	return s.writeHostKeys(append(append([]hostEntry(nil), s.hostEntries...), s.scopeEntry(req.PublicKey)))
}

// revokeHostKey removes a registered host key this build trusts; keys of
// other networks and chains are not visible to it.
func (s *Service) revokeHostKey(req HostKeyRequest) (HostKeyResponse, error) {
	if s.multi() {
		return s.revokeHostKeyMulti(req)
	}

	entries := []hostEntry{}
	found := false

	for _, e := range s.hostEntries {
		if s.trusts(e) && bytes.Equal(e.key, req.PublicKey) {
			found = true
			continue
		}

		entries = append(entries, e)
	}

	if !found {
		return HostKeyResponse{}, errHostKeyUnknown
	}

	return s.writeHostKeys(entries)
}

// writeHostKeys writes entries and serves them once the write reads back; an
// empty list deletes the object. A failed write leaves the stored list
// unknown, so signing and every authenticated provisioning and wipe request
// are refused until a restart reads a valid list or a device wipe resets it.
// The list is always written in the scoped format, with legacy entries kept
// legacy.
func (s *Service) writeHostKeys(entries []hostEntry) (HostKeyResponse, error) {
	var err error

	if len(entries) == 0 {
		err = s.deleteHostKeys()
	} else {
		b := make([]byte, hostListSize)

		for i, e := range entries {
			slot := b[i*hostEntrySize:]
			copy(slot, e.key)
			slot[ed25519.PublicKeySize], slot[ed25519.PublicKeySize+1] = e.kind, e.network
			copy(slot[ed25519.PublicKeySize+2:], e.chain[:])
		}

		if err = s.chip.WriteBinary(hostKeysID, b); err == nil {
			var got []byte

			if got, err = s.chip.ReadBinary(hostKeysID); err == nil && !bytes.Equal(got, b) {
				err = errors.New("read back differs")
			}
		}
	}

	if err != nil {
		s.logf("write host keys: %v", err)
		s.setHostEntries(nil)
		s.hostKeysBad = true

		return HostKeyResponse{}, errDevice
	}

	// a request signed while no host key existed was not checked, so its
	// challenge was not burned; a new challenge key voids every challenge
	// issued before the first host key, so none of them can replay
	if len(s.hostEntries) == 0 && len(entries) > 0 {
		s.challengeKey, s.usedChallenges, s.usedOrder = nil, nil, nil
	}

	s.setHostEntries(entries)
	s.hostKeysBad = false

	for _, k := range s.hostKeys {
		s.logf("host key %x", keyHash(k))
	}

	return HostKeyResponse{HostKeys: s.listedKeys()}, nil
}

// deleteHostKeys removes the key list object and checks it is gone, so a
// delete whose reply was lost still counts.
func (s *Service) deleteHostKeys() error {
	delErr := s.chip.Delete(hostKeysID)

	ok, err := s.chip.Exists(hostKeysID)
	if err != nil {
		return err
	}

	if ok {
		if delErr == nil {
			delErr = errors.New("object still exists")
		}

		return delErr
	}

	return nil
}
