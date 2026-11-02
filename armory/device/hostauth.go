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
	"time"
)

const (
	// hostKeysID holds the registered host public keys: maxHostKeys slots of
	// 32 bytes, an all-zero slot unused. The fixed size means a rewrite never
	// deletes and recreates the object.
	hostKeysID  uint32 = 0x20e50021
	maxHostKeys        = 4
	hostKeysLen        = maxHostKeys * ed25519.PublicKeySize

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
	PublicKey []byte `json:"public_key"`
}

// HostKeyResponse lists the registered host public keys.
type HostKeyResponse struct {
	HostKeys [][]byte `json:"host_keys"`
}

var (
	errHostKeyUnknown  = errors.New("host key not registered")
	errHostKeysBad     = errors.New("host key list unreadable; register the host keys again")
	errHostAuthMissing = errors.New("signing requires host authentication")
)

// RequireHostAuth refuses every signing request that is not authenticated
// by a registered host key, including while none is registered.
func (s *Service) RequireHostAuth() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.requireHostAuth = true
}

// loadHostKeys reads the host key list from chip. A missing object means no
// host key is registered; an unreadable one refuses signing until the list
// is written again.
func (s *Service) loadHostKeys(chip Chip) error {
	s.hostKeys, s.hostKeysBad = nil, false

	ok, err := chip.Exists(hostKeysID)
	if err != nil || !ok {
		return err
	}

	b, err := chip.ReadBinary(hostKeysID)
	if err != nil || len(b) != hostKeysLen {
		s.logf("host key list: unreadable (%d bytes, %v)", len(b), err)
		s.hostKeysBad = true

		return nil
	}

	zero := make([]byte, ed25519.PublicKeySize)

	for i := 0; i < hostKeysLen; i += ed25519.PublicKeySize {
		if k := b[i : i+ed25519.PublicKeySize]; !bytes.Equal(k, zero) {
			s.hostKeys = append(s.hostKeys, bytes.Clone(k))
			s.logf("host key %x", keyHash(k))
		}
	}

	// revoking the last key deletes the object, so a present list with no
	// key is not a valid empty list
	if len(s.hostKeys) == 0 {
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
// host holds. Challenges expire after challengeTTL.
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

	binary.BigEndian.PutUint64(c, uint64(s.clock().UnixNano())) //nolint:gosec // post-epoch time
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

	for k, t := range s.usedChallenges {
		if now.Sub(t) >= challengeTTL {
			delete(s.usedChallenges, k)
		}
	}

	var key [challengeSize]byte

	copy(key[:], ch)

	if _, used := s.usedChallenges[key]; used {
		return errBad
	}

	if s.usedChallenges == nil {
		s.usedChallenges = map[[challengeSize]byte]time.Time{}
	}

	s.usedChallenges[key] = issued

	return nil
}

// authenticate checks a signing request against the registered host keys:
// the key is registered, its signature covers the request and challenge, and
// the challenge is outstanding. The challenge is burned only after the
// signature verifies, so a forged request cannot use up a real one.
func (s *Service) authenticate(req SignRequest) error {
	return s.authenticateHost(req.HostKey, req.HostSignature, req.Challenge, RequestBinding(req))
}

// authenticateHost checks that hostKey is registered, that sig is its
// signature over binding, and that challenge is outstanding, burning it. With
// no host key registered it refuses when host authentication is required and
// accepts otherwise.
func (s *Service) authenticateHost(hostKey, sig, challenge, binding []byte) error {
	if s.hostKeysBad {
		return errHostKeysBad
	}

	if len(s.hostKeys) == 0 {
		if s.requireHostAuth {
			return errHostAuthMissing
		}

		return nil
	}

	registered := false

	for _, k := range s.hostKeys {
		if bytes.Equal(k, hostKey) {
			registered = true
			break
		}
	}

	if !registered {
		return errHostKeyUnknown
	}

	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(hostKey, binding, sig) {
		return errors.New("host signature does not verify")
	}

	return s.takeChallenge(challenge)
}

func validHostKey(k []byte) error {
	if len(k) != ed25519.PublicKeySize || bytes.Equal(k, make([]byte, ed25519.PublicKeySize)) {
		return errors.New("host key must be a 32-byte Ed25519 public key")
	}

	return nil
}

// addHostKey registers a host key. Registering a key twice is not an error.
func (s *Service) addHostKey(req HostKeyRequest) (HostKeyResponse, error) {
	if err := validHostKey(req.PublicKey); err != nil {
		return HostKeyResponse{}, err
	}

	for _, k := range s.hostKeys {
		if bytes.Equal(k, req.PublicKey) {
			return HostKeyResponse{HostKeys: s.hostKeys}, nil
		}
	}

	if len(s.hostKeys) >= maxHostKeys {
		return HostKeyResponse{}, errors.New("host key list is full; revoke a key first")
	}

	return s.writeHostKeys(append(append([][]byte(nil), s.hostKeys...), bytes.Clone(req.PublicKey)))
}

// revokeHostKey removes a registered host key.
func (s *Service) revokeHostKey(req HostKeyRequest) (HostKeyResponse, error) {
	keys := [][]byte{}

	for _, k := range s.hostKeys {
		if !bytes.Equal(k, req.PublicKey) {
			keys = append(keys, k)
		}
	}

	if len(keys) == len(s.hostKeys) {
		return HostKeyResponse{}, errHostKeyUnknown
	}

	return s.writeHostKeys(keys)
}

// writeHostKeys writes keys and serves them once the write reads back; an
// empty list deletes the object. Writing a list replaces an unreadable one;
// a failed write leaves the stored list unknown, so signing is refused until
// a write reads back.
func (s *Service) writeHostKeys(keys [][]byte) (HostKeyResponse, error) {
	var err error

	if len(keys) == 0 {
		err = s.deleteHostKeys()
	} else {
		b := make([]byte, hostKeysLen)

		for i, k := range keys {
			copy(b[i*ed25519.PublicKeySize:], k)
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
		s.hostKeys, s.hostKeysBad = nil, true

		return HostKeyResponse{}, errDevice
	}

	s.hostKeys, s.hostKeysBad = keys, false

	for _, k := range keys {
		s.logf("host key %x", keyHash(k))
	}

	return HostKeyResponse{HostKeys: keys}, nil
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
