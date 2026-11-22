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

package api

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa/internal/signer"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/kesagent/wire"
)

// Refusals of an opcert request that carries a staged-key attestation. Each
// is a distinct sentinel so the rule that refused it is observable.
var (
	ErrOpCertNotGranted = errors.New(
		"caller is not authorized for this opcert",
	)
	ErrAttestationKESKey = errors.New(
		"attestation is for a different KES verification key",
	)
	ErrAttestationColdKey = errors.New(
		"attestation is for a different cold key",
	)
	ErrAttestationAgentUntrusted = errors.New(
		"attestation signer is not a trusted KES agent for this cold key",
	)
	ErrAttestationProfile = errors.New(
		"attestation is from a different agent profile than the grant allows",
	)
)

// CallerACL maps authenticated caller identities to the grants they may use.
// A nil or empty ACL is unrestricted (single trust domain). When restricted,
// unlisted callers are denied all keys (fail closed).
type CallerACL struct {
	byCaller map[string]callerGrant
}

type callerGrant struct {
	keys      map[backend.KeyHash]bool
	opcerts   map[backend.KeyHash]map[[32]byte]bool
	kesAgents map[backend.KeyHash][]signer.KESAgentPin
}

// NewCallerACL builds an ACL from subject → permitted grants.
func NewCallerACL(entries map[string]signer.CallerGrant) *CallerACL {
	if len(entries) == 0 {
		return &CallerACL{}
	}
	m := make(map[string]callerGrant, len(entries))
	for sub, entry := range entries {
		grant := callerGrant{
			keys:      make(map[backend.KeyHash]bool, len(entry.Keys)),
			opcerts:   make(map[backend.KeyHash]map[[32]byte]bool, len(entry.OpCerts)),
			kesAgents: entry.KESAgents,
		}
		for _, h := range entry.Keys {
			grant.keys[h] = true
		}
		for h, vkeys := range entry.OpCerts {
			set := make(map[[32]byte]bool, len(vkeys))
			for _, vkey := range vkeys {
				set[vkey] = true
			}
			grant.opcerts[h] = set
		}
		m[sub] = grant
	}
	return &CallerACL{byCaller: m}
}

// Restricted reports whether the ACL constrains callers at all.
func (a *CallerACL) Restricted() bool { return a != nil && len(a.byCaller) > 0 }

// Allows reports whether caller may use the key. Unrestricted ACLs allow all.
func (a *CallerACL) Allows(caller string, hash backend.KeyHash) bool {
	// Explicit nil/empty guard (rather than delegating to Restricted) so the
	// non-nil receiver is provable at the byCaller dereference below.
	if a == nil || len(a.byCaller) == 0 {
		return true
	}
	return a.byCaller[caller].keys[hash]
}

// AllowsOpCert reports whether caller may certify kesVKey with hash. Unlike
// the general key ACL, opcert issuance always requires an explicit grant.
func (a *CallerACL) AllowsOpCert(
	caller string,
	hash backend.KeyHash,
	kesVKey []byte,
) bool {
	if a == nil || len(kesVKey) != 32 {
		return false
	}
	grant, ok := a.byCaller[caller]
	if !ok || !grant.keys[hash] {
		return false
	}
	var vkey [32]byte
	copy(vkey[:], kesVKey)
	return grant.opcerts[hash][vkey]
}

// AuthorizeAttestedOpCert decides an opcert request that carries a staged-key
// attestation. The caller must hold the cold key, and the attestation must
// verify: a valid signature by a KES agent pinned for that cold key, over
// exactly kesVKey, the cold key hash and, when the pin names one, the agent
// profile. A request with an attestation is never decided on its kes_vkeys
// entry alone, so an attestation that fails is refused rather than ignored.
func (a *CallerACL) AuthorizeAttestedOpCert(
	caller string,
	hash backend.KeyHash,
	kesVKey []byte,
	att *wire.StagedKeyAttestation,
) error {
	if a == nil || len(kesVKey) != 32 {
		return ErrOpCertNotGranted
	}
	grant, ok := a.byCaller[caller]
	if !ok || !grant.keys[hash] {
		return ErrOpCertNotGranted
	}
	if err := att.Verify(); err != nil {
		return err
	}
	if !bytes.Equal(att.KESVKey, kesVKey) {
		return ErrAttestationKESKey
	}
	if !bytes.Equal(att.ColdKeyHash, hash[:]) {
		return ErrAttestationColdKey
	}
	spki := att.SPKISHA256()
	for _, pin := range grant.kesAgents[hash] {
		if pin.SPKISHA256 != spki {
			continue
		}
		if pin.Profile != "" && pin.Profile != att.Profile {
			return fmt.Errorf("%w: %q", ErrAttestationProfile, att.Profile)
		}
		return nil
	}
	return ErrAttestationAgentUntrusted
}
