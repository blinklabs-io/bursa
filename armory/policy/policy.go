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

// Package policy decides which transaction bodies a device key may sign.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/blinklabs-io/bursa/armory/profile"
	"github.com/blinklabs-io/gouroboros/ledger"
	"github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"
)

// Role is the device key a signature is requested from.
type Role int

const (
	RoleCold Role = iota
	RoleOwner
	RoleFee
)

// Keys are the key hashes a profile's device keys resolve to.
type Keys struct {
	Pool  [28]byte // blake2b-224(cold vkey) = pool id
	Owner [28]byte // owner stake key hash
	Fee   [28]byte // fee payment key hash
}

// Decision is an allowed signing request.
type Decision struct {
	// BodyHash is blake2b-256 of the exact body bytes received.
	BodyHash [32]byte
	// Summary describes what the body does, for the operator log.
	Summary string
}

// Body map keys: inputs, outputs, fee, ttl, certificates, auxiliary data
// hash, validity start, required signers, network id, reference inputs and
// voting procedures. Everything else (withdrawals, mint, collateral,
// proposals, donations, Dijkstra sub-transactions) is refused.
var allowedKeys = map[uint64]bool{
	0: true, 1: true, 2: true, 3: true, 4: true, 7: true,
	8: true, 14: true, 15: true, 18: true, 19: true,
}

const (
	keyFee       = 2
	keyNetworkID = 15

	// Enterprise address header: key-hash payment credential, no stake part.
	enterpriseHeader = 0x60
)

var rawDecoder, _ = cbor.DecOptions{
	DupMapKey:   cbor.DupMapKeyEnforcedAPF,
	IndefLength: cbor.IndefLengthForbidden,
}.DecMode()

// Evaluate decides whether role may sign body under profile p. The era is
// chosen by the caller, never inferred. The returned error names the rule
// that refused the body.
func Evaluate(p profile.Profile, k Keys, role Role, era uint, body []byte) (Decision, error) {
	if era != ledger.TxTypeConway && era != ledger.TxTypeDijkstra {
		return Decision{}, fmt.Errorf("policy: unsupported era %d", era)
	}

	fee, err := checkRaw(p, body)

	if err != nil {
		return Decision{}, err
	}

	tx, err := ledger.NewTransactionBodyFromCbor(era, body)

	if err != nil {
		return Decision{}, fmt.Errorf("policy: decode body: %w", err)
	}

	for i, o := range tx.Outputs() {
		addr := o.Address()
		b, err := addr.Bytes()

		if err != nil || len(b) != 29 || b[0] != enterpriseHeader|p.NetworkID ||
			!bytes.Equal(b[1:], k.Fee[:]) {
			return Decision{}, fmt.Errorf("policy: output %d does not pay the fee wallet", i)
		}
	}

	summary := []string{fmt.Sprintf("fee=%d", fee)}
	var poolCert, ownerCert, voted bool

	for i, c := range tx.Certificates() {
		s, pool, owner, err := checkCert(k, era, c)

		if err != nil {
			return Decision{}, fmt.Errorf("policy: certificate %d: %w", i, err)
		}

		poolCert = poolCert || pool
		ownerCert = ownerCert || owner
		summary = append(summary, s)
	}

	for voter, procs := range tx.VotingProcedures() {
		if voter.Type != common.VoterTypeStakingPoolKeyHash || voter.Hash != k.Pool {
			return Decision{}, errors.New("policy: vote by a voter other than this pool")
		}

		voted = true
		summary = append(summary, fmt.Sprintf("vote actions=%d", len(procs)))
	}

	switch {
	case role == RoleCold && !poolCert && !voted:
		return Decision{}, errors.New("policy: nothing for the cold key to authorize")
	case role == RoleOwner && !ownerCert:
		return Decision{}, errors.New("policy: nothing for the owner key to authorize")
	case role < RoleCold || role > RoleFee:
		return Decision{}, fmt.Errorf("policy: unknown role %d", role)
	}

	return Decision{
		BodyHash: blake2b.Sum256(body),
		Summary:  strings.Join(summary, " "),
	}, nil
}

// checkRaw applies the rules gouroboros decoding would hide: exact key set,
// no duplicate keys, definite lengths, a capped fee and the network id.
func checkRaw(p profile.Profile, body []byte) (fee uint64, err error) {
	var m map[uint64]cbor.RawMessage

	if err = rawDecoder.Unmarshal(body, &m); err != nil {
		return 0, fmt.Errorf("policy: body map: %w", err)
	}

	for key := range m {
		if !allowedKeys[key] {
			return 0, fmt.Errorf("policy: body key %d not allowed", key)
		}
	}

	raw, ok := m[keyFee]

	if !ok {
		return 0, errors.New("policy: body has no fee")
	}

	if err = cbor.Unmarshal(raw, &fee); err != nil {
		return 0, fmt.Errorf("policy: fee: %w", err)
	}

	if fee > p.FeeCap() {
		return 0, fmt.Errorf("policy: fee %d above cap %d", fee, p.FeeCap())
	}

	if raw, ok = m[keyNetworkID]; ok {
		var id uint64

		if err = cbor.Unmarshal(raw, &id); err != nil || id != uint64(p.NetworkID) {
			return 0, errors.New("policy: network id does not match profile")
		}
	}

	return fee, nil
}

// checkCert allows only certificates for this pool and its owner. It reports
// whether the certificate needs the cold key or the owner key.
func checkCert(k Keys, era uint, c common.Certificate) (summary string, pool, owner bool, err error) {
	ownerCred := func(cred common.Credential) bool {
		return cred.CredType == common.CredentialTypeAddrKeyHash && [28]byte(cred.Credential) == k.Owner
	}

	switch c := c.(type) {
	case *common.PoolRegistrationCertificate:
		if [28]byte(c.Operator) != k.Pool {
			return "", false, false, errors.New("pool registration for another operator")
		}

		if len(c.PoolOwners) != 1 || [28]byte(c.PoolOwners[0]) != k.Owner {
			return "", false, false, errors.New("pool owners must be exactly the device owner")
		}

		summary = fmt.Sprintf("pool-reg pledge=%d cost=%d margin=%s relays=%d leios=%t",
			c.Pledge, c.Cost, c.Margin.RatString(), len(c.Relays), c.LeiosKey != nil)

		return summary, true, true, nil
	case *common.PoolRetirementCertificate:
		if [28]byte(c.PoolKeyHash) != k.Pool {
			return "", false, false, errors.New("retirement of another pool")
		}

		return fmt.Sprintf("pool-retire epoch=%d", c.Epoch), true, false, nil
	case *common.StakeRegistrationCertificate:
		if era == ledger.TxTypeDijkstra {
			return "", false, false, errors.New("stake registration type 0 is not valid in Dijkstra")
		}

		if !ownerCred(c.StakeCredential) {
			return "", false, false, errors.New("stake registration of another credential")
		}

		return "stake-reg", false, true, nil
	case *common.RegistrationCertificate:
		if !ownerCred(c.StakeCredential) {
			return "", false, false, errors.New("stake registration of another credential")
		}

		return "stake-reg", false, true, nil
	case *common.StakeDelegationCertificate:
		if c.StakeCredential == nil || !ownerCred(*c.StakeCredential) || [28]byte(c.PoolKeyHash) != k.Pool {
			return "", false, false, errors.New("delegation other than owner to this pool")
		}

		return "stake-deleg", false, true, nil
	case *common.StakeRegistrationDelegationCertificate:
		if !ownerCred(c.StakeCredential) || [28]byte(c.PoolKeyHash) != k.Pool {
			return "", false, false, errors.New("delegation other than owner to this pool")
		}

		return "stake-reg-deleg", false, true, nil
	}

	return "", false, false, fmt.Errorf("certificate type %T not allowed", c)
}
