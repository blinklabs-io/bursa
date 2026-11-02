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
//
// The device holds a pool's cold key and owner stake key, never funds: any
// wallet pays for the transaction and signs its own inputs. A cold or owner
// witness authorizes certificates and votes, not spending, so the rules bound
// what those certificates do rather than where the outputs go.
package policy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
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
)

// Keys are the key hashes a profile's device keys resolve to.
type Keys struct {
	Pool  [28]byte // blake2b-224(cold vkey) = pool id
	Owner [28]byte // owner stake key hash
	// Pins, when set, bind pool registrations to the VRF key hash, the
	// metadata hash and the parameter bounds the operator provisioned. Nil
	// leaves those fields unchecked.
	Pins *profile.Pins
}

// Decision is an allowed signing request.
type Decision struct {
	// BodyHash is blake2b-256 of the exact body bytes received.
	BodyHash [32]byte
	// Summary describes what the body does, for the operator log.
	Summary string
}

// Body map keys: inputs, outputs, fee, ttl, certificates, auxiliary data
// hash, validity start, required signers (guards under Dijkstra, which only
// add signature obligations), network id, reference inputs and voting
// procedures. Everything else (withdrawals, mint, collateral,
// proposals, donations, Dijkstra sub-transactions) is refused.
var allowedKeys = map[uint64]bool{
	0: true, 1: true, 2: true, 3: true, 4: true, 7: true,
	8: true, 14: true, 15: true, 18: true, 19: true,
}

const (
	keyFee       = 2
	keyNetworkID = 15

	// hashPrefix is how many bytes of the VRF key and metadata hashes the
	// registration summary shows.
	hashPrefix = 4

	// byronAddressType is the first header type without a network nibble.
	byronAddressType = 8
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

	// outputs belong to the paying wallet; only their network must match
	for i, o := range tx.Outputs() {
		addr := o.Address()
		b, err := addr.Bytes()

		if err != nil || len(b) == 0 {
			return Decision{}, fmt.Errorf("policy: output %d has no address", i)
		}

		if b[0]>>4 < byronAddressType && b[0]&0x0f != p.NetworkID {
			return Decision{}, fmt.Errorf("policy: output %d is on another network", i)
		}
	}

	summary := []string{fmt.Sprintf("fee=%d", fee)}
	var poolCert, ownerCert, voted bool

	// The ledger applies certificates in order, so a second registration
	// would replace the parameters of the first.
	registrations := 0

	for i, c := range tx.Certificates() {
		s, pool, owner, err := checkCert(p, k, era, c)
		if err != nil {
			return Decision{}, fmt.Errorf("policy: certificate %d: %w", i, err)
		}

		if _, ok := c.(*common.PoolRegistrationCertificate); ok {
			if registrations++; registrations > 1 {
				return Decision{}, fmt.Errorf("policy: certificate %d: a second pool registration in one body", i)
			}
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
	case role < RoleCold || role > RoleOwner:
		return Decision{}, fmt.Errorf("policy: unknown role %d", role)
	}

	return Decision{
		BodyHash: blake2b.Sum256(body),
		Summary:  strings.Join(summary, " "),
	}, nil
}

// checkRaw applies the rules gouroboros decoding would hide: exact key set,
// no duplicate keys, definite lengths, a present fee and the network id. A
// fee is required because a Dijkstra sub-transaction body has none.
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
func checkCert(p profile.Profile, k Keys, era uint, c common.Certificate) (summary string, pool, owner bool, err error) {
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

		if err := checkRewardAccount(p, c); err != nil {
			return "", false, false, err
		}

		if k.Pins != nil {
			if err := checkPins(*k.Pins, c); err != nil {
				return "", false, false, err
			}
		}

		// the hash prefixes let the operator see what the log recorded
		meta := "none"
		if c.PoolMetadata != nil {
			// the ledger leaves the metadata hash length open, so a short
			// one is shown whole rather than sliced past its end
			h := c.PoolMetadata.Hash
			meta = hex.EncodeToString(h[:min(len(h), hashPrefix)])
		}

		summary = fmt.Sprintf("pool-reg pledge=%d cost=%d margin=%s relays=%d leios=%t vrf=%s meta=%s",
			c.Pledge, c.Cost, c.Margin.RatString(), len(c.Relays), c.LeiosKey != nil,
			hex.EncodeToString(c.VrfKeyHash[:hashPrefix]), meta)

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

// checkRewardAccount requires the registration's reward account to be the
// one pinned in the profile at provisioning, credential type and network
// included.
func checkRewardAccount(p profile.Profile, c *common.PoolRegistrationCertificate) error {
	want, ok := p.RewardAddress()

	if !ok {
		return errors.New("profile has no reward account; pool registration refused")
	}

	network, known := c.RewardAccountNetworkId()
	cred := c.RewardAccountCredential()

	if !known || network > 0x0f || cred.CredType > common.CredentialTypeScriptHash {
		return errors.New("pool registration reward account is malformed")
	}

	got := append([]byte{0xe0 | byte(cred.CredType)<<4 | byte(network)}, cred.Credential[:]...)

	if !bytes.Equal(got, want) {
		return errors.New("pool registration reward account is not the profile's reward account")
	}

	return nil
}

// checkPins requires a registration to match the pins provisioned for the
// profile: the VRF key hash, metadata hash, relays and metadata URL exactly,
// pledge, cost and margin within bounds.
func checkPins(pins profile.Pins, c *common.PoolRegistrationCertificate) error {
	if [32]byte(c.VrfKeyHash) != pins.VRFKeyHash {
		return errors.New("pool registration VRF key hash is not the pinned one")
	}

	switch {
	case pins.MetadataHash == nil && c.PoolMetadata != nil:
		return errors.New("pool registration carries metadata, none is pinned")
	case pins.MetadataHash != nil && c.PoolMetadata == nil:
		return errors.New("pool registration has no metadata, a metadata hash is pinned")
	case pins.MetadataHash != nil && !bytes.Equal(c.PoolMetadata.Hash, pins.MetadataHash[:]):
		return errors.New("pool registration metadata hash is not the pinned one")
	}

	var url *string
	if c.PoolMetadata != nil {
		url = &c.PoolMetadata.Url
	}

	d, err := RelaysDigest(c.Relays, url)
	if err != nil {
		return fmt.Errorf("pool registration relays: %w", err)
	}

	if d != pins.RelaysDigest {
		return errors.New("pool registration relays or metadata URL are not the pinned ones")
	}

	if c.Pledge < pins.PledgeMin || c.Pledge > pins.PledgeMax {
		return fmt.Errorf("pool registration pledge %d outside the pinned bounds", c.Pledge)
	}

	if c.Cost > pins.CostMax {
		return fmt.Errorf("pool registration cost %d above the pinned maximum", c.Cost)
	}

	max := new(big.Rat).SetFrac(new(big.Int).SetUint64(pins.MarginMaxNum), new(big.Int).SetUint64(pins.MarginMaxDen))

	if c.Margin.Rat == nil || c.Margin.Cmp(max) > 0 {
		return errors.New("pool registration margin above the pinned maximum")
	}

	return nil
}

// RelaysDigest returns the digest that pins a pool registration's relays and
// metadata URL: blake2b-160 of the CBOR array [relays, url], each relay in
// its ledger encoding and in registration order, url null without metadata.
// The device and armory-pool both compute it here from decoded values, so a
// registration matches however its builder laid out the bytes.
func RelaysDigest(relays []common.PoolRelay, metadataURL *string) ([profile.RelaysDigestSize]byte, error) {
	var d [profile.RelaysDigestSize]byte

	if relays == nil {
		relays = []common.PoolRelay{}
	}

	b, err := cbor.Marshal([]any{relays, metadataURL})
	if err != nil {
		return d, err
	}

	h, err := blake2b.New(profile.RelaysDigestSize, nil)
	if err != nil {
		return d, err
	}

	h.Write(b)
	copy(d[:], h.Sum(nil))

	return d, nil
}
