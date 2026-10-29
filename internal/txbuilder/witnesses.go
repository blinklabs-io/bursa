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

package txbuilder

import (
	"bytes"
	"sort"

	"github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
)

// Witness roles reported for a built transaction.
const (
	witnessRolePayment       = "payment"
	witnessRolePoolCold      = "pool cold"
	witnessRolePoolOwner     = "pool owner"
	witnessRoleStake         = "stake"
	witnessRoleCommitteeCold = "committee cold"
	witnessRoleDrep          = "drep"
	witnessRoleVoter         = "voter"
)

// RequiredWitness is one key hash that must sign a built transaction, with
// the role that requires it.
type RequiredWitness struct {
	Hash [28]byte
	Role string
}

// requiredWitnesses returns the deduplicated key hashes a transaction with
// the given body and selected inputs needs vkey witnesses for: the payment
// key of every input, the per-certificate witnesses of the Conway ledger
// rules, and the voter of every voting procedure.
func requiredWitnesses(body conway.ConwayTransactionBody, inputs []UTxO) [][28]byte {
	reqs := requiredWitnessSet(body, inputs)
	hashes := make([][28]byte, 0, len(reqs))
	for _, r := range reqs {
		hashes = append(hashes, r.Hash)
	}
	return hashes
}

// requiredWitnessSet is requiredWitnesses with roles. Hashes are
// deduplicated, keeping the role of their first occurrence.
func requiredWitnessSet(body conway.ConwayTransactionBody, inputs []UTxO) []RequiredWitness {
	var out []RequiredWitness
	seen := map[[28]byte]bool{}
	add := func(hash [28]byte, role string) {
		if seen[hash] {
			return
		}
		seen[hash] = true
		out = append(out, RequiredWitness{Hash: hash, Role: role})
	}
	for _, u := range inputs {
		addr := u.Output.Address()
		// A script payment credential needs a script witness, not a vkey
		if _, ok := addr.PayloadPayload().(common.AddressPayloadKeyHash); ok {
			add(addr.PaymentKeyHash(), witnessRolePayment)
		}
	}
	for _, wrapper := range body.TxCertificates {
		for _, w := range certWitnesses(wrapper) {
			add(w.Hash, w.Role)
		}
	}
	var voters [][28]byte
	for voter := range body.TxVotingProcedures {
		switch voter.Type {
		case common.VoterTypeConstitutionalCommitteeHotKeyHash,
			common.VoterTypeDRepKeyHash,
			common.VoterTypeStakingPoolKeyHash:
			voters = append(voters, [28]byte(voter.Hash))
		}
	}
	sort.Slice(voters, func(i, j int) bool {
		return bytes.Compare(voters[i][:], voters[j][:]) < 0
	})
	for _, hash := range voters {
		add(hash, witnessRoleVoter)
	}
	return out
}

// certWitnesses returns the vkey witnesses the Conway ledger requires for
// one certificate. Script credentials need script witnesses, not vkeys, so
// they add none. Legacy stake registration (type 0) adds none either
// (ConwayRegCert _ SNothing -> Nothing), unlike Conway type 7.
func certWitnesses(wrapper common.CertificateWrapper) []RequiredWitness {
	credWitness := func(c common.Credential, role string) []RequiredWitness {
		if c.CredType != common.CredentialTypeAddrKeyHash {
			return nil
		}
		return []RequiredWitness{{Hash: [28]byte(c.Credential), Role: role}}
	}
	stakeWitness := func(c common.Credential) []RequiredWitness {
		return credWitness(c, witnessRoleStake)
	}
	switch cert := wrapper.Certificate.(type) {
	case *common.StakeRegistrationCertificate:
		return nil
	case *common.StakeDeregistrationCertificate:
		return stakeWitness(cert.StakeCredential)
	case *common.StakeDelegationCertificate:
		if cert.StakeCredential == nil {
			return nil
		}
		return stakeWitness(*cert.StakeCredential)
	case *common.PoolRegistrationCertificate:
		out := []RequiredWitness{{
			Hash: [28]byte(cert.Operator),
			Role: witnessRolePoolCold,
		}}
		for _, owner := range cert.PoolOwners {
			out = append(out, RequiredWitness{
				Hash: [28]byte(owner),
				Role: witnessRolePoolOwner,
			})
		}
		return out
	case *common.PoolRetirementCertificate:
		return []RequiredWitness{{
			Hash: [28]byte(cert.PoolKeyHash),
			Role: witnessRolePoolCold,
		}}
	case *common.RegistrationCertificate:
		return stakeWitness(cert.StakeCredential)
	case *common.DeregistrationCertificate:
		return stakeWitness(cert.StakeCredential)
	case *common.VoteDelegationCertificate:
		return stakeWitness(cert.StakeCredential)
	case *common.StakeVoteDelegationCertificate:
		return stakeWitness(cert.StakeCredential)
	case *common.StakeRegistrationDelegationCertificate:
		return stakeWitness(cert.StakeCredential)
	case *common.VoteRegistrationDelegationCertificate:
		return stakeWitness(cert.StakeCredential)
	case *common.StakeVoteRegistrationDelegationCertificate:
		return stakeWitness(cert.StakeCredential)
	case *common.AuthCommitteeHotCertificate:
		return credWitness(cert.ColdCredential, witnessRoleCommitteeCold)
	case *common.ResignCommitteeColdCertificate:
		return credWitness(cert.ColdCredential, witnessRoleCommitteeCold)
	case *common.RegistrationDrepCertificate:
		return credWitness(cert.DrepCredential, witnessRoleDrep)
	case *common.DeregistrationDrepCertificate:
		return credWitness(cert.DrepCredential, witnessRoleDrep)
	case *common.UpdateDrepCertificate:
		return credWitness(cert.DrepCredential, witnessRoleDrep)
	default:
		// Types 5 and 6 are rejected before this runs
		return nil
	}
}
