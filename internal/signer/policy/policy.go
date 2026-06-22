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

package policy

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

// TxPolicy constrains transaction signing for a key.
type TxPolicy struct {
	Networks                  []string `yaml:"networks"                    json:"networks"`
	AllowedOutputs            []string `yaml:"allowed_outputs"             json:"allowed_outputs"`
	MaxOutputAda              uint64   `yaml:"max_output_ada"              json:"max_output_ada"`
	MaxTotalOutAda            uint64   `yaml:"max_total_out_ada"           json:"max_total_out_ada"`
	MaxFeeAda                 uint64   `yaml:"max_fee_ada"                 json:"max_fee_ada"`
	AllowCertificates         bool     `yaml:"allow_certificates"          json:"allow_certificates"`
	AllowMint                 bool     `yaml:"allow_mint"                  json:"allow_mint"`
	AllowWithdrawals          bool     `yaml:"allow_withdrawals"           json:"allow_withdrawals"`
	AllowMultiAsset           bool     `yaml:"allow_multi_asset"           json:"allow_multi_asset"`
	AllowVotes                bool     `yaml:"allow_votes"                 json:"allow_votes"`
	AllowProposals            bool     `yaml:"allow_proposals"             json:"allow_proposals"`
	AllowTreasury             bool     `yaml:"allow_treasury"              json:"allow_treasury"`
	RequireValidityUpperBound bool     `yaml:"require_validity_upper_bound" json:"require_validity_upper_bound"`
}

// CIP8Policy constrains data signing for a key.
type CIP8Policy struct {
	MaxPayloadBytes     int  `yaml:"max_payload_bytes"     json:"max_payload_bytes"`
	RequireAddressMatch bool `yaml:"require_address_match" json:"require_address_match"`
}

// KeyPolicy is the per-key authorization rule set.
type KeyPolicy struct {
	Hash            string      `yaml:"hash"`
	Backend         string      `yaml:"backend"`
	AllowedRequests []string    `yaml:"allowed_requests"`
	Tx              *TxPolicy   `yaml:"tx_policy"`
	CIP8            *CIP8Policy `yaml:"cip8_policy"`
}

func (p KeyPolicy) allows(reqType string) bool {
	for _, r := range p.AllowedRequests {
		if r == reqType {
			return true
		}
	}
	return false
}

// Decision is the outcome of a policy evaluation.
type Decision struct {
	Allow  bool
	Reason string
}

func deny(format string, a ...any) Decision {
	return Decision{Allow: false, Reason: fmt.Sprintf(format, a...)}
}
func allow() Decision { return Decision{Allow: true} }

// Engine evaluates requests against per-key policies.
type Engine struct {
	byHash map[backend.KeyHash]KeyPolicy
}

// NewEngine indexes the policies by key hash, validating each hash.
func NewEngine(policies []KeyPolicy) (*Engine, error) {
	byHash := make(map[backend.KeyHash]KeyPolicy, len(policies))
	for _, p := range policies {
		h, err := backend.ParseKeyHash(p.Hash)
		if err != nil {
			return nil, fmt.Errorf("policy for %q: %w", p.Hash, err)
		}
		if _, exists := byHash[h]; exists {
			return nil, fmt.Errorf("duplicate policy for key hash %s", p.Hash)
		}
		// Deep-copy sub-structs to prevent aliasing with the caller's slice.
		p.AllowedRequests = append([]string(nil), p.AllowedRequests...)
		if p.Tx != nil {
			cp := *p.Tx
			cp.Networks = append([]string(nil), p.Tx.Networks...)
			cp.AllowedOutputs = append([]string(nil), p.Tx.AllowedOutputs...)
			p.Tx = &cp
		}
		if p.CIP8 != nil {
			cp := *p.CIP8
			p.CIP8 = &cp
		}
		byHash[h] = p
	}
	return &Engine{byHash: byHash}, nil
}

// PolicyFor returns the policy for a key hash, if any. The returned value
// shares slices/pointers with engine state; callers must treat it as read-only.
func (e *Engine) PolicyFor(hash backend.KeyHash) (KeyPolicy, bool) {
	p, ok := e.byHash[hash]
	return p, ok
}

const lovelacePerAda = 1_000_000

// networkOfAddress infers the network from a known bech32 address HRP.
// Testnet HRPs contain "_test" (addr_test1.., stake_test1..); mainnet uses
// addr1/stake1. Unknown or unsupported formats return "" so network checks
// fail closed.
// Note: all testnet HRP variants (preview, preprod, etc.) map uniformly to
// "testnet" — the HRP does not encode which testnet. This is a Phase 1
// limitation; callers that need to distinguish specific testnets must do so
// outside of this function.
func networkOfAddress(addr string) string {
	if strings.HasPrefix(addr, "addr_test1") || strings.HasPrefix(addr, "stake_test1") {
		return "testnet"
	}
	if strings.HasPrefix(addr, "addr1") || strings.HasPrefix(addr, "stake1") {
		return "mainnet"
	}
	return ""
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// EvaluateTx authorizes (or denies) signing the inspected transaction with the
// key identified by hash. Deny-by-default: absent policy denies.
func (e *Engine) EvaluateTx(hash backend.KeyHash, insp *bursa.TxInspection) Decision {
	if insp == nil {
		return deny("transaction inspection is nil")
	}
	p, ok := e.byHash[hash]
	if !ok {
		return deny("no policy configured for key %s", hash)
	}
	if !p.allows("tx") {
		return deny("key %s may not sign transactions", hash)
	}
	if p.Tx == nil {
		return deny("key %s has no tx_policy", hash)
	}
	tp := p.Tx

	// The transaction fee is value that leaves the signer's inputs just like
	// an output does, so it must be bounded too. Parse it up front; an
	// unparseable fee fails closed.
	fee := new(big.Int)
	if insp.Fee != "" {
		f, ok := new(big.Int).SetString(insp.Fee, 10)
		if !ok {
			return deny("unparseable fee %q", insp.Fee)
		}
		fee = f
	}
	if tp.MaxFeeAda > 0 {
		maxFee := new(big.Int).Mul(
			new(big.Int).SetUint64(tp.MaxFeeAda),
			big.NewInt(lovelacePerAda),
		)
		if fee.Cmp(maxFee) > 0 {
			return deny("fee %s exceeds max_fee_ada", insp.Fee)
		}
	}

	total := new(big.Int)
	// Use Mul to avoid uint64 overflow before promotion to big.Int.
	maxOut := new(big.Int).Mul(
		new(big.Int).SetUint64(tp.MaxOutputAda),
		big.NewInt(lovelacePerAda),
	)
	for _, out := range insp.Outputs {
		if len(tp.Networks) > 0 && !contains(tp.Networks, networkOfAddress(out.Address)) {
			return deny("output address %s is not on an allowed network", out.Address)
		}
		if len(tp.AllowedOutputs) > 0 && !contains(tp.AllowedOutputs, out.Address) {
			return deny("output address %s is not in the allowlist", out.Address)
		}
		// Native-asset movement is unbounded by the lovelace limits, so deny it
		// by default. Note: this is independent of minting (HasMint), which
		// covers creating/destroying assets rather than transferring existing
		// ones out of the signer's UTxOs.
		if out.HasAssets && !tp.AllowMultiAsset {
			return deny("output %s carries native assets", out.Address)
		}
		lov, ok := new(big.Int).SetString(out.Lovelace, 10)
		if !ok {
			return deny("unparseable output lovelace %q", out.Lovelace)
		}
		if tp.MaxOutputAda > 0 && lov.Cmp(maxOut) > 0 {
			return deny("output %s lovelace exceeds max_output_ada", out.Lovelace)
		}
		total.Add(total, lov)
	}
	// Count the fee toward the total value leaving the signer so that
	// max_total_out_ada cannot be bypassed by inflating the fee field.
	total.Add(total, fee)
	if tp.MaxTotalOutAda > 0 {
		maxTotal := new(big.Int).Mul(
			new(big.Int).SetUint64(tp.MaxTotalOutAda),
			big.NewInt(lovelacePerAda),
		)
		if total.Cmp(maxTotal) > 0 {
			return deny("total outputs plus fee exceed max_total_out_ada")
		}
	}
	if insp.CertificateCount > 0 && !tp.AllowCertificates {
		return deny("transaction contains certificates")
	}
	if insp.HasMint && !tp.AllowMint {
		return deny("transaction mints/burns assets")
	}
	if insp.WithdrawalCount > 0 && !tp.AllowWithdrawals {
		return deny("transaction contains reward withdrawals")
	}
	if insp.VotingProcedureCount > 0 && !tp.AllowVotes {
		return deny("transaction contains governance voting procedures")
	}
	if insp.ProposalProcedureCount > 0 && !tp.AllowProposals {
		return deny("transaction contains governance proposal procedures")
	}
	if insp.HasTreasuryDonation && !tp.AllowTreasury {
		return deny("transaction contains a treasury donation")
	}
	if tp.RequireValidityUpperBound && insp.TTL == 0 {
		return deny("transaction has no validity upper bound (TTL)")
	}
	return allow()
}

// EvaluateCIP8 authorizes (or denies) a CIP-8/CIP-30 data-signing request.
func (e *Engine) EvaluateCIP8(hash backend.KeyHash, payloadLen int, addressMatches bool) Decision {
	p, ok := e.byHash[hash]
	if !ok {
		return deny("no policy configured for key %s", hash)
	}
	if !p.allows("cip8") {
		return deny("key %s may not perform data signing", hash)
	}
	if p.CIP8 == nil {
		return deny("key %s has no cip8_policy", hash)
	}
	if p.CIP8.MaxPayloadBytes > 0 && payloadLen > p.CIP8.MaxPayloadBytes {
		return deny("payload of %d bytes exceeds max_payload_bytes", payloadLen)
	}
	if p.CIP8.RequireAddressMatch && !addressMatches {
		return deny("payload address does not match signing key")
	}
	return allow()
}
