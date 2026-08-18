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
	"slices"
	"strings"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

// TxPolicy constrains transaction signing for a key.
//
// Certificate and governance-vote authorization each have two mutually-aware
// forms. The coarse boolean (AllowCertificates / AllowVotes) is the original
// allow-all / deny switch. The typed allow-lists (AllowedCertificates /
// AllowedVoterKinds / AllowedDrepIds) provide per-kind gating: when an
// allow-list is non-empty it takes precedence over the boolean and permits
// only the listed kinds. An absent boolean and an empty allow-list preserve
// deny-by-default.
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

	// AllowedCertificates, when non-empty, restricts the transaction to only
	// these certificate kinds (see CertificateKindName for the vocabulary). It
	// overrides AllowCertificates.
	AllowedCertificates []string `yaml:"allowed_certificates" json:"allowed_certificates"`
	// AllowedVoterKinds, when non-empty, restricts governance voting procedures
	// to only these voter kinds (see VoterKindName). AllowedDrepIds, when
	// non-empty, further restricts DRep voters to the listed hex credential
	// ids. Either being non-empty selects allow-list mode, overriding AllowVotes.
	AllowedVoterKinds []string `yaml:"allowed_voter_kinds" json:"allowed_voter_kinds"`
	AllowedDrepIds    []string `yaml:"allowed_drep_ids"    json:"allowed_drep_ids"`
}

// VoterInfo identifies one governance voter present in a transaction's voting
// procedures. Kind is the VoterKindName; DrepId is the hex-encoded credential
// hash for DRep voters and "" for committee/pool voters.
type VoterInfo struct {
	Kind   string
	DrepId string
}

// TxOps carries the operation TYPES decoded from a transaction — the typed
// companion to the counts/booleans on bursa.TxInspection. It is produced by the
// operation layer and consumed by per-kind policy gating.
type TxOps struct {
	// Certificates lists the certificate kind name of every certificate in the
	// transaction, in transaction order (see CertificateKindName).
	Certificates []string
	// Voters lists every governance voter in the transaction's voting procedures.
	Voters []VoterInfo
}

// CallerTxOverride further restricts a key's tx policy for one caller. Every
// field is subtractive: an unset field imposes no additional restriction, and
// a set field can only tighten. It is evaluated in addition to (never in place
// of) the key's base tx policy, so it can never grant authority the base
// policy denies — the effective decision is the intersection of both.
type CallerTxOverride struct {
	Networks            []string `yaml:"networks"             json:"networks"`
	AllowedOutputs      []string `yaml:"allowed_outputs"      json:"allowed_outputs"`
	MaxOutputAda        uint64   `yaml:"max_output_ada"       json:"max_output_ada"`
	MaxTotalOutAda      uint64   `yaml:"max_total_out_ada"    json:"max_total_out_ada"`
	MaxFeeAda           uint64   `yaml:"max_fee_ada"          json:"max_fee_ada"`
	AllowedCertificates []string `yaml:"allowed_certificates" json:"allowed_certificates"`
	AllowedVoterKinds   []string `yaml:"allowed_voter_kinds"  json:"allowed_voter_kinds"`
	AllowedDrepIds      []string `yaml:"allowed_drep_ids"     json:"allowed_drep_ids"`
	// Forbid* deny an entire category outright regardless of the base policy.
	ForbidCertificates bool `yaml:"forbid_certificates" json:"forbid_certificates"`
	ForbidMint         bool `yaml:"forbid_mint"         json:"forbid_mint"`
	ForbidWithdrawals  bool `yaml:"forbid_withdrawals"  json:"forbid_withdrawals"`
	ForbidVotes        bool `yaml:"forbid_votes"        json:"forbid_votes"`
	ForbidProposals    bool `yaml:"forbid_proposals"    json:"forbid_proposals"`
	ForbidTreasury     bool `yaml:"forbid_treasury"     json:"forbid_treasury"`
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
	return slices.Contains(p.AllowedRequests, reqType)
}

// Certificate kind names. These are the stable vocabulary used in
// allowed_certificates policy lists and in TxOps.Certificates. They mirror the
// gouroboros CertificateType ordinals.
const (
	CertStakeRegistration               = "stake_registration"
	CertStakeDeregistration             = "stake_deregistration"
	CertStakeDelegation                 = "stake_delegation"
	CertPoolRegistration                = "pool_registration"
	CertPoolRetirement                  = "pool_retirement"
	CertGenesisKeyDelegation            = "genesis_key_delegation"
	CertMoveInstantaneousRewards        = "move_instantaneous_rewards"
	CertRegistration                    = "registration"
	CertDeregistration                  = "deregistration"
	CertVoteDelegation                  = "vote_delegation"
	CertStakeVoteDelegation             = "stake_vote_delegation"
	CertStakeRegistrationDelegation     = "stake_registration_delegation"
	CertVoteRegistrationDelegation      = "vote_registration_delegation"
	CertStakeVoteRegistrationDelegation = "stake_vote_registration_delegation"
	CertAuthCommitteeHot                = "auth_committee_hot"
	CertResignCommitteeCold             = "resign_committee_cold"
	CertDrepRegistration                = "drep_registration"
	CertDrepDeregistration              = "drep_deregistration"
	CertDrepUpdate                      = "drep_update"
)

// certKindNames maps gouroboros CertificateType ordinals to kind names.
var certKindNames = map[uint]string{
	0:  CertStakeRegistration,
	1:  CertStakeDeregistration,
	2:  CertStakeDelegation,
	3:  CertPoolRegistration,
	4:  CertPoolRetirement,
	5:  CertGenesisKeyDelegation,
	6:  CertMoveInstantaneousRewards,
	7:  CertRegistration,
	8:  CertDeregistration,
	9:  CertVoteDelegation,
	10: CertStakeVoteDelegation,
	11: CertStakeRegistrationDelegation,
	12: CertVoteRegistrationDelegation,
	13: CertStakeVoteRegistrationDelegation,
	14: CertAuthCommitteeHot,
	15: CertResignCommitteeCold,
	16: CertDrepRegistration,
	17: CertDrepDeregistration,
	18: CertDrepUpdate,
}

// CertificateKindName returns the stable kind name for a gouroboros
// CertificateType ordinal, or "unknown_certificate_<n>" for an unrecognized
// type so that gating on an unknown certificate fails closed (it will not match
// any configured allow-list entry).
func CertificateKindName(certType uint) string {
	if n, ok := certKindNames[certType]; ok {
		return n
	}
	return fmt.Sprintf("unknown_certificate_%d", certType)
}

// Governance voter kind names, used in allowed_voter_kinds and VoterInfo.Kind.
const (
	VoterCommitteeHotKey    = "committee_hot_key"
	VoterCommitteeHotScript = "committee_hot_script"
	VoterDrepKey            = "drep_key"
	VoterDrepScript         = "drep_script"
	VoterStakingPoolKey     = "staking_pool_key"
)

var voterKindNames = map[uint8]string{
	0: VoterCommitteeHotKey,
	1: VoterCommitteeHotScript,
	2: VoterDrepKey,
	3: VoterDrepScript,
	4: VoterStakingPoolKey,
}

// VoterKindName returns the stable kind name for a gouroboros voter Type, or
// "unknown_voter_<n>" for an unrecognized type (fails closed under gating).
func VoterKindName(voterType uint8) string {
	if n, ok := voterKindNames[voterType]; ok {
		return n
	}
	return fmt.Sprintf("unknown_voter_%d", voterType)
}

// IsDrepVoterKind reports whether a voter kind identifies a DRep (whose
// credential id is subject to allowed_drep_ids gating).
func IsDrepVoterKind(kind string) bool {
	return kind == VoterDrepKey || kind == VoterDrepScript
}

// evalConfig holds the optional inputs threaded into EvaluateTx.
type evalConfig struct {
	caller string
	ops    TxOps
}

// EvalOption configures an EvaluateTx call. Absent options preserve the
// original two-argument behavior (no caller override, no per-kind gating).
type EvalOption func(*evalConfig)

// WithCaller threads the authenticated caller into policy evaluation so that a
// configured per-caller override (see SetCallerPolicies) can further restrict
// the key's base policy.
func WithCaller(caller string) EvalOption {
	return func(c *evalConfig) { c.caller = caller }
}

// WithOps supplies the decoded operation types (certificate kinds, voters) that
// per-kind allow-list gating evaluates.
func WithOps(ops TxOps) EvalOption {
	return func(c *evalConfig) { c.ops = ops }
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
	// callerOverrides holds optional per-caller, per-key tx restrictions that
	// intersect with (only narrow) the key's base policy. caller -> key -> override.
	callerOverrides map[string]map[backend.KeyHash]*CallerTxOverride
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
			cp.AllowedCertificates = append([]string(nil), p.Tx.AllowedCertificates...)
			cp.AllowedVoterKinds = append([]string(nil), p.Tx.AllowedVoterKinds...)
			cp.AllowedDrepIds = append([]string(nil), p.Tx.AllowedDrepIds...)
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

// SetCallerPolicies installs optional per-caller tx overrides, keyed
// caller-subject -> key-hash. An override can only further restrict the key's
// base policy (see CallerTxOverride); it never widens authority. Overrides are
// deep-copied. Passing nil clears any installed overrides. Intended to be
// called once at setup before serving, alongside NewEngine.
func (e *Engine) SetCallerPolicies(overrides map[string]map[backend.KeyHash]*CallerTxOverride) {
	if len(overrides) == 0 {
		e.callerOverrides = nil
		return
	}
	cp := make(map[string]map[backend.KeyHash]*CallerTxOverride, len(overrides))
	for caller, byKey := range overrides {
		if len(byKey) == 0 {
			continue
		}
		m := make(map[backend.KeyHash]*CallerTxOverride, len(byKey))
		for h, ov := range byKey {
			if ov == nil {
				continue
			}
			cov := *ov
			cov.Networks = append([]string(nil), ov.Networks...)
			cov.AllowedOutputs = append([]string(nil), ov.AllowedOutputs...)
			cov.AllowedCertificates = append([]string(nil), ov.AllowedCertificates...)
			cov.AllowedVoterKinds = append([]string(nil), ov.AllowedVoterKinds...)
			cov.AllowedDrepIds = append([]string(nil), ov.AllowedDrepIds...)
			m[h] = &cov
		}
		if len(m) > 0 {
			cp[caller] = m
		}
	}
	if len(cp) == 0 {
		cp = nil
	}
	e.callerOverrides = cp
}

// callerOverride returns the override for a caller+key, if any is installed.
func (e *Engine) callerOverride(caller string, hash backend.KeyHash) (*CallerTxOverride, bool) {
	if caller == "" || e.callerOverrides == nil {
		return nil, false
	}
	byKey := e.callerOverrides[caller]
	if byKey == nil {
		return nil, false
	}
	// Explicit nil guard (rather than returning the map read directly) so the
	// second (bool) result is correlated with a guaranteed non-nil pointer: the
	// "ok" path can only return a non-nil *CallerTxOverride.
	ov := byKey[hash]
	if ov == nil {
		return nil, false
	}
	return ov, true
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
	return slices.Contains(set, v)
}

// parseLovelace parses a decimal lovelace string. An empty string is zero; a
// non-numeric string reports false so callers can fail closed.
func parseLovelace(s string) (*big.Int, bool) {
	if s == "" {
		return new(big.Int), true
	}
	v, ok := new(big.Int).SetString(s, 10)
	return v, ok
}

// adaToLovelace converts an ADA bound to lovelace without uint64 overflow.
func adaToLovelace(ada uint64) *big.Int {
	return new(big.Int).Mul(new(big.Int).SetUint64(ada), big.NewInt(lovelacePerAda))
}

// EvaluateTx authorizes (or denies) signing the inspected transaction with the
// key identified by hash. Deny-by-default: absent policy denies.
//
// With no options this preserves the original coarse boolean gating. Supplying
// WithOps enables per-kind allow-list gating (allowed_certificates /
// allowed_voter_kinds / allowed_drep_ids); supplying WithCaller applies any
// per-caller override, which can only further restrict the decision (the
// effective result is the intersection of the base policy and the override).
func (e *Engine) EvaluateTx(hash backend.KeyHash, insp *bursa.TxInspection, opts ...EvalOption) Decision {
	var cfg evalConfig
	for _, o := range opts {
		o(&cfg)
	}
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
	if d := gateCertificates(tp, insp, cfg.ops); !d.Allow {
		return d
	}
	if insp.HasMint && !tp.AllowMint {
		return deny("transaction mints/burns assets")
	}
	if insp.WithdrawalCount > 0 && !tp.AllowWithdrawals {
		return deny("transaction contains reward withdrawals")
	}
	if d := gateVotes(tp, insp, cfg.ops); !d.Allow {
		return d
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
	// Per-caller override: intersect with (only narrow) the base decision.
	if ov, ok := e.callerOverride(cfg.caller, hash); ok {
		if d := evalOverride(ov, insp, cfg.ops); !d.Allow {
			return d
		}
	}
	return allow()
}

// gateCertificates applies the certificate authorization: an allow-list, when
// configured, permits only the listed kinds; otherwise the coarse boolean
// applies. A tx that carries certificates but whose kinds could not be decoded
// (empty ops under allow-list mode) fails closed.
func gateCertificates(tp *TxPolicy, insp *bursa.TxInspection, ops TxOps) Decision {
	if insp.CertificateCount == 0 {
		return allow()
	}
	if len(tp.AllowedCertificates) > 0 {
		if len(ops.Certificates) == 0 {
			return deny("certificate kinds unavailable for allowed_certificates evaluation")
		}
		for _, k := range ops.Certificates {
			if !contains(tp.AllowedCertificates, k) {
				return deny("certificate kind %q is not permitted by allowed_certificates", k)
			}
		}
		return allow()
	}
	if !tp.AllowCertificates {
		return deny("transaction contains certificates")
	}
	return allow()
}

// gateVotes applies governance-vote authorization: when a voter-kind or
// DRep-id allow-list is configured, every voter must satisfy it; otherwise the
// coarse boolean applies. Voting procedures whose voters could not be decoded
// (empty ops under allow-list mode) fail closed.
func gateVotes(tp *TxPolicy, insp *bursa.TxInspection, ops TxOps) Decision {
	if insp.VotingProcedureCount == 0 {
		return allow()
	}
	if len(tp.AllowedVoterKinds) > 0 || len(tp.AllowedDrepIds) > 0 {
		if len(ops.Voters) == 0 {
			return deny("voter details unavailable for vote allow-list evaluation")
		}
		return gateVoters(tp.AllowedVoterKinds, tp.AllowedDrepIds, ops.Voters)
	}
	if !tp.AllowVotes {
		return deny("transaction contains governance voting procedures")
	}
	return allow()
}

// gateVoters denies unless every voter satisfies the voter-kind allow-list (when
// set) and, for DRep voters, the DRep-id allow-list (when set). When only a
// DRep-id list is set, non-DRep voters are denied (they carry no id to match).
func gateVoters(allowedKinds, allowedDreps []string, voters []VoterInfo) Decision {
	for _, v := range voters {
		if len(allowedKinds) > 0 && !contains(allowedKinds, v.Kind) {
			return deny("voter kind %q is not permitted by allowed_voter_kinds", v.Kind)
		}
		if len(allowedDreps) > 0 {
			if v.DrepId == "" || !contains(allowedDreps, v.DrepId) {
				return deny("voter %q is not an allowed DRep (allowed_drep_ids)", v.Kind)
			}
		}
	}
	return allow()
}

// evalOverride applies a per-caller CallerTxOverride. Every check is
// subtractive: only set fields can add a denial, so the override can only
// narrow the base decision, never widen it.
func evalOverride(ov *CallerTxOverride, insp *bursa.TxInspection, ops TxOps) Decision {
	if ov.MaxFeeAda > 0 {
		fee, ok := parseLovelace(insp.Fee)
		if !ok {
			return deny("unparseable fee %q", insp.Fee)
		}
		if fee.Cmp(adaToLovelace(ov.MaxFeeAda)) > 0 {
			return deny("fee %s exceeds caller override max_fee_ada", insp.Fee)
		}
	}
	total := new(big.Int)
	maxOut := adaToLovelace(ov.MaxOutputAda)
	for _, out := range insp.Outputs {
		if len(ov.Networks) > 0 && !contains(ov.Networks, networkOfAddress(out.Address)) {
			return deny("output address %s is not on a caller-override allowed network", out.Address)
		}
		if len(ov.AllowedOutputs) > 0 && !contains(ov.AllowedOutputs, out.Address) {
			return deny("output address %s is not in the caller-override allowlist", out.Address)
		}
		lov, ok := parseLovelace(out.Lovelace)
		if !ok {
			return deny("unparseable output lovelace %q", out.Lovelace)
		}
		if ov.MaxOutputAda > 0 && lov.Cmp(maxOut) > 0 {
			return deny("output %s lovelace exceeds caller override max_output_ada", out.Lovelace)
		}
		total.Add(total, lov)
	}
	if ov.MaxTotalOutAda > 0 {
		if fee, ok := parseLovelace(insp.Fee); ok {
			total.Add(total, fee)
		}
		if total.Cmp(adaToLovelace(ov.MaxTotalOutAda)) > 0 {
			return deny("total outputs plus fee exceed caller override max_total_out_ada")
		}
	}
	if ov.ForbidCertificates && insp.CertificateCount > 0 {
		return deny("caller override forbids certificates")
	}
	if len(ov.AllowedCertificates) > 0 && insp.CertificateCount > 0 {
		if len(ops.Certificates) == 0 {
			return deny("certificate kinds unavailable for caller override allowed_certificates")
		}
		for _, k := range ops.Certificates {
			if !contains(ov.AllowedCertificates, k) {
				return deny("certificate kind %q is not permitted by caller override", k)
			}
		}
	}
	if ov.ForbidMint && insp.HasMint {
		return deny("caller override forbids minting/burning")
	}
	if ov.ForbidWithdrawals && insp.WithdrawalCount > 0 {
		return deny("caller override forbids reward withdrawals")
	}
	if ov.ForbidVotes && insp.VotingProcedureCount > 0 {
		return deny("caller override forbids governance votes")
	}
	if (len(ov.AllowedVoterKinds) > 0 || len(ov.AllowedDrepIds) > 0) && insp.VotingProcedureCount > 0 {
		if len(ops.Voters) == 0 {
			return deny("voter details unavailable for caller override vote allow-list")
		}
		if d := gateVoters(ov.AllowedVoterKinds, ov.AllowedDrepIds, ops.Voters); !d.Allow {
			return d
		}
	}
	if ov.ForbidProposals && insp.ProposalProcedureCount > 0 {
		return deny("caller override forbids governance proposals")
	}
	if ov.ForbidTreasury && insp.HasTreasuryDonation {
		return deny("caller override forbids treasury donations")
	}
	return allow()
}

// EvaluateOpCert authorizes (or denies) an operational-certificate cold-signing
// request for the key identified by hash. Deny-by-default: a key may produce a
// cold signature over the OCertSignable bytes only when it has a policy entry
// that lists "opcert" in allowed_requests. Unlike tx/cip8 there is no bounded
// sub-policy: the KES vkey, issue counter, and KES period are operator-supplied
// values with no ledger-value semantics to constrain here.
func (e *Engine) EvaluateOpCert(hash backend.KeyHash) Decision {
	p, ok := e.byHash[hash]
	if !ok {
		return deny("no policy configured for key %s", hash)
	}
	if !p.allows("opcert") {
		return deny("key %s may not sign operational certificates", hash)
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
