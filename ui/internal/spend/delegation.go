package spend

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	apollo "github.com/blinklabs-io/apollo/v2"
	"github.com/blinklabs-io/bursa/ui/internal/chain"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

// VoteTarget is one of the four governance voting-power destinations a wallet
// can delegate to (CIP-1694). RegisterSelf additionally registers the wallet's
// own DRep credential and delegates its vote to itself.
type VoteTarget string

const (
	VoteAbstain      VoteTarget = "abstain"
	VoteNoConfidence VoteTarget = "no_confidence"
	VoteDRep         VoteTarget = "drep"
	VoteRegisterSelf VoteTarget = "register_self"
)

// Anchor is an optional governance metadata anchor (a URL plus the 32-byte
// blake2b-256 hash of the document it points to), attached to a self-DRep
// registration.
type Anchor struct {
	URL  string `json:"url"`
	Hash string `json:"hash"` // hex-encoded 32-byte blake2b-256 digest
}

// Vote selects a governance voting-power target for a delegation request.
type Vote struct {
	Type   VoteTarget `json:"type"`
	DRepID string     `json:"drep_id,omitempty"` // bech32 drep1…, when Type == VoteDRep
	Anchor *Anchor    `json:"anchor,omitempty"`  // optional, when Type == VoteRegisterSelf
}

// DelegationRequest is the caller-supplied parameters for a single
// staking/governance action. Any combination of fields may be set; the minimal
// certificate set is computed from the wallet's current on-chain state. A
// withdrawal-only request sets just Withdraw.
type DelegationRequest struct {
	PoolID   string `json:"pool_id,omitempty"` // omitted = leave stake delegation unchanged
	Vote     *Vote  `json:"vote,omitempty"`
	Withdraw bool   `json:"withdraw,omitempty"` // sweep withdrawable rewards
}

// CertKind tags an itemized certificate (or withdrawal) in the preview so the
// confirm screen can distinguish, e.g., the 2 ₳ stake deposit from the ~500 ₳
// DRep deposit.
type CertKind string

const (
	CertStakeRegistration CertKind = "stake_registration"
	CertStakeDelegation   CertKind = "stake_delegation"
	CertVoteDelegation    CertKind = "vote_delegation"
	CertDRepRegistration  CertKind = "drep_registration"
	CertWithdrawal        CertKind = "withdrawal"
)

// Cert is one itemized line in a DelegationPreview: a human-readable summary of
// a certificate (or withdrawal) plus, where applicable, the refundable deposit
// it locks (DepositLovelace) or the amount it moves (e.g. a withdrawal).
type Cert struct {
	Kind            CertKind `json:"kind"`
	Summary         string   `json:"summary"`
	DepositLovelace string   `json:"deposit_lovelace,omitempty"` // refundable deposit, decimal lovelace
	AmountLovelace  string   `json:"amount_lovelace,omitempty"`  // moved amount (withdrawal), decimal lovelace
}

// DelegationPreview is returned from BuildDelegation: the itemized certificate
// set plus the fee, total refundable deposit, withdrawal amount, and net total,
// all keyed by an opaque PendingID to pass to Confirm (the same Confirm the Send
// flow uses).
type DelegationPreview struct {
	PendingID  string `json:"pending_id"`
	Certs      []Cert `json:"certs"`
	Fee        string `json:"fee"`                  // decimal lovelace
	Deposit    string `json:"deposit"`              // total refundable deposit, decimal lovelace
	Withdrawal string `json:"withdrawal,omitempty"` // total withdrawn, decimal lovelace
	Total      string `json:"total"`                // net cost to the wallet (fee + deposits − withdrawals), decimal lovelace
}

// AccountState is the wallet's current on-chain staking/governance state, as
// needed to compute the minimal certificate set. It is populated from the node;
// a never-registered wallet has Registered == false.
type AccountState struct {
	Registered        bool          // stake key registered on chain
	CurrentPool       *string       // pool currently delegated to, nil if none
	CurrentDRep       *lcommon.Drep // governance vote target currently delegated to, nil if none
	OwnDRep           *lcommon.Drep // wallet's own DRep credential, for register_self planning
	OwnDRepRegistered bool          // wallet's own DRep credential is already registered on chain
}

// ProtocolParams holds the refundable deposit amounts the plan needs, parsed
// from the node's protocol parameters.
type ProtocolParams struct {
	KeyDeposit  uint64
	DRepDeposit uint64
}

// ErrNoChange is returned when the request asks for the wallet's current state:
// no certificates would be produced. The UI disables submit in this case.
var ErrNoChange = errors.New("requested state matches current state; nothing to do")

// chainQuerier is the slice of the Blockfrost chain client the delegation flow
// needs to verify pools/DReps and read account state + protocol params. It is an
// interface so tests can supply a fake. *chain.Client satisfies it.
type chainQuerier interface {
	Account(ctx context.Context, stakeAddr string) (chain.AccountInfo, error)
	AccountDRepID(ctx context.Context, stakeAddr string) (*string, error)
	Pool(ctx context.Context, poolID string) (chain.PoolInfo, error)
	DRep(ctx context.Context, drepID string) (chain.DRepInfo, error)
	ProtocolParams(ctx context.Context) (chain.ProtocolParams, error)
}

// SetChainQuerier attaches the node-backed query client used by the delegation
// flow (pool/DRep verification, account state, protocol params). It is separate
// from the apollo ChainContext (which builds/submits txs): pool, DRep, and
// protocol-parameter lookups go through the node's Blockfrost API. Passing nil
// disables delegation (BuildDelegation returns an error).
func (s *Service) SetChainQuerier(q chainQuerier) {
	s.mu.Lock()
	s.chainQ = q
	s.mu.Unlock()
}

func (s *Service) chainQuerierLocked() chainQuerier {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chainQ
}

// plan computes the minimal certificate set for req given the wallet's current
// on-chain state and the protocol deposits. It is pure (no I/O) and is the
// unit-tested heart of the delegation feature.
//
// Rules (per the design spec):
//   - stake key not registered and (pool or vote requested) → prepend stake
//     registration (+key deposit);
//   - pool_id set and differs from the current pool → stake-delegation cert;
//   - vote set and differs from the current vote target → vote-delegation cert;
//     register_self additionally registers the wallet's own DRep credential
//     (+drep deposit) only when it is not already registered;
//   - withdraw → a withdrawal line of the full withdrawable amount.
//
// Requesting exactly the current state yields no certs and ErrNoChange.
//
// withdrawable is the wallet's withdrawable rewards (decimal lovelace as the
// node reports it); it is only consulted when req.Withdraw is set.
func plan(current AccountState, req DelegationRequest, params ProtocolParams, withdrawable string) ([]Cert, error) {
	var certs []Cert

	wantPool := req.PoolID != ""
	wantVote := req.Vote != nil
	registerSelf := wantVote && req.Vote.Type == VoteRegisterSelf

	// A fresh wallet must register its stake key before it can delegate stake or
	// vote. (Withdrawal of rewards also implicitly requires registration, but a
	// never-registered wallet has no rewards, so we don't force it here.)
	if !current.Registered && (wantPool || wantVote) {
		certs = append(certs, Cert{
			Kind:            CertStakeRegistration,
			Summary:         "Register stake key",
			DepositLovelace: strconv.FormatUint(params.KeyDeposit, 10),
		})
	}

	// Stake delegation: only when a pool is requested AND it differs from the
	// current delegation (idempotent — re-delegating to the same pool is a no-op).
	if wantPool {
		changed := current.CurrentPool == nil || *current.CurrentPool != req.PoolID
		if changed {
			certs = append(certs, Cert{
				Kind:    CertStakeDelegation,
				Summary: "Delegate stake to " + req.PoolID,
			})
		}
	}

	// Vote delegation. register_self also registers the wallet's own DRep first,
	// but only when that DRep is not already registered. Re-selecting the current
	// vote target is a no-op, just like re-selecting the current pool.
	if wantVote {
		requestedDRep, err := requestedVoteDrep(current.OwnDRep, *req.Vote)
		if err != nil {
			return nil, err
		}
		voteChanged := current.CurrentDRep == nil || !drepEqual(*current.CurrentDRep, requestedDRep)
		if registerSelf {
			if err := validateAnchor(req.Vote.Anchor); err != nil {
				return nil, err
			}
			if !current.OwnDRepRegistered {
				cert := Cert{
					Kind:            CertDRepRegistration,
					Summary:         "Register self as a DRep",
					DepositLovelace: strconv.FormatUint(params.DRepDeposit, 10),
				}
				if completeAnchor(req.Vote.Anchor) {
					cert.Summary = "Register self as a DRep (with metadata anchor)"
				}
				certs = append(certs, cert)
			}
			if voteChanged {
				certs = append(certs, Cert{
					Kind:    CertVoteDelegation,
					Summary: "Delegate voting power to self",
				})
			}
		} else if voteChanged {
			summary, err := voteSummary(*req.Vote)
			if err != nil {
				return nil, err
			}
			certs = append(certs, Cert{Kind: CertVoteDelegation, Summary: summary})
		}
	}

	// Withdrawal of the full withdrawable amount.
	if req.Withdraw {
		amt, err := parseAmount(withdrawable)
		if err != nil || amt == 0 {
			return nil, fmt.Errorf("%w: no withdrawable rewards", ErrInvalidRequest)
		}
		certs = append(certs, Cert{
			Kind:           CertWithdrawal,
			Summary:        "Withdraw staking rewards",
			AmountLovelace: strconv.FormatUint(amt, 10),
		})
	}

	if len(certs) == 0 {
		return nil, ErrNoChange
	}
	return certs, nil
}

// voteSummary describes a non-register-self vote target for the preview, and
// validates that a specific DRep request carries a DRep ID.
func voteSummary(v Vote) (string, error) {
	switch v.Type {
	case VoteAbstain:
		return "Delegate voting power to Always Abstain", nil
	case VoteNoConfidence:
		return "Delegate voting power to Always No Confidence", nil
	case VoteDRep:
		if v.DRepID == "" {
			return "", fmt.Errorf("%w: drep_id required for a specific-DRep vote", ErrInvalidRequest)
		}
		return "Delegate voting power to " + v.DRepID, nil
	case VoteRegisterSelf:
		// voteSummary is only called for non-register-self targets; this path is
		// unreachable in normal flow but must be handled for exhaustive coverage.
		return "", fmt.Errorf("%w: use register_self path, not voteSummary", ErrInvalidRequest)
	default:
		return "", fmt.Errorf("%w: unknown vote target %q", ErrInvalidRequest, v.Type)
	}
}

func requestedVoteDrep(own *lcommon.Drep, v Vote) (lcommon.Drep, error) {
	switch v.Type {
	case VoteAbstain:
		return lcommon.Drep{Type: lcommon.DrepTypeAbstain}, nil
	case VoteNoConfidence:
		return lcommon.Drep{Type: lcommon.DrepTypeNoConfidence}, nil
	case VoteDRep:
		if v.DRepID == "" {
			return lcommon.Drep{}, fmt.Errorf("%w: drep_id required for a specific-DRep vote", ErrInvalidRequest)
		}
		return parseDRepTarget(v.DRepID)
	case VoteRegisterSelf:
		if own == nil {
			return lcommon.Drep{}, errors.New("wallet has no DRep credential derived")
		}
		return cloneDrep(*own), nil
	default:
		return lcommon.Drep{}, fmt.Errorf("%w: unknown vote target %q", ErrInvalidRequest, v.Type)
	}
}

func drepEqual(a, b lcommon.Drep) bool {
	return a.Type == b.Type && bytes.Equal(a.Credential, b.Credential)
}

func cloneDrep(d lcommon.Drep) lcommon.Drep {
	if d.Credential == nil {
		return d
	}
	out := d
	out.Credential = append([]byte(nil), d.Credential...)
	return out
}

func parseDRepTarget(id string) (lcommon.Drep, error) {
	trimmed := strings.TrimSpace(id)
	normalized := strings.ToLower(trimmed)
	switch normalized {
	case "drep_abstain", "drep_always_abstain", "drep-alwaysabstain":
		return lcommon.Drep{Type: lcommon.DrepTypeAbstain}, nil
	case "drep_no_confidence", "drep_always_no_confidence", "drep-alwaysnoconfidence":
		return lcommon.Drep{Type: lcommon.DrepTypeNoConfidence}, nil
	}
	if h, ok, err := prefixedDRepHash(trimmed, "drep-keyHash-"); ok || err != nil {
		if err != nil {
			return lcommon.Drep{}, err
		}
		return lcommon.Drep{Type: lcommon.DrepTypeAddrKeyHash, Credential: h}, nil
	}
	if h, ok, err := prefixedDRepHash(trimmed, "drep-scriptHash-"); ok || err != nil {
		if err != nil {
			return lcommon.Drep{}, err
		}
		return lcommon.Drep{Type: lcommon.DrepTypeScriptHash, Credential: h}, nil
	}
	if raw, err := hex.DecodeString(trimmed); err == nil && len(raw) == 28 {
		return lcommon.Drep{Type: lcommon.DrepTypeAddrKeyHash, Credential: raw}, nil
	}
	typ, hash, err := decodeDRepID(trimmed)
	if err != nil {
		return lcommon.Drep{}, err
	}
	return lcommon.Drep{Type: typ, Credential: hash}, nil
}

func prefixedDRepHash(id, prefix string) ([]byte, bool, error) {
	if !strings.HasPrefix(strings.ToLower(id), strings.ToLower(prefix)) {
		return nil, false, nil
	}
	h, err := hex.DecodeString(id[len(prefix):])
	if err != nil {
		return nil, true, fmt.Errorf("%w: invalid drep hash %q: %w", ErrInvalidRequest, id, err)
	}
	if len(h) != 28 {
		return nil, true, fmt.Errorf("%w: invalid drep hash %q: expected 28 bytes, got %d", ErrInvalidRequest, id, len(h))
	}
	return h, true, nil
}

// BuildDelegation queries the wallet's current on-chain state and protocol
// params, verifies any requested pool / DRep through the node, computes the
// minimal certificate set via plan(), builds the transaction with apollo
// (attaching certs + the withdrawal), stores it under a new pending id, and
// returns an itemized DelegationPreview. Confirm signs + submits it through the
// same path the Send flow uses.
func (s *Service) BuildDelegation(ctx context.Context, req DelegationRequest) (DelegationPreview, error) {
	walletID, acct, gen := s.currentBinding()
	if acct == nil {
		return DelegationPreview{}, ErrNoWallet
	}
	if len(acct.ReceiveAddresses) == 0 {
		return DelegationPreview{}, errors.New("account has no receive addresses")
	}
	q := s.chainQuerierLocked()
	if q == nil {
		return DelegationPreview{}, errors.New("no chain querier configured")
	}

	// --- gather current state + protocol params ---
	state, withdrawable, err := s.accountState(ctx, q, acct.StakeAddress)
	if err != nil {
		return DelegationPreview{}, err
	}
	pp, err := q.ProtocolParams(ctx)
	if err != nil {
		return DelegationPreview{}, fmt.Errorf("protocol params: %w", err)
	}
	params, err := toPlanParams(pp)
	if err != nil {
		return DelegationPreview{}, err
	}
	if registerSelf := req.Vote != nil && req.Vote.Type == VoteRegisterSelf; registerSelf {
		own, err := drepFromHex(acct.DRepKeyHash)
		if err != nil {
			return DelegationPreview{}, err
		}
		state.OwnDRep = own
		registered, err := s.ownDRepRegistered(ctx, q, *own)
		if err != nil {
			return DelegationPreview{}, err
		}
		state.OwnDRepRegistered = registered
	}

	// --- verify any requested pool / DRep through the node (consent law: no
	// external call — the embedded node confirms existence) ---
	if req.PoolID != "" {
		if _, err := q.Pool(ctx, req.PoolID); err != nil {
			if errors.Is(err, chain.ErrNotFound) {
				return DelegationPreview{}, fmt.Errorf("%w: pool %q not found by your node", ErrInvalidRequest, req.PoolID)
			}
			return DelegationPreview{}, fmt.Errorf("verify pool: %w", err)
		}
	}
	if req.Vote != nil && req.Vote.Type == VoteDRep {
		if req.Vote.DRepID == "" {
			return DelegationPreview{}, fmt.Errorf("%w: drep_id required for a specific-DRep vote", ErrInvalidRequest)
		}
		if _, err := q.DRep(ctx, req.Vote.DRepID); err != nil {
			if errors.Is(err, chain.ErrNotFound) {
				return DelegationPreview{}, fmt.Errorf("%w: DRep %q not found by your node", ErrInvalidRequest, req.Vote.DRepID)
			}
			return DelegationPreview{}, fmt.Errorf("verify drep: %w", err)
		}
	}

	// --- compute the minimal certificate set (pure) ---
	certs, err := plan(state, req, params, withdrawable)
	if err != nil {
		return DelegationPreview{}, err
	}

	// --- build the transaction with apollo ---
	a, utxoAddr, err := s.buildDelegationTx(ctx, acct, req, certs, params)
	if err != nil {
		return DelegationPreview{}, err
	}

	id := s.mkID()
	s.mu.Lock()
	if s.gen != gen || s.walletID != walletID {
		s.mu.Unlock()
		return DelegationPreview{}, ErrWalletChanged
	}
	s.sweepExpiredLocked()
	// Bind the pending delegation tx to the active wallet so Confirm decrypts the
	// correct seed (vault model) and has the account for address-index lookup.
	s.pending[id] = &pending{
		tx:        a,
		utxoAddr:  utxoAddr,
		created:   s.now(),
		walletID:  walletID,
		account:   acct,
		certKinds: certKindsFrom(certs),
	}
	s.mu.Unlock()

	return toDelegationPreview(id, a, certs), nil
}

// certKindsFrom extracts the set of CertKind values from the computed cert list.
func certKindsFrom(certs []Cert) []CertKind {
	kinds := make([]CertKind, len(certs))
	for i, c := range certs {
		kinds[i] = c.Kind
	}
	return kinds
}

// accountState reads the wallet's stake registration + current pool, plus its
// withdrawable rewards, from the node. A never-seen account (ErrNotFound) is an
// unregistered wallet with no rewards.
func (s *Service) accountState(ctx context.Context, q chainQuerier, stakeAddr string) (AccountState, string, error) {
	info, err := q.Account(ctx, stakeAddr)
	if errors.Is(err, chain.ErrNotFound) {
		return AccountState{Registered: false}, "0", nil
	}
	if err != nil {
		return AccountState{}, "", fmt.Errorf("account state: %w", err)
	}
	withdrawable := info.WithdrawableAmount
	if withdrawable == "" {
		withdrawable = "0"
	}
	state := AccountState{Registered: info.Registered || info.Active, CurrentPool: info.PoolID}
	drepID := info.DRepID
	if drepID == nil || *drepID == "" {
		drepID, err = q.AccountDRepID(ctx, stakeAddr)
		if err != nil {
			return AccountState{}, "", fmt.Errorf("account drep_id: %w", err)
		}
	}
	if drepID != nil && *drepID != "" {
		drep, err := parseDRepTarget(*drepID)
		if err != nil {
			return AccountState{}, "", fmt.Errorf("account drep_id: %w", err)
		}
		state.CurrentDRep = &drep
	}
	return state, withdrawable, nil
}

func drepFromHex(hashHex string) (*lcommon.Drep, error) {
	if hashHex == "" {
		return nil, errors.New("wallet has no DRep credential derived")
	}
	b, err := hex.DecodeString(hashHex)
	if err != nil {
		return nil, fmt.Errorf("drep key hash: %w", err)
	}
	if len(b) != 28 {
		return nil, fmt.Errorf("drep key hash: expected 28 bytes, got %d", len(b))
	}
	return &lcommon.Drep{Type: lcommon.DrepTypeAddrKeyHash, Credential: b}, nil
}

func (s *Service) ownDRepRegistered(ctx context.Context, q chainQuerier, own lcommon.Drep) (bool, error) {
	ids := []string{own.String()}
	if len(own.Credential) == 28 {
		ids = append(ids, hex.EncodeToString(own.Credential))
	}
	var firstErr error
	for _, id := range ids {
		info, err := q.DRep(ctx, id)
		if errors.Is(err, chain.ErrNotFound) {
			continue
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return info.Registered, nil
	}
	if firstErr != nil {
		return false, fmt.Errorf("verify own DRep: %w", firstErr)
	}
	return false, nil
}

// toPlanParams parses the node's deposit strings into the uint64 amounts plan()
// needs. drep_deposit is null in pre-Conway eras; it defaults to 0 (a self-DRep
// registration would then fail at the node, which is the correct behavior).
func toPlanParams(pp chain.ProtocolParams) (ProtocolParams, error) {
	key, err := parseAmount(pp.KeyDeposit)
	if err != nil {
		return ProtocolParams{}, fmt.Errorf("%w: key_deposit %q", ErrInvalidRequest, pp.KeyDeposit)
	}
	var drep uint64
	if pp.DRepDeposit != nil && *pp.DRepDeposit != "" {
		drep, err = parseAmount(*pp.DRepDeposit)
		if err != nil {
			return ProtocolParams{}, fmt.Errorf("%w: drep_deposit %q", ErrInvalidRequest, *pp.DRepDeposit)
		}
	}
	return ProtocolParams{KeyDeposit: key, DRepDeposit: drep}, nil
}

// buildDelegationTx constructs and completes the apollo transaction for the
// computed certificate set. It loads the wallet's UTxOs (so coin selection can
// fund the deposits + fee), attaches each certificate keyed by the wallet's
// stake credential, attaches the withdrawal to the stake address, and runs
// Complete (which auto-accounts the deposits). It returns the completed builder
// and the txref→address map Confirm uses to sign.
func (s *Service) buildDelegationTx(
	ctx context.Context,
	acct *wallet.Account,
	req DelegationRequest,
	certs []Cert,
	params ProtocolParams,
) (*apollo.Apollo, map[string]string, error) {
	changeAddr, err := lcommon.NewAddress(acct.ReceiveAddresses[0])
	if err != nil {
		return nil, nil, fmt.Errorf("change address: %w", err)
	}
	stakeAddr, err := lcommon.NewAddress(acct.StakeAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("stake address: %w", err)
	}
	stakeCred, err := lcommon.NewAddress(acct.ReceiveAddresses[0])
	if err != nil {
		return nil, nil, fmt.Errorf("base address: %w", err)
	}
	// The wallet's stake credential, derived from any base (receive) address: all
	// receive addresses share the canonical stake key, so the stake key hash is
	// the credential for every certificate.
	stakeKeyHash := stakeCred.StakeKeyHash()
	cred := lcommon.Credential{
		CredType:   lcommon.CredentialTypeAddrKeyHash,
		Credential: stakeKeyHash,
	}

	var loaded []lcommon.Utxo
	utxoAddr := make(map[string]string)
	for _, addrStr := range acct.ReceiveAddresses {
		addr, err := lcommon.NewAddress(addrStr)
		if err != nil {
			return nil, nil, fmt.Errorf("address %q: %w", addrStr, err)
		}
		utxos, err := s.chain.Utxos(ctx, addr)
		if err != nil {
			return nil, nil, fmt.Errorf("utxos for %s: %w", addrStr, err)
		}
		if len(utxos) > 0 {
			loaded = append(loaded, utxos...)
			for _, u := range utxos {
				utxoAddr[makeUtxoRef(u)] = addrStr
			}
		}
	}

	certSigners, err := delegationCertRequiredSigners(certs, stakeKeyHash, acct)
	if err != nil {
		return nil, nil, err
	}

	var a *apollo.Apollo
	var paymentSigners []lcommon.Blake2b224
	maxAttempts := len(acct.ReceiveAddresses) + 2
	for attempt := 0; attempt < maxAttempts; attempt++ {
		next := apollo.New(s.chain).
			SetWallet(apollo.NewExternalWallet(changeAddr)).
			SetChangeAddress(changeAddr).
			SetFeePadding(feePaddingLovelace).
			AddLoadedUTxOs(loaded...)
		for _, kh := range appendKeyHashes(nil, certSigners, paymentSigners) {
			next = next.AddRequiredSigner(kh)
		}
		next, err = s.applyDelegationTx(next, req, certs, params, stakeAddr, cred)
		if err != nil {
			return nil, nil, err
		}

		next, err = next.CompleteContext(ctx)
		if err != nil {
			if isInsufficientFundsError(err) {
				return nil, nil, fmt.Errorf("%w: %w", ErrInsufficientFunds, err)
			}
			return nil, nil, fmt.Errorf("complete transaction: %w", err)
		}

		tx := next.GetTx()
		if tx == nil {
			return nil, nil, errors.New("completed tx is nil")
		}
		actualPaymentSigners, err := requiredPaymentKeyHashesForInputs(tx.Body.Inputs(), utxoAddr)
		if err != nil {
			return nil, nil, err
		}
		if sameKeyHashSet(paymentSigners, actualPaymentSigners) {
			a = next
			break
		}
		paymentSigners = actualPaymentSigners
	}
	if a == nil {
		return nil, nil, errors.New("delegation required signer set did not converge")
	}
	return a, utxoAddr, nil
}

// applyDelegationTx applies each computed certificate/withdrawal to a fresh
// Apollo builder. The discrete certs keep the apollo calls one-to-one with the
// itemized preview.
func (s *Service) applyDelegationTx(
	a *apollo.Apollo,
	req DelegationRequest,
	certs []Cert,
	params ProtocolParams,
	stakeAddr lcommon.Address,
	cred lcommon.Credential,
) (*apollo.Apollo, error) {
	var err error
	for _, c := range certs {
		switch c.Kind {
		case CertStakeRegistration:
			a, err = a.RegisterStake(&cred)
			if err != nil {
				return nil, fmt.Errorf("register stake: %w", err)
			}
		case CertStakeDelegation:
			poolHash, err := poolKeyHash(req.PoolID)
			if err != nil {
				return nil, err
			}
			a, err = a.DelegateStake(&cred, poolHash)
			if err != nil {
				return nil, fmt.Errorf("delegate stake: %w", err)
			}
		case CertDRepRegistration:
			drepCred, anchor, err := s.selfDRepCredential(req)
			if err != nil {
				return nil, err
			}
			a = a.RegisterDRep(drepCred, int64(params.DRepDeposit), anchor) //nolint:gosec // deposit from node params
		case CertVoteDelegation:
			drep, err := s.voteDrep(req)
			if err != nil {
				return nil, err
			}
			a, err = a.DelegateVote(&cred, drep)
			if err != nil {
				return nil, fmt.Errorf("delegate vote: %w", err)
			}
		case CertWithdrawal:
			amt, err := parseAmount(c.AmountLovelace)
			if err != nil {
				return nil, fmt.Errorf("%w: withdrawal amount", ErrInvalidRequest)
			}
			a = a.AddWithdrawal(stakeAddr, amt, nil, nil)
		}
	}
	return a, nil
}

func delegationCertRequiredSigners(
	certs []Cert,
	stakeKeyHash lcommon.Blake2b224,
	acct *wallet.Account,
) ([]lcommon.Blake2b224, error) {
	var signers []lcommon.Blake2b224
	for _, c := range certs {
		switch c.Kind {
		case CertStakeRegistration, CertStakeDelegation, CertVoteDelegation, CertWithdrawal:
			if stakeKeyHash == (lcommon.Blake2b224{}) {
				return nil, errors.New("stake credential is missing")
			}
			signers = appendKeyHashes(signers, []lcommon.Blake2b224{stakeKeyHash})
		case CertDRepRegistration:
			drep, err := drepFromHex(acct.DRepKeyHash)
			if err != nil {
				return nil, err
			}
			signers = appendKeyHashes(signers, []lcommon.Blake2b224{lcommon.NewBlake2b224(drep.Credential)})
		}
	}
	return signers, nil
}

func appendKeyHashes(dst []lcommon.Blake2b224, sets ...[]lcommon.Blake2b224) []lcommon.Blake2b224 {
	seen := make(map[lcommon.Blake2b224]bool, len(dst))
	for _, kh := range dst {
		seen[kh] = true
	}
	for _, set := range sets {
		for _, kh := range set {
			if seen[kh] {
				continue
			}
			seen[kh] = true
			dst = append(dst, kh)
		}
	}
	return dst
}

// poolKeyHash decodes a bech32 pool1… ID into the 28-byte pool key hash apollo's
// DelegateStake expects.
func poolKeyHash(poolID string) (lcommon.Blake2b224, error) {
	pid, err := lcommon.NewPoolIdFromBech32(poolID)
	if err != nil {
		return lcommon.Blake2b224{}, fmt.Errorf("%w: invalid pool id %q: %w", ErrInvalidRequest, poolID, err)
	}
	return lcommon.Blake2b224(pid), nil
}

// voteDrep maps a vote request to apollo's Drep argument: the predefined Always
// Abstain / Always No Confidence variants, a specific DRep by its decoded key/
// script hash, or — for register_self — the wallet's own DRep key-hash
// credential.
func (s *Service) voteDrep(req DelegationRequest) (lcommon.Drep, error) {
	if req.Vote == nil {
		return lcommon.Drep{}, fmt.Errorf("%w: no vote target", ErrInvalidRequest)
	}
	switch req.Vote.Type {
	case VoteAbstain:
		return lcommon.Drep{Type: lcommon.DrepTypeAbstain}, nil
	case VoteNoConfidence:
		return lcommon.Drep{Type: lcommon.DrepTypeNoConfidence}, nil
	case VoteDRep:
		typ, hash, err := decodeDRepID(req.Vote.DRepID)
		if err != nil {
			return lcommon.Drep{}, err
		}
		return lcommon.Drep{Type: typ, Credential: hash}, nil
	case VoteRegisterSelf:
		hash, err := s.selfDRepKeyHash()
		if err != nil {
			return lcommon.Drep{}, err
		}
		return lcommon.Drep{Type: lcommon.DrepTypeAddrKeyHash, Credential: hash}, nil
	default:
		return lcommon.Drep{}, fmt.Errorf("%w: unknown vote target %q", ErrInvalidRequest, req.Vote.Type)
	}
}

// selfDRepCredential returns the wallet's own DRep credential (key hash) and the
// optional metadata anchor for a self-DRep registration.
func (s *Service) selfDRepCredential(req DelegationRequest) (lcommon.Credential, *lcommon.GovAnchor, error) {
	hash, err := s.selfDRepKeyHash()
	if err != nil {
		return lcommon.Credential{}, nil, err
	}
	cred := lcommon.Credential{
		CredType:   lcommon.CredentialTypeAddrKeyHash,
		Credential: lcommon.NewBlake2b224(hash),
	}
	var anchor *lcommon.GovAnchor
	if req.Vote != nil {
		if err := validateAnchor(req.Vote.Anchor); err != nil {
			return lcommon.Credential{}, nil, err
		}
	}
	if req.Vote != nil && completeAnchor(req.Vote.Anchor) {
		ga, err := buildAnchor(*req.Vote.Anchor)
		if err != nil {
			return lcommon.Credential{}, nil, err
		}
		anchor = &ga
	}
	return cred, anchor, nil
}

func completeAnchor(a *Anchor) bool {
	return a != nil && a.URL != "" && a.Hash != ""
}

func validateAnchor(a *Anchor) error {
	if a == nil {
		return nil
	}
	if (a.URL == "") != (a.Hash == "") {
		return fmt.Errorf("%w: anchor url and hash must both be provided", ErrInvalidRequest)
	}
	return nil
}

// selfDRepKeyHash returns the wallet's own DRep verification-key hash (CIP-0105,
// derivation role 3). It is the public credential carried on the derived
// account (wallet.Derive populates DRepKeyHash), so it needs no password at
// build time — building a self-DRep registration only requires the public key
// hash; the actual signing key is derived from the mnemonic at Confirm time.
func (s *Service) selfDRepKeyHash() ([]byte, error) {
	acct := s.currentAccount()
	if acct == nil {
		return nil, ErrNoWallet
	}
	drep, err := drepFromHex(acct.DRepKeyHash)
	if err != nil {
		return nil, err
	}
	return cloneDrep(*drep).Credential, nil
}

// buildAnchor converts a request Anchor into a gouroboros GovAnchor, validating
// the 32-byte hex hash.
func buildAnchor(a Anchor) (lcommon.GovAnchor, error) {
	hashBytes, err := hexDecode32(a.Hash)
	if err != nil {
		return lcommon.GovAnchor{}, fmt.Errorf("%w: anchor hash: %w", ErrInvalidRequest, err)
	}
	ga, err := lcommon.NewGovAnchor(a.URL, hashBytes)
	if err != nil {
		return lcommon.GovAnchor{}, fmt.Errorf("%w: anchor: %w", ErrInvalidRequest, err)
	}
	return ga, nil
}

// toDelegationPreview assembles the itemized preview from the computed certs and
// the completed apollo tx (for the fee). Deposit is the sum of every cert's
// refundable deposit; Withdrawal is the sum of withdrawal lines; Total is the
// net cost to the wallet (fee + deposits − withdrawals).
func toDelegationPreview(id string, a *apollo.Apollo, certs []Cert) DelegationPreview {
	var fee uint64
	if tx := a.GetTx(); tx != nil {
		fee = tx.Body.TxFee
	}
	deposit := new(big.Int)
	withdrawal := new(big.Int)
	for _, c := range certs {
		if c.DepositLovelace != "" {
			if v, ok := new(big.Int).SetString(c.DepositLovelace, 10); ok {
				deposit.Add(deposit, v)
			}
		}
		if c.AmountLovelace != "" && c.Kind == CertWithdrawal {
			if v, ok := new(big.Int).SetString(c.AmountLovelace, 10); ok {
				withdrawal.Add(withdrawal, v)
			}
		}
	}
	// total = fee + deposit − withdrawal
	total := new(big.Int).SetUint64(fee)
	total.Add(total, deposit)
	total.Sub(total, withdrawal)

	pv := DelegationPreview{
		PendingID: id,
		Certs:     certs,
		Fee:       strconv.FormatUint(fee, 10),
		Deposit:   deposit.String(),
		Total:     total.String(),
	}
	if withdrawal.Sign() > 0 {
		pv.Withdrawal = withdrawal.String()
	}
	return pv
}

// hexDecode32 decodes a 32-byte hex string (a blake2b-256 digest).
func hexDecode32(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	return b, nil
}

// decodeDRepID decodes a bech32 drep1… identifier into apollo's Drep type tag
// (key-hash vs script-hash) and the 28-byte credential hash. It accepts both the
// legacy CIP-0105 form (28-byte payload, key hash) and the CIP-0129 form (a
// 1-byte header followed by the 28-byte hash, where the header's low nibble is
// 2 for a key hash or 3 for a script hash). This is purely client-side bech32
// validation + decoding — no node call — so it works even if the node cannot
// resolve the DRep; the node's separate existence check (DRep()) provides the
// "not found by your node" signal.
func decodeDRepID(drepID string) (typ int, hash []byte, err error) {
	hrp, data5, derr := bech32.DecodeNoLimit(drepID)
	if derr != nil {
		return 0, nil, fmt.Errorf("%w: invalid drep id %q: %w", ErrInvalidRequest, drepID, derr)
	}
	if hrp != "drep" {
		return 0, nil, fmt.Errorf("%w: drep id %q has prefix %q, want drep", ErrInvalidRequest, drepID, hrp)
	}
	raw, derr := bech32.ConvertBits(data5, 5, 8, false)
	if derr != nil {
		return 0, nil, fmt.Errorf("%w: drep id %q: %w", ErrInvalidRequest, drepID, derr)
	}
	switch len(raw) {
	case 28:
		// Legacy CIP-0105: bare 28-byte key hash.
		return lcommon.DrepTypeAddrKeyHash, raw, nil
	case 29:
		// CIP-0129: 1-byte header + 28-byte hash. Low nibble: 2 = key, 3 = script.
		switch raw[0] & 0x0f {
		case 0x02:
			return lcommon.DrepTypeAddrKeyHash, raw[1:], nil
		case 0x03:
			return lcommon.DrepTypeScriptHash, raw[1:], nil
		default:
			return 0, nil, fmt.Errorf("%w: drep id %q has unrecognized header 0x%02x", ErrInvalidRequest, drepID, raw[0])
		}
	default:
		return 0, nil, fmt.Errorf("%w: drep id %q decodes to %d bytes, want 28 or 29", ErrInvalidRequest, drepID, len(raw))
	}
}
