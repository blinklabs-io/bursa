package wallet

import (
	"context"
	"errors"
	"sync"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
)

// ErrNoWallet is returned by query methods when no wallet has been loaded.
var ErrNoWallet = errors.New("no wallet set")

// chainQuerier is the slice of the chain client the service needs (satisfied
// by *chain.Client); it exists so tests can supply a fake.
type chainQuerier interface {
	Account(ctx context.Context, stakeAddr string) (chain.AccountInfo, error)
	AccountAddresses(ctx context.Context, stakeAddr string) ([]string, error)
	AddressUTxOs(ctx context.Context, addr string) ([]chain.UTxO, error)
	AddressTransactions(ctx context.Context, addr string) ([]chain.AddressTx, error)
	Transaction(ctx context.Context, hash string) (chain.TxInfo, error)
	TransactionUTxOs(ctx context.Context, hash string) (chain.TxUTxOs, error)
	LatestBlock(ctx context.Context) (chain.BlockTip, error)
}

// AddressView is the receive-address view: the derived window, the chain-seen
// (used) addresses, and the next unused derived address. NextUnused is empty
// when every address in the derived window is already used on chain (dynamic
// gap-limit expansion is deferred to a later phase).
type AddressView struct {
	Receive    []string `json:"receive"`
	Used       []string `json:"used"`
	NextUnused string   `json:"next_unused"`
}

// DelegationView is the delegation/rewards summary. Rewards are provisional —
// dingo has open reward-accounting bugs (#2373–#2376).
type DelegationView struct {
	PoolID       *string `json:"pool_id"`
	Active       bool    `json:"active"`
	RewardsSum   string  `json:"rewards_sum"`
	Withdrawable string  `json:"withdrawable_amount"`
	Provisional  bool    `json:"provisional"`
	Note         string  `json:"note"`
}

// Service holds the active read-only account and queries the chain for views.
type Service struct {
	chain chainQuerier

	mu      sync.RWMutex
	account *Account
}

// NewService builds a wallet service over the given chain querier.
func NewService(c chainQuerier) *Service {
	return &Service{chain: c}
}

func cloneAccount(acct *Account) *Account {
	if acct == nil {
		return nil
	}
	return &Account{
		Network:          acct.Network,
		StakeAddress:     acct.StakeAddress,
		ReceiveAddresses: cloneStringSlice(acct.ReceiveAddresses),
		DRepKeyHash:      acct.DRepKeyHash,
		ChangeAddresses:  cloneStringSlice(acct.ChangeAddresses),
	}
}

func cloneStringSlice(in []string) []string {
	if in == nil {
		return nil
	}
	return append([]string(nil), in...)
}

// SetWallet derives and stores the active account (windowN receive addresses).
func (s *Service) SetWallet(mnemonic, network string, windowN int) (*Account, error) {
	acct, err := Derive(mnemonic, network, windowN)
	if err != nil {
		return nil, err
	}
	if err := s.SetAccount(acct); err != nil {
		return nil, err
	}
	return cloneAccount(acct), nil
}

// SetAccount stores an already-derived active account. Passing nil clears the
// active account, used when the vault is locked or the active wallet is removed.
func (s *Service) SetAccount(acct *Account) error {
	if acct == nil {
		s.mu.Lock()
		s.account = nil
		s.mu.Unlock()
		return nil
	}
	stored := cloneAccount(acct)
	s.mu.Lock()
	s.account = stored
	s.mu.Unlock()
	return nil
}

func (s *Service) currentAccount() (*Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.account == nil {
		return nil, ErrNoWallet
	}
	return cloneAccount(s.account), nil
}

// scanAddresses returns the addresses to query for funds and history: the
// node-reported account addresses (used/change addresses, available once the
// stake key is registered on chain) unioned with the wallet's derived receive
// addresses. The derived set is essential — a self-sovereign wallet whose stake
// key is not yet registered on chain gets a 404 (ErrNotFound) from the node's
// account index, but it still holds funds at its derived receive addresses. The
// account-reported set still matters once registered: it surfaces used/change
// addresses outside the derived receive window.
func (s *Service) scanAddresses(ctx context.Context, acct *Account) ([]string, error) {
	discovered, err := s.chain.AccountAddresses(ctx, acct.StakeAddress)
	if err != nil && !errors.Is(err, chain.ErrNotFound) {
		return nil, err
	}
	seen := make(map[string]bool, len(discovered)+len(acct.ReceiveAddresses))
	out := make([]string, 0, len(discovered)+len(acct.ReceiveAddresses))
	for _, a := range append(discovered, acct.ReceiveAddresses...) {
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out, nil
}

// Balance aggregates the UTxO set across the account's addresses (chain-seen and
// derived; see scanAddresses).
func (s *Service) Balance(ctx context.Context) (Balance, error) {
	acct, err := s.currentAccount()
	if err != nil {
		return Balance{}, err
	}
	addrs, err := s.scanAddresses(ctx, acct)
	if err != nil {
		return Balance{}, err
	}
	var all []chain.UTxO
	for _, a := range addrs {
		us, err := s.chain.AddressUTxOs(ctx, a)
		if errors.Is(err, chain.ErrNotFound) {
			continue
		}
		if err != nil {
			return Balance{}, err
		}
		all = append(all, us...)
	}
	return AggregateBalance(all)
}

// Addresses reports the derived receive window, the chain-seen used addresses,
// and the first derived address not yet seen on chain.
func (s *Service) Addresses(ctx context.Context) (AddressView, error) {
	acct, err := s.currentAccount()
	if err != nil {
		return AddressView{}, err
	}
	used, err := s.chain.AccountAddresses(ctx, acct.StakeAddress)
	if err != nil && !errors.Is(err, chain.ErrNotFound) {
		return AddressView{}, err
	}
	// ErrNotFound: no chain-seen addresses yet → used stays empty; NextUnused is receive[0].
	usedSet := map[string]bool{}
	for _, a := range used {
		usedSet[a] = true
	}
	receive := cloneStringSlice(acct.ReceiveAddresses)
	next := ""
	for _, a := range receive {
		if !usedSet[a] {
			next = a
			break
		}
	}
	return AddressView{Receive: receive, Used: cloneStringSlice(used), NextUnused: next}, nil
}

// Transactions returns the merged, newest-first history across the account's
// chain-seen and derived addresses, enriched with each transaction's
// direction, net ADA/asset deltas, fee, and confirmation count relative to
// the wallet's own addresses. Enrichment is node-only: it queries the node's
// tx and tx/utxos endpoints and diffs the result against the wallet's own
// addresses — no third-party indexer is involved.
func (s *Service) Transactions(ctx context.Context) ([]Tx, error) {
	acct, err := s.currentAccount()
	if err != nil {
		return nil, err
	}
	addrs, err := s.scanAddresses(ctx, acct)
	if err != nil {
		return nil, err
	}
	var per [][]chain.AddressTx
	for _, a := range addrs {
		ts, err := s.chain.AddressTransactions(ctx, a)
		if errors.Is(err, chain.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		per = append(per, ts)
	}
	merged := MergeTransactions(per)
	if len(merged) == 0 {
		return merged, nil
	}

	// A tip-lookup failure must not fail the whole history — the merged list
	// (and each tx's own enrichment) is still valid; only the confirmation
	// count relative to the tip is unknowable. Degrade to "pending" (0
	// confirmations) for every entry rather than discarding the list.
	tip, tipErr := s.chain.LatestBlock(ctx)
	mine := ownerSet(addrs, acct)
	for i := range merged {
		if tipErr != nil {
			merged[i].Confirmations, merged[i].Pending = 0, true
		} else {
			merged[i].Confirmations, merged[i].Pending = txConfirmations(tip.Height, merged[i].BlockHeight)
		}
		if err := s.enrichTx(ctx, &merged[i], mine); err != nil {
			return nil, err
		}
	}
	return merged, nil
}

// enrichTx fills in a Tx's direction/net-amount/fee fields by querying the
// node for the transaction's summary and inputs+outputs. A transaction the
// node no longer has a record of (e.g. pruned under the lean-node
// history-expiry setting) is left with its basic fields only — set by the
// caller before enrichTx runs — rather than failing the whole history.
func (s *Service) enrichTx(ctx context.Context, tx *Tx, mine map[string]bool) error {
	info, err := s.chain.Transaction(ctx, tx.TxHash)
	if errors.Is(err, chain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	// The fee is already known once the tx summary comes back; set it now so
	// it survives even if the UTxO-detail call below fails or is pruned
	// (lean-node history-expiry can drop UTxO detail on a tx whose summary
	// is still retained).
	tx.Fee = feeOrZero(info.Fees)
	utxos, err := s.chain.TransactionUTxOs(ctx, tx.TxHash)
	if errors.Is(err, chain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	direction, netLovelace, deltas, err := computeTxDelta(utxos.Inputs, utxos.Outputs, mine)
	if err != nil {
		return err
	}
	tx.Direction = direction
	tx.NetLovelace = netLovelace
	tx.AssetDeltas = deltas
	return nil
}

// TransactionDetail returns the drill-down view of a single transaction: its
// enriched summary (direction/net-amount/fee/confirmations) plus the full
// input/output breakdown, each entry marked as belonging to the active
// wallet's own addresses or not. Node-only, like Transactions.
func (s *Service) TransactionDetail(ctx context.Context, hash string) (TxDetail, error) {
	acct, err := s.currentAccount()
	if err != nil {
		return TxDetail{}, err
	}
	addrs, err := s.scanAddresses(ctx, acct)
	if err != nil {
		return TxDetail{}, err
	}
	mine := ownerSet(addrs, acct)

	info, err := s.chain.Transaction(ctx, hash)
	if err != nil {
		return TxDetail{}, err
	}
	utxos, err := s.chain.TransactionUTxOs(ctx, hash)
	if err != nil {
		return TxDetail{}, err
	}
	// A tip-lookup failure must not turn a found transaction into a 404 (serve()
	// maps chain.ErrNotFound to 404, which would otherwise misreport a tx that
	// genuinely exists purely because the tip call failed). Degrade to
	// "pending" (0 confirmations) instead of propagating the tip error.
	tip, tipErr := s.chain.LatestBlock(ctx)

	direction, netLovelace, deltas, err := computeTxDelta(utxos.Inputs, utxos.Outputs, mine)
	if err != nil {
		return TxDetail{}, err
	}
	inputs, err := toTxIOs(utxos.Inputs, mine)
	if err != nil {
		return TxDetail{}, err
	}
	outputs, err := toTxIOs(utxos.Outputs, mine)
	if err != nil {
		return TxDetail{}, err
	}
	var confirmations uint64
	var pending bool
	if tipErr != nil {
		confirmations, pending = 0, true
	} else {
		confirmations, pending = txConfirmations(tip.Height, info.BlockHeight)
	}

	return TxDetail{
		Tx: Tx{
			TxHash:        hash,
			TxIndex:       info.Index,
			BlockHeight:   info.BlockHeight,
			BlockTime:     info.BlockTime,
			Direction:     direction,
			NetLovelace:   netLovelace,
			AssetDeltas:   deltas,
			Fee:           feeOrZero(info.Fees),
			Confirmations: confirmations,
			Pending:       pending,
		},
		Inputs:  inputs,
		Outputs: outputs,
	}, nil
}

// feeOrZero normalizes an empty fee string (the node omits it in edge cases)
// to "0" so callers always see a valid decimal string.
func feeOrZero(fee string) string {
	if fee == "" {
		return "0"
	}
	return fee
}

// toAddrSet builds a membership set from an address list, for O(1) "is this
// address mine" checks during transaction-delta computation.
func toAddrSet(addrs []string) map[string]bool {
	set := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		set[a] = true
	}
	return set
}

// ownerSet builds the "is this address mine" membership set used to classify
// a transaction's direction and net amount. It is deliberately wider than
// addrs (the set scanAddresses returns for querying history): it also
// includes the account's locally-derived change addresses, which the node's
// account index may not report yet (e.g. before the stake key is registered,
// or before the node has seen a spend from them) but which the wallet still
// controls. Excluding them would misclassify a wallet-owned change output as
// external and skew direction/net-amount for spends that touch such an
// address.
func ownerSet(addrs []string, acct *Account) map[string]bool {
	return toAddrSet(append(addrs, acct.ChangeAddresses...))
}

// Delegation returns the current delegation/rewards summary (provisional).
func (s *Service) Delegation(ctx context.Context) (DelegationView, error) {
	acct, err := s.currentAccount()
	if err != nil {
		return DelegationView{}, err
	}
	info, err := s.chain.Account(ctx, acct.StakeAddress)
	if err != nil && !errors.Is(err, chain.ErrNotFound) {
		return DelegationView{}, err
	}
	if errors.Is(err, chain.ErrNotFound) {
		info.RewardsSum = "0"
		info.WithdrawableAmount = "0"
	}
	// ErrNotFound: account not seen on chain → zero info (not active, not delegating).
	return DelegationView{
		PoolID:       info.PoolID,
		Active:       info.Active,
		RewardsSum:   info.RewardsSum,
		Withdrawable: info.WithdrawableAmount,
		Provisional:  true,
		Note:         "rewards are provisional; dingo reward accounting has open issues (#2373-#2376)",
	}, nil
}
