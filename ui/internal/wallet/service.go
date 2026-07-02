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
// chain-seen and derived addresses.
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
	return MergeTransactions(per), nil
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
