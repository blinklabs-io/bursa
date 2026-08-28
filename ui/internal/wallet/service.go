package wallet

import (
	"context"
	"errors"
	"sync"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
)

// ErrNoWallet is returned by query methods when no wallet has been loaded.
var ErrNoWallet = errors.New("no wallet set")

const maxConcurrentTxEnrichments = 4

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
	AccountRewards(ctx context.Context, stakeAddr string) ([]chain.Reward, error)
}

// AddressView is the receive-address view: the derived window, the chain-seen
// (used) addresses, and the next unused derived address. UsageKnown is false
// when the node was not queried; in that state Used and NextUnused must not be
// interpreted as evidence that an address is unused. When usage is known,
// NextUnused is empty only if every address in the derived window is already
// used on chain (dynamic gap-limit expansion is deferred to a later phase).
type AddressView struct {
	Receive    []string `json:"receive"`
	Used       []string `json:"used"`
	UsageKnown bool     `json:"usage_known"`
	NextUnused string   `json:"next_unused"`
}

// provisionalRewardsNote is shown to the user beside a provisional rewards
// figure. It deliberately does not name dingo or its issue numbers: the person
// reading it is looking at their own wallet, and an upstream tracker reference
// tells them nothing they can act on. The cause stays recorded on
// DelegationView below, where the people who can act on it will read it.
const provisionalRewardsNote = "Rewards are provisional and may not match on-chain totals exactly."

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

// RewardEntry is one epoch's stake reward for the active wallet's stake
// address, mirroring one chain.Reward. Type is the reward kind (e.g.
// "member"/"leader") when the node reports it; empty otherwise.
type RewardEntry struct {
	Epoch  int32  `json:"epoch"`
	Amount string `json:"amount"`
	PoolID string `json:"pool_id"`
	Type   string `json:"type,omitempty"`
}

// RewardHistory is the per-epoch stake-reward history (newest epochs last, as
// the node returns them). Provisional mirrors DelegationView: dingo's reward
// accounting has open issues, so the amounts are advisory.
type RewardHistory struct {
	Rewards     []RewardEntry `json:"rewards"`
	Provisional bool          `json:"provisional"`
	Note        string        `json:"note"`
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
		AccountIndex:     acct.AccountIndex,
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

func addressView(acct *Account, used []string, usageKnown bool) AddressView {
	receive := cloneStringSlice(acct.ReceiveAddresses)
	used = cloneStringSlice(used)
	if used == nil {
		used = []string{}
	}
	view := AddressView{
		Receive:    receive,
		Used:       used,
		UsageKnown: usageKnown,
	}
	if !usageKnown {
		return view
	}
	usedSet := make(map[string]bool, len(used))
	for _, a := range used {
		usedSet[a] = true
	}
	for _, a := range receive {
		if !usedSet[a] {
			view.NextUnused = a
			break
		}
	}
	return view
}

// LocalAddresses reports the locally derived receive window without querying
// the node. It is available during startup and bootstrap, before the node can
// report which addresses have already appeared on chain.
func (s *Service) LocalAddresses() (AddressView, error) {
	acct, err := s.currentAccount()
	if err != nil {
		return AddressView{}, err
	}
	return addressView(acct, nil, false), nil
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
	// A script (multi-signature) account has no stake credential, so there is
	// no account to discover addresses under — its addresses are exactly the
	// script address it was created with. Asking the node to resolve an empty
	// stake address is not a not-found, it is a malformed request.
	if acct.StakeAddress == "" {
		out := make([]string, 0, len(acct.ReceiveAddresses))
		seen := make(map[string]bool, len(acct.ReceiveAddresses))
		for _, a := range acct.ReceiveAddresses {
			if a == "" || seen[a] {
				continue
			}
			seen[a] = true
			out = append(out, a)
		}
		return out, nil
	}

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

// Balance aggregates the UTxO set across the active account's addresses
// (chain-seen and derived; see scanAddresses).
func (s *Service) Balance(ctx context.Context) (Balance, error) {
	acct, err := s.currentAccount()
	if err != nil {
		return Balance{}, err
	}
	return s.BalanceForAccount(ctx, acct)
}

// BalanceForAccount aggregates the UTxO set for an explicitly supplied account,
// independent of the currently bound one. It backs the multi-account listing,
// which shows a per-account balance summary without rebinding the service. A nil
// account is treated as "no wallet".
func (s *Service) BalanceForAccount(ctx context.Context, acct *Account) (Balance, error) {
	if acct == nil {
		return Balance{}, ErrNoWallet
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
	// Same reason as scanAddresses: a script (multi-signature) account has no
	// stake credential, so there is nothing to look up and an empty stake
	// address is a malformed request rather than a not-found. Its receive window
	// is exactly the script address it was created with, but its on-chain usage
	// remains unknown because this path deliberately makes no chain query.
	if acct.StakeAddress == "" {
		return addressView(acct, nil, false), nil
	}
	used, err := s.chain.AccountAddresses(ctx, acct.StakeAddress)
	if err != nil && !errors.Is(err, chain.ErrNotFound) {
		return AddressView{}, err
	}
	if errors.Is(err, chain.ErrNotFound) {
		// The account endpoint returns 404 for an unregistered stake credential,
		// even when one of its derived payment addresses already holds funds. That
		// response cannot establish that the receive window is unused.
		return addressView(acct, nil, false), nil
	}
	return addressView(acct, used, true), nil
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
	}
	if err := s.enrichTxs(ctx, merged, mine); err != nil {
		return nil, err
	}
	return merged, nil
}

func (s *Service) enrichTxs(ctx context.Context, txs []Tx, mine map[string]bool) error {
	workers := maxConcurrentTxEnrichments
	if len(txs) < workers {
		workers = len(txs)
	}
	if workers == 0 {
		return nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan int)
	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if err := s.enrichTx(ctx, &txs[i], mine); err != nil {
					select {
					case errCh <- err:
						cancel()
					default:
					}
					return
				}
			}
		}()
	}

send:
	for i := range txs {
		select {
		case <-ctx.Done():
			break send
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()

	select {
	case err := <-errCh:
		return err
	default:
		return ctx.Err()
	}
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
	utxosPruned := errors.Is(err, chain.ErrNotFound)
	if err != nil && !utxosPruned {
		return TxDetail{}, err
	}
	// A tip-lookup failure must not turn a found transaction into a 404 (serve()
	// maps chain.ErrNotFound to 404, which would otherwise misreport a tx that
	// genuinely exists purely because the tip call failed). Degrade to
	// "pending" (0 confirmations) instead of propagating the tip error.
	tip, tipErr := s.chain.LatestBlock(ctx)
	var confirmations uint64
	var pending bool
	if tipErr != nil {
		confirmations, pending = 0, true
	} else {
		confirmations, pending = txConfirmations(tip.Height, info.BlockHeight)
	}

	if utxosPruned {
		return TxDetail{
			Tx: Tx{
				TxHash:        hash,
				TxIndex:       info.Index,
				BlockHeight:   info.BlockHeight,
				BlockTime:     info.BlockTime,
				Fee:           feeOrZero(info.Fees),
				Confirmations: confirmations,
				Pending:       pending,
			},
			Inputs:  []TxIO{},
			Outputs: []TxIO{},
		}, nil
	}

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
	owned := make([]string, 0, len(addrs)+len(acct.ChangeAddresses))
	owned = append(owned, addrs...)
	owned = append(owned, acct.ChangeAddresses...)
	return toAddrSet(owned)
}

// Delegation returns the current delegation/rewards summary (provisional).
func (s *Service) Delegation(ctx context.Context) (DelegationView, error) {
	acct, err := s.currentAccount()
	if err != nil {
		return DelegationView{}, err
	}
	// A script account has no stake credential, so it can never be delegating;
	// asking the node about an empty stake address is a malformed request.
	if acct.StakeAddress == "" {
		return DelegationView{
			RewardsSum:   "0",
			Withdrawable: "0",
			Provisional:  true,
			Note:         provisionalRewardsNote,
		}, nil
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
		Note:         provisionalRewardsNote,
	}, nil
}

// Rewards returns the per-epoch stake-reward history for the active wallet's
// stake address, read node-locally through the chain client. A stake key not
// yet seen on chain (ErrNotFound) yields an empty history rather than an error.
func (s *Service) Rewards(ctx context.Context) (RewardHistory, error) {
	acct, err := s.currentAccount()
	if err != nil {
		return RewardHistory{}, err
	}
	// No stake credential, so there is no reward history to read and an empty
	// stake address would be a malformed request.
	if acct.StakeAddress == "" {
		return RewardHistory{
			Rewards:     []RewardEntry{},
			Provisional: true,
			Note:        provisionalRewardsNote,
		}, nil
	}
	rewards, err := s.chain.AccountRewards(ctx, acct.StakeAddress)
	if err != nil && !errors.Is(err, chain.ErrNotFound) {
		return RewardHistory{}, err
	}
	// ErrNotFound: stake key not registered / no rewards yet → empty history.
	entries := make([]RewardEntry, 0, len(rewards))
	for _, r := range rewards {
		entries = append(entries, RewardEntry{
			Epoch:  r.Epoch,
			Amount: r.Amount,
			PoolID: r.PoolID,
			Type:   r.Type,
		})
	}
	return RewardHistory{
		Rewards:     entries,
		Provisional: true,
		Note:        provisionalRewardsNote,
	}, nil
}
