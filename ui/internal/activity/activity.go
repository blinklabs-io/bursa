// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package activity detects node-local wallet activity worth surfacing as a
// desktop/browser notification: a newly confirmed incoming transaction to the
// active wallet's own addresses, and a new per-epoch stake-reward payout. It
// reads ONLY node-local wallet state (the same Transactions/Rewards paths the
// read-only wallet views use), so it makes no external calls and needs no
// external-consent gate.
//
// It is poll-driven: the SPA polls GET /wallet/activity on its existing status
// cadence, and each Poll returns just the events that are genuinely new since
// the previous Poll. Dedup is per active wallet — the first Poll after a wallet
// binds primes a baseline (every existing tx/reward is marked already-seen and
// NO events are emitted), so history never spams a notification; only activity
// that appears afterwards is reported, exactly once.
package activity

import (
	"context"
	"slices"
	"strconv"
	"sync"

	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

// Reader is the node-local wallet-state surface the detector needs. It is
// satisfied by *wallet.Service; an interface so the detector can be tested with
// a fake and stays decoupled from the chain client.
type Reader interface {
	Transactions(ctx context.Context) ([]wallet.Tx, error)
	Rewards(ctx context.Context) (wallet.RewardHistory, error)
}

// Kind classifies an activity event.
type Kind string

const (
	// KindReceived is a newly confirmed incoming transaction that paid the
	// active wallet's own addresses.
	KindReceived Kind = "received"
	// KindReward is a new per-epoch stake-reward payout for the active wallet's
	// stake address.
	KindReward Kind = "reward"
)

// Event is one notification-worthy occurrence. ID is a stable dedup key so a
// client that shows the same Poll result twice (e.g. a re-render) still raises
// at most one notification. Lovelace is the decimal net amount received (for
// KindReceived) or the reward amount (for KindReward).
type Event struct {
	ID       string `json:"id"`
	Kind     Kind   `json:"kind"`
	Lovelace string `json:"lovelace"`
	TxHash   string `json:"tx_hash,omitempty"`
	Epoch    int32  `json:"epoch,omitempty"`
}

// Service tracks the last-seen wallet state so each Poll reports only newly
// appeared activity. It is safe for concurrent use.
type Service struct {
	reader Reader

	mu          sync.Mutex
	walletID    string          // active wallet the baseline belongs to ("" = none)
	primed      bool            // baseline established for walletID
	seenTx      map[string]bool // recent tx hashes already reported/baselined
	seenTxOrder []string        // newest-first retention order for seenTx
	lastEpoch   int32           // highest reward epoch already reported/baselined
	hasEpoch    bool            // lastEpoch is meaningful
}

// maxTrackedTransactions bounds the transaction-hash retention used for
// notification deduplication. Wallet history can be much larger than the
// useful notification window; keeping only its newest entries prevents a
// long-lived wallet session from growing memory with its entire history.
const maxTrackedTransactions = 1024

// New builds a detector over the given node-local reader.
func New(r Reader) *Service {
	return &Service{reader: r}
}

// SetActive binds the wallet whose activity is tracked. A change of wallet (or
// clearing to "") resets the baseline so the next Poll re-primes against the
// new wallet's history instead of emitting its whole past as "new". Called from
// the same bind/clear points that push the active account onto the read
// services, so the detector always tracks the wallet currently in view.
func (s *Service) SetActive(walletID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if walletID == s.walletID {
		return
	}
	s.walletID = walletID
	s.primed = false
	s.seenTx = nil
	s.seenTxOrder = nil
	s.lastEpoch = 0
	s.hasEpoch = false
}

// Poll returns the activity events that are new since the previous Poll for the
// currently bound wallet. With no wallet bound it returns nil. The first Poll
// after a wallet binds primes the baseline and returns no events (so existing
// history is never notified); subsequent Polls return only genuinely new
// incoming transactions and reward epochs, each exactly once.
func (s *Service) Poll(ctx context.Context) ([]Event, error) {
	s.mu.Lock()
	walletID := s.walletID
	s.mu.Unlock()
	if walletID == "" {
		return nil, nil
	}

	txs, err := s.reader.Transactions(ctx)
	if err != nil {
		return nil, err
	}
	rewards, err := s.reader.Rewards(ctx)
	if err != nil {
		return nil, err
	}
	// The watermark logic below (both the baseline and event loops) assumes
	// chronological order so it can track "highest epoch seen so far" with a
	// single running value. The reader's ordering is not guaranteed (a real
	// node/API may return unordered or descending history), so sort a copy
	// ascending here rather than trust the source order — otherwise a lower
	// epoch arriving after a higher one in the slice is skipped by the
	// already-advanced watermark, silently dropping (baseline) or losing
	// (event loop) that epoch's notification.
	sortedRewards := slices.Clone(rewards.Rewards)
	slices.SortFunc(sortedRewards, func(a, b wallet.RewardEntry) int {
		return int(a.Epoch) - int(b.Epoch)
	})

	s.mu.Lock()
	defer s.mu.Unlock()
	// A wallet switch (including to a different non-empty wallet, or to none)
	// between the unlocked read above and here means these results belong to a
	// wallet that is no longer active; drop them rather than priming/reporting
	// against the wrong wallet's baseline.
	if s.walletID != walletID {
		return nil, nil
	}
	if s.seenTx == nil {
		s.seenTx = make(map[string]bool)
	}
	recentTxs := recentReceived(txs)

	if !s.primed {
		// Baseline: record the recent existing receipts without emitting anything.
		// This deliberately checks Direction only, NOT isIncoming's Pending
		// exclusion: a transient tip-lookup failure degrades every tx to
		// Pending=true (see wallet.Service.Transactions), and baselining with
		// isIncoming would then drop an already-confirmed receipt from the
		// baseline, causing it to be reported as newly "received" once the tip
		// lookup recovers on a later poll.
		for _, tx := range recentTxs {
			s.seenTx[tx.TxHash] = true
			s.seenTxOrder = append(s.seenTxOrder, tx.TxHash)
		}
		for _, r := range sortedRewards {
			if !s.hasEpoch || r.Epoch > s.lastEpoch {
				s.lastEpoch = r.Epoch
				s.hasEpoch = true
			}
		}
		s.primed = true
		return nil, nil
	}

	var events []Event
	for _, tx := range recentTxs {
		if !isIncoming(tx) || s.seenTx[tx.TxHash] {
			continue
		}
		s.rememberTx(tx.TxHash)
		events = append(events, Event{
			ID:       "tx:" + tx.TxHash,
			Kind:     KindReceived,
			Lovelace: tx.NetLovelace,
			TxHash:   tx.TxHash,
		})
	}
	for _, r := range sortedRewards {
		if s.hasEpoch && r.Epoch <= s.lastEpoch {
			continue
		}
		s.lastEpoch = r.Epoch
		s.hasEpoch = true
		events = append(events, Event{
			ID:       "reward:" + strconv.FormatInt(int64(r.Epoch), 10),
			Kind:     KindReward,
			Lovelace: r.Amount,
			Epoch:    r.Epoch,
		})
	}
	return events, nil
}

// rememberTx adds a hash to the bounded deduplication window. Callers hold
// s.mu. The transaction list is traversed newest-first, so the newest hash is
// kept at the front and eviction from the end drops the oldest history.
func (s *Service) rememberTx(hash string) {
	if s.seenTx[hash] {
		return
	}
	s.seenTx[hash] = true
	s.seenTxOrder = append(s.seenTxOrder, "")
	copy(s.seenTxOrder[1:], s.seenTxOrder[:len(s.seenTxOrder)-1])
	s.seenTxOrder[0] = hash
	if len(s.seenTxOrder) <= maxTrackedTransactions {
		return
	}
	oldest := s.seenTxOrder[len(s.seenTxOrder)-1]
	s.seenTxOrder = s.seenTxOrder[:len(s.seenTxOrder)-1]
	delete(s.seenTx, oldest)
}

// recentReceived returns at most the newest received transactions. The wallet
// service currently returns newest-first, but sort here as a contract guard for
// other Reader implementations and tests. Pending received entries are kept in
// the baseline window so a transient tip lookup failure cannot turn old history
// into a notification after recovery.
func recentReceived(txs []wallet.Tx) []wallet.Tx {
	sorted := slices.Clone(txs)
	slices.SortFunc(sorted, func(a, b wallet.Tx) int {
		if a.BlockHeight != b.BlockHeight {
			if a.BlockHeight > b.BlockHeight {
				return -1
			}
			return 1
		}
		if a.TxIndex != b.TxIndex {
			if a.TxIndex > b.TxIndex {
				return -1
			}
			return 1
		}
		if a.TxHash > b.TxHash {
			return -1
		}
		if a.TxHash < b.TxHash {
			return 1
		}
		return 0
	})

	out := make([]wallet.Tx, 0, min(len(sorted), maxTrackedTransactions))
	for _, tx := range sorted {
		if tx.Direction != wallet.TxDirectionReceived {
			continue
		}
		out = append(out, tx)
		if len(out) == maxTrackedTransactions {
			break
		}
	}
	return out
}

// isIncoming reports whether tx is a confirmed transaction that paid the wallet
// without spending any of its own inputs — the "you received funds" case. A
// still-pending (unconfirmed) tx is excluded: only settled receipts notify.
func isIncoming(tx wallet.Tx) bool {
	return tx.Direction == wallet.TxDirectionReceived && !tx.Pending
}
