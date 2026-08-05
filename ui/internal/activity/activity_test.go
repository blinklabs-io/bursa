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

package activity

import (
	"context"
	"errors"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

// fakeReader is a controllable node-local wallet-state source.
type fakeReader struct {
	txs     []wallet.Tx
	rewards wallet.RewardHistory
	txErr   error
	rewErr  error
}

func (f *fakeReader) Transactions(context.Context) ([]wallet.Tx, error) {
	return f.txs, f.txErr
}

func (f *fakeReader) Rewards(context.Context) (wallet.RewardHistory, error) {
	return f.rewards, f.rewErr
}

func received(hash, net string) wallet.Tx {
	return wallet.Tx{TxHash: hash, Direction: wallet.TxDirectionReceived, NetLovelace: net}
}

func TestPollNoWalletBoundReturnsNil(t *testing.T) {
	r := &fakeReader{txs: []wallet.Tx{received("abc", "1000000")}}
	svc := New(r)
	events, err := svc.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if events != nil {
		t.Fatalf("expected nil events with no wallet bound, got %v", events)
	}
}

func TestFirstPollPrimesBaselineNoEvents(t *testing.T) {
	r := &fakeReader{
		txs:     []wallet.Tx{received("abc", "1000000")},
		rewards: wallet.RewardHistory{Rewards: []wallet.RewardEntry{{Epoch: 100, Amount: "5"}}},
	}
	svc := New(r)
	svc.SetActive("w1")
	events, err := svc.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("first poll must not emit history, got %v", events)
	}
}

func TestNewIncomingTxEmitsOneEventThenDedups(t *testing.T) {
	r := &fakeReader{}
	svc := New(r)
	svc.SetActive("w1")
	if _, err := svc.Poll(context.Background()); err != nil { // prime empty baseline
		t.Fatalf("prime: %v", err)
	}

	r.txs = []wallet.Tx{received("tx1", "2500000")}
	events, err := svc.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d (%v)", len(events), events)
	}
	e := events[0]
	if e.Kind != KindReceived || e.TxHash != "tx1" || e.Lovelace != "2500000" || e.ID != "tx:tx1" {
		t.Fatalf("unexpected event: %+v", e)
	}

	// Same tx still present on the next poll → no duplicate.
	events, err = svc.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("duplicate tx must not re-emit, got %v", events)
	}
}

func TestPendingIncomingTxIsNotEmitted(t *testing.T) {
	r := &fakeReader{}
	svc := New(r)
	svc.SetActive("w1")
	if _, err := svc.Poll(context.Background()); err != nil {
		t.Fatalf("prime: %v", err)
	}
	pending := received("tx1", "1000000")
	pending.Pending = true
	r.txs = []wallet.Tx{pending}
	events, err := svc.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("pending (unconfirmed) tx must not notify, got %v", events)
	}
}

func TestPrimingBaselinesPendingReceiptToAvoidFalseNotifyOnTipRecovery(t *testing.T) {
	// A transient tip-lookup failure degrades every tx to Pending=true (see
	// wallet.Service.Transactions), including ones that are actually already
	// confirmed. If the very first (priming) poll for a wallet lands during such
	// a failure, an already-confirmed receipt must still be baselined — not
	// reported as "new" once a later poll's tip lookup recovers and the same tx
	// correctly reports Pending=false.
	degraded := received("tx1", "1000000")
	degraded.Pending = true
	r := &fakeReader{txs: []wallet.Tx{degraded}}
	svc := New(r)
	svc.SetActive("w1")
	events, err := svc.Poll(context.Background())
	if err != nil {
		t.Fatalf("prime: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("priming must not emit history, got %v", events)
	}

	// Tip lookup recovers: the same tx now correctly reports Pending=false.
	r.txs = []wallet.Tx{received("tx1", "1000000")}
	events, err = svc.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("already-baselined tx must not re-emit once confirmed, got %v", events)
	}
}

func TestSentAndSelfTxAreNotEmitted(t *testing.T) {
	r := &fakeReader{}
	svc := New(r)
	svc.SetActive("w1")
	if _, err := svc.Poll(context.Background()); err != nil {
		t.Fatalf("prime: %v", err)
	}
	r.txs = []wallet.Tx{
		{TxHash: "sent", Direction: wallet.TxDirectionSent, NetLovelace: "-1000000"},
		{TxHash: "self", Direction: wallet.TxDirectionSelf, NetLovelace: "0"},
	}
	events, err := svc.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("sent/self txs must not notify, got %v", events)
	}
}

func TestNewRewardEpochEmitsEventThenDedups(t *testing.T) {
	r := &fakeReader{
		rewards: wallet.RewardHistory{Rewards: []wallet.RewardEntry{{Epoch: 100, Amount: "5"}}},
	}
	svc := New(r)
	svc.SetActive("w1")
	if _, err := svc.Poll(context.Background()); err != nil { // baseline lastEpoch=100
		t.Fatalf("prime: %v", err)
	}

	r.rewards = wallet.RewardHistory{Rewards: []wallet.RewardEntry{
		{Epoch: 100, Amount: "5"},
		{Epoch: 101, Amount: "7000000"},
	}}
	events, err := svc.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 reward event, got %d (%v)", len(events), events)
	}
	e := events[0]
	if e.Kind != KindReward || e.Epoch != 101 || e.Lovelace != "7000000" || e.ID != "reward:101" {
		t.Fatalf("unexpected reward event: %+v", e)
	}

	events, err = svc.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("same reward epoch must not re-emit, got %v", events)
	}
}

func TestSetActiveResetsBaseline(t *testing.T) {
	r := &fakeReader{}
	svc := New(r)
	svc.SetActive("w1")
	if _, err := svc.Poll(context.Background()); err != nil {
		t.Fatalf("prime: %v", err)
	}
	// A different wallet's history must re-prime, not emit as "new".
	r.txs = []wallet.Tx{received("txX", "1000000")}
	svc.SetActive("w2")
	events, err := svc.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("switching wallets must re-prime (no events), got %v", events)
	}
}

func TestPollPropagatesReaderErrors(t *testing.T) {
	wantErr := errors.New("node down")
	r := &fakeReader{txErr: wantErr}
	svc := New(r)
	svc.SetActive("w1")
	if _, err := svc.Poll(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("Poll error = %v, want %v", err, wantErr)
	}
}
