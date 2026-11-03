package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

// fakeBackend implements Backend with canned values.
type fakeBackend struct {
	networkID      int
	balance        string
	utxos          []string
	signedTx       string
	submitID       string
	signSig        string
	signKey        string
	usedAddrs      []string
	inspectSummary spend.TxSummary
	inspectErr     error

	// recorded call args
	signTxCalled    bool
	signTxPassword  string
	signTxTx        string
	signTxPartial   bool
	inspectTx       string
	usedPaginate    *Paginate
	signDataCalled  bool
	signDataAddr    string
	signDataPayload string
}

type blockingInspectBackend struct {
	*fakeBackend
	started chan string
	release <-chan struct{}
}

func (b *blockingInspectBackend) InspectTx(ctx context.Context, txHex string) (spend.TxSummary, error) {
	select {
	case b.started <- txHex:
	case <-ctx.Done():
		return spend.TxSummary{}, ctx.Err()
	}
	select {
	case <-b.release:
		return b.inspectSummary, nil
	case <-ctx.Done():
		return spend.TxSummary{}, ctx.Err()
	}
}

type blockingBalanceBackend struct {
	fakeBackend

	mu               sync.Mutex
	walletID         string
	accountIndex     uint32
	balanceStarted   chan struct{}
	releaseBalance   chan struct{}
	rebound          chan struct{}
	balanceStartOnce sync.Once
	reboundOnce      sync.Once
}

func (b *blockingBalanceBackend) SetAccount(walletID string, acct *wallet.Account) {
	b.mu.Lock()
	b.walletID = walletID
	b.accountIndex = 0
	if acct != nil {
		b.accountIndex = acct.AccountIndex
	}
	b.mu.Unlock()
	if walletID == "wallet-b" {
		b.reboundOnce.Do(func() { close(b.rebound) })
	}
}

func (b *blockingBalanceBackend) Balance(_ context.Context) (string, error) {
	b.balanceStartOnce.Do(func() { close(b.balanceStarted) })
	<-b.releaseBalance
	b.mu.Lock()
	defer b.mu.Unlock()
	return fmt.Sprintf("%s/%d", b.walletID, b.accountIndex), nil
}

func (b *fakeBackend) NetworkID() int { return b.networkID }

func (b *fakeBackend) Utxos(_ context.Context, _ string, _ *Paginate) ([]string, error) {
	return b.utxos, nil
}

func (b *fakeBackend) Balance(_ context.Context) (string, error) { return b.balance, nil }

func (b *fakeBackend) UsedAddresses(_ context.Context, paginate *Paginate) ([]string, error) {
	b.usedPaginate = paginate
	return b.usedAddrs, nil
}

func (b *fakeBackend) UnusedAddresses(_ context.Context) ([]string, error) { return nil, nil }

func (b *fakeBackend) ChangeAddress(_ context.Context) (string, error) { return "addr1change", nil }

func (b *fakeBackend) RewardAddresses(_ context.Context) ([]string, error) { return nil, nil }

func (b *fakeBackend) Collateral(_ context.Context, _ string) ([]string, error) { return nil, nil }

func (b *fakeBackend) InspectTx(_ context.Context, txHex string) (spend.TxSummary, error) {
	b.inspectTx = txHex
	return b.inspectSummary, b.inspectErr
}

func (b *fakeBackend) SignTx(_ context.Context, txHex string, partialSign bool, password string) (string, error) {
	b.signTxCalled = true
	b.signTxTx = txHex
	b.signTxPartial = partialSign
	b.signTxPassword = password
	return b.signedTx, nil
}

func (b *fakeBackend) SignData(addr, payload, _ string) (string, string, error) {
	b.signDataCalled = true
	b.signDataAddr = addr
	b.signDataPayload = payload
	return b.signSig, b.signKey, nil
}

func (b *fakeBackend) SubmitTx(_ context.Context, _ string) (string, error) {
	return b.submitID, nil
}

func (b *fakeBackend) PubDRepKey(_ string) (string, error)               { return "drepkey", nil }
func (b *fakeBackend) RegisteredPubStakeKeys(_ string) ([]string, error) { return nil, nil }
func (b *fakeBackend) UnregisteredPubStakeKeys(_ string) ([]string, error) {
	return []string{"stakekey1"}, nil
}

// ctx returns a background context with a 5-second deadline whose cancel is
// registered with t.Cleanup so no goroutine leaks.
func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

func bindTestIdentity(s *Service) accountIdentity {
	identity := accountIdentity{WalletID: "test-wallet", AccountIndex: 0}
	s.SetActiveAccount(identity.WalletID, &wallet.Account{AccountIndex: identity.AccountIndex})
	return identity
}

// decideWhenPending spins (bounded) until at least one request is pending, then decides.
func decideWhenPending(s *Service, d Decision) {
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		pending := s.Pending()
		if len(pending) > 0 {
			_ = s.Decide(pending[0].ID, d)
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitForPendingID(t *testing.T, s *Service) string {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		pending := s.Pending()
		if len(pending) > 0 {
			return pending[0].ID
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no connector request became pending")
	return ""
}

// ConfirmPairForTest is a test helper that runs BeginPair+ConfirmPair for the given extensionID.
func (s *Service) ConfirmPairForTest(extensionID string) (string, error) {
	code, err := s.BeginPair(extensionID)
	if err != nil {
		return "", err
	}
	return s.ConfirmPair(extensionID, code)
}

// TestServiceEnableThenRead verifies the core enable→grant→read flow.
func TestServiceEnableThenRead(t *testing.T) {
	be := &fakeBackend{balance: "1a002dc6c0"}
	s := NewService(t.TempDir(), be, func() {})
	bindTestIdentity(s)
	_, _ = s.ConfirmPairForTest("ext")

	// ungranted read refused
	if _, err := s.Handle(ctx(t), "https://a.io", "getBalance", nil); err != ErrNotGranted {
		t.Fatalf("want ErrNotGranted, got %v", err)
	}

	// enable enqueues; approve in a goroutine
	go decideWhenPending(s, Decision{Approved: true})
	if _, err := s.Handle(ctx(t), "https://a.io", "enable", nil); err != nil {
		t.Fatalf("enable: %v", err)
	}

	// now read is silent
	out, err := s.Handle(ctx(t), "https://a.io", "getBalance", nil)
	if err != nil || string(out) != `"1a002dc6c0"` {
		t.Fatalf("getBalance: %s %v", out, err)
	}
}

// TestServiceSignTxApprove verifies signTx calls Backend.SignTx with the approved password.
func TestServiceSignTxApprove(t *testing.T) {
	totalCollateral := "1000000"
	be := &fakeBackend{
		signedTx: "deadbeef",
		inspectSummary: spend.TxSummary{
			Outputs: []spend.TxSummaryOutput{{Address: "addr_test1approval", Lovelace: "2000000"}},
			Fee:     "170000",
			CollateralInputs: []spend.TxSummaryInput{{
				TxHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Index:  1, Resolved: true, Address: "addr_test1collateral", Lovelace: "3000000",
			}},
			TotalCollateral: &totalCollateral,
		},
	}
	s := NewService(t.TempDir(), be, func() {})
	bindTestIdentity(s)
	_, _ = s.ConfirmPairForTest("ext")

	// Grant origin first via enable.
	go decideWhenPending(s, Decision{Approved: true})
	if _, err := s.Handle(ctx(t), "https://b.io", "enable", nil); err != nil {
		t.Fatalf("enable: %v", err)
	}

	params, _ := json.Marshal(map[string]interface{}{
		"tx":          "cafebabe",
		"partialSign": true,
	})
	type handleResult struct {
		out json.RawMessage
		err error
	}
	result := make(chan handleResult, 1)
	handleCtx := ctx(t)
	go func() {
		out, err := s.Handle(handleCtx, "https://b.io", "signTx", params)
		result <- handleResult{out: out, err: err}
	}()

	var pending Request
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		requests := s.Pending()
		if len(requests) > 0 {
			pending = requests[0]
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if pending.ID == "" {
		t.Fatal("signTx request did not reach the approval queue")
	}
	if pending.Effects == nil || pending.Effects.Fee != "170000" ||
		len(pending.Effects.Outputs) != 1 || pending.Effects.Outputs[0].Address != "addr_test1approval" ||
		len(pending.Effects.CollateralInputs) != 1 || pending.Effects.CollateralInputs[0].Address != "addr_test1collateral" ||
		pending.Effects.TotalCollateral == nil || *pending.Effects.TotalCollateral != totalCollateral {
		t.Fatalf("queued effects = %+v, want inspector summary", pending.Effects)
	}
	wire, err := json.Marshal(pending)
	if err != nil {
		t.Fatalf("marshal pending request: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatalf("unmarshal pending request: %v", err)
	}
	if _, ok := fields["effects"]; !ok {
		t.Fatalf("pending request JSON has no effects field: %s", wire)
	}
	if err := s.Decide(pending.ID, Decision{Approved: true, Password: "secret"}); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	got := <-result
	out, err := got.out, got.err
	if err != nil {
		t.Fatalf("signTx approved: %v", err)
	}
	if string(out) != `"deadbeef"` {
		t.Fatalf("signTx result: %s", out)
	}
	if !be.signTxCalled || be.signTxPassword != "secret" || be.signTxTx != "cafebabe" {
		t.Fatalf("signTx backend call wrong: called=%v pw=%q tx=%q", be.signTxCalled, be.signTxPassword, be.signTxTx)
	}
	if be.inspectTx != "cafebabe" || be.signTxTx != be.inspectTx || !be.signTxPartial {
		t.Fatalf("inspect/sign binding wrong: inspected=%q signed=%q partial=%v", be.inspectTx, be.signTxTx, be.signTxPartial)
	}
}

func TestServiceSignTxInspectionFailureDoesNotPromptOrSign(t *testing.T) {
	be := &fakeBackend{inspectErr: errors.New("decode failed")}
	prompts := 0
	s := NewService(t.TempDir(), be, func() { prompts++ })
	bindTestIdentity(s)
	_, _ = s.ConfirmPairForTest("ext")

	go decideWhenPending(s, Decision{Approved: true})
	if _, err := s.Handle(ctx(t), "https://decode.example", "enable", nil); err != nil {
		t.Fatalf("enable: %v", err)
	}
	prompts = 0

	params := json.RawMessage(`{"tx":"cafebabe","partialSign":false}`)
	if _, err := s.Handle(ctx(t), "https://decode.example", "signTx", params); !errors.Is(err, ErrInvalidParams) {
		t.Fatalf("signTx inspection error = %v, want ErrInvalidParams", err)
	}
	if prompts != 0 {
		t.Fatalf("inspection failure prompted %d times, want 0", prompts)
	}
	if len(s.Pending()) != 0 {
		t.Fatalf("inspection failure queued request: %+v", s.Pending())
	}
	if be.signTxCalled {
		t.Fatal("inspection failure reached SignTx")
	}
}

func TestServiceSignTxInspectionUsesQueueAdmission(t *testing.T) {
	origin := "https://bounded.example"
	release := make(chan struct{})
	be := &blockingInspectBackend{
		fakeBackend: &fakeBackend{inspectSummary: spend.TxSummary{Fee: "170000"}},
		started:     make(chan string, maxPendingRequestsPerOrigin),
		release:     release,
	}
	s := NewService(t.TempDir(), be, func() {})
	identity := bindTestIdentity(s)
	if err := s.grants.Grant(origin, identity); err != nil {
		t.Fatalf("grant: %v", err)
	}

	results := make(chan error, maxPendingRequestsPerOrigin)
	for i := 0; i < maxPendingRequestsPerOrigin; i++ {
		params := json.RawMessage(fmt.Sprintf(`{"tx":"%02x","partialSign":false}`, i))
		handleCtx := ctx(t)
		go func(handleCtx context.Context, params json.RawMessage) {
			_, err := s.Handle(handleCtx, origin, "signTx", params)
			results <- err
		}(handleCtx, params)
	}
	for i := 0; i < maxPendingRequestsPerOrigin; i++ {
		select {
		case <-be.started:
		case <-time.After(time.Second):
			t.Fatalf("only %d inspections reached the backend", i)
		}
	}
	if got := s.Pending(); len(got) != 0 {
		t.Fatalf("requests visible while inspection is blocked: %+v", got)
	}

	overflow := json.RawMessage(`{"tx":"ff","partialSign":false}`)
	if _, err := s.Handle(ctx(t), origin, "signTx", overflow); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("overflow signTx error = %v, want ErrQueueFull", err)
	}
	if got := len(be.started); got != 0 {
		t.Fatalf("overflow request reached inspector; started channel has %d unexpected entries", got)
	}

	close(release)
	deadline := time.Now().Add(time.Second)
	for len(s.Pending()) != maxPendingRequestsPerOrigin && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	pending := s.Pending()
	if len(pending) != maxPendingRequestsPerOrigin {
		t.Fatalf("published requests = %d, want %d", len(pending), maxPendingRequestsPerOrigin)
	}
	for _, req := range pending {
		if req.Effects == nil {
			t.Fatalf("published request %s has no verified effects", req.ID)
		}
		if err := s.Decide(req.ID, Decision{Approved: false}); err != nil {
			t.Fatalf("reject %s: %v", req.ID, err)
		}
	}
	for i := 0; i < maxPendingRequestsPerOrigin; i++ {
		if err := <-results; !errors.Is(err, ErrUserDeclined) {
			t.Fatalf("signTx result %d = %v, want ErrUserDeclined", i, err)
		}
	}
}

// TestServiceSignTxReject verifies signTx returns ErrUserDeclined on reject.
func TestServiceSignTxReject(t *testing.T) {
	be := &fakeBackend{signedTx: "deadbeef", inspectSummary: spend.TxSummary{Fee: "1"}}
	s := NewService(t.TempDir(), be, func() {})
	bindTestIdentity(s)
	_, _ = s.ConfirmPairForTest("ext")

	// Grant origin first.
	go decideWhenPending(s, Decision{Approved: true})
	if _, err := s.Handle(ctx(t), "https://c.io", "enable", nil); err != nil {
		t.Fatalf("enable: %v", err)
	}

	params, _ := json.Marshal(map[string]interface{}{"tx": "aabbcc", "partialSign": false})
	go decideWhenPending(s, Decision{Approved: false})
	_, err := s.Handle(ctx(t), "https://c.io", "signTx", params)
	if err != ErrUserDeclined {
		t.Fatalf("want ErrUserDeclined, got %v", err)
	}
}

// TestServiceEnableReject verifies that a rejected enable does not grant.
func TestServiceEnableReject(t *testing.T) {
	be := &fakeBackend{}
	s := NewService(t.TempDir(), be, func() {})
	identity := bindTestIdentity(s)
	_, _ = s.ConfirmPairForTest("ext")

	go decideWhenPending(s, Decision{Approved: false})
	_, err := s.Handle(ctx(t), "https://d.io", "enable", nil)
	if err != ErrUserDeclined {
		t.Fatalf("want ErrUserDeclined, got %v", err)
	}
	if s.grants.IsGranted("https://d.io", identity) {
		t.Fatal("origin must not be granted after rejected enable")
	}
}

// TestServicePairCodeMismatch verifies ConfirmPair returns ErrPairCodeMismatch on wrong code.
func TestServicePairCodeMismatch(t *testing.T) {
	s := NewService(t.TempDir(), &fakeBackend{}, nil)
	code, err := s.BeginPair("ext2")
	if err != nil {
		t.Fatalf("BeginPair: %v", err)
	}
	if _, err := s.ConfirmPair("ext2", code+"X"); err != ErrPairCodeMismatch {
		t.Fatalf("want ErrPairCodeMismatch, got %v", err)
	}
	if _, err := s.ConfirmPair("ext2", code); err != nil {
		t.Fatalf("correct code after mismatch should still pair: %v", err)
	}
}

func TestServicePairCodeFormat(t *testing.T) {
	s := NewService(t.TempDir(), &fakeBackend{}, nil)
	code, err := s.BeginPair("ext-format")
	if err != nil {
		t.Fatalf("BeginPair: %v", err)
	}
	if len(code) != pairCodeDigits {
		t.Fatalf("pair code length = %d, want %d", len(code), pairCodeDigits)
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			t.Fatalf("pair code %q contains non-digit %q", code, r)
		}
	}
}

// TestServiceBeginPairRejectsInvalidExtensionID verifies malformed extension IDs
// are refused rather than cached.
func TestServiceBeginPairRejectsInvalidExtensionID(t *testing.T) {
	s := NewService(t.TempDir(), &fakeBackend{}, nil)
	for _, bad := range []string{"", "chrome-extension://", "chrome-extension://has/slash"} {
		if _, err := s.BeginPair(bad); !errors.Is(err, ErrInvalidExtensionID) {
			t.Errorf("BeginPair(%q): want ErrInvalidExtensionID, got %v", bad, err)
		}
	}
	if got := len(s.PendingPairings()); got != 0 {
		t.Fatalf("invalid IDs must not be cached, got %d pending", got)
	}
}

// TestServicePairCodeExpires verifies an expired code no longer confirms and is
// dropped from the pending list.
func TestServicePairCodeExpires(t *testing.T) {
	s := NewService(t.TempDir(), &fakeBackend{}, nil)
	now := time.Now()
	s.now = func() time.Time { return now }

	code, err := s.BeginPair("ext-expire")
	if err != nil {
		t.Fatalf("BeginPair: %v", err)
	}

	// Advance past the TTL.
	now = now.Add(pairCodeTTL + time.Second)
	if _, err := s.ConfirmPair("ext-expire", code); !errors.Is(err, ErrPairCodeMismatch) {
		t.Fatalf("expired code: want ErrPairCodeMismatch, got %v", err)
	}
	if got := len(s.PendingPairings()); got != 0 {
		t.Fatalf("expired code must be pruned, got %d pending", got)
	}
}

// TestServicePairCodeAttemptCap verifies a code is discarded after too many
// wrong guesses, so it cannot be brute-forced.
func TestServicePairCodeAttemptCap(t *testing.T) {
	s := NewService(t.TempDir(), &fakeBackend{}, nil)
	code, err := s.BeginPair("ext-cap")
	if err != nil {
		t.Fatalf("BeginPair: %v", err)
	}

	wrong := "000000000000"
	if wrong == code {
		wrong = "000000000001"
	}
	for i := 0; i < pairCodeMaxAttempts; i++ {
		if _, err := s.ConfirmPair("ext-cap", wrong); !errors.Is(err, ErrPairCodeMismatch) {
			t.Fatalf("attempt %d: want ErrPairCodeMismatch, got %v", i, err)
		}
	}
	// The correct code must now be rejected too: the entry was discarded.
	if _, err := s.ConfirmPair("ext-cap", code); !errors.Is(err, ErrPairCodeMismatch) {
		t.Fatalf("after attempt cap, correct code should fail: got %v", err)
	}
}

// TestServiceBeginPairBounded verifies the pending map cannot grow past its cap.
func TestServiceBeginPairBounded(t *testing.T) {
	s := NewService(t.TempDir(), &fakeBackend{}, nil)
	var originalCode string
	for i := 0; i < maxPendingPairCodes; i++ {
		id := fmt.Sprintf("chrome-extension://ext-%d", i)
		code, err := s.BeginPair(id)
		if err != nil {
			t.Fatalf("BeginPair(%s): %v", id, err)
		}
		if i == 0 {
			originalCode = code
		}
	}
	if _, err := s.BeginPair("chrome-extension://one-too-many"); !errors.Is(err, ErrTooManyPairings) {
		t.Fatalf("want ErrTooManyPairings past cap, got %v", err)
	}
	// Re-initiating an existing extension ID must preserve the claimant's code
	// so a competing initiation cannot invalidate an in-progress pairing.
	code, err := s.BeginPair("chrome-extension://ext-0")
	if err != nil {
		t.Fatalf("re-pair existing id: %v", err)
	}
	pending := s.PendingPairings()
	if len(pending) != maxPendingPairCodes {
		t.Fatalf("re-pair changed pending count: got %d, want %d", len(pending), maxPendingPairCodes)
	}
	if code != originalCode {
		t.Fatalf("re-pair replaced the existing code: original %q, returned %q", originalCode, code)
	}
	var found bool
	for _, pairing := range pending {
		if pairing.ExtensionID == "chrome-extension://ext-0" {
			found = true
			if pairing.Code != code {
				t.Fatalf("re-pair returned code %q, pending code is %q", code, pairing.Code)
			}
			break
		}
	}
	if !found {
		t.Fatal("re-pair removed the existing pending extension")
	}
}

// TestServiceGrantsAndRevoke exercises Grants() and RevokeGrant().
func TestServiceGrantsAndRevoke(t *testing.T) {
	be := &fakeBackend{}
	s := NewService(t.TempDir(), be, nil)
	bindTestIdentity(s)
	_, _ = s.ConfirmPairForTest("ext")

	go decideWhenPending(s, Decision{Approved: true})
	if _, err := s.Handle(ctx(t), "https://e.io", "enable", nil); err != nil {
		t.Fatalf("enable: %v", err)
	}

	grants := s.Grants()
	if len(grants) != 1 || grants[0] != "https://e.io" {
		t.Fatalf("unexpected grants: %v", grants)
	}

	if err := s.RevokeGrant("https://e.io"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if _, err := s.Handle(ctx(t), "https://e.io", "getBalance", nil); err != ErrNotGranted {
		t.Fatalf("after revoke want ErrNotGranted, got %v", err)
	}
}

func TestServiceGrantDoesNotFollowActiveAccount(t *testing.T) {
	be := &fakeBackend{balance: "balance-a"}
	s := NewService(t.TempDir(), be, nil)
	const origin = "https://identity.example"

	s.SetActiveAccount("wallet-a", &wallet.Account{AccountIndex: 0})
	go decideWhenPending(s, Decision{Approved: true})
	if _, err := s.Handle(ctx(t), origin, "enable", nil); err != nil {
		t.Fatalf("enable account 0: %v", err)
	}
	if _, err := s.Handle(ctx(t), origin, "getBalance", nil); err != nil {
		t.Fatalf("getBalance account 0: %v", err)
	}

	s.SetActiveAccount("wallet-a", &wallet.Account{AccountIndex: 1})
	if _, err := s.Handle(ctx(t), origin, "getBalance", nil); !errors.Is(err, ErrNotGranted) {
		t.Fatalf("getBalance after account switch error = %v, want ErrNotGranted", err)
	}
	out, err := s.Handle(ctx(t), origin, "isEnabled", nil)
	if err != nil {
		t.Fatalf("isEnabled after account switch: %v", err)
	}
	if string(out) != "false" {
		t.Fatalf("isEnabled after account switch = %s, want false", out)
	}

	s.SetActiveAccount("wallet-b", &wallet.Account{AccountIndex: 0})
	if _, err := s.Handle(ctx(t), origin, "getBalance", nil); !errors.Is(err, ErrNotGranted) {
		t.Fatalf("getBalance after wallet switch error = %v, want ErrNotGranted", err)
	}

	s.SetActiveAccount("wallet-a", &wallet.Account{AccountIndex: 0})
	if _, err := s.Handle(ctx(t), origin, "getBalance", nil); err != nil {
		t.Fatalf("getBalance after restoring approved identity: %v", err)
	}
}

func TestServiceProtectedReadSerializesAccountRebinding(t *testing.T) {
	be := &blockingBalanceBackend{
		balanceStarted: make(chan struct{}),
		releaseBalance: make(chan struct{}),
		rebound:        make(chan struct{}),
	}
	s := NewService(t.TempDir(), be, nil)
	identity := accountIdentity{WalletID: "wallet-a", AccountIndex: 0}
	s.SetActiveAccount(identity.WalletID, &wallet.Account{AccountIndex: identity.AccountIndex})
	const origin = "https://race.example"
	if err := s.grants.Grant(origin, identity); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	type result struct {
		body json.RawMessage
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		body, err := s.Handle(context.Background(), origin, "getBalance", nil)
		resultCh <- result{body: body, err: err}
	}()
	<-be.balanceStarted

	rebindDone := make(chan struct{})
	rebindStarted := make(chan struct{})
	go func() {
		close(rebindStarted)
		s.SetActiveAccount("wallet-b", &wallet.Account{AccountIndex: 0})
		close(rebindDone)
	}()
	<-rebindStarted
	select {
	case <-be.rebound:
		t.Fatal("backend account changed during an authorized read")
	case <-time.After(250 * time.Millisecond):
	}
	close(be.releaseBalance)

	got := <-resultCh
	if got.err != nil {
		t.Fatalf("getBalance: %v", got.err)
	}
	if string(got.body) != `"wallet-a/0"` {
		t.Fatalf("getBalance = %s, want wallet-a account 0", got.body)
	}
	<-rebindDone
	select {
	case <-be.rebound:
	default:
		t.Fatal("account did not rebind after the protected read completed")
	}
}

func TestServicePendingApprovalRejectsIdentitySwitch(t *testing.T) {
	t.Run("enable", func(t *testing.T) {
		s := NewService(t.TempDir(), &fakeBackend{}, nil)
		s.SetActiveAccount("wallet-a", &wallet.Account{AccountIndex: 0})
		const origin = "https://enable.example"

		done := make(chan error, 1)
		handleCtx := ctx(t)
		go func() {
			_, err := s.Handle(handleCtx, origin, "enable", nil)
			done <- err
		}()
		pendingID := waitForPendingID(t, s)
		s.SetActiveAccount("wallet-b", &wallet.Account{AccountIndex: 0})
		if err := s.Decide(pendingID, Decision{Approved: true}); err != nil {
			t.Fatalf("decide enable: %v", err)
		}
		if err := <-done; !errors.Is(err, ErrNotGranted) {
			t.Fatalf("enable after wallet switch error = %v, want ErrNotGranted", err)
		}
		if grants := s.Grants(); len(grants) != 0 {
			t.Fatalf("switched wallet received grants: %v", grants)
		}
	})

	t.Run("signTx", func(t *testing.T) {
		be := &fakeBackend{signedTx: "deadbeef"}
		s := NewService(t.TempDir(), be, nil)
		identity := accountIdentity{WalletID: "wallet-a", AccountIndex: 0}
		s.SetActiveAccount(identity.WalletID, &wallet.Account{AccountIndex: identity.AccountIndex})
		const origin = "https://sign.example"
		if err := s.grants.Grant(origin, identity); err != nil {
			t.Fatalf("Grant: %v", err)
		}

		done := make(chan error, 1)
		handleCtx := ctx(t)
		go func() {
			_, err := s.Handle(
				handleCtx, origin, "signTx",
				json.RawMessage(`{"tx":"aabbcc","partialSign":false}`),
			)
			done <- err
		}()
		pendingID := waitForPendingID(t, s)
		s.SetActiveAccount("wallet-a", &wallet.Account{AccountIndex: 1})
		if err := s.Decide(pendingID, Decision{Approved: true, Password: "secret"}); err != nil {
			t.Fatalf("decide signTx: %v", err)
		}
		if err := <-done; !errors.Is(err, ErrNotGranted) {
			t.Fatalf("signTx after account switch error = %v, want ErrNotGranted", err)
		}
		if be.signTxCalled {
			t.Fatal("backend SignTx called after the approved identity changed")
		}
	})
}

// TestServiceSubscribe verifies that a subscriber receives request notifications.
func TestServiceSubscribe(t *testing.T) {
	s := NewService(t.TempDir(), &fakeBackend{}, nil)
	bindTestIdentity(s)
	_, _ = s.ConfirmPairForTest("ext")

	ch, unsub := s.Subscribe()
	defer unsub()

	go func() {
		decideWhenPending(s, Decision{Approved: true})
	}()

	// enable will enqueue a request; the subscriber should see it.
	handleDone := make(chan error, 1)
	handleCtx := ctx(t)
	go func() {
		_, err := s.Handle(handleCtx, "https://f.io", "enable", nil)
		handleDone <- err
	}()

	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("subscriber did not receive request")
	}

	// Wait for Handle to finish writing the grant before t.TempDir cleanup.
	// Returning immediately after the notification races the atomic grant-file
	// rename with removal of the temporary directory.
	if err := <-handleDone; err != nil {
		t.Fatalf("enable: %v", err)
	}
}

// TestServiceUnpair verifies Unpair clears the token.
func TestServiceUnpair(t *testing.T) {
	s := NewService(t.TempDir(), &fakeBackend{}, nil)
	_, err := s.ConfirmPairForTest("ext")
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if err := s.Unpair(); err != nil {
		t.Fatalf("unpair: %v", err)
	}
	if s.VerifyToken("anything", "ext") {
		t.Fatal("token should be invalid after unpair")
	}
}

// TestServiceNetworkIDAndIsEnabled checks non-blocking read methods.
func TestServiceNetworkIDAndIsEnabled(t *testing.T) {
	be := &fakeBackend{networkID: 1}
	s := NewService(t.TempDir(), be, nil)
	bindTestIdentity(s)
	_, _ = s.ConfirmPairForTest("ext")

	// isEnabled returns false for ungranted origin (no error).
	out, err := s.Handle(ctx(t), "https://g.io", "isEnabled", nil)
	if err != nil {
		t.Fatalf("isEnabled ungranted: %v", err)
	}
	if string(out) != "false" {
		t.Fatalf("isEnabled want false, got %s", out)
	}

	// Grant and check getNetworkId.
	go decideWhenPending(s, Decision{Approved: true})
	if _, err := s.Handle(ctx(t), "https://g.io", "enable", nil); err != nil {
		t.Fatalf("enable: %v", err)
	}

	out, err = s.Handle(ctx(t), "https://g.io", "getNetworkId", nil)
	if err != nil {
		t.Fatalf("getNetworkId: %v", err)
	}
	if string(out) != "1" {
		t.Fatalf("getNetworkId want 1, got %s", out)
	}

	// isEnabled is true now.
	out, err = s.Handle(ctx(t), "https://g.io", "isEnabled", nil)
	if err != nil {
		t.Fatalf("isEnabled granted: %v", err)
	}
	if string(out) != "true" {
		t.Fatalf("isEnabled want true, got %s", out)
	}
}

func TestServiceGetUsedAddressesPassesPagination(t *testing.T) {
	be := &fakeBackend{usedAddrs: []string{"addr1", "addr2"}}
	s := NewService(t.TempDir(), be, nil)
	bindTestIdentity(s)
	_, _ = s.ConfirmPairForTest("ext")

	go decideWhenPending(s, Decision{Approved: true})
	if _, err := s.Handle(ctx(t), "https://g.io", "enable", nil); err != nil {
		t.Fatalf("enable: %v", err)
	}

	params := json.RawMessage(`{"paginate":{"page":1,"limit":1}}`)
	out, err := s.Handle(ctx(t), "https://g.io", "getUsedAddresses", params)
	if err != nil {
		t.Fatalf("getUsedAddresses: %v", err)
	}
	if string(out) != `["addr1","addr2"]` {
		t.Fatalf("getUsedAddresses result = %s", out)
	}
	if be.usedPaginate == nil || be.usedPaginate.Page != 1 || be.usedPaginate.Limit != 1 {
		t.Fatalf("backend paginate = %+v, want page=1 limit=1", be.usedPaginate)
	}
}

// TestServiceCIP95PrefixedMethods is a cross-layer contract test.
// It hard-codes the EXACT method strings that injected.ts emits for the three
// CIP-95 provider calls (search for "cip95." in ui/extension/src/injected.ts).
// If you rename those strings in the provider you MUST update these cases too.
func TestServiceCIP95PrefixedMethods(t *testing.T) {
	// The three strings below MUST match the sendRequest() calls in injected.ts.
	prefixedMethods := []string{
		"cip95.getPubDRepKey",
		"cip95.getRegisteredPubStakeKeys",
		"cip95.getUnregisteredPubStakeKeys",
	}

	be := &fakeBackend{}
	s := NewService(t.TempDir(), be, func() {})
	bindTestIdentity(s)
	_, _ = s.ConfirmPairForTest("ext")

	// Grant origin via enable.
	go decideWhenPending(s, Decision{Approved: true})
	if _, err := s.Handle(ctx(t), "https://dapp.example", "enable", nil); err != nil {
		t.Fatalf("enable: %v", err)
	}

	for _, method := range prefixedMethods {
		method := method // capture
		t.Run(method, func(t *testing.T) {
			// Approve the password prompt in background.
			go decideWhenPending(s, Decision{Approved: true, Password: ""})
			_, err := s.Handle(ctx(t), "https://dapp.example", method, nil)
			// Must NOT return ErrRefused (the default case) — reaching the Backend is the contract.
			if err == ErrRefused {
				t.Fatalf("method %q fell through to default (ErrRefused): cross-layer contract broken", method)
			}
			// ErrUserDeclined or nil are both acceptable here (decision-dependent).
		})
	}
}

// TestServicePendingPairings verifies that PendingPairings returns pending codes
// and that confirming removes them.
func TestServicePendingPairings(t *testing.T) {
	svc := NewService(t.TempDir(), &fakeBackend{networkID: 0}, nil)

	// Initially no pending pairings.
	if got := svc.PendingPairings(); len(got) != 0 {
		t.Fatalf("want 0 pending pairings, got %d", len(got))
	}

	// Begin a pairing: code is generated internally.
	const extID = "chrome-extension://test-pending-pairings"
	code, err := svc.BeginPair(extID)
	if err != nil {
		t.Fatalf("BeginPair: %v", err)
	}

	pairings := svc.PendingPairings()
	if len(pairings) != 1 {
		t.Fatalf("want 1 pending pairing, got %d", len(pairings))
	}
	if pairings[0].ExtensionID != extID {
		t.Errorf("extension_id: want %q, got %q", extID, pairings[0].ExtensionID)
	}
	if pairings[0].Code != code {
		t.Errorf("code: want %q, got %q", code, pairings[0].Code)
	}

	// Confirming removes the pairing from the pending list.
	if _, err := svc.ConfirmPair(extID, code); err != nil {
		t.Fatalf("ConfirmPair: %v", err)
	}
	if got := svc.PendingPairings(); len(got) != 0 {
		t.Fatalf("after confirm: want 0 pending pairings, got %d", len(got))
	}
}

func TestServiceNormalizesRawExtensionID(t *testing.T) {
	s := NewService(t.TempDir(), &fakeBackend{}, nil)
	code, err := s.BeginPair("abcdefghijklmnopabcdefghijklmnop")
	if err != nil {
		t.Fatalf("BeginPair: %v", err)
	}
	token, err := s.ConfirmPair("abcdefghijklmnopabcdefghijklmnop", code)
	if err != nil {
		t.Fatalf("ConfirmPair: %v", err)
	}
	if !s.VerifyToken(token, "chrome-extension://abcdefghijklmnopabcdefghijklmnop") {
		t.Fatal("token minted with raw extension id should verify against chrome-extension:// origin")
	}
	extID, paired := s.PairedExtensionID()
	if !paired {
		t.Fatal("want paired")
	}
	if extID != "chrome-extension://abcdefghijklmnopabcdefghijklmnop" {
		t.Fatalf("paired extension id = %q, want chrome-extension:// form", extID)
	}
}

func TestServiceRejectsMalformedSigningParamsBeforePrompt(t *testing.T) {
	prompts := 0
	s := NewService(t.TempDir(), &fakeBackend{}, func() { prompts++ })
	const origin = "https://signing.example"
	identity := bindTestIdentity(s)
	if err := s.grants.Grant(origin, identity); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	tests := []struct {
		method string
		params json.RawMessage
	}{
		{method: "signTx", params: json.RawMessage(`{"tx":`)},
		{method: "signTx", params: json.RawMessage(`{}`)},
		{method: "signData", params: json.RawMessage(`{"addr":"aa"}`)},
		{method: "signData", params: nil},
		{method: "submitTx", params: json.RawMessage(`null`)},
	}
	for _, tc := range tests {
		t.Run(tc.method+"/"+string(tc.params), func(t *testing.T) {
			if _, err := s.Handle(ctx(t), origin, tc.method, tc.params); !errors.Is(err, ErrInvalidParams) {
				t.Fatalf("Handle error = %v, want ErrInvalidParams", err)
			}
		})
	}
	if prompts != 0 {
		t.Fatalf("prompt called %d times for invalid params, want 0", prompts)
	}
	if pending := s.Pending(); len(pending) != 0 {
		t.Fatalf("invalid params queued requests: %+v", pending)
	}
}

// TestServiceSignDataAcceptsEmptyPayload verifies that a present-but-empty
// payload ("" — valid hex for the empty byte sequence) is not rejected before
// the approval UI: it must reach the queue, be approved, and be passed through
// to the backend. Only an absent payload field is rejected (covered by
// TestServiceRejectsMalformedSigningParamsBeforePrompt).
func TestServiceSignDataAcceptsEmptyPayload(t *testing.T) {
	be := &fakeBackend{signSig: "sig", signKey: "key"}
	s := NewService(t.TempDir(), be, func() {})
	const origin = "https://signdata.example"
	identity := bindTestIdentity(s)
	if err := s.grants.Grant(origin, identity); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	params := json.RawMessage(`{"addr":"aa","payload":""}`)
	go decideWhenPending(s, Decision{Approved: true, Password: "pw"})
	out, err := s.Handle(ctx(t), origin, "signData", params)
	if err != nil {
		t.Fatalf("signData with empty payload: %v", err)
	}
	if string(out) != `{"key":"key","signature":"sig"}` {
		t.Fatalf("signData result = %s", out)
	}
	if !be.signDataCalled {
		t.Fatal("backend SignData was not called for an empty payload")
	}
	if be.signDataAddr != "aa" || be.signDataPayload != "" {
		t.Fatalf("backend received addr=%q payload=%q, want addr=%q payload=\"\"",
			be.signDataAddr, be.signDataPayload, "aa")
	}
}
