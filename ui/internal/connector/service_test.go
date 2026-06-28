package connector

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// fakeBackend implements Backend with canned values.
type fakeBackend struct {
	networkID int
	balance   string
	utxos     []string
	signedTx  string
	submitID  string
	signSig   string
	signKey   string

	// recorded call args
	signTxCalled   bool
	signTxPassword string
	signTxTx       string
	signTxPartial  bool
}

func (b *fakeBackend) NetworkID() int { return b.networkID }

func (b *fakeBackend) Utxos(_ context.Context, _ string, _ *Paginate) ([]string, error) {
	return b.utxos, nil
}

func (b *fakeBackend) Balance(_ context.Context) (string, error) { return b.balance, nil }

func (b *fakeBackend) UsedAddresses(_ context.Context) ([]string, error) { return nil, nil }

func (b *fakeBackend) UnusedAddresses(_ context.Context) ([]string, error) { return nil, nil }

func (b *fakeBackend) ChangeAddress(_ context.Context) (string, error) { return "addr1change", nil }

func (b *fakeBackend) RewardAddresses(_ context.Context) ([]string, error) { return nil, nil }

func (b *fakeBackend) Collateral(_ context.Context, _ string) ([]string, error) { return nil, nil }

func (b *fakeBackend) SignTx(_ context.Context, txHex string, partialSign bool, password string) (string, error) {
	b.signTxCalled = true
	b.signTxTx = txHex
	b.signTxPartial = partialSign
	b.signTxPassword = password
	return b.signedTx, nil
}

func (b *fakeBackend) SignData(_, _, password string) (string, string, error) {
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

// ConfirmPairForTest is a test helper that runs BeginPair+ConfirmPair for the given extensionID.
func (s *Service) ConfirmPairForTest(extensionID string) (string, error) {
	code := s.BeginPair(extensionID)
	return s.ConfirmPair(extensionID, code)
}

// TestServiceEnableThenRead verifies the core enable→grant→read flow.
func TestServiceEnableThenRead(t *testing.T) {
	be := &fakeBackend{balance: "1a002dc6c0"}
	s := NewService(t.TempDir(), be, func() {})
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
	be := &fakeBackend{signedTx: "deadbeef"}
	s := NewService(t.TempDir(), be, func() {})
	_, _ = s.ConfirmPairForTest("ext")

	// Grant origin first via enable.
	go decideWhenPending(s, Decision{Approved: true})
	if _, err := s.Handle(ctx(t), "https://b.io", "enable", nil); err != nil {
		t.Fatalf("enable: %v", err)
	}

	params, _ := json.Marshal(map[string]interface{}{
		"tx":          "cafebabe",
		"partialSign": false,
	})
	go decideWhenPending(s, Decision{Approved: true, Password: "secret"})
	out, err := s.Handle(ctx(t), "https://b.io", "signTx", params)
	if err != nil {
		t.Fatalf("signTx approved: %v", err)
	}
	if string(out) != `"deadbeef"` {
		t.Fatalf("signTx result: %s", out)
	}
	if !be.signTxCalled || be.signTxPassword != "secret" || be.signTxTx != "cafebabe" {
		t.Fatalf("signTx backend call wrong: called=%v pw=%q tx=%q", be.signTxCalled, be.signTxPassword, be.signTxTx)
	}
}

// TestServiceSignTxReject verifies signTx returns ErrUserDeclined on reject.
func TestServiceSignTxReject(t *testing.T) {
	be := &fakeBackend{signedTx: "deadbeef"}
	s := NewService(t.TempDir(), be, func() {})
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
	_, _ = s.ConfirmPairForTest("ext")

	go decideWhenPending(s, Decision{Approved: false})
	_, err := s.Handle(ctx(t), "https://d.io", "enable", nil)
	if err != ErrUserDeclined {
		t.Fatalf("want ErrUserDeclined, got %v", err)
	}
	if s.grants.IsGranted("https://d.io") {
		t.Fatal("origin must not be granted after rejected enable")
	}
}

// TestServicePairCodeMismatch verifies ConfirmPair returns ErrPairCodeMismatch on wrong code.
func TestServicePairCodeMismatch(t *testing.T) {
	s := NewService(t.TempDir(), &fakeBackend{}, nil)
	code := s.BeginPair("ext2")
	_, err := s.ConfirmPair("ext2", code+"X")
	if err != ErrPairCodeMismatch {
		t.Fatalf("want ErrPairCodeMismatch, got %v", err)
	}
}

// TestServiceGrantsAndRevoke exercises Grants() and RevokeGrant().
func TestServiceGrantsAndRevoke(t *testing.T) {
	be := &fakeBackend{}
	s := NewService(t.TempDir(), be, nil)
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

// TestServiceSubscribe verifies that a subscriber receives request notifications.
func TestServiceSubscribe(t *testing.T) {
	s := NewService(t.TempDir(), &fakeBackend{}, nil)
	_, _ = s.ConfirmPairForTest("ext")

	ch, unsub := s.Subscribe()
	defer unsub()

	go func() {
		decideWhenPending(s, Decision{Approved: true})
	}()

	// enable will enqueue a request; the subscriber should see it.
	done := make(chan struct{})
	go func() {
		_, _ = s.Handle(ctx(t), "https://f.io", "enable", nil)
	}()
	go func() {
		select {
		case <-ch:
		case <-time.After(3 * time.Second):
			t.Errorf("subscriber did not receive request")
		}
		close(done)
	}()
	<-done
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
	code := svc.BeginPair(extID)

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
