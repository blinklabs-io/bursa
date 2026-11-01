package keystore

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// exhaustProcessUnlockBudget puts the process-wide budget at its failure limit
// and restores an empty budget when the test ends, so later tests that run the
// production KDF are unaffected.
func exhaustProcessUnlockBudget(t *testing.T) {
	t.Helper()
	processUnlockBudget.mu.Lock()
	processUnlockBudget.active = false
	processUnlockBudget.failures = unlockFailureLimit
	processUnlockBudget.windowStart = time.Now()
	processUnlockBudget.mu.Unlock()
	t.Cleanup(resetProcessUnlockBudget)
}

func resetProcessUnlockBudget() {
	processUnlockBudget.mu.Lock()
	defer processUnlockBudget.mu.Unlock()
	processUnlockBudget.active = false
	processUnlockBudget.failures = 0
	processUnlockBudget.windowStart = time.Time{}
}

func processUnlockFailures() int {
	processUnlockBudget.mu.Lock()
	defer processUnlockBudget.mu.Unlock()
	return processUnlockBudget.failures
}

// productionContainer has production-range KDF params, so decrypt reaches the
// budget check. Its ciphertext never authenticates.
func productionContainer() Container {
	return Container{
		Version: containerVersion,
		KDF:     "scrypt",
		N:       productionKDF.n, R: productionKDF.r, P: productionKDF.p,
		Salt:       hex.EncodeToString(make([]byte, saltLen)),
		Nonce:      hex.EncodeToString(make([]byte, gcmNonceLen)),
		Ciphertext: hex.EncodeToString(make([]byte, 32)),
	}
}

func TestUnlockBudgetLimitsFailures(t *testing.T) {
	var b unlockBudget
	for i := range unlockFailureLimit {
		finish, err := b.begin()
		if err != nil {
			t.Fatalf("attempt %d: begin: %v", i+1, err)
		}
		finish(true)
	}
	if _, err := b.begin(); !errors.Is(err, ErrUnlockLimited) {
		t.Fatalf("begin after %d failures = %v, want ErrUnlockLimited", unlockFailureLimit, err)
	}
}

func TestUnlockBudgetIgnoresSuccesses(t *testing.T) {
	var b unlockBudget
	for i := range unlockFailureLimit * 2 {
		finish, err := b.begin()
		if err != nil {
			t.Fatalf("attempt %d: begin: %v", i+1, err)
		}
		finish(false)
	}
	if b.failures != 0 {
		t.Fatalf("failures = %d after successful attempts, want 0", b.failures)
	}
}

func TestUnlockBudgetRejectsConcurrentDerivation(t *testing.T) {
	var b unlockBudget
	finish, err := b.begin()
	if err != nil {
		t.Fatalf("first begin: %v", err)
	}
	if _, err := b.begin(); !errors.Is(err, ErrUnlockLimited) {
		t.Fatalf("begin during an active derivation = %v, want ErrUnlockLimited", err)
	}
	finish(false)
	finish, err = b.begin()
	if err != nil {
		t.Fatalf("begin after the active derivation finished: %v", err)
	}
	finish(false)
}

func TestUnlockBudgetWindowResets(t *testing.T) {
	var b unlockBudget
	for range unlockFailureLimit {
		finish, err := b.begin()
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		finish(true)
	}
	if _, err := b.begin(); !errors.Is(err, ErrUnlockLimited) {
		t.Fatalf("begin at the limit = %v, want ErrUnlockLimited", err)
	}
	// Age the window instead of waiting for it to elapse.
	b.windowStart = b.windowStart.Add(-unlockFailureWindow)
	finish, err := b.begin()
	if err != nil {
		t.Fatalf("begin after the window elapsed: %v", err)
	}
	finish(true)
	if b.failures != 1 {
		t.Fatalf("failures = %d after reset and one failure, want 1", b.failures)
	}
}

func TestOpenProductionKDFLimited(t *testing.T) {
	exhaustProcessUnlockBudget(t)
	blob, err := json.Marshal(productionContainer())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := Open(blob, []byte("longpassword")); !errors.Is(err, ErrUnlockLimited) {
		t.Fatalf("Open with an exhausted budget = %v, want ErrUnlockLimited", err)
	}
}

func TestUnlockProductionKDFLimited(t *testing.T) {
	exhaustProcessUnlockBudget(t)
	blob, err := json.Marshal(productionContainer())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "keystore.json")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := New(path).Unlock("longpassword"); !errors.Is(err, ErrUnlockLimited) {
		t.Fatalf("Unlock with an exhausted budget = %v, want ErrUnlockLimited", err)
	}
}

// The cheap test KDF is outside the budget: an exhausted budget does not block
// it, and its failures are not counted.
func TestCheapKDFExemptFromUnlockBudget(t *testing.T) {
	exhaustProcessUnlockBudget(t)
	seal, open := CheapTestSealer()
	blob, err := seal([]byte("plaintext"), "right-password")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := open(blob, []byte("wrong-password")); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("open with wrong password = %v, want ErrDecryptFailed", err)
	}
	got, err := open(blob, []byte("right-password"))
	if err != nil {
		t.Fatalf("open with right password: %v", err)
	}
	if string(got) != "plaintext" {
		t.Fatalf("open = %q, want plaintext", got)
	}
	if n := processUnlockFailures(); n != unlockFailureLimit {
		t.Fatalf("process failures = %d after cheap KDF attempts, want %d", n, unlockFailureLimit)
	}
}

// One wrong password at production cost is counted once and releases the
// active slot.
func TestProductionKDFFailureCounted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping production-cost scrypt in -short mode")
	}
	resetProcessUnlockBudget()
	t.Cleanup(resetProcessUnlockBudget)
	blob, err := json.Marshal(productionContainer())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	_, err = Open(blob, []byte("longpassword"))
	if !errors.Is(err, ErrDecryptFailed) || !strings.Contains(err.Error(), "wrong password") {
		t.Fatalf("Open = %v, want ErrDecryptFailed", err)
	}
	processUnlockBudget.mu.Lock()
	failures, active := processUnlockBudget.failures, processUnlockBudget.active
	processUnlockBudget.mu.Unlock()
	if failures != 1 || active {
		t.Fatalf("budget after one failure: failures=%d active=%v, want 1 false", failures, active)
	}
}
