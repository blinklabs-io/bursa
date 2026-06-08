//go:build integration

package wallet_test

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

func TestWalletQueriesLivePreview(t *testing.T) {
	dir := t.TempDir()

	var lastErr error
	for attempt := 1; attempt <= 5; attempt++ {
		err := runWalletQueriesLivePreview(t, dir, attempt)
		if err == nil {
			return
		}
		if !isAddrInUse(err) {
			t.Fatal(err)
		}
		lastErr = err
		t.Logf("Blockfrost port raced on attempt %d; retrying with a new port: %v", attempt, err)
	}
	t.Fatalf("preview node Blockfrost port still unavailable after retries: %v", lastErr)
}

func runWalletQueriesLivePreview(t *testing.T, dir string, attempt int) error {
	t.Helper()
	bfPort, err := freeTCPPort()
	if err != nil {
		return err
	}
	sup := supervisor.New(supervisor.Config{
		Network:        "preview",
		DataDir:        filepath.Join(dir, fmt.Sprintf("db-%d", attempt)),
		SocketPath:     filepath.Join(dir, fmt.Sprintf("node-%d.socket", attempt)),
		UtxorpcPort:    0,
		BlockfrostPort: bfPort,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx); err != nil {
		return fmt.Errorf("Start: %w", err)
	}
	defer sup.Stop()

	deadline := time.Now().Add(90 * time.Second)
	for {
		st := sup.Status()
		if st.State == supervisor.StateSyncing || st.State == supervisor.StateReady {
			break
		}
		if st.State == supervisor.StateError {
			return fmt.Errorf("node errored: %s", st.Err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("node not syncing within 90s; last state: %s", st.State)
		}
		time.Sleep(2 * time.Second)
	}

	svc := wallet.NewService(chain.NewClient(bfPort))
	acct, err := svc.SetWallet(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"preview", 5,
	)
	if err != nil {
		return fmt.Errorf("SetWallet: %w", err)
	}
	t.Logf("stake address: %s", acct.StakeAddress)

	if _, err := svc.Addresses(ctx); err != nil {
		return fmt.Errorf("Addresses: %w", err)
	}
	if _, err := svc.Balance(ctx); err != nil {
		return fmt.Errorf("Balance: %w", err)
	}
	return nil
}

func freeTCPPort() (uint, error) {
	// Dingo's Blockfrost API accepts a numeric port only, and port 0 disables the
	// server. Pick an ephemeral port, then let the caller retry if another process
	// binds it before Dingo starts.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("Listen: %w", err)
	}
	bfPort := uint(l.Addr().(*net.TCPAddr).Port)
	if err := l.Close(); err != nil {
		return 0, fmt.Errorf("close port probe: %w", err)
	}
	return bfPort, nil
}

func isAddrInUse(err error) bool {
	return strings.Contains(err.Error(), "address already in use") ||
		strings.Contains(err.Error(), "EADDRINUSE")
}
