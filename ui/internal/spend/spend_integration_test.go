//go:build integration

package spend_test

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/apollo/v2/backend/utxorpc"

	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

// previewTestMnemonic is the standard 12-word test vector; its preview account
// is normally unfunded, so Build is expected to report insufficient funds.
const previewTestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// TestSpendBuildLivePreview boots a preview node and exercises spend.Build against
// the node's live UTxO-RPC endpoint. It does NOT submit (that needs a funded
// account): a clean preview or a clear insufficient-funds error both pass.
func TestSpendBuildLivePreview(t *testing.T) {
	dir := t.TempDir()
	var lastErr error
	for attempt := 1; attempt <= 5; attempt++ {
		err := runSpendBuildLivePreview(t, dir, attempt)
		if err == nil {
			return
		}
		if !isAddrInUse(err) {
			t.Fatal(err)
		}
		lastErr = err
		t.Logf("utxorpc port raced on attempt %d; retrying with a new port: %v", attempt, err)
	}
	t.Fatalf("preview node utxorpc port still unavailable after retries: %v", lastErr)
}

func runSpendBuildLivePreview(t *testing.T, dir string, attempt int) error {
	t.Helper()
	rpcPort, err := freeTCPPort()
	if err != nil {
		return err
	}
	sup := supervisor.New(supervisor.Config{
		Network:        "preview",
		DataDir:        filepath.Join(dir, fmt.Sprintf("db-%d", attempt)),
		SocketPath:     filepath.Join(dir, fmt.Sprintf("node-%d.socket", attempt)),
		UtxorpcPort:    rpcPort,
		BlockfrostPort: 0,
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

	// preview is a testnet → network id 0.
	cc := utxorpc.NewUtxoRpcChainContext(fmt.Sprintf("http://127.0.0.1:%d", rpcPort), 0, nil)
	ks := keystore.New(filepath.Join(dir, fmt.Sprintf("keystore-%d.json", attempt)))
	svc := spend.NewService(cc, ks, nil)
	if _, err := svc.SetWallet(previewTestMnemonic, "preview", "integration-pw"); err != nil {
		return fmt.Errorf("SetWallet: %w", err)
	}

	acct, err := wallet.Derive(previewTestMnemonic, "preview", 2)
	if err != nil {
		return fmt.Errorf("Derive: %w", err)
	}
	pv, err := svc.Build(ctx, spend.SendRequest{To: acct.ReceiveAddresses[1], Lovelace: "1000000"})
	if err != nil {
		// Unfunded wallet (or partial UTxO view while syncing) → insufficient
		// funds. That is the expected outcome here, not a failure.
		low := strings.ToLower(err.Error())
		if strings.Contains(low, "insufficient") || strings.Contains(low, "utxo") {
			t.Logf("Build reported expected insufficient funds: %v", err)
			return nil
		}
		return fmt.Errorf("Build: unexpected error: %w", err)
	}
	t.Logf("Build produced a preview: pending=%s fee=%s", pv.PendingID, pv.Fee)
	return nil
}

func freeTCPPort() (uint, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("Listen: %w", err)
	}
	port := uint(l.Addr().(*net.TCPAddr).Port)
	if err := l.Close(); err != nil {
		return 0, fmt.Errorf("close port probe: %w", err)
	}
	return port, nil
}

func isAddrInUse(err error) bool {
	return strings.Contains(err.Error(), "address already in use") ||
		strings.Contains(err.Error(), "EADDRINUSE")
}
