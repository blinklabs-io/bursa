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
//
// Command bursa-wallet is the Bursa full-node wallet: a single binary that
// embeds and supervises Dingo and exposes a local control surface.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/blinklabs-io/apollo/v2/backend/utxorpc"
	"github.com/blinklabs-io/bursa/ui/internal/api"
	"github.com/blinklabs-io/bursa/ui/internal/cardanonet"
	"github.com/blinklabs-io/bursa/ui/internal/chain"
	"github.com/blinklabs-io/bursa/ui/internal/dex"
	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
	"github.com/blinklabs-io/bursa/ui/internal/webui"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bursa-wallet:", err)
		os.Exit(1)
	}
}

func run() error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	network := envOr("BURSA_NETWORK", "preview")
	netID, err := cardanonet.AddressNetworkID(network)
	if err != nil {
		return fmt.Errorf("invalid BURSA_NETWORK %q: must be one of %s", network, cardanonet.SupportedNetworks())
	}
	dataDir := filepath.Join(home, ".bursa-wallet", network)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}

	const (
		utxorpcPort    uint = 5555
		blockfrostPort uint = 5556
	)
	// Mithril fast-sync is on by default; BURSA_SYNC=genesis opts out.
	mithrilEnabled := !strings.EqualFold(envOr("BURSA_SYNC", "mithril"), "genesis")
	sup := supervisor.New(supervisor.Config{
		Network:        network,
		DataDir:        filepath.Join(dataDir, "db"),
		SocketPath:     filepath.Join(dataDir, "node.socket"),
		UtxorpcPort:    utxorpcPort,
		BlockfrostPort: blockfrostPort,
		Logger:         logger,
		MithrilEnabled: mithrilEnabled,
	})

	// The wallet queries the node's own loopback Blockfrost endpoint.
	chainClient := chain.NewClient(blockfrostPort)
	walletSvc := wallet.NewService(chainClient)

	// DEX swap quotes are computed entirely from the embedded node (pool UTxOs at
	// the DEX script addresses via the same loopback Blockfrost endpoint) — no
	// external service. shai's pool locators are mainnet-only.
	dexSvc := dex.NewService(chainClient, network)

	// Spending builds/signs/submits through the node's loopback UTxO-RPC
	// endpoint; the mnemonic is encrypted at rest under the data dir.
	chainCtx := utxorpc.NewUtxoRpcChainContext(
		fmt.Sprintf("http://127.0.0.1:%d", utxorpcPort), netID, nil,
	)
	keyStore := keystore.New(filepath.Join(dataDir, "keystore.json"))
	spendSvc := spend.NewService(chainCtx, keyStore, nil)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := sup.Start(ctx); err != nil {
		return fmt.Errorf("start node: %w", err)
	}
	defer sup.Stop()

	srv := &http.Server{
		Addr:              "127.0.0.1:8090", // loopback only
		Handler:           api.NewHandler(sup, walletSvc, spendSvc, dexSvc, network, webui.Handler()),
		ReadHeaderTimeout: 5 * time.Second,
	}
	srvErr := make(chan error, 1)
	go func() {
		logger.Info("control surface listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
		}
	}()

	// Block until it's time to shut down. The default (headless) build waits for a
	// signal and serves the UI over loopback for a browser; the `webview` build
	// opens a native window onto the same loopback UI and waits for it to close.
	uiErr := awaitUI(ctx, "http://"+srv.Addr, logger, srvErr)

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	return uiErr
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
