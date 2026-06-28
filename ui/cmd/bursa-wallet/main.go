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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/blinklabs-io/apollo/v2/backend/utxorpc"
	"github.com/blinklabs-io/bursa/ui/internal/api"
	"github.com/blinklabs-io/bursa/ui/internal/cardanonet"
	"github.com/blinklabs-io/bursa/ui/internal/chain"
	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/settings"
	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
	"github.com/blinklabs-io/bursa/ui/internal/vault"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
	"github.com/blinklabs-io/bursa/ui/internal/webui"
)

// vaultKeystore adapts the encrypted vault to the spend service's Keystore
// interface. The vault owns seed encryption and the active-wallet selection, so
// Unlock decrypts the ACTIVE wallet's seed under the supplied spending password;
// Create is unsupported (wallets are added via the vault) and Exists is true
// whenever a wallet is active.
type vaultKeystore struct{ v *vault.Vault }

func (k vaultKeystore) Exists() bool { return k.v.ActiveID() != "" }

func (k vaultKeystore) Create(string, string) error {
	return errors.New("wallets are added through the vault, not the keystore")
}

func (k vaultKeystore) Unlock(password string) ([]byte, error) {
	return k.v.UnlockSeed(password)
}

func (k vaultKeystore) UnlockFor(walletID, password string) ([]byte, error) {
	return k.v.UnlockSeedFor(walletID, password)
}

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

	// The lean-node (history-expiry) profile is now a persisted, user-facing app
	// setting (the source of truth) rather than an env-only control. BURSA_LEAN
	// only SEEDS the first-run default — once a value is persisted (default off,
	// or whatever the user later sets in the Settings screen), the env is ignored.
	// This keeps the env as the initial-default seed for mobile builds.
	settingsStore, err := settings.Load(filepath.Join(dataDir, "settings.json"))
	if err != nil {
		return fmt.Errorf("load settings: %w", err)
	}
	if err := settingsStore.SeedDefault(envBool("BURSA_LEAN", false)); err != nil {
		return fmt.Errorf("seed lean-node default: %w", err)
	}

	sup := supervisor.New(supervisor.Config{
		Network:        network,
		DataDir:        filepath.Join(dataDir, "db"),
		SocketPath:     filepath.Join(dataDir, "node.socket"),
		UtxorpcPort:    utxorpcPort,
		BlockfrostPort: blockfrostPort,
		Logger:         logger,
		MithrilEnabled: mithrilEnabled,
		// Read the persisted setting fresh at each node Start, so a toggle in the
		// Settings screen takes effect on the next node restart.
		HistoryExpiry: settingsStore.HistoryExpiry,
	})

	// The wallet queries the node's own loopback Blockfrost endpoint.
	walletSvc := wallet.NewService(chain.NewClient(blockfrostPort))

	// The vault is the encrypted multi-wallet store: a single file under the data
	// dir holding the wallet index (encrypted under the vault password) and each
	// wallet's seed (encrypted under its own spending password). It replaces the
	// old single plaintext/keystore model — no plaintext seeds at rest.
	vlt := vault.New(filepath.Join(dataDir, "vault.json"))
	legacyKeyStore := keystore.New(filepath.Join(dataDir, "keystore.json"))

	// Spending builds/signs/submits through the node's loopback UTxO-RPC
	// endpoint; the active wallet's seed is decrypted from the vault on demand.
	chainCtx := utxorpc.NewUtxoRpcChainContext(
		fmt.Sprintf("http://127.0.0.1:%d", utxorpcPort), netID, nil,
	)
	spendSvc := spend.NewService(chainCtx, vaultKeystore{v: vlt}, nil)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := sup.Start(ctx); err != nil {
		return fmt.Errorf("start node: %w", err)
	}
	defer sup.Stop()

	srv := &http.Server{
		Addr: "127.0.0.1:8090", // loopback only
		Handler: api.NewHandler(
			sup, vlt, walletSvc, spendSvc,
			&settingsController{store: settingsStore, sup: sup},
			network, webui.Handler(),
			api.WithLegacyKeystore(legacyKeyStore),
		),
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

// envBool reads a boolean env var, falling back to def when unset or unparsable.
// Accepts the usual strconv.ParseBool truthy/falsy values (1/0, t/f, true/false).
func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// settingsController adapts the persisted settings store + the supervisor to the
// api.SettingsController surface. The store is the source of truth for the
// lean-node profile; the supervisor reports what the running node was actually
// built with, so a change can be flagged as needing a node restart.
type settingsController struct {
	store *settings.Store
	sup   *supervisor.Supervisor
}

func (c *settingsController) HistoryExpiry() bool { return c.store.HistoryExpiry() }

func (c *settingsController) SetHistoryExpiry(enabled bool) error {
	return c.store.SetHistoryExpiry(enabled)
}

// HistoryExpiryRestartRequired reports whether the persisted value differs from
// what the running node was launched with. History expiry is a node-construction
// option, so it only takes effect on the next node start: if no node has been
// launched yet (ran=false), there is nothing to restart, so it is not required.
func (c *settingsController) HistoryExpiryRestartRequired() bool {
	applied, ran := c.sup.AppliedHistoryExpiry()
	if !ran {
		return false
	}
	return applied != c.store.HistoryExpiry()
}
