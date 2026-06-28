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
	"github.com/blinklabs-io/bursa/ui/internal/multisig"
	"github.com/blinklabs-io/bursa/ui/internal/poolops"
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
	sup := supervisor.New(supervisor.Config{
		Network:        network,
		DataDir:        filepath.Join(dataDir, "db"),
		SocketPath:     filepath.Join(dataDir, "node.socket"),
		UtxorpcPort:    utxorpcPort,
		BlockfrostPort: blockfrostPort,
		Logger:         logger,
		MithrilEnabled: mithrilEnabled,
	})

	// The wallet queries the node's own loopback Blockfrost endpoint. The same
	// client also verifies pasted pool/DRep IDs and reads protocol params for the
	// staking flow (consent law: the embedded node is the only network contact).
	chainClient := chain.NewClient(blockfrostPort)
	walletSvc := wallet.NewService(chainClient)

	// The vault is the encrypted multi-wallet store: a single file under the data
	// dir holding the wallet index (encrypted under the vault password) and each
	// wallet's seed (encrypted under its own spending password). It replaces the
	// old single plaintext/keystore model — no plaintext seeds at rest.
	vlt := vault.New(filepath.Join(dataDir, "vault.json"))
	legacyKeyStore := keystore.New(filepath.Join(dataDir, "keystore.json"))

	// DEX swap quotes are computed entirely from the embedded node (pool UTxOs at
	// the DEX script addresses via the same loopback Blockfrost endpoint) — no
	// external service. shai's pool locators are mainnet-only.
	dexSvc := dex.NewService(chainClient, network)

	// Spending builds/signs/submits through the node's loopback UTxO-RPC
	// endpoint; the active wallet's seed is decrypted from the vault on demand.
	// Delegation txs additionally query pool/DRep/account state + protocol params
	// through the Blockfrost client.
	chainCtx := utxorpc.NewUtxoRpcChainContext(
		fmt.Sprintf("http://127.0.0.1:%d", utxorpcPort), netID, nil,
	)
	spendSvc := spend.NewService(chainCtx, vaultKeystore{v: vlt}, nil)
	spendSvc.SetChainQuerier(chainClient)

	// Stake Pool Operations: derives cold/VRF/KES credentials and builds/submits
	// pool certificates on the active wallet, sharing the spend chain context for
	// submission. Genesis (for KES-period math) comes from the node's loopback
	// Blockfrost endpoint; the tip comes from the supervisor — no external call.
	poolGenesis := chain.NewClient(blockfrostPort)
	poolSvc := poolops.NewService(
		chainCtx, vaultKeystore{v: vlt},
		genesisAdapter{c: poolGenesis},
		tipAdapter{sup: sup},
	)

	// Native multi-sig accounts are persisted in a JSON file under the data dir;
	// signing uses the active wallet's CIP-1854 key, decrypted from the vault.
	multisigSvc := multisig.NewService(chainCtx, vaultKeystore{v: vlt}, filepath.Join(dataDir, "multisig.json"))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := sup.Start(ctx); err != nil {
		return fmt.Errorf("start node: %w", err)
	}
	defer sup.Stop()

	srv := &http.Server{
		Addr:              "127.0.0.1:8090", // loopback only
		Handler:           api.NewHandler(sup, vlt, walletSvc, spendSvc, chainClient, poolSvc, multisigSvc, dexSvc, network, webui.Handler(), api.WithLegacyKeystore(legacyKeyStore)),
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

// genesisAdapter adapts the loopback Blockfrost chain client to the genesis
// subset the SPO toolkit's KES-period math needs.
type genesisAdapter struct{ c *chain.Client }

func (g genesisAdapter) Genesis(ctx context.Context) (poolops.Genesis, error) {
	gen, err := g.c.Genesis(ctx)
	if err != nil {
		return poolops.Genesis{}, err
	}
	return poolops.Genesis{
		SlotsPerKESPeriod: gen.SlotsPerKESPeriod,
		MaxKESEvolutions:  gen.MaxKESEvolutions,
		EpochLength:       gen.EpochLength,
	}, nil
}

// tipAdapter exposes the supervisor's current tip slot to the SPO toolkit.
type tipAdapter struct{ sup *supervisor.Supervisor }

func (t tipAdapter) TipSlot() uint64 { return t.sup.Status().Tip }
