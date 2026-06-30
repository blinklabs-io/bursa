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

// Package boot wires the Bursa full-node wallet stack — the supervised embedded
// Dingo node, the loopback Blockfrost-backed wallet/spend services, the
// persisted app settings, and the HTTP control surface that serves the API plus
// the embedded SPA. It is the single source of truth for "how the wallet boots"
// so every front end (the desktop binary in cmd/bursa-wallet and the gomobile
// binding in ui/mobile) brings up an identical stack on a loopback listener.
package boot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
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

// Loopback node ports. These are fixed loopback ports the embedded node binds
// for its UTxO-RPC and Blockfrost endpoints; the wallet/spend services and the
// supervisor's tip poller reach the node over these. Only the control surface
// (the HTTP API + SPA) uses an OS-assigned port (see Config.Addr).
const (
	utxorpcPort    uint = 5555
	blockfrostPort uint = 5556
)

// Config controls a wallet boot. The zero value is not usable: Network and
// DataDir are required.
type Config struct {
	// Network is the Cardano network the embedded node runs on
	// ("preview" | "preprod" | "mainnet").
	Network string
	// DataDir is the per-network data directory (db, node socket, settings,
	// keystore). It is created (0700) if missing.
	DataDir string
	// Addr is the control-surface listen address. Use "127.0.0.1:8090" for the
	// fixed desktop port or "127.0.0.1:0" to let the OS assign a free loopback
	// port (mobile); the bound port is reported by App.Addr after Start.
	Addr string
	// Logger receives node + control-surface logs. Defaults to a stderr text
	// logger when nil.
	Logger *slog.Logger
	// MithrilEnabled bootstraps a fresh node DB from a Mithril snapshot before
	// serving (faster first sync). The zero value is false (genesis sync).
	MithrilEnabled bool
	// LeanDefault seeds the first-run default for the lean-node (history-expiry)
	// profile. It only takes effect when no value has been persisted yet; once a
	// user toggles the Settings screen, the persisted value is the source of
	// truth and this seed is ignored. Mobile builds pass true.
	LeanDefault bool
}

// App is a booted wallet stack: a running supervised node and an HTTP control
// surface listening on a loopback port. It is returned by Boot and torn down by
// Stop. It is the shared runtime both the desktop binary and the mobile binding
// drive.
type App struct {
	srv      *http.Server
	listener net.Listener
	sup      *supervisor.Supervisor
	logger   *slog.Logger

	// ctx is the parent context supplied to Boot; it is forwarded to
	// supervisor.Reconnect so the re-dial is cancelled if the app is torn down.
	ctx context.Context
	// stop cancels the node/supervisor context; srvErr surfaces a control-surface
	// ListenAndServe failure to the caller (and to awaitUI on the desktop).
	stop    context.CancelFunc
	srvErr  chan error
	stopped bool
}

// Boot brings up the full wallet stack described by cfg and starts serving on a
// loopback listener. It returns once the node goroutine is launched and the
// control surface is accepting connections (readiness — the node finishing sync
// — is reported separately via the /status API). The caller owns the returned
// App and must call Stop to tear it down.
//
// Boot is the single wiring path shared by cmd/bursa-wallet (desktop) and
// ui/mobile (the gomobile binding) so both front ends boot an identical stack.
func Boot(ctx context.Context, cfg Config) (*App, error) {
	if cfg.Network == "" {
		return nil, errors.New("boot: network is required")
	}
	if cfg.DataDir == "" {
		return nil, errors.New("boot: data dir is required")
	}
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:0"
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	netID, err := cardanonet.AddressNetworkID(cfg.Network)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid network %q: must be one of %s",
			cfg.Network, cardanonet.SupportedNetworks(),
		)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir %q: %w", cfg.DataDir, err)
	}

	// The lean-node (history-expiry) profile is a persisted, user-facing setting
	// (the source of truth). LeanDefault only seeds the first-run default; once a
	// value is persisted it is honored and the seed is ignored.
	settingsStore, err := settings.Load(filepath.Join(cfg.DataDir, "settings.json"))
	if err != nil {
		return nil, fmt.Errorf("load settings: %w", err)
	}
	if err := settingsStore.SeedDefault(cfg.LeanDefault); err != nil {
		return nil, fmt.Errorf("seed lean-node default: %w", err)
	}

	sup := supervisor.New(supervisor.Config{
		Network:        cfg.Network,
		DataDir:        filepath.Join(cfg.DataDir, "db"),
		SocketPath:     filepath.Join(cfg.DataDir, "node.socket"),
		UtxorpcPort:    utxorpcPort,
		BlockfrostPort: blockfrostPort,
		Logger:         logger,
		MithrilEnabled: cfg.MithrilEnabled,
		// Read the persisted setting fresh at each node Start, so a toggle in the
		// Settings screen takes effect on the next node restart.
		HistoryExpiry: settingsStore.HistoryExpiry,
	})

	// The wallet queries the node's own loopback Blockfrost endpoint.
	walletSvc := wallet.NewService(chain.NewClient(blockfrostPort))

	// The vault is the encrypted multi-wallet store: a single file under the data
	// dir holding the wallet index (encrypted under the vault password) and each
	// wallet's seed (encrypted under its own spending password). It replaces the
	// old single plaintext/keystore model — no plaintext seeds at rest. The legacy
	// keystore is accepted only for explicit migration into the vault.
	vlt := vault.New(filepath.Join(cfg.DataDir, "vault.json"))
	legacyKeyStore := keystore.New(filepath.Join(cfg.DataDir, "keystore.json"))

	// Spending builds/signs/submits through the node's loopback UTxO-RPC
	// endpoint; the active wallet's seed is decrypted from the vault on demand.
	chainCtx := utxorpc.NewUtxoRpcChainContext(
		fmt.Sprintf("http://127.0.0.1:%d", utxorpcPort), netID, nil,
	)
	spendSvc := spend.NewService(chainCtx, vaultKeystore{v: vlt}, nil)

	// Bind the control-surface listener BEFORE starting the node so an
	// OS-assigned port (127.0.0.1:0) is known to the caller the moment Boot
	// returns — the mobile WebView needs the concrete port to load the SPA.
	listener, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("bind control surface %q: %w", cfg.Addr, err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	if err := sup.Start(runCtx); err != nil {
		cancel()
		_ = listener.Close()
		return nil, fmt.Errorf("start node: %w", err)
	}

	srv := &http.Server{
		Handler: api.NewHandler(
			sup, vlt, walletSvc, spendSvc,
			&settingsController{store: settingsStore, sup: sup},
			cfg.Network, webui.Handler(),
			api.WithLegacyKeystore(legacyKeyStore),
		),
		ReadHeaderTimeout: 5 * time.Second,
	}
	srvErr := make(chan error, 1)
	go func() {
		logger.Info("control surface listening", "addr", listener.Addr().String())
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
		}
	}()

	return &App{
		srv:      srv,
		listener: listener,
		sup:      sup,
		logger:   logger,
		ctx:      ctx,
		stop:     cancel,
		srvErr:   srvErr,
	}, nil
}

// Addr returns the control surface's bound listen address (host:port). With a
// "127.0.0.1:0" config this is the concrete OS-assigned loopback port.
func (a *App) Addr() string { return a.listener.Addr().String() }

// URL returns the control surface base URL (http://host:port) for a WebView or
// browser to load.
func (a *App) URL() string { return "http://" + a.Addr() }

// Port returns the control surface's bound TCP port.
func (a *App) Port() int {
	if tcp, ok := a.listener.Addr().(*net.TCPAddr); ok {
		return tcp.Port
	}
	return 0
}

// Err returns the channel that surfaces a fatal control-surface error (a failed
// Serve). It is buffered (size 1); a clean Stop never sends on it.
func (a *App) Err() <-chan error { return a.srvErr }

// Stop tears the stack down: it shuts the control surface down gracefully
// (draining in-flight requests up to a timeout), then cancels the node context
// so the embedded node and supervisor wind down. It is safe to call once; a
// second call is a no-op.
func (a *App) Stop() error {
	if a.stopped {
		return nil
	}
	a.stopped = true
	a.logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := a.srv.Shutdown(shutdownCtx)
	// Cancel the node context AFTER the control surface drains so in-flight API
	// calls don't see the node yanked out from under them mid-request.
	a.stop()
	a.sup.Stop()
	return err
}

// OnNetworkChanged re-dials the embedded node's peers after a host network
// change (e.g. WiFi↔cellular, loss→regain). It delegates to
// supervisor.Reconnect which performs a Stop-then-relaunch cycle on the node,
// re-establishing all peer connections while preserving the synced DataDir.
//
// It is a safe no-op when called before Boot or after Stop.
func (a *App) OnNetworkChanged() error {
	if a.sup == nil {
		return nil
	}
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return a.sup.Reconnect(ctx)
}

// OnResume re-dials the embedded node's peers after the app returns from the
// background. Peers go stale during suspension (the OS may have torn down TCP
// connections), so a Reconnect cycle re-establishes them without data loss (the
// synced DataDir is preserved; Mithril bootstrap is skipped).
//
// It is a safe no-op when called before Boot or after Stop.
func (a *App) OnResume() error {
	if a.sup == nil {
		return nil
	}
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return a.sup.Reconnect(ctx)
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
