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
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"sync"
	"time"

	"github.com/blinklabs-io/dingo"
	"github.com/blinklabs-io/dingo/config/cardano"
	"github.com/blinklabs-io/dingo/connmanager"
	"github.com/blinklabs-io/dingo/topology"
)

// Config configures the embedded node. All network endpoints bind to loopback.
type Config struct {
	Network        string // "preview" | "preprod" | "mainnet"
	DataDir        string
	SocketPath     string // N2C unix socket (for adder/oracle in later phases)
	UtxorpcPort    uint
	BlockfrostPort uint
	Logger         *slog.Logger
	// CaughtUpThreshold is how recent the latest block must be to be "ready".
	CaughtUpThreshold time.Duration
	// MithrilEnabled bootstraps a fresh node DB from a Mithril snapshot before
	// serving. The zero value is false (genesis sync); main.go enables it by
	// default and BURSA_SYNC=genesis opts out.
	MithrilEnabled bool
	// HistoryExpiry reports whether the "lean node" (history-expiry) profile is
	// enabled. It is a provider (not a static bool) so the persisted user setting
	// is the source of truth: it is read fresh every time the node config is built
	// (each launch, including after asynchronous bootstrap), letting a toggled
	// setting take effect on the next node restart. A nil provider, or one
	// returning false, keeps full immutable block history (behavior unchanged).
	// When it returns true (the lean/mobile profile), the node periodically
	// prunes immutable blocks older than the stability window, keeping the ledger
	// state and recent blocks — a much smaller on-disk footprint at the cost of
	// deep block history.
	HistoryExpiry func() bool
}

// NodeRunner is the interface the supervisor uses to create and run the embedded
// node. It is an interface (not a concrete dingo.Node) so the orchestration can
// be unit-tested without network connectivity (the production implementation
// calls dingo.New and then node.Run).
type NodeRunner interface {
	// Run starts the node and blocks until ctx is cancelled. An error from a
	// graceful cancellation (ctx.Err() != nil) is treated as orderly shutdown.
	Run(ctx context.Context) error
}

// NodeFactory creates a NodeRunner from a dingo config. It is injectable for
// tests (the real factory calls dingo.New).
type NodeFactory interface {
	New(cfg dingo.Config) (NodeRunner, error)
}

// dingoNodeFactory is the production NodeFactory backed by dingo.New.
type dingoNodeFactory struct{}

func (dingoNodeFactory) New(cfg dingo.Config) (NodeRunner, error) { return dingo.New(cfg) }

// Supervisor owns the embedded Dingo node's lifecycle and exposes its status.
type Supervisor struct {
	cfg     Config
	cancel  context.CancelFunc
	runDone chan struct{}
	runID   uint64

	lifecycleMu sync.Mutex
	mu          sync.RWMutex
	status      Status
	// applied records the history-expiry value the currently-running node was
	// built with, so the API can tell whether a changed setting still needs a
	// restart to take effect. ran is false until the node has been launched at
	// least once this process.
	applied struct {
		historyExpiry bool
		ran           bool
	}

	now          func() time.Time // injectable clock for tests
	bootstrapper Bootstrapper     // injectable for tests
	nodeFactory  NodeFactory      // injectable for tests
}

func New(cfg Config) *Supervisor {
	if cfg.CaughtUpThreshold == 0 {
		cfg.CaughtUpThreshold = 2 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Supervisor{
		cfg:          cfg,
		status:       Status{State: StateStopped},
		now:          time.Now,
		bootstrapper: mithrilBootstrapper{logger: cfg.Logger},
		nodeFactory:  dingoNodeFactory{},
	}
}

// historyExpiryEnabled resolves the lean-node profile from the (optional)
// provider. A nil provider means the feature is not wired in (default off).
func (cfg Config) historyExpiryEnabled() bool {
	return cfg.HistoryExpiry != nil && cfg.HistoryExpiry()
}

// nodeConfigOptions builds the dingo option set for the embedded node. It is a
// standalone function (not inlined into Start) so the config wiring — in
// particular the opt-in history-expiry profile — can be unit-tested without
// constructing a real node. historyExpiry is the resolved profile value, passed
// in so the caller controls when the source-of-truth provider is read.
func nodeConfigOptions(
	cfg Config,
	historyExpiry bool,
	cardanoCfg *cardano.CardanoNodeConfig,
	topologyCfg *topology.TopologyConfig,
) []dingo.ConfigOptionFunc {
	opts := []dingo.ConfigOptionFunc{
		dingo.WithNetwork(cfg.Network),
		dingo.WithCardanoNodeConfig(cardanoCfg),
		dingo.WithTopologyConfig(topologyCfg),
		dingo.WithDatabasePath(cfg.DataDir),
		dingo.WithStorageMode(dingo.StorageModeAPI),
		// Without an explicit capacity the mempool defaults to 0 bytes and
		// rejects every transaction ("mempool full: capacity=0 bytes"), so the
		// wallet could never submit a spend. Match Dingo's own Praos default
		// (1 MiB) — ample for a single-user wallet submitting its own txs.
		dingo.WithMempoolCapacity(1 << 20),
		dingo.WithBindAddr("127.0.0.1"),
		dingo.WithUtxorpcPort(cfg.UtxorpcPort),
		dingo.WithBlockfrostPort(cfg.BlockfrostPort),
		dingo.WithListeners(connmanager.ListenerConfig{
			ListenNetwork: "unix",
			ListenAddress: cfg.SocketPath,
			UseNtC:        true,
		}),
		dingo.WithLogger(cfg.Logger),
	}
	// Lean-node profile: opt in to dingo's history expiry so the node prunes
	// immutable block history past the stability window. Off by default, where
	// the node keeps full history (behavior unchanged).
	if historyExpiry {
		opts = append(opts, dingo.WithHistoryExpiry(dingo.HistoryExpiryConfig{
			Enabled:   true,
			Frequency: time.Hour,
		}))
	}
	return opts
}

// AppliedHistoryExpiry reports the history-expiry value the currently/last
// launched node was built with, and whether a node has been launched at all
// this process (ran). The API compares this against the persisted setting to
// decide whether a change still needs a node restart to take effect.
func (s *Supervisor) AppliedHistoryExpiry() (applied bool, ran bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.applied.historyExpiry, s.applied.ran
}

// ErrAlreadyStarted is returned by Start when the supervisor is already running.
// Reconnect folds this sentinel to nil (the node is running, which is the
// desired post-reconnect state) so callers can use errors.Is to distinguish it
// from real failures.
var ErrAlreadyStarted = errors.New("supervisor already started")

// Start constructs the node, launches it, and begins polling its tip. It
// returns once the node goroutine is launched; readiness is reported via Status.
func (s *Supervisor) Start(ctx context.Context) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	return s.start(ctx)
}

func (s *Supervisor) start(ctx context.Context) error {
	// Guard against double-start: reserve s.cancel atomically so a second Start
	// can't overwrite (and orphan) the first node and poll loop.
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return ErrAlreadyStarted
	}
	runCtx, cancel := context.WithCancel(ctx)
	runDone := make(chan struct{})
	var completeOnce sync.Once
	completeRun := func() {
		completeOnce.Do(func() {
			close(runDone)
		})
	}
	s.runID++
	runID := s.runID
	s.cancel = cancel
	s.runDone = runDone
	s.mu.Unlock()

	// fail releases the reservation so Start can be retried if we error out
	// before the node goroutine is launched.
	fail := func(err error) error {
		s.mu.Lock()
		if s.activeRunLocked(runID) {
			s.cancel = nil
			s.runDone = nil
		}
		s.mu.Unlock()
		cancel()
		completeRun()
		return err
	}

	// Dingo's ledger state dereferences the network config (genesis) on startup,
	// so it must be provided. Load it from disk if present, otherwise fall back
	// to the config embedded in Dingo for the well-known networks.
	// This mirrors how Dingo's own CLI wires the node.
	cardanoCfg, err := cardano.LoadCardanoNodeConfigWithFallback(
		s.cfg.Network+"/config.json", s.cfg.Network, cardano.EmbeddedConfigFS,
	)
	if err != nil {
		return fail(fmt.Errorf("load Dingo network config: %w", err))
	}

	// Outbound peers: load the network's embedded topology (bootstrap peers +
	// peer snapshot) so the node can follow the chain to the live tip once the
	// Mithril snapshot is loaded. Without a topology, Dingo configures no
	// outbound peers and the node never advances past the bootstrap tip (stuck
	// in "syncing"). Mirrors how Dingo's own node wires topology from its
	// embedded config.
	topologyCfg, err := topology.NewTopologyConfigFromFS(
		cardano.EmbeddedConfigFS, path.Join(s.cfg.Network, "topology.json"),
	)
	if err != nil {
		return fail(fmt.Errorf("load Dingo topology config: %w", err))
	}

	// launch creates the node, marks it starting, and begins serving + polling.
	// Used by both the direct and post-bootstrap paths.
	launch := func() error {
		// Read the lean-node profile from its persisted source of truth at the
		// actual construction point. In the Mithril path, Start returns while
		// bootstrap is still running, so reading earlier can freeze a stale value
		// before the first node exists.
		historyExpiry := s.cfg.historyExpiryEnabled()
		nodeCfg := dingo.NewConfig(nodeConfigOptions(s.cfg, historyExpiry, cardanoCfg, topologyCfg)...)
		node, err := s.nodeFactory.New(nodeCfg)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.applied.historyExpiry = historyExpiry
		s.applied.ran = true
		s.mu.Unlock()
		s.setStateForRun(runID, StateStarting)
		go func() {
			defer completeRun()
			if err := node.Run(runCtx); err != nil && runCtx.Err() == nil {
				s.setErrorForRun(runID, err)
			}
		}()
		go s.pollLoop(runCtx, runID)
		return nil
	}

	if !shouldBootstrap(s.cfg.MithrilEnabled, s.cfg.DataDir) {
		if err := launch(); err != nil {
			return fail(fmt.Errorf("create node: %w", err))
		}
		return nil
	}

	// Mithril bootstrap path: run asynchronously so /status stays live; node
	// creation is deferred until the snapshot import finishes (mithril.Sync and
	// the node cannot both hold the DB).
	s.setStateForRun(runID, StateBootstrapping)
	go s.bootstrapThenLaunch(runCtx, runID, launch, completeRun)
	return nil
}

// bootstrapThenLaunch runs the Mithril bootstrap and, on success, records the
// completion marker and launches the node. Any failure → StateError (no fallback).
func (s *Supervisor) bootstrapThenLaunch(ctx context.Context, runID uint64, launch func() error, completeRun func()) {
	launched := false
	defer func() {
		if !launched {
			completeRun()
		}
	}()

	err := s.bootstrapper.Bootstrap(ctx, BootstrapParams{
		Network: s.cfg.Network,
		DataDir: s.cfg.DataDir,
		OnProgress: func(bp BootstrapProgress) {
			s.onProgressForRun(runID, bp)
		},
	})
	if err != nil {
		// A bootstrap aborted by context cancellation (Stop or parent shutdown)
		// is an orderly wind-down, not a failure — same guard as node.Run.
		if ctx.Err() == nil {
			s.setErrorForRun(runID, fmt.Errorf("mithril bootstrap: %w", err))
		}
		return
	}
	if ctx.Err() != nil {
		return
	}
	// Record completion before launch, deliberately: mithril.Sync's success
	// contract is a complete, servable DB, while a launch failure (dingo.New
	// only validates config) is not something a re-bootstrap can fix. An
	// unwritten marker here would make the next start re-download the entire
	// snapshot over an already-complete DB.
	if err := markBootstrapDone(s.cfg.DataDir); err != nil {
		if ctx.Err() == nil {
			s.setErrorForRun(runID, fmt.Errorf("record bootstrap completion: %w", err))
		}
		return
	}
	if ctx.Err() != nil {
		return
	}
	if err := launch(); err != nil {
		if ctx.Err() == nil {
			s.setErrorForRun(runID, fmt.Errorf("create node: %w", err))
		}
		return
	}
	launched = true
}

// onProgress stores the latest bootstrap progress on the status snapshot.
// Only called from test code; nolint:unused because lint runs with tests:false.
func (s *Supervisor) onProgress(bp BootstrapProgress) { //nolint:unused
	s.onProgressForRun(s.currentRunID(), bp)
}

func (s *Supervisor) onProgressForRun(runID uint64, bp BootstrapProgress) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Once the supervisor is torn down or a newer run has started, a late
	// callback from an old bootstrap must not write into the current snapshot.
	if !s.activeRunLocked(runID) || s.status.State != StateBootstrapping {
		return
	}
	s.status.Bootstrap = &bp
}

// Stop cancels the node's context, waits for the active run to exit, and marks
// the supervisor stopped.
func (s *Supervisor) Stop() {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.waitForRunExit(s.stop())
}

func (s *Supervisor) stop() <-chan struct{} {
	s.mu.Lock()
	cancel := s.cancel
	runDone := s.runDone
	// Clear the start guard so the supervisor can be started again after being
	// stopped, and record the terminal state under the same lock so a late poll
	// can't race between the unlock and the state write.
	s.cancel = nil
	s.runDone = nil
	s.status.State = StateStopped
	s.status.Bootstrap = nil // a clean shutdown is not a diagnostic failure
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return runDone
}

func (s *Supervisor) waitForRunExit(runDone <-chan struct{}) {
	if runDone != nil {
		<-runDone
	}
}

// Status returns the latest snapshot.
func (s *Supervisor) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

// Only called from test code; nolint:unused because lint runs with tests:false.
func (s *Supervisor) setState(st NodeState) { //nolint:unused
	s.setStateForRun(s.currentRunID(), st)
}

func (s *Supervisor) setStateForRun(runID uint64, st NodeState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Once the supervisor is torn down or a newer run has started, a late
	// goroutine must not resurrect or mutate the current run's state.
	if !s.activeRunLocked(runID) {
		return
	}
	s.status.State = st
	if st != StateBootstrapping {
		s.status.Bootstrap = nil
	}
}

// Only called from test code; nolint:unused because lint runs with tests:false.
func (s *Supervisor) setError(err error) { //nolint:unused
	s.setErrorForRun(s.currentRunID(), err)
}

func (s *Supervisor) setErrorForRun(runID uint64, err error) {
	s.mu.Lock()
	// If the supervisor was already torn down or a newer run has started, don't
	// override the current run's terminal state.
	if !s.activeRunLocked(runID) {
		s.mu.Unlock()
		return
	}
	cancel := s.cancel
	s.cancel = nil
	s.runDone = nil
	s.status.State = StateError
	// Status.Bootstrap is intentionally retained on error so /status shows how
	// far a bootstrap got before failing (diagnostics).
	s.status.Err = err.Error()
	s.mu.Unlock()
	// Wind down the node/poll-loop goroutines and free the start guard so the
	// supervisor can be started again after the failure.
	cancel()
}

// Only called from test code; nolint:unused because lint runs with tests:false.
func (s *Supervisor) currentRunID() uint64 { //nolint:unused
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.runID
}

func (s *Supervisor) activeRunLocked(runID uint64) bool {
	return s.cancel != nil && s.runID == runID
}

// pollLoop polls the node's own loopback Blockfrost endpoint for the latest
// block and updates Status. Reaching the node over the wire (not via internals)
// is deliberate — it is the same pattern every subsystem uses.
func (s *Supervisor) pollLoop(ctx context.Context, runID uint64) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	url := fmt.Sprintf("http://127.0.0.1:%d/api/v0/blocks/latest", s.cfg.BlockfrostPort)
	client := &http.Client{Timeout: 3 * time.Second}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			slot, blkTime, ok := fetchLatestBlock(ctx, client, url)
			isCaughtUp := caughtUp(blkTime, s.now(), s.cfg.CaughtUpThreshold)
			s.mu.Lock()
			// Don't move off a terminal/stopped state; once Stop sets
			// StateStopped, a late poll must not revert it to syncing/ready.
			if s.activeRunLocked(runID) && s.status.State != StateError && s.status.State != StateStopped {
				s.status.State = deriveState(ok, isCaughtUp)
				// CaughtUp must reflect every poll, not just successful ones: a
				// failed poll yields isCaughtUp=false, so updating it here keeps
				// the snapshot consistent instead of reporting caughtUp=true
				// alongside a syncing state. Tip/LatestBlockTime are left as the
				// last known values (a coherent "last seen block" reading).
				s.status.CaughtUp = isCaughtUp
				if ok {
					t := blkTime
					s.status.Tip = slot
					s.status.LatestBlockTime = &t
				}
			}
			s.mu.Unlock()
		}
	}
}

// fetchLatestBlock queries Blockfrost /blocks/latest; ok=false until a block exists.
func fetchLatestBlock(ctx context.Context, c *http.Client, url string) (slot uint64, t time.Time, ok bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, time.Time{}, false
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, time.Time{}, false
	}
	if resp == nil {
		return 0, time.Time{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, time.Time{}, false
	}
	var body struct {
		Slot uint64 `json:"slot"`
		Time int64  `json:"time"` // unix seconds (Blockfrost block time)
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, time.Time{}, false
	}
	return body.Slot, time.Unix(body.Time, 0).UTC(), true
}
