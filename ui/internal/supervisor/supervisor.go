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
	"sync"
	"time"

	"github.com/blinklabs-io/dingo"
	"github.com/blinklabs-io/dingo/config/cardano"
	"github.com/blinklabs-io/dingo/connmanager"
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
}

// Supervisor owns the embedded Dingo node's lifecycle and exposes its status.
type Supervisor struct {
	cfg    Config
	cancel context.CancelFunc

	mu     sync.RWMutex
	status Status

	now func() time.Time // injectable clock for tests
}

func New(cfg Config) *Supervisor {
	if cfg.CaughtUpThreshold == 0 {
		cfg.CaughtUpThreshold = 2 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Supervisor{
		cfg:    cfg,
		status: Status{State: StateStopped},
		now:    time.Now,
	}
}

// Start constructs the node, launches it, and begins polling its tip. It
// returns once the node goroutine is launched; readiness is reported via Status.
func (s *Supervisor) Start(ctx context.Context) error {
	// Guard against double-start: reserve s.cancel atomically so a second Start
	// can't overwrite (and orphan) the first node and poll loop.
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return errors.New("supervisor already started")
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.mu.Unlock()

	// fail releases the reservation so Start can be retried if we error out
	// before the node goroutine is launched.
	fail := func(err error) error {
		s.mu.Lock()
		s.cancel = nil
		s.mu.Unlock()
		cancel()
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
	nodeCfg := dingo.NewConfig(
		dingo.WithNetwork(s.cfg.Network),
		dingo.WithCardanoNodeConfig(cardanoCfg),
		dingo.WithDatabasePath(s.cfg.DataDir),
		dingo.WithStorageMode(dingo.StorageModeAPI),
		dingo.WithBindAddr("127.0.0.1"),
		dingo.WithUtxorpcPort(s.cfg.UtxorpcPort),
		dingo.WithBlockfrostPort(s.cfg.BlockfrostPort),
		dingo.WithListeners(connmanager.ListenerConfig{
			ListenNetwork: "unix",
			ListenAddress: s.cfg.SocketPath,
			UseNtC:        true,
		}),
		dingo.WithLogger(s.cfg.Logger),
	)
	node, err := dingo.New(nodeCfg)
	if err != nil {
		return fail(fmt.Errorf("create node: %w", err))
	}
	s.setState(StateStarting)

	go func() {
		if err := node.Run(runCtx); err != nil && runCtx.Err() == nil {
			s.setError(err)
		}
	}()
	go s.pollLoop(runCtx)
	return nil
}

// Stop cancels the node's context and marks the supervisor stopped.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	// Clear the start guard so the supervisor can be started again after being
	// stopped, and record the terminal state under the same lock so a late poll
	// can't race between the unlock and the state write.
	s.cancel = nil
	s.status.State = StateStopped
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Status returns the latest snapshot.
func (s *Supervisor) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *Supervisor) setState(st NodeState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.State = st
}

func (s *Supervisor) setError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.State = StateError
	s.status.Err = err.Error()
}

// pollLoop polls the node's own loopback Blockfrost endpoint for the latest
// block and updates Status. Reaching the node over the wire (not via internals)
// is deliberate — it is the same pattern every subsystem uses.
func (s *Supervisor) pollLoop(ctx context.Context) {
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
			if s.status.State != StateError && s.status.State != StateStopped {
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
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return 0, time.Time{}, false
	}
	defer resp.Body.Close()
	var body struct {
		Slot uint64 `json:"slot"`
		Time int64  `json:"time"` // unix seconds (Blockfrost block time)
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, time.Time{}, false
	}
	return body.Slot, time.Unix(body.Time, 0).UTC(), true
}
