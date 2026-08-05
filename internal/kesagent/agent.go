// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kesagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/blinklabs-io/bursa/internal/kesagent/securemem"
	"github.com/blinklabs-io/gouroboros/kes"
	"github.com/blinklabs-io/gouroboros/ledger"
)

// Errors returned by the agent.
var (
	ErrNoActiveKey  = errors.New("kesagent: no active KES key installed")
	ErrNoStagedKey  = errors.New("kesagent: no staged KES key")
	ErrExhausted    = errors.New("kesagent: active KES key has exhausted its evolutions")
	ErrPastPeriod   = errors.New("kesagent: requested KES period is in the past for the active key")
	ErrOpCertColdVK = errors.New("kesagent: opcert cold vkey does not match configured cold vkey")
	ErrOpCertKESVK  = errors.New("kesagent: opcert KES vkey does not match the staged key")
	ErrColdVKey     = errors.New("kesagent: configured cold verification key must be 32 bytes")
)

// Config configures an Agent.
type Config struct {
	Mode              string        // ModeServeKey | ModeSign
	Depth             uint64        // KES tree depth (default kes.CardanoKesDepth)
	SystemStart       time.Time     // Shelley genesis system start
	SlotLength        time.Duration // wall-clock duration of one slot
	SlotsPerKESPeriod uint64        // slots per KES period
	MaxKESEvolutions  uint64        // max opcert evolutions (mainnet: 62)
	ColdVKey          []byte        // 32-byte pool cold verification key
	EvolveInterval    time.Duration // scheduler tick (default 1m)
	GuardPath         string        // durable monotonic period store path
	Version           string        // agent version string (for info)
}

// keyState is the in-memory state of a KES key. The raw secret key bytes live
// in the locked secure buffer; only the (public) verification key and metadata
// live on the heap.
type keyState struct {
	depth       uint64
	period      uint64 // internal, 0-based key period
	startPeriod uint64 // absolute KES period at internal period 0 (opcert period)
	buf         *securemem.Buffer
	vkey        []byte
	opcert      []byte // installed opcert CBOR (active keys only)
	exhausted   bool
}

func (k *keyState) absPeriod() uint64 { return k.startPeriod + k.period }

func (k *keyState) endPeriod() uint64 {
	return k.startPeriod + kes.MaxPeriod(k.depth) - 1
}

func (k *keyState) close() {
	if k != nil && k.buf != nil {
		_ = k.buf.Close()
	}
}

// Agent is the KES agent core: key custody, evolution, signing, and serve-key
// broadcast. It is safe for concurrent use.
type Agent struct {
	cfg     Config
	logger  *slog.Logger
	metrics *Metrics
	guard   *PeriodGuard

	mu      sync.Mutex
	active  *keyState
	staged  *keyState
	subs    map[int]chan KeyPush
	nextSub int

	now func() time.Time // injectable clock (tests)
}

// New constructs an Agent, validating configuration and opening the durable
// period guard.
func New(cfg Config, logger *slog.Logger, metrics *Metrics) (*Agent, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Mode != ModeServeKey && cfg.Mode != ModeSign {
		return nil, fmt.Errorf("kesagent: invalid mode %q", cfg.Mode)
	}
	if cfg.Depth == 0 {
		cfg.Depth = kes.CardanoKesDepth
	}
	if cfg.SystemStart.IsZero() {
		return nil, errors.New("kesagent: system_start is required")
	}
	if cfg.SlotLength <= 0 {
		return nil, errors.New("kesagent: slot_length must be positive")
	}
	if cfg.SlotsPerKESPeriod == 0 {
		return nil, errors.New("kesagent: slots_per_kes_period must be positive")
	}
	if cfg.MaxKESEvolutions == 0 {
		cfg.MaxKESEvolutions = 62
	}
	if len(cfg.ColdVKey) != ed25519.PublicKeySize {
		return nil, ErrColdVKey
	}
	if cfg.EvolveInterval <= 0 {
		cfg.EvolveInterval = time.Minute
	}
	guard, err := NewPeriodGuard(cfg.GuardPath)
	if err != nil {
		return nil, err
	}
	return &Agent{
		cfg:     cfg,
		logger:  logger,
		metrics: metrics,
		guard:   guard,
		subs:    make(map[int]chan KeyPush),
		now:     time.Now,
	}, nil
}

// kesPeriodDuration is the wall-clock length of one KES period.
func (a *Agent) kesPeriodDuration() time.Duration {
	return a.cfg.SlotLength * time.Duration(a.cfg.SlotsPerKESPeriod) // #nosec G115
}

// currentKESPeriod computes the current absolute KES period from genesis
// parameters and the agent clock.
func (a *Agent) currentKESPeriod() uint64 {
	elapsed := a.now().Sub(a.cfg.SystemStart)
	if elapsed <= 0 {
		return 0
	}
	per := a.kesPeriodDuration()
	if per <= 0 {
		return 0
	}
	return uint64(elapsed / per) // #nosec G115
}

// GenStagedKey generates a fresh KES key into the staging slot and returns its
// verification key. Any previously staged key is dropped and wiped.
func (a *Agent) GenStagedKey() ([]byte, error) {
	var seed [kes.SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("kesagent: read entropy: %w", err)
	}
	defer securemem.Wipe(seed[:])

	sk, vkey, err := kes.KeyGen(a.cfg.Depth, seed[:])
	if err != nil {
		return nil, fmt.Errorf("kesagent: keygen: %w", err)
	}
	buf, err := securemem.New(len(sk.Data))
	if err != nil {
		securemem.Wipe(sk.Data)
		return nil, err
	}
	if err := buf.Set(sk.Data); err != nil {
		securemem.Wipe(sk.Data)
		_ = buf.Close()
		return nil, err
	}
	securemem.Wipe(sk.Data) // transient heap copy erased; material now only in buf

	ks := &keyState{depth: a.cfg.Depth, period: 0, buf: buf, vkey: vkey}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.staged.close()
	a.staged = ks
	vkeyOut := make([]byte, len(vkey))
	copy(vkeyOut, vkey)
	a.logger.Info("generated staged KES key", "kes_vkey", hex.EncodeToString(vkey))
	return vkeyOut, nil
}

// InstallKey validates an operational certificate against the configured cold
// verification key and the staged KES key, promotes the staged key to active,
// evolves it to the current period, and (serve-key mode) pushes it. It returns
// the resulting agent info.
func (a *Agent) InstallKey(opcertBytes []byte) (*AgentInfo, error) {
	dec, err := decodeOpCert(opcertBytes)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.staged == nil {
		return nil, ErrNoStagedKey
	}
	// The agent holds only the cold vkey; the opcert must carry the same one.
	if !bytes.Equal(dec.coldVkey, a.cfg.ColdVKey) {
		return nil, ErrOpCertColdVK
	}
	// Verify the cold-key signature over the OCertSignable representation.
	if err := ledger.VerifyOpCertSignature(dec.ledgerOpCert(), a.cfg.ColdVKey); err != nil {
		return nil, fmt.Errorf("kesagent: opcert signature invalid: %w", err)
	}
	// The opcert must commit to the staged KES vkey.
	if !bytes.Equal(dec.kesVkey, a.staged.vkey) {
		return nil, ErrOpCertKESVK
	}
	// Period sanity: not from the future, and not already expired.
	cur := a.currentKESPeriod()
	if dec.kesPeriod > cur {
		return nil, fmt.Errorf(
			"kesagent: opcert KES period %d is in the future (current %d)",
			dec.kesPeriod, cur,
		)
	}
	maxEvol := a.cfg.MaxKESEvolutions
	if m := kes.MaxPeriod(a.cfg.Depth); m < maxEvol {
		maxEvol = m
	}
	if cur-dec.kesPeriod >= maxEvol {
		return nil, fmt.Errorf(
			"kesagent: opcert expired: %d evolutions since period %d >= max %d",
			cur-dec.kesPeriod, dec.kesPeriod, maxEvol,
		)
	}

	// Promote staged -> active.
	a.active.close()
	ks := a.staged
	a.staged = nil
	ks.startPeriod = dec.kesPeriod
	ks.opcert = append([]byte(nil), opcertBytes...)
	ks.exhausted = false
	a.active = ks

	// Evolve to the current period and serve.
	a.evolveToLocked(cur)
	if err := a.guard.Authorize(hex.EncodeToString(ks.vkey), a.active.absPeriod()); err != nil {
		// Roll back the install: refuse to serve a rolled-back period.
		a.active.close()
		a.active = nil
		return nil, err
	}
	a.metrics.setCurrentPeriod(a.active.absPeriod())
	a.metrics.setExhausted(a.active.exhausted)
	a.broadcastLocked()
	a.logger.Info("installed KES key",
		"kes_vkey", hex.EncodeToString(ks.vkey),
		"start_period", ks.startPeriod,
		"active_period", a.active.absPeriod(),
	)
	return a.infoLocked(), nil
}

// DropKey wipes the active and/or staged key. target is "active", "staged", or
// "all" (default "all").
func (a *Agent) DropKey(target string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch target {
	case "active":
		a.active.close()
		a.active = nil
	case "staged":
		a.staged.close()
		a.staged = nil
	case "", "all":
		a.active.close()
		a.active = nil
		a.staged.close()
		a.staged = nil
	default:
		return fmt.Errorf("kesagent: unknown drop target %q", target)
	}
	a.metrics.setExhausted(false)
	a.logger.Info("dropped KES key", "target", target)
	return nil
}

// Sign produces a KES signature over msg at the given absolute KES period. The
// key is evolved forward as needed; it never signs a period below the monotonic
// floor or below the active key's current period.
func (a *Agent) Sign(period uint64, msg []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active == nil {
		a.metrics.incSign("error")
		return nil, ErrNoActiveKey
	}
	if period < a.active.absPeriod() {
		a.metrics.incSign("error")
		return nil, fmt.Errorf("%w: requested %d, key at %d",
			ErrPastPeriod, period, a.active.absPeriod())
	}
	if period > a.active.absPeriod() {
		a.evolveToLocked(period)
	}
	if a.active.absPeriod() != period {
		a.metrics.incSign("error")
		return nil, fmt.Errorf("%w: cannot reach period %d (key ends at %d)",
			ErrExhausted, period, a.active.endPeriod())
	}
	if err := a.guard.Authorize(hex.EncodeToString(a.active.vkey), period); err != nil {
		a.metrics.incSign("error")
		return nil, err
	}
	sk := &kes.SecretKey{
		Depth:  a.active.depth,
		Period: a.active.period,
		Data:   a.active.buf.Bytes(),
	}
	sig, err := kes.Sign(sk, a.active.period, msg)
	if err != nil {
		a.metrics.incSign("error")
		return nil, fmt.Errorf("kesagent: sign: %w", err)
	}
	a.metrics.incSign("ok")
	a.metrics.setCurrentPeriod(a.active.absPeriod())
	return sig, nil
}

// evolveToLocked evolves the active key forward until its absolute period
// reaches targetAbs or the key is exhausted. Caller must hold a.mu.
func (a *Agent) evolveToLocked(targetAbs uint64) {
	for a.active != nil && a.active.absPeriod() < targetAbs {
		nextInternal := a.active.period + 1
		if nextInternal >= kes.MaxPeriod(a.active.depth) {
			if !a.active.exhausted {
				a.active.exhausted = true
				a.metrics.setExhausted(true)
				a.logger.Warn("KES key exhausted; a new key must be installed",
					"kes_vkey", hex.EncodeToString(a.active.vkey),
					"active_period", a.active.absPeriod(),
					"target_period", targetAbs,
				)
			}
			return
		}
		cur := &kes.SecretKey{
			Depth:  a.active.depth,
			Period: a.active.period,
			Data:   a.active.buf.Bytes(),
		}
		next, err := kes.Update(cur) // reads (and internally copies) cur.Data
		if err != nil {
			if !a.active.exhausted {
				a.active.exhausted = true
				a.metrics.setExhausted(true)
				a.logger.Warn("KES key update failed; marking exhausted",
					"error", err,
					"kes_vkey", hex.EncodeToString(a.active.vkey),
				)
			}
			return
		}
		// Interim forward-erasure: wipe the spent key material now, then install
		// the evolved key. TODO adopt gouroboros SecretKey.Zeroize once pinned.
		a.active.buf.Zeroize()
		if err := a.active.buf.Set(next.Data); err != nil {
			securemem.Wipe(next.Data)
			a.logger.Error("failed to store evolved KES key", "error", err)
			a.active.exhausted = true
			return
		}
		securemem.Wipe(next.Data) // erase the transient evolved copy
		a.active.period = next.Period
		a.metrics.incEvolutions()
	}
}

// buildKeyPushLocked builds a KeyPush for the current active key. Caller holds a.mu.
func (a *Agent) buildKeyPushLocked() (KeyPush, bool) {
	if a.active == nil {
		return KeyPush{}, false
	}
	return KeyPush{
		Type:       "key_push",
		Period:     a.active.absPeriod(),
		Depth:      a.active.depth,
		KESSignKey: a.active.buf.Clone(),
		KESVKey:    append([]byte(nil), a.active.vkey...),
		OpCert:     append([]byte(nil), a.active.opcert...),
	}, true
}

// broadcastLocked pushes the current key to all serve-key subscribers. Caller
// holds a.mu.
func (a *Agent) broadcastLocked() {
	kp, ok := a.buildKeyPushLocked()
	if !ok {
		return
	}
	for _, ch := range a.subs {
		// Latest-wins: drain any stale push, then enqueue the newest.
		select {
		case <-ch:
		default:
		}
		select {
		case ch <- kp:
		default:
		}
		a.metrics.incServedKeys()
	}
}

// subscribe registers a serve-key subscriber and returns its id, its channel,
// and the current key push (if a key is active) to send immediately.
func (a *Agent) subscribe() (int, chan KeyPush, *KeyPush) {
	a.mu.Lock()
	defer a.mu.Unlock()
	id := a.nextSub
	a.nextSub++
	ch := make(chan KeyPush, 1)
	a.subs[id] = ch
	if kp, ok := a.buildKeyPushLocked(); ok {
		return id, ch, &kp
	}
	return id, ch, nil
}

func (a *Agent) unsubscribe(id int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.subs, id)
}

// Tick advances the scheduler once: it evolves the active key to the current
// period and, if it advanced, authorizes and broadcasts the new key.
func (a *Agent) Tick() {
	cur := a.currentKESPeriod()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.metrics.setCurrentPeriod(cur)
	if a.active == nil {
		return
	}
	prev := a.active.absPeriod()
	a.evolveToLocked(cur)
	newAbs := a.active.absPeriod()
	a.metrics.setCurrentPeriod(newAbs)
	a.metrics.setExhausted(a.active.exhausted)
	if newAbs > prev {
		if err := a.guard.Authorize(hex.EncodeToString(a.active.vkey), newAbs); err != nil {
			a.logger.Error("period guard refused evolved key; not serving",
				"error", err, "period", newAbs)
			return
		}
		a.broadcastLocked()
		a.logger.Info("evolved KES key", "active_period", newAbs)
	}
}

// Run drives the evolution scheduler until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) {
	a.Tick() // evolve immediately on start
	ticker := time.NewTicker(a.cfg.EvolveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.Tick()
		}
	}
}

// Info returns a status snapshot.
func (a *Agent) Info() *AgentInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.infoLocked()
}

func (a *Agent) infoLocked() *AgentInfo {
	floor, floorSet := a.guard.Floor()
	info := &AgentInfo{
		Version:          a.cfg.Version,
		Mode:             a.cfg.Mode,
		CurrentPeriod:    a.currentKESPeriod(),
		MonotonicFloor:   floor,
		FloorInitialized: floorSet,
	}
	if a.active != nil {
		info.HasActiveKey = true
		info.ActivePeriod = a.active.absPeriod()
		info.ActiveStart = a.active.startPeriod
		info.ActiveEnd = a.active.endPeriod()
		info.ActiveKESVKey = append([]byte(nil), a.active.vkey...)
		info.Exhausted = a.active.exhausted
	}
	if a.staged != nil {
		info.StagedKESVKey = append([]byte(nil), a.staged.vkey...)
	}
	return info
}

// Close wipes all key material.
func (a *Agent) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.active.close()
	a.active = nil
	a.staged.close()
	a.staged = nil
}
