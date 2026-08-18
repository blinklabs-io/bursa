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
	"math"
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
	maxEvol     uint64 // max evolutions this key may serve, min(cfg.MaxKESEvolutions, kes.MaxPeriod(depth)); set at promotion
	buf         *securemem.Buffer
	vkey        []byte
	opcert      []byte // installed opcert CBOR (active keys only)
	issueNumber uint64 // opcert issue counter (active keys only)
	exhausted   bool
}

func (k *keyState) absPeriod() uint64 { return k.startPeriod + k.period }

func (k *keyState) endPeriod() uint64 {
	return k.startPeriod + k.maxEvol - 1
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

	// guardedPeriod/guardedSet track the last KES period the scheduler (Tick)
	// successfully authorized and broadcast, so a transient guard-store
	// failure is retried on the next tick instead of being silently dropped
	// for the rest of the period (evolveToLocked has already advanced
	// a.active in memory regardless of guard-store success).
	guardedPeriod uint64
	guardedSet    bool

	now func() time.Time // injectable clock (tests)
}

// maxEvolutions returns the effective evolution ceiling for keys created
// under the current config: the smaller of the configured max opcert
// evolutions and the KES tree's cryptographic evolution limit. Cardano
// treats an opcert as expired once MaxKESEvolutions is reached even when the
// KES tree itself could evolve further.
func (a *Agent) maxEvolutions() uint64 {
	m := a.cfg.MaxKESEvolutions
	if treeMax := kes.MaxPeriod(a.cfg.Depth); treeMax < m {
		m = treeMax
	}
	return m
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
	// SlotLength > 0 is guaranteed above, so guard the KES-period-duration
	// multiplication (SlotLength * SlotsPerKESPeriod) against int64 overflow.
	// An oversized slots_per_kes_period would otherwise wrap to a non-positive
	// duration and silently freeze currentKESPeriod at 0, stalling evolution.
	if cfg.SlotsPerKESPeriod > uint64(math.MaxInt64)/uint64(cfg.SlotLength) {
		return nil, fmt.Errorf(
			"kesagent: slot_length (%s) * slots_per_kes_period (%d) overflows the KES period duration",
			cfg.SlotLength, cfg.SlotsPerKESPeriod,
		)
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
	if !buf.Locked() {
		a.logger.Warn("KES secret key buffer could not be locked in memory (mlock unavailable or refused); key material may be swappable to disk")
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
	maxEvol := a.maxEvolutions()
	if cur-dec.kesPeriod >= maxEvol {
		return nil, fmt.Errorf(
			"kesagent: opcert expired: %d evolutions since period %d >= max %d",
			cur-dec.kesPeriod, dec.kesPeriod, maxEvol,
		)
	}

	// Promote staged -> active, but keep the previous active key around
	// (undestroyed) until authorization is known to succeed: a rollback
	// refusal below must not leave the agent with no working key at all.
	oldActive := a.active
	ks := a.staged
	a.staged = nil
	ks.startPeriod = dec.kesPeriod
	ks.maxEvol = maxEvol
	ks.opcert = append([]byte(nil), opcertBytes...)
	ks.issueNumber = dec.issueNumber
	ks.exhausted = false
	a.active = ks

	// Evolve to the current period and serve.
	a.evolveToLocked(cur)
	if a.active == nil {
		// evolveToLocked can only clear a.active on an internal key-store
		// failure (see the buf.Set failure path); treat it the same as a
		// guard refusal and restore the previous key.
		a.active = oldActive
		return nil, errors.New("kesagent: failed to evolve newly installed key to the current period")
	}
	if err := a.guard.Authorize(hex.EncodeToString(ks.vkey), a.active.absPeriod()); err != nil {
		// Roll back the install: keep serving the previous active key
		// rather than discarding a working key on a rollback refusal.
		a.active.close()
		a.active = oldActive
		return nil, err
	}
	oldActive.close()
	a.guardedPeriod = a.active.absPeriod()
	a.guardedSet = true
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
		a.guardedSet = false
	case "staged":
		a.staged.close()
		a.staged = nil
	case "", "all":
		a.active.close()
		a.active = nil
		a.staged.close()
		a.staged = nil
		a.guardedSet = false
	default:
		return fmt.Errorf("kesagent: unknown drop target %q", target)
	}
	// Dropping only the staged key leaves the active key (and its exhaustion
	// state) untouched; derive the gauge from whatever remains active rather
	// than always clearing it.
	if a.active != nil {
		a.metrics.setExhausted(a.active.exhausted)
	} else {
		a.metrics.setExhausted(false)
	}
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
	if a.active == nil {
		// evolveToLocked discarded the key after a store failure.
		a.metrics.incSign("error")
		return nil, ErrNoActiveKey
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

// storeEvolvedKey writes an evolved KES key into the active locked buffer. It
// is a variable so tests can exercise the discard-on-failure branch in
// evolveToLocked, which is otherwise unreachable: Buffer.Set fails only on a
// closed buffer or a length mismatch, and a.mu serializes both away in every
// real call path.
var storeEvolvedKey = func(buf *securemem.Buffer, data []byte) error {
	return buf.Set(data)
}

// evolveToLocked evolves the active key forward until its absolute period
// reaches targetAbs or the key is exhausted. Caller must hold a.mu.
func (a *Agent) evolveToLocked(targetAbs uint64) {
	for a.active != nil && a.active.absPeriod() < targetAbs {
		nextInternal := a.active.period + 1
		if nextInternal >= a.active.maxEvol {
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
		if err := storeEvolvedKey(a.active.buf, next.Data); err != nil {
			securemem.Wipe(next.Data)
			a.logger.Error("failed to store evolved KES key; discarding the key", "error", err)
			// The buffer was already zeroized above and next.Data failed to
			// land, so a.active.period is stale relative to its now-zeroed
			// buffer contents. Discard the key entirely rather than leaving
			// it installed: Sign() would otherwise happily sign over the
			// zeroed buffer for the (unchanged) period it still reports.
			a.active.close()
			a.active = nil
			// No active key exists at all now, so "exhausted" (which implies a
			// key that reached its final period) is the wrong signal; clear it
			// rather than reporting a false key-exhaustion health state.
			a.metrics.setExhausted(false)
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
	base, ok := a.buildKeyPushLocked()
	if !ok {
		return
	}
	// base.KESSignKey is a plaintext clone of the locked signing key. Hand each
	// subscriber its OWN copy (so one handler wiping its copy after writing
	// cannot corrupt another's) and wipe every copy the moment it is no longer
	// needed, so superseded key material does not linger on the swappable heap
	// and defeat the forward-erasure done on evolution.
	defer securemem.Wipe(base.KESSignKey)
	for _, ch := range a.subs {
		kp := base
		kp.KESSignKey = append([]byte(nil), base.KESSignKey...)
		// Latest-wins: drain and wipe any stale push, then enqueue the newest.
		select {
		case stale := <-ch:
			securemem.Wipe(stale.KESSignKey)
		default:
		}
		select {
		case ch <- kp:
			a.metrics.incServedKeys()
		default:
			// Subscriber channel is still full (shouldn't happen since we just
			// drained it above, but be defensive): wipe the copy we could not
			// deliver rather than dropping it un-erased, and don't count it.
			securemem.Wipe(kp.KESSignKey)
		}
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
	// Drain and wipe any key push still queued for this subscriber so its
	// plaintext signing-key copy does not outlive the subscription on the heap.
	if ch, ok := a.subs[id]; ok {
		select {
		case kp := <-ch:
			securemem.Wipe(kp.KESSignKey)
		default:
		}
	}
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
	a.evolveToLocked(cur)
	if a.active == nil {
		// evolveToLocked discarded the key after a store failure.
		return
	}
	newAbs := a.active.absPeriod()
	a.metrics.setCurrentPeriod(newAbs)
	a.metrics.setExhausted(a.active.exhausted)
	// Authorize (and broadcast) whenever the current period hasn't already
	// been successfully authorized: gating only on "did the in-memory key
	// just evolve" would mean a transient guard-store failure (e.g. a full
	// disk) is never retried, since evolveToLocked has already advanced
	// a.active in memory and won't advance it again for the same period.
	if a.guardedSet && a.guardedPeriod == newAbs {
		return
	}
	if err := a.guard.Authorize(hex.EncodeToString(a.active.vkey), newAbs); err != nil {
		a.logger.Error("period guard refused evolved key; not serving",
			"error", err, "period", newAbs)
		return
	}
	a.guardedPeriod = newAbs
	a.guardedSet = true
	a.broadcastLocked()
	a.logger.Info("evolved KES key", "active_period", newAbs)
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
		info.ActiveIssueNumber = a.active.issueNumber
		info.ActiveOpCert = append([]byte(nil), a.active.opcert...)
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
