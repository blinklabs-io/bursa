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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/kesagent/securemem"
	"github.com/blinklabs-io/gouroboros/kes"
	"github.com/blinklabs-io/gouroboros/ledger"
)

// Errors returned by the agent.
var (
	ErrNoActiveKey = errors.New("kesagent: no active KES key installed")
	ErrNoStagedKey = errors.New("kesagent: no staged KES key")
	ErrExhausted   = errors.New(
		"kesagent: active KES key has exhausted its evolutions",
	)
	ErrPastPeriod = errors.New(
		"kesagent: requested KES period is in the past for the active key",
	)
	ErrFuturePeriod = errors.New(
		"kesagent: requested KES period is in the future",
	)
	// ErrFutureSlot is returned for a header whose slot is ahead of the
	// profile's current slot by more than its clock-skew allowance.
	// Recording such a slot would refuse every earlier slot until it.
	ErrFutureSlot = errors.New(
		"kesagent: header slot is ahead of the current slot",
	)
	ErrOpCertColdVK = errors.New(
		"kesagent: opcert cold vkey does not match configured cold vkey",
	)
	ErrOpCertKESVK = errors.New(
		"kesagent: opcert KES vkey does not match the staged key",
	)
	ErrColdVKey = errors.New(
		"kesagent: configured cold verification key must be 32 bytes",
	)
)

// Config configures an Agent. An agent serves one or more profiles, each a
// pool on a network. Profiles lists them; when it is empty, the single-pool
// fields below form one profile named DefaultProfileName, which is how a
// configuration written before profiles keeps working unchanged.
type Config struct {
	Mode           string        // ModeServeKey | ModeSign
	EvolveInterval time.Duration // scheduler tick (default 1m)
	Version        string        // agent version string (for info)
	Profiles       []ProfileConfig

	// Single-pool fields, used only when Profiles is empty.
	Depth       uint64    // KES tree depth (default kes.CardanoKesDepth)
	SystemStart time.Time // Shelley genesis system start
	// ShelleyStartSlot and ShelleyStartTime anchor the slot clock at the
	// first Shelley slot, for networks whose Byron era ran with longer slots
	// (mainnet, preprod). Without them the anchor is slot 0 at SystemStart,
	// which is right only where every slot has had SlotLength since genesis.
	ShelleyStartSlot  uint64
	ShelleyStartTime  time.Time
	SlotLength        time.Duration // wall-clock duration of one slot
	SlotsPerKESPeriod uint64        // slots per KES period
	MaxKESEvolutions  uint64        // max opcert evolutions (mainnet: 62)
	ColdVKey          []byte        // 32-byte pool cold verification key
	GuardPath         string        // durable monotonic period store path
	MaxClockSkew      time.Duration // header slot lead allowed (default DefaultMaxClockSkew)
}

// ProfileConfig configures one profile: a pool's cold verification key, the
// genesis parameters of the network it forges on, and the durable guard file
// that holds its period floor and last signed slot.
type ProfileConfig struct {
	Name        string
	Depth       uint64    // KES tree depth (default kes.CardanoKesDepth)
	SystemStart time.Time // Shelley genesis system start
	// ShelleyStartSlot and ShelleyStartTime anchor the slot clock at the
	// first Shelley slot, for networks whose Byron era ran with longer slots
	// (mainnet, preprod). Without them the anchor is slot 0 at SystemStart,
	// which is right only where every slot has had SlotLength since genesis.
	ShelleyStartSlot  uint64
	ShelleyStartTime  time.Time
	SlotLength        time.Duration // wall-clock duration of one slot
	SlotsPerKESPeriod uint64        // slots per KES period
	MaxKESEvolutions  uint64        // max opcert evolutions (mainnet: 62)
	ColdVKey          []byte        // 32-byte pool cold verification key
	GuardPath         string        // durable monotonic period store path
	MaxClockSkew      time.Duration // header slot lead allowed (default DefaultMaxClockSkew)
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
	coldSig     []byte // installed opcert cold-key signature (active keys only)
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

// profile is one pool on one network: its staged and active KES keys, its
// period guard and its serve-key subscribers. Each profile has its own lock
// and guard file, so a refusal, a slow guard write or a key change in one
// profile never holds up another.
type profile struct {
	cfg     ProfileConfig
	mode    string
	logger  *slog.Logger
	metrics *Metrics
	guard   *PeriodGuard
	nowFn   *func() time.Time // the agent's clock

	mu      sync.Mutex
	active  *keyState
	staged  *keyState
	subs    map[int]chan KeyPush
	nextSub int

	// guardedPeriod/guardedSet track the active KES period most recently
	// authorized for release. A transient guard-store failure leaves this at
	// the prior period so the evolved key stays private and Tick retries.
	guardedPeriod uint64
	guardedSet    bool
}

func (p *profile) now() time.Time { return (*p.nowFn)() }

// maxEvolutions returns the effective evolution ceiling for keys created
// under the current config: the smaller of the configured max opcert
// evolutions and the KES tree's cryptographic evolution limit. Cardano
// treats an opcert as expired once MaxKESEvolutions is reached even when the
// KES tree itself could evolve further.
func (p *profile) maxEvolutions() uint64 {
	m := p.cfg.MaxKESEvolutions
	if treeMax := kes.MaxPeriod(p.cfg.Depth); treeMax < m {
		m = treeMax
	}
	return m
}

// newProfile validates cfg and opens the profile's durable period guard.
func newProfile(
	cfg ProfileConfig,
	mode string,
	logger *slog.Logger,
	metrics *Metrics,
	nowFn *func() time.Time,
) (*profile, error) {
	if cfg.Depth == 0 {
		cfg.Depth = kes.CardanoKesDepth
	}
	if cfg.SystemStart.IsZero() {
		return nil, errors.New("kesagent: system_start is required")
	}
	if cfg.ShelleyStartTime.IsZero() && cfg.ShelleyStartSlot != 0 {
		return nil, errors.New(
			"kesagent: shelley_start_slot requires shelley_start_time",
		)
	}
	if !cfg.ShelleyStartTime.IsZero() &&
		cfg.ShelleyStartTime.Before(cfg.SystemStart) {
		return nil, errors.New(
			"kesagent: shelley_start_time is before system_start",
		)
	}
	// currentSlot adds at most math.MaxInt64 elapsed slots to the anchor
	// slot, so an anchor at or below math.MaxInt64 cannot wrap the sum.
	if cfg.ShelleyStartSlot > math.MaxInt64 {
		return nil, fmt.Errorf(
			"kesagent: shelley_start_slot %d exceeds %d",
			cfg.ShelleyStartSlot,
			int64(math.MaxInt64),
		)
	}
	if cfg.SlotLength <= 0 {
		return nil, errors.New("kesagent: slot_length must be positive")
	}
	if cfg.SlotsPerKESPeriod == 0 {
		return nil, errors.New(
			"kesagent: slots_per_kes_period must be positive",
		)
	}
	// A KES period longer than a time.Duration can hold is no real network's
	// and means a misconfigured slot_length or slots_per_kes_period.
	if cfg.SlotsPerKESPeriod > uint64(math.MaxInt64)/uint64(cfg.SlotLength) {
		return nil, fmt.Errorf(
			"kesagent: slot_length (%s) * slots_per_kes_period (%d) overflows the KES period duration",
			cfg.SlotLength,
			cfg.SlotsPerKESPeriod,
		)
	}
	if cfg.MaxKESEvolutions == 0 {
		cfg.MaxKESEvolutions = 62
	}
	if cfg.MaxClockSkew < 0 {
		return nil, errors.New("kesagent: max_clock_skew must not be negative")
	}
	if cfg.MaxClockSkew == 0 {
		cfg.MaxClockSkew = DefaultMaxClockSkew
	}
	if len(cfg.ColdVKey) != ed25519.PublicKeySize {
		return nil, ErrColdVKey
	}
	if cfg.GuardPath == "" {
		return nil, errors.New("kesagent: guard_path is required")
	}
	guard, err := NewPeriodGuard(cfg.GuardPath)
	if err != nil {
		return nil, err
	}
	return &profile{
		cfg:     cfg,
		mode:    mode,
		logger:  logger.With("profile", cfg.Name),
		metrics: metrics.forProfile(cfg.Name),
		guard:   guard,
		nowFn:   nowFn,
		subs:    make(map[int]chan KeyPush),
	}, nil
}

// DefaultMaxClockSkew is the clock-skew allowance for a header's slot when a
// profile sets none: five one-second slots.
const DefaultMaxClockSkew = 5 * time.Second

// currentSlot computes the current absolute slot from the profile's slot
// clock anchor: the first Shelley slot and its time when configured,
// otherwise slot 0 at SystemStart. Before the anchor it is the anchor slot.
func (p *profile) currentSlot() uint64 {
	anchorSlot, anchorTime := uint64(0), p.cfg.SystemStart
	if !p.cfg.ShelleyStartTime.IsZero() {
		anchorSlot, anchorTime = p.cfg.ShelleyStartSlot, p.cfg.ShelleyStartTime
	}
	elapsed := p.now().Sub(anchorTime)
	if elapsed <= 0 {
		return anchorSlot
	}
	return anchorSlot + uint64(elapsed/p.cfg.SlotLength) // #nosec G115 -- elapsed and SlotLength are positive
}

// currentKESPeriod is the absolute KES period of the current slot.
func (p *profile) currentKESPeriod() uint64 {
	return p.currentSlot() / p.cfg.SlotsPerKESPeriod
}

// GenStagedKey generates a fresh KES key into the staging slot and returns its
// verification key. Any previously staged key is dropped and wiped.
func (p *profile) GenStagedKey() ([]byte, error) {
	var seed [kes.SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("kesagent: read entropy: %w", err)
	}
	defer securemem.Wipe(seed[:])

	sk, vkey, err := kes.KeyGen(p.cfg.Depth, seed[:])
	if err != nil {
		return nil, fmt.Errorf("kesagent: keygen: %w", err)
	}
	buf, err := securemem.New(len(sk.Data))
	if err != nil {
		securemem.Wipe(sk.Data)
		return nil, err
	}
	if !buf.Locked() {
		p.logger.Warn(
			"KES secret key buffer could not be locked in memory (mlock unavailable or refused); key material may be swappable to disk",
		)
	}
	if err := buf.Set(sk.Data); err != nil {
		securemem.Wipe(sk.Data)
		_ = buf.Close()
		return nil, err
	}
	securemem.Wipe(
		sk.Data,
	) // transient heap copy erased; material now only in buf

	ks := &keyState{depth: p.cfg.Depth, period: 0, buf: buf, vkey: vkey}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.staged.close()
	p.staged = ks
	vkeyOut := make([]byte, len(vkey))
	copy(vkeyOut, vkey)
	p.logger.Info(
		"generated staged KES key",
		"kes_vkey",
		hex.EncodeToString(vkey),
	)
	return vkeyOut, nil
}

// InstallKey validates an operational certificate against the configured cold
// verification key and the staged KES key, promotes the staged key to active,
// evolves it to the current period, and (serve-key mode) pushes it. It returns
// the resulting agent info.
func (p *profile) InstallKey(opcertBytes []byte) (*AgentInfo, error) {
	dec, err := bursa.DecodeOpCert(opcertBytes)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.staged == nil {
		return nil, ErrNoStagedKey
	}
	// The agent holds only the cold vkey; the opcert must carry the same one.
	if !bytes.Equal(dec.ColdVKey, p.cfg.ColdVKey) {
		return nil, ErrOpCertColdVK
	}
	// Verify the cold-key signature over the OCertSignable representation.
	if err := ledger.VerifyOpCertSignature(dec.LedgerOpCert(), p.cfg.ColdVKey); err != nil {
		return nil, fmt.Errorf("kesagent: opcert signature invalid: %w", err)
	}
	// The opcert must commit to the staged KES vkey.
	if !bytes.Equal(dec.KESVKey, p.staged.vkey) {
		return nil, ErrOpCertKESVK
	}
	// Period sanity: not from the future, and not already expired.
	cur := p.currentKESPeriod()
	if dec.KESPeriod > cur {
		return nil, fmt.Errorf(
			"kesagent: opcert KES period %d is in the future (current %d)",
			dec.KESPeriod, cur,
		)
	}
	maxEvol := p.maxEvolutions()
	if cur-dec.KESPeriod >= maxEvol {
		return nil, fmt.Errorf(
			"kesagent: opcert expired: %d evolutions since period %d >= max %d",
			cur-dec.KESPeriod, dec.KESPeriod, maxEvol,
		)
	}

	// Promote staged -> active, but keep the previous active key around
	// (undestroyed) until authorization is known to succeed: a rollback
	// refusal below must not leave the agent with no working key at all.
	oldActive := p.active
	ks := p.staged
	p.staged = nil
	ks.startPeriod = dec.KESPeriod
	ks.maxEvol = maxEvol
	ks.opcert = append([]byte(nil), opcertBytes...)
	ks.issueNumber = dec.IssueNumber
	ks.coldSig = append([]byte(nil), dec.ColdSig...)
	ks.exhausted = false
	p.active = ks

	// Evolve to the current period and serve.
	p.evolveToLocked(cur)
	if p.active == nil {
		// evolveToLocked can only clear p.active on an internal key-store
		// failure (see the buf.Set failure path); treat it the same as a
		// guard refusal and restore the previous key.
		p.active = oldActive
		return nil, errors.New(
			"kesagent: failed to evolve newly installed key to the current period",
		)
	}
	if err := p.guard.Authorize(hex.EncodeToString(ks.vkey), p.active.absPeriod()); err != nil {
		// Roll back the install: keep serving the previous active key
		// rather than discarding a working key on a rollback refusal.
		p.active.close()
		p.active = oldActive
		// The floor may have advanced anyway (a rename that committed before a
		// later step failed), which would leave the restored key below it.
		// buildKeyPushLocked refuses to build such a push, but a push built
		// before this call can still be sitting in a subscriber's channel;
		// drain those so a producer cannot sign below the committed floor.
		p.dropQueuedPushesBelowFloorLocked()
		return nil, err
	}
	oldActive.close()
	p.guardedPeriod = p.active.absPeriod()
	p.guardedSet = true
	p.metrics.setCurrentPeriod(p.active.absPeriod())
	p.metrics.setExhausted(p.active.exhausted)
	p.broadcastLocked()
	p.logger.Info("installed KES key",
		"kes_vkey", hex.EncodeToString(ks.vkey),
		"start_period", ks.startPeriod,
		"active_period", p.active.absPeriod(),
	)
	return p.infoLocked(), nil
}

// DropKey wipes the active and/or staged key. target is "active", "staged", or
// "all" (default "all").
func (p *profile) DropKey(target string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch target {
	case "active":
		p.active.close()
		p.active = nil
		p.guardedSet = false
	case "staged":
		p.staged.close()
		p.staged = nil
	case "", "all":
		p.active.close()
		p.active = nil
		p.staged.close()
		p.staged = nil
		p.guardedSet = false
	default:
		return fmt.Errorf("kesagent: unknown drop target %q", target)
	}
	// Dropping only the staged key leaves the active key (and its exhaustion
	// state) untouched; derive the gauge from whatever remains active rather
	// than always clearing it.
	if p.active != nil {
		p.metrics.setExhausted(p.active.exhausted)
	} else {
		p.metrics.setExhausted(false)
	}
	p.logger.Info("dropped KES key", "target", target)
	return nil
}

// Sign produces a KES signature over msg at the given absolute KES period. The
// key is evolved forward as needed, but never beyond the wall-clock period
// derived from the configured genesis schedule. It never signs a period below
// the monotonic floor or below the active key's current period.
func (p *profile) Sign(period uint64, msg []byte) ([]byte, error) {
	return p.sign(period, msg, false)
}

// SignHeader is Sign for a request that must be a Praos block header body: the
// message has to decode as one, name a slot inside the requested period, and
// carry the operational certificate fields and issuer key the agent installed.
// Sign mode serves only this entry point, so the key cannot be used as an
// oracle for arbitrary messages.
func (p *profile) SignHeader(period uint64, headerBody []byte) ([]byte, error) {
	return p.sign(period, headerBody, true)
}

func (p *profile) sign(period uint64, msg []byte, typed bool) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active == nil {
		p.metrics.incSign("error")
		return nil, ErrNoActiveKey
	}
	var slot uint64
	if typed {
		var err error
		if slot, err = p.checkHeaderLocked(period, msg); err != nil {
			p.metrics.incSign("error")
			return nil, err
		}
	}
	currentPeriod := p.currentKESPeriod()
	if period > currentPeriod {
		p.metrics.incSign("error")
		return nil, fmt.Errorf("%w: requested %d, current %d",
			ErrFuturePeriod, period, currentPeriod)
	}
	if typed {
		// A slot recorded ahead of the clock would refuse every earlier
		// slot until the clock reached it.
		current := p.currentSlot()
		ahead := uint64(p.cfg.MaxClockSkew / p.cfg.SlotLength) // #nosec G115 -- both positive
		if slot > current && slot-current > ahead {
			p.metrics.incSign("error")
			return nil, fmt.Errorf("%w: slot %d, current %d, allowance %d slots",
				ErrFutureSlot, slot, current, ahead)
		}
	}
	if period < p.active.absPeriod() {
		p.metrics.incSign("error")
		return nil, fmt.Errorf("%w: requested %d, key at %d",
			ErrPastPeriod, period, p.active.absPeriod())
	}
	if period > p.active.absPeriod() {
		p.evolveToLocked(period)
	}
	if p.active == nil {
		// evolveToLocked discarded the key after a store failure.
		p.metrics.incSign("error")
		return nil, ErrNoActiveKey
	}
	if p.active.absPeriod() != period {
		p.metrics.incSign("error")
		return nil, fmt.Errorf("%w: cannot reach period %d (key ends at %d)",
			ErrExhausted, period, p.active.endPeriod())
	}
	vkeyHex := hex.EncodeToString(p.active.vkey)
	var guardErr error
	if typed {
		// One header body per slot, never an older slot: the record is durable
		// before the signature leaves the agent, so producers sharing this
		// agent cannot publish two blocks for the pool in one slot.
		guardErr = p.guard.AuthorizeHeader(vkeyHex, period, slot, msg)
	} else {
		guardErr = p.guard.Authorize(vkeyHex, period)
	}
	if guardErr != nil {
		p.metrics.incSign("error")
		return nil, guardErr
	}
	sk := &kes.SecretKey{
		Depth:  p.active.depth,
		Period: p.active.period,
		Data:   p.active.buf.Bytes(),
	}
	sig, err := kes.Sign(sk, p.active.period, msg)
	if err != nil {
		p.metrics.incSign("error")
		return nil, fmt.Errorf("kesagent: sign: %w", err)
	}
	p.metrics.incSign("ok")
	p.metrics.setCurrentPeriod(p.active.absPeriod())
	return sig, nil
}

// storeEvolvedKey writes an evolved KES key into the active locked buffer. It
// is a variable so tests can exercise the discard-on-failure branch in
// evolveToLocked, which is otherwise unreachable: Buffer.Set fails only on a
// closed buffer or a length mismatch, and p.mu serializes both away in every
// real call path.
var storeEvolvedKey = func(buf *securemem.Buffer, data []byte) error {
	return buf.Set(data)
}

// evolveToLocked evolves the active key forward until its absolute period
// reaches targetAbs or the key is exhausted. Caller must hold p.mu.
func (p *profile) evolveToLocked(targetAbs uint64) {
	for p.active != nil && p.active.absPeriod() < targetAbs {
		nextInternal := p.active.period + 1
		if nextInternal >= p.active.maxEvol {
			if !p.active.exhausted {
				p.active.exhausted = true
				p.metrics.setExhausted(true)
				p.logger.Warn("KES key exhausted; a new key must be installed",
					"kes_vkey", hex.EncodeToString(p.active.vkey),
					"active_period", p.active.absPeriod(),
					"target_period", targetAbs,
				)
			}
			return
		}
		cur := &kes.SecretKey{
			Depth:  p.active.depth,
			Period: p.active.period,
			Data:   p.active.buf.Bytes(),
		}
		next, err := kes.Update(cur) // reads (and internally copies) cur.Data
		if err != nil {
			if !p.active.exhausted {
				p.active.exhausted = true
				p.metrics.setExhausted(true)
				p.logger.Warn("KES key update failed; marking exhausted",
					"error", err,
					"kes_vkey", hex.EncodeToString(p.active.vkey),
				)
			}
			return
		}
		// Interim forward-erasure: wipe the spent key material now, then install
		// the evolved key. TODO adopt gouroboros SecretKey.Zeroize once pinned.
		p.active.buf.Zeroize()
		if err := storeEvolvedKey(p.active.buf, next.Data); err != nil {
			securemem.Wipe(next.Data)
			p.logger.Error(
				"failed to store evolved KES key; discarding the key",
				"error",
				err,
			)
			// The buffer was already zeroized above and next.Data failed to
			// land, so p.active.period is stale relative to its now-zeroed
			// buffer contents. Discard the key entirely rather than leaving
			// it installed: Sign() would otherwise happily sign over the
			// zeroed buffer for the (unchanged) period it still reports.
			p.active.close()
			p.active = nil
			// No active key exists at all now, so "exhausted" (which implies a
			// key that reached its final period) is the wrong signal; clear it
			// rather than reporting a false key-exhaustion health state.
			p.metrics.setExhausted(false)
			return
		}
		securemem.Wipe(next.Data) // erase the transient evolved copy
		p.active.period = next.Period
		p.metrics.incEvolutions()
	}
}

// activeAuthorizedLocked reports whether the active key's exact period passed
// its most recent guard authorization. Caller holds p.mu.
func (p *profile) activeAuthorizedLocked() bool {
	return p.active != nil && p.guardedSet &&
		p.guardedPeriod == p.active.absPeriod()
}

// buildKeyPushLocked builds a KeyPush for the current active key. Caller holds p.mu.
func (p *profile) buildKeyPushLocked() (KeyPush, bool) {
	// The active key advances before Tick persists the new guard floor. Do not
	// release that evolved key until authorization for its exact period succeeds;
	// guardedPeriod remains at the last successful period so Tick can retry.
	if !p.activeAuthorizedLocked() {
		return KeyPush{}, false
	}
	// Never hand a producer a key for a period the guard has already moved past:
	// serving it would let the producer sign below the monotonic floor, which is
	// the rollback the guard exists to prevent. The two can diverge when an
	// install advances the floor but then fails and restores the previous key.
	if floor, set := p.guard.Floor(); set && p.active.absPeriod() < floor {
		p.logger.Warn("refusing to serve a key below the period guard floor",
			"active_period", p.active.absPeriod(),
			"floor", floor,
			"kes_vkey", hex.EncodeToString(p.active.vkey),
		)
		return KeyPush{}, false
	}
	return KeyPush{
		Type:       "key_push",
		Period:     p.active.absPeriod(),
		Depth:      p.active.depth,
		KESSignKey: p.active.buf.Clone(),
		KESVKey:    append([]byte(nil), p.active.vkey...),
		OpCert:     append([]byte(nil), p.active.opcert...),
	}, true
}

// broadcastLocked pushes the current key to all serve-key subscribers. Caller
// holds p.mu.
func (p *profile) broadcastLocked() {
	base, ok := p.buildKeyPushLocked()
	if !ok {
		return
	}
	// base.KESSignKey is a plaintext clone of the locked signing key. Hand each
	// subscriber its OWN copy (so one handler wiping its copy after writing
	// cannot corrupt another's) and wipe every copy the moment it is no longer
	// needed, so superseded key material does not linger on the swappable heap
	// and defeat the forward-erasure done on evolution.
	defer securemem.Wipe(base.KESSignKey)
	for _, ch := range p.subs {
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
			p.metrics.incServedKeys()
		default:
			// Subscriber channel is still full (shouldn't happen since we just
			// drained it above, but be defensive): wipe the copy we could not
			// deliver rather than dropping it un-erased, and don't count it.
			securemem.Wipe(kp.KESSignKey)
		}
	}
}

// dropQueuedPushesBelowFloorLocked drains and wipes any queued key push whose
// period is below the guard floor. Caller holds p.mu.
//
// buildKeyPushLocked refuses to build a below-floor push, but that only covers
// pushes not yet built: a push enqueued while the key and the floor still
// agreed stays in its subscriber's buffered channel, and a serve-key client
// reading it would be handed a key for a period the floor has since passed.
func (p *profile) dropQueuedPushesBelowFloorLocked() {
	floor, set := p.guard.Floor()
	if !set {
		return
	}
	for id, ch := range p.subs {
		select {
		case kp := <-ch:
			if kp.Period < floor {
				p.logger.Warn(
					"dropping queued KES key push below the guard floor",
					"subscriber",
					id,
					"push_period",
					kp.Period,
					"floor",
					floor,
				)
				securemem.Wipe(kp.KESSignKey)
				continue
			}
			// Above the floor: put it back rather than dropping a valid push.
			select {
			case ch <- kp:
			default:
				securemem.Wipe(kp.KESSignKey)
			}
		default:
		}
	}
}

// subscribe registers a serve-key subscriber and returns its id, its channel,
// and the current key push (if a key is active) to send immediately.
func (p *profile) subscribe() (int, chan KeyPush, *KeyPush) {
	p.mu.Lock()
	defer p.mu.Unlock()
	id := p.nextSub
	p.nextSub++
	ch := make(chan KeyPush, 1)
	p.subs[id] = ch
	if kp, ok := p.buildKeyPushLocked(); ok {
		return id, ch, &kp
	}
	return id, ch, nil
}

func (p *profile) unsubscribe(id int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Drain and wipe any key push still queued for this subscriber so its
	// plaintext signing-key copy does not outlive the subscription on the heap.
	if ch, ok := p.subs[id]; ok {
		select {
		case kp := <-ch:
			securemem.Wipe(kp.KESSignKey)
		default:
		}
	}
	delete(p.subs, id)
}

// Tick advances the scheduler once: it evolves the active key to the current
// period and, if it advanced, authorizes and broadcasts the new key.
func (p *profile) Tick() {
	cur := p.currentKESPeriod()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.metrics.setCurrentPeriod(cur)
	if p.active == nil {
		return
	}
	p.evolveToLocked(cur)
	if p.active == nil {
		// evolveToLocked discarded the key after a store failure.
		return
	}
	newAbs := p.active.absPeriod()
	p.metrics.setCurrentPeriod(newAbs)
	p.metrics.setExhausted(p.active.exhausted)
	// Authorize (and broadcast) whenever the current period hasn't already
	// been successfully authorized: gating only on "did the in-memory key
	// just evolve" would mean a transient guard-store failure (e.g. a full
	// disk) is never retried, since evolveToLocked has already advanced
	// p.active in memory and won't advance it again for the same period.
	if p.activeAuthorizedLocked() {
		return
	}
	if err := p.guard.Authorize(hex.EncodeToString(p.active.vkey), newAbs); err != nil {
		p.logger.Error("period guard refused evolved key; not serving",
			"error", err, "period", newAbs)
		return
	}
	p.guardedPeriod = newAbs
	p.guardedSet = true
	p.broadcastLocked()
	p.logger.Info("evolved KES key", "active_period", newAbs)
}

// info returns a status snapshot of the profile.
func (p *profile) info() *AgentInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.infoLocked()
}

func (p *profile) infoLocked() *AgentInfo {
	floor, floorSet := p.guard.Floor()
	info := &AgentInfo{
		Profile:          p.cfg.Name,
		Mode:             p.mode,
		CurrentPeriod:    p.currentKESPeriod(),
		MonotonicFloor:   floor,
		FloorInitialized: floorSet,
	}
	if p.active != nil {
		info.HasActiveKey = true
		info.ActivePeriod = p.active.absPeriod()
		info.ActiveStart = p.active.startPeriod
		info.ActiveEnd = p.active.endPeriod()
		info.ActiveKESVKey = append([]byte(nil), p.active.vkey...)
		info.ActiveIssueNumber = p.active.issueNumber
		info.ActiveOpCert = append([]byte(nil), p.active.opcert...)
		info.Exhausted = p.active.exhausted
	}
	if p.staged != nil {
		info.StagedKESVKey = append([]byte(nil), p.staged.vkey...)
	}
	return info
}

// close wipes all key material.
func (p *profile) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active.close()
	p.active = nil
	p.staged.close()
	p.staged = nil
}
