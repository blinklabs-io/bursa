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
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger/babbage"
)

// DefaultProfileName names the one profile built from a single-pool Config.
const DefaultProfileName = "default"

// Profile selection errors. They are distinct so a caller can report which
// way a request failed to name exactly one profile.
var (
	// ErrUnknownProfile is returned when a request names a profile, or
	// carries a key, that no configured profile has.
	ErrUnknownProfile = errors.New("kesagent: no such profile")
	// ErrAmbiguousProfile is returned when a request does not say which
	// profile it is for and the agent has more than one, or when a header
	// matches more than one profile.
	ErrAmbiguousProfile = errors.New(
		"kesagent: request does not select exactly one profile",
	)
	// ErrProfileMismatch is returned when a header routes to a profile other
	// than the one the request or its session named.
	ErrProfileMismatch = errors.New(
		"kesagent: header belongs to a different profile",
	)
)

var profileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Agent is the KES agent core: key custody, evolution, signing and serve-key
// broadcast for one or more profiles. It is safe for concurrent use.
//
// The profile list is fixed at construction, so routing reads it without a
// lock; each profile serializes its own state.
type Agent struct {
	cfg      Config
	logger   *slog.Logger
	metrics  *Metrics
	profiles []*profile
	byName   map[string]*profile

	now func() time.Time // injectable clock (tests); profiles read it
}

// New constructs an Agent, validating configuration and opening every
// profile's durable period guard.
func New(cfg Config, logger *slog.Logger, metrics *Metrics) (*Agent, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Mode != ModeServeKey && cfg.Mode != ModeSign {
		return nil, fmt.Errorf("kesagent: invalid mode %q", cfg.Mode)
	}
	if cfg.EvolveInterval <= 0 {
		cfg.EvolveInterval = time.Minute
	}
	profileCfgs := cfg.Profiles
	if len(profileCfgs) == 0 {
		profileCfgs = []ProfileConfig{{
			Name:              DefaultProfileName,
			Depth:             cfg.Depth,
			SystemStart:       cfg.SystemStart,
			ShelleyStartSlot:  cfg.ShelleyStartSlot,
			ShelleyStartTime:  cfg.ShelleyStartTime,
			SlotLength:        cfg.SlotLength,
			SlotsPerKESPeriod: cfg.SlotsPerKESPeriod,
			MaxKESEvolutions:  cfg.MaxKESEvolutions,
			MaxClockSkew:      cfg.MaxClockSkew,
			ColdVKey:          cfg.ColdVKey,
			GuardPath:         cfg.GuardPath,
		}}
	} else if cfg.ColdVKey != nil || cfg.GuardPath != "" ||
		!cfg.SystemStart.IsZero() || cfg.ShelleyStartSlot != 0 ||
		!cfg.ShelleyStartTime.IsZero() || cfg.MaxClockSkew != 0 {
		return nil, errors.New(
			"kesagent: set either profiles or the single-pool fields, not both",
		)
	}
	// A key pushed to a producer is the key; with several, a subscriber
	// would not know which one it was handed.
	if cfg.Mode == ModeServeKey && len(profileCfgs) != 1 {
		return nil, errors.New("kesagent: serve-key mode takes exactly one profile")
	}
	a := &Agent{
		cfg:     cfg,
		logger:  logger,
		metrics: metrics,
		byName:  make(map[string]*profile, len(profileCfgs)),
		now:     time.Now,
	}
	guards := make(map[string]string, len(profileCfgs))
	type guardFile struct {
		name string
		info os.FileInfo
	}
	var existingGuards []guardFile
	pools := make(map[string]string, len(profileCfgs))
	for _, pc := range profileCfgs {
		if !profileNamePattern.MatchString(pc.Name) {
			a.Close()
			return nil, fmt.Errorf(
				"kesagent: profile name %q must be 1-64 letters, digits, '.', '_' or '-'",
				pc.Name,
			)
		}
		if _, dup := a.byName[pc.Name]; dup {
			a.Close()
			return nil, fmt.Errorf("kesagent: duplicate profile name %q", pc.Name)
		}
		// Two profiles writing one guard file would overwrite each other's
		// floor and slot record, which is the rollback the guard prevents.
		if pc.GuardPath != "" {
			abs, err := filepath.Abs(pc.GuardPath)
			if err != nil {
				a.Close()
				return nil, fmt.Errorf(
					"kesagent: profile %q guard path: %w",
					pc.Name,
					err,
				)
			}
			if other, dup := guards[abs]; dup {
				a.Close()
				return nil, fmt.Errorf(
					"kesagent: profiles %q and %q share guard file %q",
					other,
					pc.Name,
					abs,
				)
			}
			guards[abs] = pc.Name
			// The same file reached through a symlink or a hard link.
			if info, err := os.Stat(abs); err == nil {
				for _, g := range existingGuards {
					if os.SameFile(g.info, info) {
						a.Close()
						return nil, fmt.Errorf(
							"kesagent: profiles %q and %q share guard file %q",
							g.name,
							pc.Name,
							abs,
						)
					}
				}
				existingGuards = append(
					existingGuards,
					guardFile{name: pc.Name, info: info},
				)
			}
		}
		// Each profile keeps its own slot record, so two profiles for one
		// pool on one network would each sign a header for the same slot:
		// two blocks from the pool in that slot. One cold key stays allowed
		// on several networks, which a different genesis start tells apart.
		poolKey := hex.EncodeToString(pc.ColdVKey) + "@" +
			pc.SystemStart.UTC().Format(time.RFC3339Nano)
		if other, dup := pools[poolKey]; dup {
			a.Close()
			return nil, fmt.Errorf(
				"kesagent: profiles %q and %q are the same pool on the same network",
				other,
				pc.Name,
			)
		}
		pools[poolKey] = pc.Name
		p, err := newProfile(
			pc,
			cfg.Mode,
			logger,
			metrics,
			&a.now,
			cfg.SharedGuard,
		)
		if err != nil {
			a.Close()
			return nil, fmt.Errorf("profile %q: %w", pc.Name, err)
		}
		a.profiles = append(a.profiles, p)
		a.byName[pc.Name] = p
	}
	return a, nil
}

// soleProfile returns the agent's only profile, or ErrAmbiguousProfile when
// it has several.
func (a *Agent) soleProfile() (*profile, error) {
	if len(a.profiles) != 1 {
		return nil, ErrAmbiguousProfile
	}
	return a.profiles[0], nil
}

// profileByName returns the named profile. An empty name selects the sole
// profile.
func (a *Agent) profileByName(name string) (*profile, error) {
	if name == "" {
		return a.soleProfile()
	}
	p, ok := a.byName[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProfile, name)
	}
	return p, nil
}

// selectProfile picks the profile a remote session is for. With kesVKey set it
// is the profile whose active key has that verification key, and name, when
// also set, must name the same profile; with only name it is the named
// profile; with neither it is the sole profile. It does no I/O and changes no
// guard or key state, so it is safe to call before the caller is authorized
// for the profile it selects.
func (a *Agent) selectProfile(name string, kesVKey []byte) (*profile, error) {
	if len(kesVKey) == 0 {
		return a.profileByName(name)
	}
	var match *profile
	for _, p := range a.profiles {
		if !p.hasActiveVKey(kesVKey) {
			continue
		}
		if match != nil {
			return nil, ErrAmbiguousProfile
		}
		match = p
	}
	if match == nil {
		return nil, fmt.Errorf("%w: no active key matches", ErrUnknownProfile)
	}
	if name != "" && name != match.cfg.Name {
		return nil, fmt.Errorf(
			"%w: key belongs to %q, request names %q",
			ErrProfileMismatch,
			match.cfg.Name,
			name,
		)
	}
	return match, nil
}

// hasActiveVKey reports whether vkey is the profile's active key. It reads
// the routing snapshot, not the key under p.mu, so routing a request never
// waits on another profile's signing; the routed profile re-checks the key
// under its own lock before signing.
func (p *profile) hasActiveVKey(vkey []byte) bool {
	active := p.activeVKey.Load()
	return active != nil && bytes.Equal(*active, vkey)
}

// routeHeader returns the profile a header body belongs to: the one whose cold
// key is the header's issuer and whose active key is the KES key its
// operational certificate names. One cold key can serve several networks;
// the KES key tells those profiles apart. The full header checks run later
// under the routed profile's lock.
func (a *Agent) routeHeader(headerBody []byte) (*profile, error) {
	var hb babbage.BabbageBlockHeaderBody
	if _, err := cbor.Decode(headerBody, &hb); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidHeader, err)
	}
	var match *profile
	for _, p := range a.profiles {
		if !bytes.Equal(hb.IssuerVkey[:], p.cfg.ColdVKey) ||
			!p.hasActiveVKey(hb.OpCert.HotVkey) {
			continue
		}
		if match != nil {
			return nil, ErrAmbiguousProfile
		}
		match = p
	}
	if match == nil {
		return nil, fmt.Errorf(
			"%w: header matches no profile's cold key and active KES key",
			ErrUnknownProfile,
		)
	}
	return match, nil
}

// signHeaderFor signs a header body for the profile it routes to. bound, when
// set, is the profile the request or its session is for; a header that routes
// elsewhere is refused before any guard write.
func (a *Agent) signHeaderFor(
	bound *profile,
	period uint64,
	headerBody []byte,
) ([]byte, error) {
	// A single-profile agent needs no routing, and its own header checks
	// give the more specific reason for a header that does not match it.
	var p *profile
	var err error
	if len(a.profiles) == 1 {
		p = a.profiles[0]
	} else {
		p, err = a.routeHeader(headerBody)
	}
	if err != nil {
		if bound != nil {
			bound.metrics.incSign("error")
		}
		return nil, err
	}
	if bound != nil && bound != p {
		bound.metrics.incSign("error")
		return nil, fmt.Errorf(
			"%w: header is for %q, request is for %q",
			ErrProfileMismatch,
			p.cfg.Name,
			bound.cfg.Name,
		)
	}
	return p.SignHeader(period, headerBody)
}

// SignHeader signs a Praos block header body with the key of the profile the
// header names. See profile.SignHeader for the checks.
func (a *Agent) SignHeader(period uint64, headerBody []byte) ([]byte, error) {
	return a.signHeaderFor(nil, period, headerBody)
}

// Sign signs an arbitrary message with the sole profile's key. It is not
// reachable from the service socket, which serves only SignHeader.
func (a *Agent) Sign(period uint64, msg []byte) ([]byte, error) {
	p, err := a.soleProfile()
	if err != nil {
		return nil, err
	}
	return p.Sign(period, msg)
}

// GenStagedKey stages a fresh KES key in the sole profile.
func (a *Agent) GenStagedKey() ([]byte, error) {
	p, err := a.soleProfile()
	if err != nil {
		return nil, err
	}
	return p.GenStagedKey()
}

// InstallKey installs an operational certificate in the sole profile.
func (a *Agent) InstallKey(opcertBytes []byte) (*AgentInfo, error) {
	p, err := a.soleProfile()
	if err != nil {
		return nil, err
	}
	info, err := p.InstallKey(opcertBytes)
	if err != nil {
		return nil, err
	}
	info.Version = a.cfg.Version
	return info, nil
}

// DropKey drops key material from the sole profile.
func (a *Agent) DropKey(target string) error {
	p, err := a.soleProfile()
	if err != nil {
		return err
	}
	return p.DropKey(target)
}

// Info returns the sole profile's status, or with several profiles a
// snapshot that carries only the agent-wide fields; ProfilesInfo lists them.
func (a *Agent) Info() *AgentInfo {
	p, err := a.soleProfile()
	if err != nil {
		return &AgentInfo{Version: a.cfg.Version, Mode: a.cfg.Mode}
	}
	return a.profileInfo(p)
}

// ProfilesInfo returns a status snapshot of every profile, in configuration
// order.
func (a *Agent) ProfilesInfo() []AgentInfo {
	out := make([]AgentInfo, 0, len(a.profiles))
	for _, p := range a.profiles {
		out = append(out, *a.profileInfo(p))
	}
	return out
}

func (a *Agent) profileInfo(p *profile) *AgentInfo {
	info := p.info()
	info.Version = a.cfg.Version
	return info
}

// subscribe registers a serve-key subscriber with the sole profile; serve-key
// mode is single-profile by construction.
func (a *Agent) subscribe() (*profile, int, chan KeyPush, *KeyPush) {
	p := a.profiles[0]
	id, ch, current := p.subscribe()
	return p, id, ch, current
}

// Tick advances every profile's scheduler once.
func (a *Agent) Tick() {
	for _, p := range a.profiles {
		p.Tick()
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

// Close wipes all key material in every profile and releases the guard file
// locks.
func (a *Agent) Close() {
	for _, p := range a.profiles {
		p.close()
	}
}

// attestedKeyState is the public key state a remote session is admitted
// against: the profile's cold key, active KES key, operational certificate
// and period.
func (p *profile) attestedKeyState() (attestedKeyState, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.mode != ModeSign {
		return attestedKeyState{}, errors.New(
			"kesagent: attested service requires sign mode",
		)
	}
	if p.active == nil || !p.activeAuthorizedLocked() {
		return attestedKeyState{}, ErrNoActiveKey
	}
	if floor, set := p.guard.Floor(); set && p.active.absPeriod() < floor {
		return attestedKeyState{}, ErrPeriodRollback
	}
	return attestedKeyState{
		coldVKey: append([]byte(nil), p.cfg.ColdVKey...),
		kesVKey:  append([]byte(nil), p.active.vkey...),
		opcert:   append([]byte(nil), p.active.opcert...),
		period:   p.active.absPeriod(),
	}, nil
}
