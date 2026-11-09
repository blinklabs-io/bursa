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
	"errors"
	"fmt"
	"time"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/gouroboros/kes"
)

// keyStoreTimeout bounds each key store call. Some are made under the
// profile lock, so a hung database must not hold it.
const keyStoreTimeout = 5 * time.Second

// defaultKeyPollInterval is how often Run checks the key store for a newly
// installed key when Config.KeyPollInterval is unset.
const defaultKeyPollInterval = 10 * time.Second

// stageShared seals a freshly generated key and writes it to the key store as
// the profile's staged key, replacing any staged before.
func (p *profile) stageShared(
	ctx context.Context,
	sk *kes.SecretKey,
	vkey []byte,
) error {
	sealed, err := p.sealer.seal(sk.Depth, sk.Period, vkey, sk.Data)
	if err != nil {
		return err
	}
	rec := SealedKey{
		KESVKey:      append([]byte(nil), vkey...),
		Depth:        sk.Depth,
		SealedPeriod: sk.Period,
		Sealed:       sealed,
	}
	// A key this replica's identities cannot open could not be installed
	// here either; refuse it now rather than at install time.
	buf, err := p.sealer.unseal(rec)
	if err != nil {
		return fmt.Errorf(
			"kesagent: the sealed key does not open with this agent's age identity (do age_recipients include it?): %w",
			err,
		)
	}
	_ = buf.Close()
	ctx, cancel := context.WithTimeout(ctx, keyStoreTimeout)
	defer cancel()
	return p.keys.PutStaged(ctx, p.keyPool, p.keyNetwork, rec)
}

// installShared installs the key staged in the key store: it checks the
// opcert against that key, unseals and activates it, and records it as
// installed. If another replica installed the same key with a different
// opcert first, this install is refused and the previous key stays active.
func (p *profile) installShared(
	ctx context.Context,
	dec *bursa.DecodedOpCert,
	opcertBytes []byte,
) (*AgentInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*keyStoreTimeout)
	defer cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	rec, ok, err := p.keys.Staged(ctx, p.keyPool, p.keyNetwork)
	if err != nil {
		return nil, err
	}
	if !ok {
		return p.installedAlreadyLocked(ctx, opcertBytes)
	}
	cur, maxEvol, err := p.checkOpCert(dec, rec.KESVKey)
	if err != nil {
		return nil, err
	}
	ks, err := p.unsealKeyState(rec, dec, cur)
	if err != nil {
		return nil, err
	}
	var gen uint64
	commit := func() error {
		g, err := p.keys.Install(
			ctx,
			p.keyPool,
			p.keyNetwork,
			rec.KESVKey,
			opcertBytes,
		)
		gen = g
		return err
	}
	if err := p.activateLocked(
		ks, dec, opcertBytes, cur, maxEvol, commit, "installed KES key",
	); err != nil {
		return nil, err
	}
	p.markSeenLocked(gen, opcertBytes)
	// Whatever this replica staged locally is either the key just installed
	// or one the store no longer holds.
	p.staged.close()
	p.staged = nil
	return p.infoLocked(), nil
}

// installedAlreadyLocked answers an install that found no staged key. When
// the installed record carries this very opcert (another replica installed
// it first) the install succeeds as a load of that record; otherwise there
// is nothing to install. Caller holds p.mu.
func (p *profile) installedAlreadyLocked(
	ctx context.Context,
	opcertBytes []byte,
) (*AgentInfo, error) {
	rec, ok, err := p.keys.Installed(ctx, p.keyPool, p.keyNetwork)
	if err != nil {
		return nil, err
	}
	if !ok || !bytes.Equal(rec.OpCert, opcertBytes) {
		return nil, ErrNoStagedKey
	}
	if p.active == nil || !p.seenSet || p.seenGen != rec.Generation ||
		!bytes.Equal(p.seenOpCert, rec.OpCert) {
		if err := p.loadRecordLocked(rec); err != nil {
			return nil, err
		}
		p.markSeenLocked(rec.Generation, rec.OpCert)
	}
	// As in installShared: a key staged here is either the one installed or
	// one the store no longer holds.
	p.staged.close()
	p.staged = nil
	return p.infoLocked(), nil
}

// unsealKeyState opens rec's signing key into a key state ready for
// activateLocked, certified by dec at current period cur.
func (p *profile) unsealKeyState(
	rec SealedKey,
	dec *bursa.DecodedOpCert,
	cur uint64,
) (*keyState, error) {
	if rec.Depth != p.cfg.Depth {
		return nil, fmt.Errorf(
			"kesagent: stored KES key has depth %d, profile uses %d",
			rec.Depth,
			p.cfg.Depth,
		)
	}
	// A stored key already evolved past the current period cannot sign it.
	if rec.SealedPeriod > cur-dec.KESPeriod {
		return nil, fmt.Errorf(
			"kesagent: stored KES key is at period %d, past the current period %d",
			dec.KESPeriod+rec.SealedPeriod,
			cur,
		)
	}
	buf, err := p.sealer.unseal(rec)
	if err != nil {
		return nil, err
	}
	if !buf.Locked() {
		p.logger.Warn(
			"KES secret key buffer could not be locked in memory (mlock unavailable or refused); key material may be swappable to disk",
		)
	}
	return &keyState{
		depth:  rec.Depth,
		period: rec.SealedPeriod,
		buf:    buf,
		vkey:   append([]byte(nil), rec.KESVKey...),
	}, nil
}

// syncInstalledKey loads the profile's installed key from the key store when
// it differs from the one this replica last installed or loaded. A read or
// load failure keeps the current key, if any, and is retried on the next
// sync.
func (p *profile) syncInstalledKey(ctx context.Context) error {
	if p.keys == nil {
		return nil
	}
	// Read under the lock: a read taken before a concurrent local install
	// would otherwise look older than the key that install just activated.
	p.mu.Lock()
	defer p.mu.Unlock()
	rec, ok, err := p.keys.Installed(ctx, p.keyPool, p.keyNetwork)
	if err != nil {
		p.loadErr = err
		p.noteKeyErrorLocked("read the installed KES key", err)
		return err
	}
	if !ok || (p.seenSet && rec.Generation == p.seenGen &&
		bytes.Equal(rec.OpCert, p.seenOpCert)) {
		p.loadErr = nil
		p.lastKeyErr = ""
		return nil
	}
	if err := p.loadRecordLocked(rec); err != nil {
		p.loadErr = err
		p.noteKeyErrorLocked(
			fmt.Sprintf("load installed KES key generation %d", rec.Generation),
			err,
		)
		return err
	}
	p.markSeenLocked(rec.Generation, rec.OpCert)
	return nil
}

// loadRecordLocked activates an installed record after the same opcert
// checks InstallKey makes: the record's state alone is not trusted, since
// anyone who can write the table can mark a key installed. Caller holds p.mu.
func (p *profile) loadRecordLocked(rec SealedKey) error {
	if len(rec.OpCert) == 0 {
		return errors.New("kesagent: installed KES key record has no opcert")
	}
	dec, err := bursa.DecodeOpCert(rec.OpCert)
	if err != nil {
		return err
	}
	cur, maxEvol, err := p.checkOpCert(dec, rec.KESVKey)
	if err != nil {
		return err
	}
	ks, err := p.unsealKeyState(rec, dec, cur)
	if err != nil {
		return err
	}
	return p.activateLocked(
		ks,
		dec,
		rec.OpCert,
		cur,
		maxEvol,
		nil,
		"loaded installed KES key from the shared key store",
	)
}

// loadFailure returns the error a sign request reports while the profile
// holds no key because the shared key could not be loaded, or nil.
func (p *profile) loadFailure() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active != nil || p.loadErr == nil {
		return nil
	}
	return p.noKeyErrorLocked()
}

// noKeyErrorLocked is the error for a sign request while the profile holds
// no key. Caller holds p.mu.
func (p *profile) noKeyErrorLocked() error {
	if p.loadErr != nil {
		return fmt.Errorf(
			"%w: the installed key in the shared key store could not be loaded: %w",
			ErrNoActiveKey,
			p.loadErr,
		)
	}
	return ErrNoActiveKey
}

// markSeenLocked records the installed record now active. Caller holds p.mu.
func (p *profile) markSeenLocked(gen uint64, opcert []byte) {
	p.seenGen = gen
	p.seenOpCert = append([]byte(nil), opcert...)
	p.seenSet = true
	p.loadErr = nil
	p.lastKeyErr = ""
}

// noteKeyErrorLocked logs a key store failure once, not on every poll that
// repeats it. Caller holds p.mu.
func (p *profile) noteKeyErrorLocked(what string, err error) {
	msg := what + ": " + err.Error()
	if msg == p.lastKeyErr {
		return
	}
	p.lastKeyErr = msg
	p.logger.Error("shared KES key store: "+what, "error", err)
}

// SyncKeys loads, for every profile, the installed key from the shared key
// store when it differs from the one the profile holds. It does nothing
// without a key store. A profile that fails keeps its current key (if any)
// and refuses signs while it has none; the errors are returned joined.
func (a *Agent) SyncKeys(ctx context.Context) error {
	if a.cfg.KeyStore == nil {
		return nil
	}
	var errs []error
	for _, p := range a.profiles {
		pctx, cancel := context.WithTimeout(ctx, keyStoreTimeout)
		if err := p.syncInstalledKey(pctx); err != nil {
			errs = append(errs, fmt.Errorf("profile %q: %w", p.cfg.Name, err))
		}
		cancel()
	}
	return errors.Join(errs...)
}
