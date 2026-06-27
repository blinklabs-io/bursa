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

// Package vault is the encrypted, multi-wallet store for the full-node wallet.
//
// It implements the LAYERED unlock model:
//
//   - A single vault password unlocks the instance. It decrypts the vault INDEX
//     — the wallet list with the read-only material (name, network, account
//     xpub, and the derived stake/receive addresses). Unlocking grants
//     read-only access (balances, addresses, history, staking) across ALL
//     wallets, with no per-wallet prompt and no seed re-entry on later launches.
//   - Spending from a wallet additionally requires THAT wallet's own spending
//     password, which decrypts its seed (an inline keystore blob) so a signing
//     key can be derived. The seed never leaves its encrypted form at rest.
//
// Both layers reuse the keystore's scrypt + AES-256-GCM scheme (no new crypto):
// the index is sealed with keystore.Seal under the vault password; each wallet's
// seed is sealed the same way under its spending password.
//
// The on-disk file is a single JSON object:
//
//	{
//	  "format": 1,
//	  "index": <keystore Container, encrypted under the vault password>,
//	  "seeds": { "<wallet id>": <keystore Container, encrypted under spend pw> }
//	}
//
// The plaintext index (inside the encrypted "index" blob) is:
//
//	{ "wallets": [ { "id", "name", "network", "account_xpub", "account": {…} } ] }
//
// Splitting seeds out of the encrypted index keeps each seed reachable with only
// its own spending password — unlocking the vault never exposes any seed.
package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

// formatVersion is the on-disk envelope version (distinct from the keystore
// Container version each blob carries).
const formatVersion = 1

// maxVaultLen caps the read of the vault file. A vault with a handful of wallets
// is a few KiB; anything past this is not one of ours.
const maxVaultLen = 4 * 1024 * 1024

// Sentinel errors. The API layer maps these to HTTP status codes.
var (
	// ErrNoVault: no vault file exists yet (→ first-run create flow).
	ErrNoVault = errors.New("no vault")
	// ErrVaultExists: Create called when a vault file already exists.
	ErrVaultExists = errors.New("vault already exists")
	// ErrLocked: an operation needs the vault unlocked but it is locked.
	ErrLocked = errors.New("vault is locked")
	// ErrWrongPassword: a vault or spending password failed authentication.
	ErrWrongPassword = errors.New("incorrect password")
	// ErrUnknownWallet: no wallet with the given id is in the vault.
	ErrUnknownWallet = errors.New("unknown wallet")
	// ErrNoActiveWallet: an operation needs an active wallet but none is set.
	ErrNoActiveWallet = errors.New("no active wallet")
	// ErrDuplicateWallet: a wallet derived from the same seed (same stake
	// address) is already in the vault.
	ErrDuplicateWallet = errors.New("wallet already exists in vault")
)

// WalletMeta is the read-only record kept for one wallet inside the index. It
// holds everything needed to serve read-only views without the seed: the
// derived account (stake address + receive-address window) and the account
// xpub. The seed itself lives in the separate, spend-password-encrypted seeds
// map and is never part of this record.
type WalletMeta struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Network     string          `json:"network"`
	AccountXpub string          `json:"account_xpub"`
	Account     *wallet.Account `json:"account"`
}

// index is the plaintext payload sealed under the vault password.
type index struct {
	Wallets []WalletMeta `json:"wallets"`
}

// envelope is the on-disk JSON: an encrypted index plus per-wallet encrypted
// seed blobs keyed by wallet id.
type envelope struct {
	Format int                           `json:"format"`
	Index  keystore.Container            `json:"index"`
	Seeds  map[string]keystore.Container `json:"seeds"`
}

// Vault is a thread-safe handle to the on-disk vault file. When unlocked it
// caches the decrypted index in memory (the seeds stay encrypted); Lock clears
// that cache.
type Vault struct {
	path string

	// seal/open are the encrypt/decrypt primitives; production uses the
	// keystore's full-cost scrypt + AES-256-GCM. Tests swap in a cheap KDF via
	// SetCipher to keep the suite fast.
	seal keystore.Sealer
	open keystore.Opener

	mu       sync.RWMutex
	idx      *index // non-nil only while unlocked
	activeID string // id of the active wallet (empty if none)
}

// New returns a Vault backed by the file at path. It does not touch the file
// until a method needs it.
func New(path string) *Vault {
	return &Vault{path: path, seal: keystore.Seal, open: keystore.Open}
}

// SetCipher overrides the seal/open primitives. Only tests use it, to swap in a
// cheap KDF (keystore.CheapTestSealer); production keeps the full-cost default.
func (v *Vault) SetCipher(seal keystore.Sealer, open keystore.Opener) {
	v.mu.Lock()
	v.seal = seal
	v.open = open
	v.mu.Unlock()
}

// Exists reports whether a vault file is present.
func (v *Vault) Exists() bool {
	_, err := os.Stat(v.path)
	return err == nil
}

// Locked reports whether the vault is currently locked (no decrypted index in
// memory). A non-existent vault reads as locked.
func (v *Vault) Locked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.idx == nil
}

// WalletCount returns the number of wallets in the vault. It works whether the
// vault is locked or unlocked: when unlocked it uses the cached index; when
// locked it reads the envelope and counts the seed blobs (the index is
// encrypted, but the seed map keys are wallet ids in cleartext, so a count is
// available without the vault password). Returns 0 when no vault exists.
func (v *Vault) WalletCount() int {
	v.mu.RLock()
	if v.idx != nil {
		n := len(v.idx.Wallets)
		v.mu.RUnlock()
		return n
	}
	v.mu.RUnlock()
	env, err := v.readEnvelope()
	if err != nil {
		return 0
	}
	return len(env.Seeds)
}

// Create initializes a new, empty vault sealed under the vault password and
// leaves it unlocked. It refuses to overwrite an existing vault. The caller is
// responsible for enforcing the password-length floor (the API does, via
// keystore.MinPasswordLen).
func (v *Vault) Create(vaultPassword string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.Exists() {
		return ErrVaultExists
	}
	idx := &index{Wallets: []WalletMeta{}}
	if err := v.persistLocked(idx, map[string]keystore.Container{}, vaultPassword); err != nil {
		return err
	}
	v.idx = idx
	v.activeID = ""
	return nil
}

// Unlock decrypts the index with the vault password and caches it, granting
// read-only access to every wallet. The seeds remain encrypted. If exactly one
// wallet is present it becomes active; otherwise no wallet is auto-activated.
func (v *Vault) Unlock(vaultPassword string) ([]WalletMeta, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	env, err := v.readEnvelope()
	if err != nil {
		return nil, err
	}
	idx, err := v.decodeIndex(env.Index, vaultPassword)
	if err != nil {
		return nil, err
	}
	v.idx = idx
	if len(idx.Wallets) == 1 {
		v.activeID = idx.Wallets[0].ID
	}
	return cloneWallets(idx.Wallets), nil
}

// Lock drops the decrypted index from memory. Subsequent read-only operations
// fail with ErrLocked until Unlock is called again.
func (v *Vault) Lock() {
	v.mu.Lock()
	v.idx = nil
	v.activeID = ""
	v.mu.Unlock()
}

// Wallets returns the wallet list (read-only metadata). The vault must be
// unlocked.
func (v *Vault) Wallets() ([]WalletMeta, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.idx == nil {
		return nil, ErrLocked
	}
	return cloneWallets(v.idx.Wallets), nil
}

// AddWallet derives the account for mnemonic/network, encrypts the seed under
// spendPassword, records the read-only metadata in the index (re-sealed under
// the vault password), and returns the new wallet's metadata. The vault must be
// unlocked. A wallet whose seed derives the same stake address as an existing
// one is rejected (ErrDuplicateWallet). The added wallet becomes active.
//
// account window N receive addresses are derived (matching the read-only
// wallet's default), so read-only views work straight away without the seed.
func (v *Vault) AddWallet(name, mnemonic, network, vaultPassword, spendPassword string, windowN int) (WalletMeta, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.idx == nil {
		return WalletMeta{}, ErrLocked
	}

	acct, err := wallet.Derive(mnemonic, network, windowN)
	if err != nil {
		return WalletMeta{}, err
	}
	xpub, err := wallet.AccountXpub(mnemonic)
	if err != nil {
		return WalletMeta{}, err
	}

	// Reject a duplicate seed: two wallets sharing a stake address are the same
	// wallet, and would collide in read-only views.
	for _, w := range v.idx.Wallets {
		if w.Account != nil && w.Account.StakeAddress == acct.StakeAddress {
			return WalletMeta{}, fmt.Errorf("%w: %q", ErrDuplicateWallet, w.Name)
		}
	}

	seedBlob, err := v.seal([]byte(mnemonic), spendPassword)
	if err != nil {
		return WalletMeta{}, err
	}
	var seed keystore.Container
	if err := json.Unmarshal(seedBlob, &seed); err != nil {
		return WalletMeta{}, err
	}

	id := newID()
	meta := WalletMeta{
		ID:          id,
		Name:        name,
		Network:     network,
		AccountXpub: xpub,
		Account:     acct,
	}

	// Load the current seed map (the cached index does not hold seeds), append
	// the new seed, and re-persist the whole envelope under the vault password.
	env, err := v.readEnvelope()
	if err != nil {
		return WalletMeta{}, err
	}
	seeds := env.Seeds
	if seeds == nil {
		seeds = map[string]keystore.Container{}
	}
	newIdx := &index{Wallets: append(cloneWallets(v.idx.Wallets), meta)}
	seeds[id] = seed
	if err := v.persistLocked(newIdx, seeds, vaultPassword); err != nil {
		return WalletMeta{}, err
	}
	v.idx = newIdx
	v.activeID = id
	return meta, nil
}

// RemoveWallet deletes the wallet with id (its metadata and its encrypted seed)
// and re-persists the vault under the vault password. The vault must be
// unlocked. Removing the active wallet clears the active selection.
func (v *Vault) RemoveWallet(id, vaultPassword string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.idx == nil {
		return ErrLocked
	}
	found := false
	kept := make([]WalletMeta, 0, len(v.idx.Wallets))
	for _, w := range v.idx.Wallets {
		if w.ID == id {
			found = true
			continue
		}
		kept = append(kept, w)
	}
	if !found {
		return fmt.Errorf("%w: %q", ErrUnknownWallet, id)
	}
	env, err := v.readEnvelope()
	if err != nil {
		return err
	}
	seeds := env.Seeds
	delete(seeds, id)
	newIdx := &index{Wallets: kept}
	if err := v.persistLocked(newIdx, seeds, vaultPassword); err != nil {
		return err
	}
	v.idx = newIdx
	if v.activeID == id {
		v.activeID = ""
	}
	return nil
}

// SetActive marks the wallet with id as active. The vault must be unlocked and
// the id must exist.
func (v *Vault) SetActive(id string) (WalletMeta, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.idx == nil {
		return WalletMeta{}, ErrLocked
	}
	for _, w := range v.idx.Wallets {
		if w.ID == id {
			v.activeID = id
			return *cloneWallet(&w), nil
		}
	}
	return WalletMeta{}, fmt.Errorf("%w: %q", ErrUnknownWallet, id)
}

// Active returns the active wallet's metadata, or ErrNoActiveWallet if none is
// set. The vault must be unlocked.
func (v *Vault) Active() (WalletMeta, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.idx == nil {
		return WalletMeta{}, ErrLocked
	}
	if v.activeID == "" {
		return WalletMeta{}, ErrNoActiveWallet
	}
	for _, w := range v.idx.Wallets {
		if w.ID == v.activeID {
			return *cloneWallet(&w), nil
		}
	}
	return WalletMeta{}, ErrNoActiveWallet
}

// ActiveID returns the active wallet id (empty if none).
func (v *Vault) ActiveID() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.activeID
}

// UnlockSeed decrypts the active wallet's seed (the mnemonic) with its spending
// password. The caller MUST zero the returned bytes once a signing key has been
// derived. The vault must be unlocked and a wallet must be active.
func (v *Vault) UnlockSeed(spendPassword string) ([]byte, error) {
	return v.unlockSeedFor(v.ActiveID(), spendPassword)
}

// UnlockSeedFor decrypts the seed for the wallet with id, with its spending
// password. The vault must be unlocked. See UnlockSeed for cleanup duties.
func (v *Vault) UnlockSeedFor(id, spendPassword string) ([]byte, error) {
	return v.unlockSeedFor(id, spendPassword)
}

func (v *Vault) unlockSeedFor(id, spendPassword string) ([]byte, error) {
	v.mu.RLock()
	locked := v.idx == nil
	v.mu.RUnlock()
	if locked {
		return nil, ErrLocked
	}
	if id == "" {
		return nil, ErrNoActiveWallet
	}
	env, err := v.readEnvelope()
	if err != nil {
		return nil, err
	}
	seed, ok := env.Seeds[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownWallet, id)
	}
	blob, err := json.Marshal(seed)
	if err != nil {
		return nil, err
	}
	mnemonic, err := v.open(blob, []byte(spendPassword))
	if err != nil {
		if errors.Is(err, keystore.ErrDecryptFailed) {
			return nil, fmt.Errorf("%w: %w", ErrWrongPassword, err)
		}
		return nil, err
	}
	return mnemonic, nil
}

// ---------------------------------------------------------------------------
// persistence helpers
// ---------------------------------------------------------------------------

// readEnvelope reads and parses the on-disk envelope. Callers may hold v.mu in
// either mode; it only touches the file, not the in-memory cache. A missing
// file returns ErrNoVault.
func (v *Vault) readEnvelope() (envelope, error) {
	f, err := os.Open(v.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return envelope{}, ErrNoVault
		}
		return envelope{}, err
	}
	defer f.Close()
	blob, err := io.ReadAll(io.LimitReader(f, maxVaultLen+1))
	if err != nil {
		return envelope{}, err
	}
	if len(blob) > maxVaultLen {
		return envelope{}, fmt.Errorf("vault file exceeds %d bytes", maxVaultLen)
	}
	var env envelope
	if err := json.Unmarshal(blob, &env); err != nil {
		return envelope{}, fmt.Errorf("not a vault file: %w", err)
	}
	if env.Format != formatVersion {
		return envelope{}, fmt.Errorf("unsupported vault format %d", env.Format)
	}
	if env.Seeds == nil {
		env.Seeds = map[string]keystore.Container{}
	}
	return env, nil
}

// persistLocked seals idx under vaultPassword and atomically writes the
// envelope (index + seeds) to disk. Callers hold v.mu.
func (v *Vault) persistLocked(idx *index, seeds map[string]keystore.Container, vaultPassword string) error {
	plain, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	sealed, err := v.seal(plain, vaultPassword)
	if err != nil {
		return err
	}
	var idxContainer keystore.Container
	if err := json.Unmarshal(sealed, &idxContainer); err != nil {
		return err
	}
	env := envelope{Format: formatVersion, Index: idxContainer, Seeds: seeds}
	out, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return writeFileAtomic(v.path, out, 0o600)
}

// decodeIndex opens the encrypted index Container with vaultPassword and parses
// the plaintext index. A wrong password maps to ErrWrongPassword.
func (v *Vault) decodeIndex(c keystore.Container, vaultPassword string) (*index, error) {
	blob, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	plain, err := v.open(blob, []byte(vaultPassword))
	if err != nil {
		if errors.Is(err, keystore.ErrDecryptFailed) {
			return nil, fmt.Errorf("%w: %w", ErrWrongPassword, err)
		}
		return nil, err
	}
	var idx index
	if err := json.Unmarshal(plain, &idx); err != nil {
		return nil, fmt.Errorf("corrupt vault index: %w", err)
	}
	return &idx, nil
}

// writeFileAtomic writes data to path via a temp file + rename, so a crash mid
// write cannot leave a half-written (and thus unopenable) vault.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".vault-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// clone helpers (defensive copies so callers cannot mutate the cached index)
// ---------------------------------------------------------------------------

func cloneWallets(in []WalletMeta) []WalletMeta {
	out := make([]WalletMeta, 0, len(in))
	for i := range in {
		out = append(out, *cloneWallet(&in[i]))
	}
	return out
}

func cloneWallet(w *WalletMeta) *WalletMeta {
	c := *w
	if w.Account != nil {
		acct := *w.Account
		acct.ReceiveAddresses = append([]string(nil), w.Account.ReceiveAddresses...)
		c.Account = &acct
	}
	return &c
}
