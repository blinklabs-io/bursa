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
// Both layers reuse the keystore's scrypt + AES-256-GCM scheme (no new crypto).
// The index is encrypted under a per-vault random Vault Encryption Key (VEK); the
// VEK is itself wrapped by a KeyProtector (today: a password protector that seals
// it under scrypt(vault password)). Each wallet's seed is sealed the same way
// directly under its spending password. This VEK indirection means the vault
// password (and, in a later task, a TPM) guard one small key rather than
// encrypting the wallet data directly, so re-keying is O(1).
//
// The on-disk file (format 2) is a single JSON object:
//
//	{
//	  "format": 2,
//	  "key": { "password": <Container wrapping the VEK under the vault password> },
//	  "index": <keystore Container, encrypted under the VEK>,
//	  "seeds": { "<wallet id>": <keystore Container, encrypted under spend pw> }
//	}
//
// Format 1 (legacy) had no "key" section and encrypted the index directly under
// the vault password. Such vaults are still read (decrypted with the password as
// before) and transparently upgraded to format 2 on first Unlock.
//
// The plaintext index (inside the encrypted "index" blob) is:
//
//	{ "wallets": [ { "id", "name", "network", "account_xpub", "account": {…} } ] }
//
// Splitting seeds out of the encrypted index keeps each seed reachable with only
// its own spending password — unlocking the vault never exposes any seed.
package vault

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"unicode/utf8"

	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

// formatVersion is the on-disk envelope version this code writes (distinct from
// the keystore Container version each blob carries). Format 2 introduced the VEK
// indirection and the "key" section.
const formatVersion = 2

// legacyFormatVersion is the original envelope version: no "key" section, with
// the index encrypted directly under the vault password. Such vaults are still
// read and transparently upgraded to formatVersion on Unlock.
const legacyFormatVersion = 1

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
	// ErrTPMUnavailable: EnableTPM was asked to bind the vault to a TPM, but no
	// usable TPM is present (unsupported platform, no device, or no permission).
	ErrTPMUnavailable = errors.New("TPM unavailable")
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

// keySection records how the Vault Encryption Key is protected. The VEK is
// wrapped by one or more protectors. A format-2 envelope always carries Password
// (the universal, portable, never-brick fallback). When the user opts in, it
// ALSO carries Tpm — the same VEK additionally sealed to this machine's TPM. On
// unlock the TPM protector is tried first; on any TPM failure (absent, disabled,
// unseal/PCR error) the password protector recovers the same VEK, so a missing
// TPM never bricks the vault.
type keySection struct {
	// Password is the VEK wrapped under scrypt(vault password) + AES-GCM. It is
	// the universal, portable protector and the fallback path.
	Password keystore.Container `json:"password"`
	// Tpm is the VEK sealed to a TPM 2.0 device (present only when TPM protection
	// is enabled). Readers without the TPM ignore it and use Password.
	Tpm *tpmSection `json:"tpm,omitempty"`
}

// envelope is the on-disk JSON: the wrapped VEK (key), an encrypted index, plus
// per-wallet encrypted seed blobs keyed by wallet id. Format 1 envelopes have no
// Key section; Key is omitted (omitempty) so a format-1 file round-trips cleanly.
type envelope struct {
	Format int                           `json:"format"`
	Key    *keySection                   `json:"key,omitempty"`
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
	// SetCipher to keep the suite fast. They encrypt the index (under the VEK)
	// and each seed (under its spend password).
	seal keystore.Sealer
	open keystore.Opener

	// pwProtector wraps/unwraps the VEK under the vault password, reusing
	// seal/open. It is rebuilt whenever seal/open change (New, SetCipher).
	pwProtector KeyProtector

	// tpmProt seals/unseals the VEK to a TPM 2.0 device when the user opts in. It
	// is nil until configured (New wires the production device-backed protector;
	// tests inject a fake via SetTPMProtector). A nil tpmProt means TPM features
	// are unavailable and the vault is password-only.
	tpmProt *tpmProtector

	mu       sync.RWMutex
	idx      *index // non-nil only while unlocked
	activeID string // id of the active wallet (empty if none)
}

// New returns a Vault backed by the file at path. It does not touch the file
// until a method needs it. It wires the production TPM protector (device-backed);
// on platforms/machines with no TPM that protector simply reports unavailable and
// the vault stays password-only.
func New(path string) *Vault {
	return &Vault{
		path:        path,
		seal:        keystore.Seal,
		open:        keystore.Open,
		pwProtector: newPasswordProtector(keystore.Seal, keystore.Open),
		tpmProt:     newTPMProtector(),
	}
}

// SetTPMProtector overrides the TPM protector. Only tests use it, to inject an
// in-memory fake so the suite exercises the TPM wiring without a device or the
// (CGO-only) simulator.
func (v *Vault) SetTPMProtector(p *tpmProtector) {
	v.mu.Lock()
	v.tpmProt = p
	v.mu.Unlock()
}

// SetCipher overrides the seal/open primitives. Only tests use it, to swap in a
// cheap KDF (keystore.CheapTestSealer); production keeps the full-cost default.
// The password protector is rebuilt so it uses the same (cheap) primitives.
func (v *Vault) SetCipher(seal keystore.Sealer, open keystore.Opener) {
	v.mu.Lock()
	v.seal = seal
	v.open = open
	v.pwProtector = newPasswordProtector(seal, open)
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
	vek, err := newVEK()
	if err != nil {
		return err
	}
	defer keystore.Zero(vek)
	idx := &index{Wallets: []WalletMeta{}}
	if err := v.persistLocked(idx, map[string]keystore.Container{}, vek, vaultPassword, nil); err != nil {
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
	vek, idx, err := v.recoverVEKAndIndexLocked(env, vaultPassword)
	if err != nil {
		return nil, err
	}
	defer keystore.Zero(vek)
	// Format-1 vaults have no key section: transparently re-key to format 2 so
	// the next Unlock takes the modern path. If the rewrite fails (e.g. a
	// read-only disk), abort the unlock and surface the error rather than caching
	// an unlocked state over a file that is still legacy. The on-disk vault stays
	// a valid format 1, so a later Unlock simply retries the upgrade — nothing is
	// lost. Format-1 vaults never carry a TPM section, so persist with tpm=nil.
	if env.Format == legacyFormatVersion {
		if err := v.persistLocked(idx, env.Seeds, vek, vaultPassword, nil); err != nil {
			return nil, fmt.Errorf("vault: upgrade format 1->2 failed: %w", err)
		}
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

// TPMStatusInfo is the snapshot returned by TPMStatus for the API/UI.
type TPMStatusInfo struct {
	// Available reports whether a usable TPM is present on this machine now.
	Available bool `json:"available"`
	// Reason is a human-readable explanation when Available is false.
	Reason string `json:"reason"`
	// Enabled reports whether the on-disk vault carries a TPM protector.
	Enabled bool `json:"enabled"`
	// PCRBound reports whether the enabled TPM protector is PCR-bound.
	PCRBound bool `json:"pcrBound"`
}

// TPMStatus reports whether a TPM is available on this machine and whether the
// vault is currently TPM-enrolled. It reads the envelope (no unlock needed) for
// the enrolled/pcrBound flags and probes the device for availability. A missing
// vault reports Enabled=false. The probe never blocks.
func (v *Vault) TPMStatus() TPMStatusInfo {
	v.mu.RLock()
	prot := v.tpmProt
	v.mu.RUnlock()

	var info TPMStatusInfo
	if prot != nil {
		info.Available, info.Reason = prot.Available()
	} else {
		info.Reason = "tpm: not supported on this platform"
	}
	if env, err := v.readEnvelope(); err == nil && env.Key != nil && env.Key.Tpm != nil {
		info.Enabled = true
		info.PCRBound = env.Key.Tpm.PCRBound
	}
	return info
}

// EnableTPM adds a TPM protector to the vault: it authenticates vaultPassword,
// recovers the VEK, seals it to this machine's TPM (with auth derived from
// vaultPassword), and re-persists the envelope with BOTH protectors. The
// password protector is always kept, so a later machine/TPM loss never bricks
// the vault (this is an explicit never-brick guarantee; there is no TPM-only
// mode here). pcrBound additionally binds the seal to a conservative PCR policy
// (PCR 7) — brittle across firmware updates, so the password copy is the
// mandatory recovery path. Enable is an O(1) re-wrap: no index/seed re-encryption.
func (v *Vault) EnableTPM(vaultPassword string, pcrBound bool) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.tpmProt == nil {
		return fmt.Errorf("%w: TPM not supported on this platform", ErrTPMUnavailable)
	}
	if ok, reason := v.tpmProt.Available(); !ok {
		return fmt.Errorf("%w: %s", ErrTPMUnavailable, reason)
	}
	env, vek, idx, err := v.authenticatedEnvelopeLocked(vaultPassword)
	if err != nil {
		return err
	}
	defer keystore.Zero(vek)
	sec, err := v.tpmProt.WrapTPM(vek, vaultPassword, pcrBound)
	if err != nil {
		return err
	}
	// Re-persist with the SAME VEK + the existing seeds, adding the TPM section
	// and keeping the password protector. O(1): only the small key section is
	// re-wrapped; index/seed blobs are untouched.
	return v.persistLocked(idx, env.Seeds, vek, vaultPassword, &sec)
}

// DisableTPM drops the TPM protector and re-persists with the password protector
// only. It authenticates vaultPassword and keeps the VEK unchanged. The
// password protector is never the thing removed, so this cannot brick the vault.
// A no-op (no TPM section present) succeeds silently.
func (v *Vault) DisableTPM(vaultPassword string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	env, vek, idx, err := v.authenticatedEnvelopeLocked(vaultPassword)
	if err != nil {
		return err
	}
	defer keystore.Zero(vek)
	if env.Key == nil || env.Key.Tpm == nil {
		return nil // already password-only
	}
	return v.persistLocked(idx, env.Seeds, vek, vaultPassword, nil)
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

	env, vek, idx, err := v.authenticatedEnvelopeLocked(vaultPassword)
	if err != nil {
		return WalletMeta{}, err
	}
	defer keystore.Zero(vek)

	meta, seed, err := v.prepareWallet(name, mnemonic, network, spendPassword, windowN)
	if err != nil {
		return WalletMeta{}, err
	}

	// Reject a duplicate seed: two wallets sharing a stake address are the same
	// wallet, and would collide in read-only views.
	for _, w := range idx.Wallets {
		if w.Account != nil && meta.Account != nil && w.Account.StakeAddress == meta.Account.StakeAddress {
			return WalletMeta{}, fmt.Errorf("%w: %q", ErrDuplicateWallet, w.Name)
		}
	}

	// Load the current seed map (the cached index does not hold seeds), append
	// the new seed, and re-persist the whole envelope under the same VEK.
	seeds := env.Seeds
	if seeds == nil {
		seeds = map[string]keystore.Container{}
	}
	newIdx := &index{Wallets: append(cloneWallets(idx.Wallets), meta)}
	seeds[meta.ID] = seed
	if err := v.persistLocked(newIdx, seeds, vek, vaultPassword, tpmOf(env)); err != nil {
		return WalletMeta{}, err
	}
	v.idx = newIdx
	v.activeID = meta.ID
	return meta, nil
}

// ImportWallet creates a new vault containing a single wallet. It is used for
// legacy keystore migration so the final vault is written in one atomic persist:
// failure leaves no empty vault behind to block a retry.
func (v *Vault) ImportWallet(name, mnemonic, network, vaultPassword, spendPassword string, windowN int) (WalletMeta, error) {
	mnemonicBytes := []byte(mnemonic)
	defer keystore.Zero(mnemonicBytes)
	return v.importWallet(name, mnemonicBytes, network, vaultPassword, spendPassword, windowN)
}

// ImportWalletMnemonicBytes is the zeroable-byte variant used when the
// plaintext mnemonic came from a decryptable buffer. The caller keeps ownership
// of mnemonic and should zero it after this method returns.
func (v *Vault) ImportWalletMnemonicBytes(name string, mnemonic []byte, network, vaultPassword, spendPassword string, windowN int) (WalletMeta, error) {
	return v.importWallet(name, mnemonic, network, vaultPassword, spendPassword, windowN)
}

func (v *Vault) importWallet(name string, mnemonic []byte, network, vaultPassword, spendPassword string, windowN int) (WalletMeta, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.Exists() {
		return WalletMeta{}, ErrVaultExists
	}
	meta, seed, err := v.prepareWalletBytes(name, mnemonic, network, spendPassword, windowN)
	if err != nil {
		return WalletMeta{}, err
	}
	vek, err := newVEK()
	if err != nil {
		return WalletMeta{}, err
	}
	defer keystore.Zero(vek)
	idx := &index{Wallets: []WalletMeta{meta}}
	seeds := map[string]keystore.Container{meta.ID: seed}
	if err := v.persistLocked(idx, seeds, vek, vaultPassword, nil); err != nil {
		return WalletMeta{}, err
	}
	v.idx = idx
	v.activeID = meta.ID
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
	for _, w := range v.idx.Wallets {
		if w.ID == id {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("%w: %q", ErrUnknownWallet, id)
	}
	env, vek, idx, err := v.authenticatedEnvelopeLocked(vaultPassword)
	if err != nil {
		return err
	}
	defer keystore.Zero(vek)
	seeds := env.Seeds
	delete(seeds, id)
	newIdx := &index{Wallets: keptWallets(idx, id)}
	if len(newIdx.Wallets) == len(idx.Wallets) {
		return fmt.Errorf("%w: %q", ErrUnknownWallet, id)
	}
	if err := v.persistLocked(newIdx, seeds, vek, vaultPassword, tpmOf(env)); err != nil {
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
	switch env.Format {
	case legacyFormatVersion, formatVersion:
		// supported (format 1 is read + upgraded; format 2 is current)
	default:
		return envelope{}, fmt.Errorf("unsupported vault format %d", env.Format)
	}
	if env.Format >= formatVersion && env.Key == nil {
		return envelope{}, fmt.Errorf("corrupt vault: format %d missing key section", env.Format)
	}
	if env.Seeds == nil {
		env.Seeds = map[string]keystore.Container{}
	}
	return env, nil
}

// authenticatedEnvelopeLocked reads the envelope and authenticates vaultPassword
// by recovering the VEK and decrypting the index. It returns the envelope and
// the recovered VEK/index so the caller can re-persist under the same VEK
// without a second derivation or index decrypt. The caller MUST zero the returned
// VEK. Callers hold v.mu.
func (v *Vault) authenticatedEnvelopeLocked(vaultPassword string) (envelope, []byte, *index, error) {
	env, err := v.readEnvelope()
	if err != nil {
		return envelope{}, nil, nil, err
	}
	vek, idx, err := v.recoverVEKAndIndexLocked(env, vaultPassword)
	if err != nil {
		return envelope{}, nil, nil, err
	}
	return env, vek, idx, nil
}

// recoverVEKAndIndexLocked recovers the Vault Encryption Key for env and decodes
// the index with it. For format 2 it unwraps the VEK from the key section's
// password protector; for format 1 (legacy) the index was encrypted directly
// under the password, so the password itself acts as the VEK material. Either
// way it returns the VEK to use for re-persisting and the decoded index. A wrong
// password maps to ErrWrongPassword. The caller MUST zero the returned VEK.
func (v *Vault) recoverVEKAndIndexLocked(env envelope, vaultPassword string) ([]byte, *index, error) {
	if env.Format == legacyFormatVersion {
		// Legacy: index sealed directly under scrypt(password). Decode it with
		// the password, then mint a fresh VEK for the upgrade to format 2.
		idx, err := v.decodeIndexWith(env.Index, vaultPassword)
		if err != nil {
			return nil, nil, err
		}
		vek, err := newVEK()
		if err != nil {
			return nil, nil, err
		}
		return vek, idx, nil
	}
	// Format 2: recover the VEK. If the envelope has a TPM protector and a TPM is
	// usable, try it first; on any TPM failure, fall back to the password
	// protector (the never-brick law). A wrong vault password still fails there,
	// while a stale/tampered TPM section cannot block password recovery.
	vek, err := v.recoverVEKLocked(env, vaultPassword)
	if err != nil {
		return nil, nil, err
	}
	idx, err := v.decodeIndexWith(env.Index, string(vek))
	if err != nil {
		keystore.Zero(vek)
		return nil, nil, err
	}
	return vek, idx, nil
}

// recoverVEKLocked unwraps the format-2 VEK, preferring the TPM protector when
// present and usable and falling back to the password protector on TPM failure.
// The password protector remains authoritative for recovery; a wrong password
// fails there too. The caller MUST zero the returned VEK. Callers hold v.mu.
func (v *Vault) recoverVEKLocked(env envelope, vaultPassword string) ([]byte, error) {
	if env.Key.Tpm != nil && v.tpmProt != nil {
		if ok, _ := v.tpmProt.Available(); ok {
			vek, err := v.tpmProt.UnwrapTPM(*env.Key.Tpm, vaultPassword)
			if err == nil {
				return vek, nil
			}
			// TPM errors (device gone, load/unseal failure, PCR mismatch, stale
			// object auth) are non-fatal: fall through to the password protector.
		}
	}
	return v.pwProtector.Unwrap(env.Key.Password, vaultPassword)
}

// persistLocked encrypts idx under vek, wraps vek under vaultPassword via the
// password protector, and atomically writes the format-2 envelope (key + index
// + seeds) to disk. tpm, when non-nil, is carried through unchanged so a routine
// re-persist (AddWallet, RemoveWallet, ...) never drops a TPM protector. The
// password protector is ALWAYS written (the never-brick fallback). Callers hold
// v.mu and own zeroing vek.
func (v *Vault) persistLocked(idx *index, seeds map[string]keystore.Container, vek []byte, vaultPassword string, tpm *tpmSection) error {
	idxContainer, err := v.sealIndex(idx, vek)
	if err != nil {
		return err
	}
	wrapped, err := v.pwProtector.Wrap(vek, vaultPassword)
	if err != nil {
		return err
	}
	env := envelope{
		Format: formatVersion,
		Key:    &keySection{Password: wrapped, Tpm: tpm},
		Index:  idxContainer,
		Seeds:  seeds,
	}
	out, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return writeFileAtomic(v.path, out, 0o600)
}

// sealIndex encrypts the plaintext index under the VEK (the VEK drives the
// scrypt+AES-GCM seal as the "password"), returning the index Container.
func (v *Vault) sealIndex(idx *index, vek []byte) (keystore.Container, error) {
	plain, err := json.Marshal(idx)
	if err != nil {
		return keystore.Container{}, err
	}
	sealed, err := v.seal(plain, string(vek))
	if err != nil {
		return keystore.Container{}, err
	}
	var c keystore.Container
	if err := json.Unmarshal(sealed, &c); err != nil {
		return keystore.Container{}, err
	}
	return c, nil
}

// decodeIndexWith opens the encrypted index Container with key (the VEK for
// format 2, or the vault password for legacy format 1) and parses the plaintext
// index. A wrong key maps to ErrWrongPassword.
func (v *Vault) decodeIndexWith(c keystore.Container, key string) (*index, error) {
	blob, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	plain, err := v.open(blob, []byte(key))
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

// tpmOf returns the envelope's TPM protector section (or nil). It is used to
// carry an existing TPM protector through a routine re-persist so AddWallet /
// RemoveWallet never drop it.
func tpmOf(env envelope) *tpmSection {
	if env.Key == nil {
		return nil
	}
	return env.Key.Tpm
}

func keptWallets(idx *index, id string) []WalletMeta {
	if idx == nil {
		return nil
	}
	kept := make([]WalletMeta, 0, len(idx.Wallets))
	for _, w := range idx.Wallets {
		if w.ID != id {
			kept = append(kept, w)
		}
	}
	return kept
}

// newVEK returns a fresh random 32-byte Vault Encryption Key.
func newVEK() ([]byte, error) {
	vek := make([]byte, vekLen)
	if _, err := rand.Read(vek); err != nil {
		return nil, fmt.Errorf("vault: generating VEK: %w", err)
	}
	return vek, nil
}

func (v *Vault) prepareWallet(name, mnemonic, network, spendPassword string, windowN int) (WalletMeta, keystore.Container, error) {
	mnemonicBytes := []byte(mnemonic)
	defer keystore.Zero(mnemonicBytes)
	return v.prepareWalletBytes(name, mnemonicBytes, network, spendPassword, windowN)
}

func (v *Vault) prepareWalletBytes(name string, mnemonic []byte, network, spendPassword string, windowN int) (WalletMeta, keystore.Container, error) {
	if utf8.RuneCountInString(spendPassword) < keystore.MinPasswordLen {
		return WalletMeta{}, keystore.Container{}, fmt.Errorf("password must be at least %d characters", keystore.MinPasswordLen)
	}
	acct, err := wallet.DeriveFromMnemonicBytes(mnemonic, network, windowN)
	if err != nil {
		return WalletMeta{}, keystore.Container{}, err
	}
	xpub, err := wallet.AccountXpubFromMnemonicBytes(mnemonic)
	if err != nil {
		return WalletMeta{}, keystore.Container{}, err
	}
	seedBlob, err := v.seal(mnemonic, spendPassword)
	if err != nil {
		return WalletMeta{}, keystore.Container{}, err
	}
	var seed keystore.Container
	if err := json.Unmarshal(seedBlob, &seed); err != nil {
		return WalletMeta{}, keystore.Container{}, err
	}
	meta := WalletMeta{
		ID:          newID(),
		Name:        name,
		Network:     network,
		AccountXpub: xpub,
		Account:     acct,
	}
	return meta, seed, nil
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
	dirFile, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirFile.Close()
	if err := dirFile.Sync(); err != nil {
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
		acct.ChangeAddresses = append([]string(nil), w.Account.ChangeAddresses...)
		c.Account = &acct
	}
	return &c
}
