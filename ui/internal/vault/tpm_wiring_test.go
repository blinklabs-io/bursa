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

package vault

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	tpmpkg "github.com/blinklabs-io/bursa/ui/internal/tpm"
)

// newTPMTestVault returns a vault wired to the cheap KDF and a fake TPM
// protector, plus the fake so a test can flip availability/inject failures.
func newTPMTestVault(t *testing.T) (*Vault, *fakeTPM) {
	t.Helper()
	v := New(filepath.Join(t.TempDir(), "vault.json"))
	seal, open := keystore.CheapTestSealer()
	v.SetCipher(seal, open)
	f := newFakeTPM()
	v.SetTPMProtector(newFakeTPMProtector(f))
	return v, f
}

// TestEnableTPMThenLockUnlock: enabling TPM, then locking, then unlocking opens
// via the TPM protector — the headline flow.
func TestEnableTPMThenLockUnlock(t *testing.T) {
	v, _ := newTPMTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.EnableTPM(vaultPw, false); err != nil {
		t.Fatalf("EnableTPM: %v", err)
	}
	// The envelope now carries both protectors (never just TPM).
	env := readEnvelopeFile(t, v.path)
	if env.Key == nil || env.Key.Tpm == nil {
		t.Fatal("EnableTPM did not write a key.tpm section")
	}
	if env.Key.Password.Ciphertext == "" {
		t.Fatal("EnableTPM must KEEP the password protector (never-brick)")
	}

	v.Lock()
	wallets, err := v.Unlock(vaultPw)
	if err != nil {
		t.Fatalf("Unlock after EnableTPM: %v", err)
	}
	if len(wallets) != 0 {
		t.Fatalf("wallets = %d, want 0", len(wallets))
	}
}

// TestUnlockFallsBackWhenTPMAbsent: a TPM-enrolled vault opened on a machine
// where the TPM is now gone must fall back to the password protector and unlock.
func TestUnlockFallsBackWhenTPMAbsent(t *testing.T) {
	v, f := newTPMTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.EnableTPM(vaultPw, false); err != nil {
		t.Fatalf("EnableTPM: %v", err)
	}
	v.Lock()

	// Simulate the TPM vanishing (hardware removed / vault moved machines).
	f.available = false
	f.reason = "no TPM device"
	f.failUnseal = errors.New("device not present")

	wallets, err := v.Unlock(vaultPw)
	if err != nil {
		t.Fatalf("Unlock should fall back to password when TPM absent: %v", err)
	}
	if len(wallets) != 0 {
		t.Fatalf("wallets = %d, want 0", len(wallets))
	}
}

// TestUnlockTPMUnsealErrorFallsBack: even if the TPM is "present" but unseal
// fails (e.g. cleared TPM, SRK changed), unlock falls back to the password copy.
func TestUnlockTPMUnsealErrorFallsBack(t *testing.T) {
	v, f := newTPMTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.EnableTPM(vaultPw, false); err != nil {
		t.Fatalf("EnableTPM: %v", err)
	}
	v.Lock()
	f.failUnseal = errors.New("unseal failed: SRK changed")

	if _, err := v.Unlock(vaultPw); err != nil {
		t.Fatalf("Unlock should fall back on TPM unseal error: %v", err)
	}
}

func TestUnlockFallsBackWhenTPMReturnsMalformedVEK(t *testing.T) {
	v, f := newTPMTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.EnableTPM(vaultPw, false); err != nil {
		t.Fatalf("EnableTPM: %v", err)
	}
	for key, entry := range f.store {
		entry.secret = []byte("short")
		f.store[key] = entry
	}
	v.Lock()

	if _, err := v.Unlock(vaultPw); err != nil {
		t.Fatalf("Unlock should fall back when TPM returns malformed VEK: %v", err)
	}
}

// TestUnlockWrongPasswordWithTPM: a wrong password must still fail (it gates the
// TPM protector and the fallback password protector). It must NOT silently open.
func TestUnlockWrongPasswordWithTPM(t *testing.T) {
	v, _ := newTPMTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.EnableTPM(vaultPw, false); err != nil {
		t.Fatalf("EnableTPM: %v", err)
	}
	v.Lock()
	if _, err := v.Unlock("wrong-password"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Unlock wrong password = %v, want ErrWrongPassword", err)
	}
}

func TestUnlockFallsBackWhenTPMReportsWrongPassword(t *testing.T) {
	v, f := newTPMTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.EnableTPM(vaultPw, false); err != nil {
		t.Fatalf("EnableTPM: %v", err)
	}
	v.Lock()
	f.failUnseal = tpmpkg.ErrWrongPassword

	if _, err := v.Unlock(vaultPw); err != nil {
		t.Fatalf("Unlock should fall back when TPM auth fails but password is correct: %v", err)
	}
}

// TestDisableTPMRestoresPortability: after DisableTPM the key.tpm section is
// gone, the password protector remains, and unlock works with no TPM at all.
func TestDisableTPMRestoresPortability(t *testing.T) {
	v, f := newTPMTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.EnableTPM(vaultPw, false); err != nil {
		t.Fatalf("EnableTPM: %v", err)
	}
	if err := v.DisableTPM(vaultPw); err != nil {
		t.Fatalf("DisableTPM: %v", err)
	}
	env := readEnvelopeFile(t, v.path)
	if env.Key.Tpm != nil {
		t.Fatal("DisableTPM must drop the key.tpm section")
	}
	if env.Key.Password.Ciphertext == "" {
		t.Fatal("DisableTPM must keep the password protector")
	}

	// Unlock now must not touch the TPM at all: make the TPM hostile to prove it.
	f.available = false
	f.failUnseal = errors.New("TPM must not be used after disable")
	v.Lock()
	if _, err := v.Unlock(vaultPw); err != nil {
		t.Fatalf("Unlock after DisableTPM (TPM disabled): %v", err)
	}
}

// TestEnableTPMNeverDropsPasswordCopy is the never-brick invariant: a fresh
// handle (no TPM at all) must still open a TPM-enrolled vault with the password.
func TestEnableTPMNeverDropsPasswordCopy(t *testing.T) {
	v, _ := newTPMTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.EnableTPM(vaultPw, false); err != nil {
		t.Fatalf("EnableTPM: %v", err)
	}

	// A brand-new Vault handle with NO TPM protector configured (simulating the
	// file copied to a plain machine) must still open via the password protector.
	v2 := New(v.path)
	seal, open := keystore.CheapTestSealer()
	v2.SetCipher(seal, open)
	// deliberately no SetTPMProtector
	if _, err := v2.Unlock(vaultPw); err != nil {
		t.Fatalf("portable password unlock of TPM-enrolled vault: %v", err)
	}
}

// TestEnableTPMWrongPasswordRejected: EnableTPM authenticates the vault password
// first; a wrong one must not rewrite the vault.
func TestEnableTPMWrongPassword(t *testing.T) {
	v, _ := newTPMTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.EnableTPM("wrong-password", false); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("EnableTPM wrong password = %v, want ErrWrongPassword", err)
	}
	env := readEnvelopeFile(t, v.path)
	if env.Key.Tpm != nil {
		t.Fatal("EnableTPM with wrong password must not add a TPM section")
	}
}

// TestEnableTPMUnavailableRejected: enabling on a machine with no usable TPM is
// rejected up front (rather than writing an un-unsealable section).
func TestEnableTPMUnavailable(t *testing.T) {
	v, f := newTPMTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.available = false
	f.reason = "no TPM device"
	if err := v.EnableTPM(vaultPw, false); err == nil {
		t.Fatal("EnableTPM should fail when no TPM is available")
	}
}

// TestTPMStatus reports availability and enabled state from the envelope.
func TestTPMStatus(t *testing.T) {
	v, f := newTPMTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	st := v.TPMStatus()
	if !st.Available {
		t.Fatalf("status.Available = false, want true (fake is available)")
	}
	if st.Enabled {
		t.Fatal("status.Enabled = true before EnableTPM")
	}
	if err := v.EnableTPM(vaultPw, false); err != nil {
		t.Fatalf("EnableTPM: %v", err)
	}
	st = v.TPMStatus()
	if !st.Enabled {
		t.Fatal("status.Enabled = false after EnableTPM")
	}
	f.available = false
	f.reason = "gone"
	st = v.TPMStatus()
	if st.Available {
		t.Fatal("status.Available = true after TPM went away")
	}
	if !st.Enabled {
		t.Fatal("status.Enabled should stay true (envelope still has the section)")
	}
}
