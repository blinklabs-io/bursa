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
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	tpmpkg "github.com/blinklabs-io/bursa/ui/internal/tpm"
)

// fakeTPM is an in-memory stand-in for the real TPM seal/unseal command path. It
// lets the default (CGO_ENABLED=0) suite exercise the tpmProtector + vault
// wiring without a device or the simulator. It models the security-relevant
// behaviour the vault depends on: the password gates unseal, the blobs are
// opaque, and absence/failure can be injected.
type fakeTPM struct {
	available bool
	reason    string
	// failSeal / failUnseal inject hard failures (e.g. device vanished).
	failSeal   error
	failUnseal error
	// store maps the returned public blob to (secret, password) so Unseal can
	// check the auth value exactly as the TPM would.
	store map[string]fakeEntry
}

type fakeEntry struct {
	secret   []byte
	password string
	pcrBound bool
}

func newFakeTPM() *fakeTPM {
	return &fakeTPM{available: true, store: map[string]fakeEntry{}}
}

func (f *fakeTPM) Available() (bool, string) { return f.available, f.reason }

func (f *fakeTPM) Seal(secret []byte, password string, pcrBound bool) (*tpmpkg.Sealed, error) {
	if f.failSeal != nil {
		return nil, f.failSeal
	}
	pub := make([]byte, 16)
	_, _ = rand.Read(pub)
	authSalt := make([]byte, 16)
	_, _ = rand.Read(authSalt)
	key := hex.EncodeToString(pub)
	cp := append([]byte(nil), secret...)
	f.store[key] = fakeEntry{secret: cp, password: password, pcrBound: pcrBound}
	return &tpmpkg.Sealed{
		Public:   pub,
		Private:  []byte("opaque-private-" + key),
		AuthSalt: authSalt,
		PCRBound: pcrBound,
	}, nil
}

func (f *fakeTPM) Unseal(sealed *tpmpkg.Sealed, password string) ([]byte, error) {
	if f.failUnseal != nil {
		return nil, f.failUnseal
	}
	e, ok := f.store[hex.EncodeToString(sealed.Public)]
	if !ok {
		return nil, errors.New("fakeTPM: unknown sealed object")
	}
	// The password gates unseal in BOTH modes: the real TPM enforces it via the
	// object's UserAuth (non-PCR) or via the compound
	// PolicyAuthValue+PolicyPCR policy (PCR-bound), so a wrong password fails
	// regardless of pcrBound. PCR-state mismatch is the other PCR-bound failure
	// mode, but it has no analogue at this vault seam (PCR values never flow
	// through the protector interface) — it is validated against the real policy
	// in TestPCRMismatchFailsClosedSimulator / TestPCRBoundWrongPasswordFailsSimulator.
	if password != e.password {
		return nil, tpmpkg.ErrWrongPassword
	}
	return append([]byte(nil), e.secret...), nil
}

// newFakeTPMProtector wires a tpmProtector to a fakeTPM seam.
func newFakeTPMProtector(f *fakeTPM) *tpmProtector {
	return &tpmProtector{
		available: f.Available,
		seal:      f.Seal,
		unseal:    f.Unseal,
	}
}

func TestTPMProtectorWrapUnwrapRoundTrip(t *testing.T) {
	f := newFakeTPM()
	p := newFakeTPMProtector(f)
	vek := make([]byte, vekLen)
	if _, err := rand.Read(vek); err != nil {
		t.Fatalf("rand: %v", err)
	}

	sec, err := p.WrapTPM(vek, vaultPw, false)
	if err != nil {
		t.Fatalf("WrapTPM: %v", err)
	}
	if sec.Public == "" || sec.Private == "" || sec.AuthSalt == "" {
		t.Fatalf("WrapTPM produced empty blobs: %+v", sec)
	}
	// The wrapped section must never carry the VEK in clear.
	if bytes.Contains([]byte(sec.Public+sec.Private), vek) {
		t.Fatal("VEK appears in the TPM section blobs")
	}

	got, err := p.UnwrapTPM(sec, vaultPw)
	if err != nil {
		t.Fatalf("UnwrapTPM: %v", err)
	}
	if !bytes.Equal(got, vek) {
		t.Fatal("UnwrapTPM did not recover the original VEK")
	}
}

func TestTPMProtectorWrongPassword(t *testing.T) {
	f := newFakeTPM()
	p := newFakeTPMProtector(f)
	vek := make([]byte, vekLen)
	_, _ = rand.Read(vek)

	sec, err := p.WrapTPM(vek, vaultPw, false)
	if err != nil {
		t.Fatalf("WrapTPM: %v", err)
	}
	if _, err := p.UnwrapTPM(sec, "wrong-password"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("UnwrapTPM wrong password = %v, want ErrWrongPassword", err)
	}
}

func TestTPMProtectorUnavailable(t *testing.T) {
	f := newFakeTPM()
	f.available = false
	f.reason = "no TPM device"
	p := newFakeTPMProtector(f)
	ok, reason := p.Available()
	if ok || reason == "" {
		t.Fatalf("Available() = (%v, %q), want (false, non-empty)", ok, reason)
	}
}

func TestTPMProtectorRejectsWrongVEKLength(t *testing.T) {
	p := newFakeTPMProtector(newFakeTPM())
	if _, err := p.WrapTPM([]byte("short"), vaultPw, false); err == nil {
		t.Fatal("WrapTPM should reject a VEK that is not vekLen bytes")
	}
}

func TestTPMProtectorRejectsInvalidUnsealedVEKLength(t *testing.T) {
	p := &tpmProtector{
		available: func() (bool, string) { return true, "" },
		unseal: func(_ *tpmpkg.Sealed, _ string) ([]byte, error) {
			return []byte("short"), nil
		},
	}
	sec := tpmSection{
		Public:      hex.EncodeToString([]byte("public")),
		Private:     hex.EncodeToString([]byte("private")),
		AuthSalt:    hex.EncodeToString(bytes.Repeat([]byte{0xA5}, 16)),
		SRKTemplate: srkTemplateID,
	}
	if _, err := p.UnwrapTPM(sec, vaultPw); err == nil {
		t.Fatal("UnwrapTPM should reject a TPM-unsealed VEK that is not vekLen bytes")
	}
}

func TestTPMProtectorRejectsUnsupportedSRKTemplate(t *testing.T) {
	p := newFakeTPMProtector(newFakeTPM())
	sec := tpmSection{
		Public:      hex.EncodeToString([]byte("public")),
		Private:     hex.EncodeToString([]byte("private")),
		SRKTemplate: "unknown-srk",
	}
	if _, err := p.UnwrapTPM(sec, vaultPw); err == nil {
		t.Fatal("UnwrapTPM should reject unsupported SRK templates")
	}
}
