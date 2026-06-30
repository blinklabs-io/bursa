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
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	tpmpkg "github.com/blinklabs-io/bursa/ui/internal/tpm"
)

// tpmSection is the envelope's key.tpm record: the at-rest result of sealing the
// VEK to this machine's TPM. The public/private blobs are hex-encoded TPM2
// KeyedHash object portions, meaningless off the TPM that created them — that is
// the machine-binding the feature delivers. A reader on a machine without the
// TPM ignores this (and uses key.password); only when present and the TPM is
// usable is it tried first.
type tpmSection struct {
	// Public is the hex of the sealed object's TPM2B_PUBLIC contents.
	Public string `json:"public"`
	// Private is the hex of the sealed object's TPM2B_PRIVATE.
	Private string `json:"private"`
	// AuthSalt is the hex of the random salt used by the TPM package to derive
	// the object's auth value from the vault password.
	AuthSalt string `json:"authSalt"`
	// SRKTemplate names the SRK template used so the SRK can be recreated
	// deterministically at unseal time (recorded for forward-compatibility).
	SRKTemplate string `json:"srkTemplate"`
	// PCRBound records whether the seal is bound to a PCR policy (default false;
	// see design §4.4 — PCR binding is brittle and opt-in). When true, the
	// password protector MUST be kept as the recovery path.
	PCRBound bool `json:"pcrBound"`
	// PCRs is the PCR selection the seal was bound to when PCRBound is true (nil
	// otherwise). It MUST be persisted and restored: the unseal policy session
	// rebuilds its PolicyPCR over exactly these indices, and a mismatch (e.g. an
	// empty selection) would never satisfy the policy — silently degrading the
	// TPM path to password fallback on every reload.
	PCRs []uint `json:"pcrs,omitempty"`
}

// srkTemplateID is the on-disk identifier for the SRK template the tpm package
// uses (ECC P-256). Stored so a future template change stays backward-readable.
const srkTemplateID = "ecc-p256-srk"

// tpmSealer / tpmUnsealer are the seams over the real tpm package's Seal/Unseal.
// Production wires the device-backed functions; tests inject an in-memory fake so
// the default CGO_ENABLED=0 suite never needs a TPM or the (CGO) simulator.
type (
	tpmSealer   func(secret []byte, password string, pcrBound bool) (*tpmpkg.Sealed, error)
	tpmUnsealer func(sealed *tpmpkg.Sealed, password string) ([]byte, error)
)

// tpmProtector wraps/unwraps the VEK by sealing it to a TPM 2.0 device. Unlike
// the password protector it does not produce a keystore.Container (TPM blobs are
// not scrypt records); it produces a tpmSection. It is always paired with a
// password protector in the envelope so a missing/disabled TPM never bricks the
// vault.
type tpmProtector struct {
	// available reports whether a TPM can be used now (cheap device probe). It
	// must never block unlock.
	available func() (bool, string)
	// seal/unseal are the device command path (or a test fake).
	seal   tpmSealer
	unseal tpmUnsealer
}

// newTPMProtector returns a production tpmProtector bound to the real device via
// the tpm package, opening a fresh transport per operation and flushing it after.
func newTPMProtector() *tpmProtector {
	return &tpmProtector{
		available: tpmpkg.Available,
		seal: func(secret []byte, password string, pcrBound bool) (*tpmpkg.Sealed, error) {
			tp, err := tpmpkg.Open()
			if err != nil {
				return nil, err
			}
			defer func() { _ = tp.Close() }()
			return tpmpkg.Seal(tp, secret, password, pcrBound)
		},
		unseal: func(sealed *tpmpkg.Sealed, password string) ([]byte, error) {
			tp, err := tpmpkg.Open()
			if err != nil {
				return nil, err
			}
			defer func() { _ = tp.Close() }()
			return tpmpkg.Unseal(tp, sealed, password)
		},
	}
}

// Available reports whether the TPM can be used, with a reason when not.
func (p *tpmProtector) Available() (bool, string) {
	if p.available == nil {
		return false, "tpm: not configured"
	}
	return p.available()
}

// WrapTPM seals vek to the TPM with auth derived from password, returning the
// tpmSection to persist. pcrBound additionally binds the seal to a PCR policy
// (brittle; the caller MUST keep the password protector as recovery).
func (p *tpmProtector) WrapTPM(vek []byte, password string, pcrBound bool) (tpmSection, error) {
	if len(vek) != vekLen {
		return tpmSection{}, fmt.Errorf("vault: VEK must be %d bytes, got %d", vekLen, len(vek))
	}
	sealed, err := p.seal(vek, password, pcrBound)
	if err != nil {
		return tpmSection{}, fmt.Errorf("vault: TPM seal: %w", err)
	}
	return tpmSection{
		Public:      hex.EncodeToString(sealed.Public),
		Private:     hex.EncodeToString(sealed.Private),
		AuthSalt:    hex.EncodeToString(sealed.AuthSalt),
		SRKTemplate: srkTemplateID,
		PCRBound:    sealed.PCRBound,
		PCRs:        sealed.PCRs,
	}, nil
}

// UnwrapTPM recovers the VEK from sec by unsealing on the TPM, authenticating
// with password. A wrong password maps to ErrWrongPassword; any other failure
// (device gone, load error, PCR mismatch) is returned wrapped so the caller can
// fall back to the password protector.
func (p *tpmProtector) UnwrapTPM(sec tpmSection, password string) ([]byte, error) {
	if sec.SRKTemplate != srkTemplateID {
		return nil, fmt.Errorf("vault: unsupported TPM SRK template %q", sec.SRKTemplate)
	}
	pub, err := hex.DecodeString(sec.Public)
	if err != nil {
		return nil, fmt.Errorf("vault: corrupt TPM public blob: %w", err)
	}
	priv, err := hex.DecodeString(sec.Private)
	if err != nil {
		return nil, fmt.Errorf("vault: corrupt TPM private blob: %w", err)
	}
	authSalt, err := hex.DecodeString(sec.AuthSalt)
	if err != nil {
		return nil, fmt.Errorf("vault: corrupt TPM auth salt: %w", err)
	}
	vek, err := p.unseal(&tpmpkg.Sealed{
		Public:   pub,
		Private:  priv,
		AuthSalt: authSalt,
		PCRBound: sec.PCRBound,
		PCRs:     sec.PCRs,
	}, password)
	if err != nil {
		if errors.Is(err, tpmpkg.ErrWrongPassword) {
			return nil, fmt.Errorf("%w: %w", ErrWrongPassword, err)
		}
		return nil, fmt.Errorf("vault: TPM unseal: %w", err)
	}
	if len(vek) != vekLen {
		keystore.Zero(vek)
		return nil, fmt.Errorf("vault: TPM unseal returned invalid VEK length: got %d want %d", len(vek), vekLen)
	}
	return vek, nil
}
