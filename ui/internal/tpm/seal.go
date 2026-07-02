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

package tpm

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// ErrWrongPassword is returned by Unseal when the supplied password does not
// match the sealed object's TPM auth value (TPM_RC_BAD_AUTH). Repeated wrong
// passwords also advance the TPM's dictionary-attack lockout counter, so the
// caller should surface this distinctly from a generic failure.
var ErrWrongPassword = errors.New("tpm: wrong password")

// Sealed is the at-rest result of sealing the VEK to this TPM: the public and
// private portions of a TPM2 KeyedHash sealed object, produced by Create under
// the SRK. Both blobs are meaningless off the TPM that created them — that is
// the machine-binding the feature provides. The vault stores them (hex) in the
// envelope's key.tpm section.
type Sealed struct {
	// Public is the TPM2B_PUBLIC of the sealed object (TPMT_PUBLIC + name alg).
	Public []byte
	// Private is the TPM2B_PRIVATE: the encrypted sensitive area, bound to this
	// TPM's SRK.
	Private []byte
	// AuthSalt is the random scrypt salt used to derive the TPM object's auth
	// value from the vault password. It is not secret, but it must be persisted
	// with the TPM blobs so unseal can reproduce the same auth value.
	AuthSalt []byte
	// PCRBound records whether the object was sealed with a PolicyPCR policy. The
	// default is false (password/HMAC auth + SRK machine-binding only); see the
	// design doc §4.4 for why PCR binding is brittle and opt-in.
	PCRBound bool
	// PCRs is the PCR selection used when PCRBound is true (nil otherwise). PCR 7
	// (secure-boot state) is the conservative default when enabled.
	PCRs []uint
}

// pcr7 is the conservative default PCR selection (secure-boot state) used when
// PCR binding is enabled. Boot-aggregate PCRs (0..9) are intentionally avoided —
// they change on routine firmware/OS updates and would brick the seal.
var pcr7 = []uint{7}

// srkTemplate returns the standard ECC P-256 SRK template (owner hierarchy,
// restricted | decrypt | fixedTPM | fixedParent, empty auth). It is
// deterministically re-derivable, so we recreate the SRK each session rather
// than persisting it (no EvictControl/ownership concerns).
func srkTemplate() tpm2.TPMTPublic { return tpm2.ECCSRKTemplate }

// createSRK recreates the SRK primary key in the owner hierarchy. The caller
// MUST FlushContext the returned handle.
func createSRK(tp transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	srk, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(srkTemplate()),
	}.Execute(tp)
	if err != nil {
		return nil, fmt.Errorf("tpm: create SRK: %w", err)
	}
	return srk, nil
}

// flush best-effort flushes a transient handle; errors are ignored because a
// failed flush must not propagate over a successful seal/unseal (and the handle
// is freed when the transport closes anyway).
func flush(tp transport.TPM, h tpm2.TPMHandle) {
	_, _ = tpm2.FlushContext{FlushHandle: h}.Execute(tp)
}

func saltedEncryptOptions(srk *tpm2.CreatePrimaryResponse, encryptOut bool) ([]tpm2.AuthOption, error) {
	pub, err := srk.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpm: decode SRK public: %w", err)
	}
	direction := tpm2.EncryptIn
	if encryptOut {
		direction = tpm2.EncryptOut
	}
	return []tpm2.AuthOption{
		tpm2.AESEncryption(128, direction),
		tpm2.Salted(srk.ObjectHandle, *pub),
	}, nil
}

// sealTemplate returns the KeyedHash public template for a sealed-data object.
// When a non-nil authPolicy is supplied (PCR-bound), it is set as the object's
// AuthPolicy and UserWithAuth is cleared so the policy session is the only auth
// path; that policy is a compound PolicyAuthValue + PolicyPCR (see pcr.go), so
// it still requires the object's UserAuth (derived from the vault password) in
// addition to the PCR state. In the non-PCR default, password/HMAC auth via
// UserAuth is used directly. Either way the password is always required.
func sealTemplate(authPolicy []byte) tpm2.TPMTPublic {
	pub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
			NoDA:         false, // keep DA protection: throttle password guessing
		},
	}
	if len(authPolicy) > 0 {
		pub.ObjectAttributes.UserWithAuth = false
		pub.AuthPolicy = tpm2.TPM2BDigest{Buffer: authPolicy}
	}
	return pub
}

// Seal seals secret to tp's TPM as a KeyedHash object under a freshly
// recreated SRK, with a derived value from password as the object's TPM auth
// value. When pcrBound is true, the object is additionally bound to a
// conservative PCR policy (PCR 7); the caller
// is responsible for always keeping a non-TPM (password) copy of the secret as a
// recovery path. Returns the OutPublic/OutPrivate blobs to persist.
//
// Seal issues only the TPM commands needed (CreatePrimary, optional policy
// digest computation, Create) and flushes every transient handle.
func Seal(tp transport.TPM, secret []byte, password string, pcrBound bool) (*Sealed, error) {
	srk, err := createSRK(tp)
	if err != nil {
		return nil, err
	}
	defer flush(tp, srk.ObjectHandle)

	authSalt, err := newAuthSalt()
	if err != nil {
		return nil, fmt.Errorf("tpm: auth salt: %w", err)
	}
	auth, err := authValue(password, authSalt)
	if err != nil {
		return nil, err
	}
	defer zero(auth)

	var authPolicy []byte
	var pcrs []uint
	if pcrBound {
		// Copy the package-level default so a caller mutating Sealed.PCRs cannot
		// alter pcr7 and corrupt future PCR-bound seals.
		pcrs = append([]uint(nil), pcr7...)
		authPolicy, err = computePCRPolicyDigest(tp, pcrs)
		if err != nil {
			return nil, err
		}
	}

	encOpts, err := saltedEncryptOptions(srk, false)
	if err != nil {
		return nil, err
	}
	create := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srk.ObjectHandle,
			Name:   srk.Name,
			Auth: tpm2.HMAC(
				tpm2.TPMAlgSHA256,
				16,
				append([]tpm2.AuthOption{tpm2.Auth(nil)}, encOpts...)...,
			),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{Buffer: auth},
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: secret,
				}),
			},
		},
		InPublic: tpm2.New2B(sealTemplate(authPolicy)),
	}
	rsp, err := create.Execute(tp)
	if err != nil {
		return nil, fmt.Errorf("tpm: seal (create): %w", err)
	}
	return &Sealed{
		Public:   rsp.OutPublic.Bytes(),
		Private:  rsp.OutPrivate.Buffer,
		AuthSalt: authSalt,
		PCRBound: pcrBound,
		PCRs:     pcrs,
	}, nil
}

// Unseal recovers the secret sealed by Seal. It recreates the SRK, loads the
// stored object, and unseals it with the auth value derived from password. When
// the object was PCR-bound, a compound PolicyAuthValue + PolicyPCR session is
// used and the derived password value is supplied as that session's auth value,
// so BOTH the password AND the matching PCR state are required (never PCRs
// alone). A wrong password maps to ErrWrongPassword in both modes; a PCR
// mismatch surfaces as a policy error. Every transient handle is flushed.
//
// The caller owns zeroing the returned secret once it is no longer needed.
func Unseal(tp transport.TPM, sealed *Sealed, password string) ([]byte, error) {
	srk, err := createSRK(tp)
	if err != nil {
		return nil, err
	}
	defer flush(tp, srk.ObjectHandle)

	auth, err := authValue(password, sealed.AuthSalt)
	if err != nil {
		return nil, err
	}
	defer zero(auth)

	// sealed.Public holds the marshalled TPMT_PUBLIC (the inner contents, as
	// returned by OutPublic.Bytes at seal time). Rewrap it as a TPM2B for Load.
	load := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: srk.ObjectHandle,
			Name:   srk.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: tpm2.TPM2BPrivate{Buffer: sealed.Private},
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](sealed.Public),
	}
	loaded, err := load.Execute(tp)
	if err != nil {
		return nil, fmt.Errorf("tpm: unseal (load): %w", err)
	}
	defer flush(tp, loaded.ObjectHandle)

	encOpts, err := saltedEncryptOptions(srk, true)
	if err != nil {
		return nil, err
	}
	unseal := tpm2.Unseal{}
	if sealed.PCRBound {
		sess, cleanup, perr := pcrPolicySession(tp, sealed.PCRs, auth, encOpts...)
		if perr != nil {
			return nil, perr
		}
		defer func() { _ = cleanup() }()
		unseal.ItemHandle = tpm2.AuthHandle{
			Handle: loaded.ObjectHandle,
			Name:   loaded.Name,
			Auth:   sess,
		}
	} else {
		unseal.ItemHandle = tpm2.AuthHandle{
			Handle: loaded.ObjectHandle,
			Name:   loaded.Name,
			Auth: tpm2.HMAC(
				tpm2.TPMAlgSHA256,
				16,
				append([]tpm2.AuthOption{tpm2.Auth(auth)}, encOpts...)...,
			),
		}
	}
	rsp, err := unseal.Execute(tp)
	if err != nil {
		if errors.Is(err, tpm2.TPMRCBadAuth) || errors.Is(err, tpm2.TPMRCAuthFail) {
			return nil, fmt.Errorf("%w: %w", ErrWrongPassword, err)
		}
		return nil, fmt.Errorf("tpm: unseal: %w", err)
	}
	return rsp.OutData.Buffer, nil
}
