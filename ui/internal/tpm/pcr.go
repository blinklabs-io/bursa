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

const maxPCRIndex = 23

// pcrSelection builds a SHA-256 PCR selection over the given PCR indices. PCR
// binding is opt-in and brittle (see design §4.4); the conservative default is
// PCR 7 (secure-boot state).
func pcrSelection(pcrs []uint) (tpm2.TPMLPCRSelection, error) {
	if len(pcrs) == 0 {
		return tpm2.TPMLPCRSelection{}, errors.New("tpm: PCR selection is empty")
	}
	for _, pcr := range pcrs {
		if pcr > maxPCRIndex {
			return tpm2.TPMLPCRSelection{}, fmt.Errorf("tpm: PCR index %d out of range 0-%d", pcr, maxPCRIndex)
		}
	}
	return tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
			},
		},
	}, nil
}

// computePCRPolicyDigest runs a trial session to derive the compound AuthPolicy
// digest to bake into the sealed object's template at seal time. A trial session
// computes the policy digest without enforcing it. The policy is
// PolicyAuthValue + PolicyPCR, so it commits to BOTH the object's auth value
// (the vault password) AND the selected PCR state: unsealing later requires the
// password AND the matching boot state, never PCRs alone (spec §2/§4.1/§4.3 —
// "TPM presence alone is insufficient without the password"). The order
// (PolicyAuthValue then PolicyPCR) must match pcrPolicySession's enforcing order
// or the digests will not agree.
func computePCRPolicyDigest(tp transport.TPM, pcrs []uint) ([]byte, error) {
	selection, err := pcrSelection(pcrs)
	if err != nil {
		return nil, err
	}
	sess, cleanup, err := tpm2.PolicySession(tp, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		return nil, fmt.Errorf("tpm: PCR trial session: %w", err)
	}
	defer func() { _ = cleanup() }()
	if _, err := (tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}).Execute(tp); err != nil {
		return nil, fmt.Errorf("tpm: PolicyAuthValue (trial): %w", err)
	}
	if _, err := (tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs:          selection,
	}).Execute(tp); err != nil {
		return nil, fmt.Errorf("tpm: PolicyPCR (trial): %w", err)
	}
	dig, err := (tpm2.PolicyGetDigest{PolicySession: sess.Handle()}).Execute(tp)
	if err != nil {
		return nil, fmt.Errorf("tpm: PolicyGetDigest: %w", err)
	}
	return dig.PolicyDigest.Buffer, nil
}

// pcrPolicySession opens a real (enforcing) compound PolicyAuthValue + PolicyPCR
// session for unseal. The scrypt-derived value from the vault password is
// supplied as the session's auth value (tpm2.Auth) so the session HMAC proves
// knowledge of the object's auth value, satisfying the PolicyAuthValue branch;
// PolicyPCR then binds the current boot state. Unseal therefore requires BOTH
// the password AND the matching PCRs.
//
// It returns the session to use as the object's auth and a cleanup func to flush
// it. A wrong password makes the session HMAC fail (TPM_RC_AUTH_FAIL, surfaced
// as ErrWrongPassword by the caller); a PCR mismatch makes PolicyPCR fail closed
// (machine state changed) — in both cases the password recovery path remains
// available. The command order here MUST mirror computePCRPolicyDigest.
func pcrPolicySession(tp transport.TPM, pcrs []uint, auth []byte, opts ...tpm2.AuthOption) (tpm2.Session, func() error, error) {
	selection, err := pcrSelection(pcrs)
	if err != nil {
		return nil, nil, err
	}
	opts = append([]tpm2.AuthOption{tpm2.Auth(auth)}, opts...)
	sess, cleanup, err := tpm2.PolicySession(tp, tpm2.TPMAlgSHA256, 16, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("tpm: PCR policy session: %w", err)
	}
	if _, err := (tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}).Execute(tp); err != nil {
		_ = cleanup()
		return nil, nil, fmt.Errorf("tpm: PolicyAuthValue: %w", err)
	}
	if _, err := (tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs:          selection,
	}).Execute(tp); err != nil {
		_ = cleanup()
		return nil, nil, fmt.Errorf("tpm: PolicyPCR: %w", err)
	}
	return sess, cleanup, nil
}
