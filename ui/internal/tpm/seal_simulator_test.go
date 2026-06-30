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

//go:build tpmsimulator

// This file exercises the REAL go-tpm command path (CreatePrimary/Create/Load/
// Unseal, plus the PCR policy path) against the in-process software TPM from
// go-tpm-tools/simulator.
//
// The simulator requires CGO (it links the ms-tpm-20-ref C reference TPM), so
// this whole file is gated behind the `tpmsimulator` build tag AND must be run
// with CGO_ENABLED=1 and a C toolchain:
//
//	CGO_ENABLED=1 go test -tags tpmsimulator ./internal/tpm/
//
// The DEFAULT test suite (no tag) never imports the simulator and stays
// CGO-free; it covers the seal/unseal contract via a higher-level fake at the
// vault's tpmProtector seam.

package tpm

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// extendPCR7 extends SHA-256 PCR 7 so that a PCR-bound policy sealed against the
// prior value no longer satisfies, exercising the fail-closed path.
func extendPCR7(t *testing.T, tp transport.TPM) {
	t.Helper()
	_, err := (tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(7),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{HashAlg: tpm2.TPMAlgSHA256, Digest: bytes.Repeat([]byte{0x5A}, 32)},
			},
		},
	}).Execute(tp)
	if err != nil {
		t.Fatalf("PCRExtend: %v", err)
	}
}

func openSim(t *testing.T) transport.TPMCloser {
	t.Helper()
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("open simulator: %v", err)
	}
	t.Cleanup(func() { _ = sim.Close() })
	return sim
}

func TestSealUnsealRoundTripSimulator(t *testing.T) {
	tp := openSim(t)
	secret := bytes.Repeat([]byte{0xAB}, 32)
	const pw = "vault-password-xyz"

	sealed, err := Seal(tp, secret, pw, false)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(sealed.Public) == 0 || len(sealed.Private) == 0 {
		t.Fatal("Seal produced empty public/private blobs")
	}
	if bytes.Contains(sealed.Private, secret) {
		t.Fatal("sealed private blob leaks the secret in clear")
	}

	got, err := Unseal(tp, sealed, pw)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("Unseal recovered %x, want %x", got, secret)
	}
}

func TestUnsealWrongPasswordSimulator(t *testing.T) {
	tp := openSim(t)
	secret := bytes.Repeat([]byte{0x11}, 32)

	sealed, err := Seal(tp, secret, "right-password", false)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Unseal(tp, sealed, "wrong-password"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Unseal wrong password = %v, want ErrWrongPassword", err)
	}
}

func TestPCRBoundSealUnsealSimulator(t *testing.T) {
	tp := openSim(t)
	secret := bytes.Repeat([]byte{0x22}, 32)
	const pw = "vault-password-xyz"

	sealed, err := Seal(tp, secret, pw, true)
	if err != nil {
		t.Fatalf("Seal pcrBound: %v", err)
	}
	if !sealed.PCRBound || len(sealed.PCRs) == 0 {
		t.Fatalf("Seal pcrBound metadata = %+v, want PCRBound + PCRs set", sealed)
	}
	// PCRs are unchanged since seal, so unseal succeeds.
	got, err := Unseal(tp, sealed, pw)
	if err != nil {
		t.Fatalf("Unseal pcrBound (matching PCRs): %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("PCR-bound unseal recovered wrong secret")
	}
}

// TestPCRBoundWrongPasswordFailsSimulator is the security contract for the
// advanced PCR-bound mode: the password is required EVEN when the PCRs match.
// The compound PolicyAuthValue + PolicyPCR policy means a wrong password fails
// the session HMAC (ErrWrongPassword), so an attacker who has the vault file on
// the right machine at the right boot state still cannot recover the secret
// without the password (spec §2/§4.1/§4.3). This is the regression test for the
// PCR-only-auth bug.
func TestPCRBoundWrongPasswordFailsSimulator(t *testing.T) {
	tp := openSim(t)
	secret := bytes.Repeat([]byte{0x44}, 32)

	sealed, err := Seal(tp, secret, "right-password", true)
	if err != nil {
		t.Fatalf("Seal pcrBound: %v", err)
	}
	// PCRs are unchanged (they match), but the password is wrong: unseal MUST
	// still fail. If this passes, PCR state alone is authorizing the unseal —
	// exactly the threat-model violation this test guards against.
	if _, err := Unseal(tp, sealed, "wrong-password"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("PCR-bound unseal with wrong password = %v, want ErrWrongPassword", err)
	}
}

func TestPCRMismatchFailsClosedSimulator(t *testing.T) {
	tp := openSim(t)
	secret := bytes.Repeat([]byte{0x33}, 32)
	const pw = "vault-password-xyz"

	sealed, err := Seal(tp, secret, pw, true)
	if err != nil {
		t.Fatalf("Seal pcrBound: %v", err)
	}
	// Mutate PCR 7 so the policy no longer matches: unseal must fail closed.
	extendPCR7(t, tp)
	if _, err := Unseal(tp, sealed, pw); err == nil {
		t.Fatal("PCR-bound unseal after PCR change should fail closed, got nil")
	}
}
