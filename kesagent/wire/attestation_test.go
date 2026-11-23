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

package wire

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"testing"
)

func TestStagedKeyAttestationMessageGolden(t *testing.T) {
	t.Parallel()
	got := StagedKeyAttestationMessage(
		"p",
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 28),
	)
	want := hex.EncodeToString([]byte("bursa-kes-agent-staged-key-v1")) +
		"0000000000000001" + "70" +
		"0000000000000020" + hex.EncodeToString(bytes.Repeat([]byte{0x01}, 32)) +
		"000000000000001c" + hex.EncodeToString(bytes.Repeat([]byte{0x02}, 28))
	if hex.EncodeToString(got) != want {
		t.Fatalf("message = %x\nwant      %s", got, want)
	}
}

func testIdentities(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]crypto.Signer{"ed25519": ed, "ecdsa": ec, "rsa": rs}
}

func signedFixture(t *testing.T, id crypto.Signer) *StagedKeyAttestation {
	t.Helper()
	att, err := SignStagedKey(
		id,
		"pool-a",
		bytes.Repeat([]byte{0x11}, 32),
		bytes.Repeat([]byte{0x22}, 28),
	)
	if err != nil {
		t.Fatalf("SignStagedKey: %v", err)
	}
	return att
}

func TestStagedKeyAttestationVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	for name, id := range testIdentities(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := signedFixture(t, id).Verify(); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

func TestStagedKeyAttestationVerifyRefusals(t *testing.T) {
	t.Parallel()
	for name, id := range testIdentities(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mutations := map[string]struct {
				mutate func(a *StagedKeyAttestation)
				want   error
			}{
				"flipped signature": {func(a *StagedKeyAttestation) {
					a.Signature[len(a.Signature)-1] ^= 0x01
				}, ErrStagedKeyAttestationSignature},
				"other profile": {func(a *StagedKeyAttestation) {
					a.Profile = "pool-b"
				}, ErrStagedKeyAttestationSignature},
				"other kes vkey": {func(a *StagedKeyAttestation) {
					a.KESVKey[0] ^= 0x01
				}, ErrStagedKeyAttestationSignature},
				"other cold hash": {func(a *StagedKeyAttestation) {
					a.ColdKeyHash[0] ^= 0x01
				}, ErrStagedKeyAttestationSignature},
				"empty profile": {func(a *StagedKeyAttestation) {
					a.Profile = ""
				}, ErrStagedKeyAttestationMalformed},
				"short kes vkey": {func(a *StagedKeyAttestation) {
					a.KESVKey = a.KESVKey[:31]
				}, ErrStagedKeyAttestationMalformed},
				"short cold hash": {func(a *StagedKeyAttestation) {
					a.ColdKeyHash = a.ColdKeyHash[:27]
				}, ErrStagedKeyAttestationMalformed},
				"garbage spki": {func(a *StagedKeyAttestation) {
					a.SPKI = []byte{0x01, 0x02}
				}, ErrStagedKeyAttestationMalformed},
				"no signature": {func(a *StagedKeyAttestation) {
					a.Signature = nil
				}, ErrStagedKeyAttestationMalformed},
			}
			for mname, m := range mutations {
				t.Run(mname, func(t *testing.T) {
					t.Parallel()
					att := signedFixture(t, id)
					m.mutate(att)
					if err := att.Verify(); !errors.Is(err, m.want) {
						t.Fatalf("Verify = %v, want %v", err, m.want)
					}
				})
			}
		})
	}
	var nilAtt *StagedKeyAttestation
	if err := nilAtt.Verify(); !errors.Is(err, ErrStagedKeyAttestationMalformed) {
		t.Fatalf("nil Verify = %v", err)
	}
}

func TestStagedKeyAttestationSignatureIsDomainSeparated(t *testing.T) {
	t.Parallel()
	_, id, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := signedFixture(t, id)
	// A signature over the same fields without the domain tag must not verify.
	raw := StagedKeyAttestationMessage(att.Profile, att.KESVKey, att.ColdKeyHash)
	att.Signature = ed25519.Sign(id, raw[len(StagedKeyAttestationDomain):])
	if err := att.Verify(); !errors.Is(err, ErrStagedKeyAttestationSignature) {
		t.Fatalf("Verify = %v, want signature error", err)
	}
}
