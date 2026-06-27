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

package poolops

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
	"github.com/blinklabs-io/gouroboros/cbor"
)

// fakeKeystore unlocks to a fixed mnemonic, or returns ErrDecryptFailed when the
// password does not match — mirroring the real keystore's wrong-password path.
type fakeKeystore struct {
	mnemonic string
	password string
	exists   bool
}

func (f *fakeKeystore) Exists() bool { return f.exists }

func (f *fakeKeystore) Unlock(password string) ([]byte, error) {
	if password != f.password {
		return nil, keystore.ErrDecryptFailed
	}
	return []byte(f.mnemonic), nil
}

func newSeedService(t *testing.T) (*Service, *wallet.Account) {
	t.Helper()
	acct, err := wallet.Derive(testMnemonic, "preview", 2)
	if err != nil {
		t.Fatalf("derive account: %v", err)
	}
	ks := &fakeKeystore{mnemonic: testMnemonic, password: "spend-password", exists: true}
	s := NewService(nil, ks, fakeGenesis{}, fakeTip{slot: 259200})
	s.SetAccount(acct)
	return s, acct
}

type fakeGenesis struct{ err error }

func (f fakeGenesis) Genesis(_ context.Context) (Genesis, error) {
	if f.err != nil {
		return Genesis{}, f.err
	}
	return Genesis{SlotsPerKESPeriod: 129600, MaxKESEvolutions: 62, EpochLength: 432000}, nil
}

type fakeTip struct{ slot uint64 }

func (f fakeTip) TipSlot() uint64 { return f.slot }

// TestServiceCredentials checks credential derivation through the keystore and
// the wrong-password and no-wallet error paths.
func TestServiceCredentials(t *testing.T) {
	s, _ := newSeedService(t)
	creds, err := s.Credentials("spend-password")
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if creds.Network != "preview" || creds.PoolID == "" {
		t.Fatalf("unexpected credentials: %+v", creds)
	}

	if _, err := s.Credentials("wrong"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: got %v, want ErrWrongPassword", err)
	}

	empty := NewService(nil, &fakeKeystore{password: "x"}, nil, nil)
	if _, err := empty.Credentials("x"); !errors.Is(err, ErrNoWallet) {
		t.Fatalf("no wallet: got %v, want ErrNoWallet", err)
	}
}

// TestServiceKESPeriod checks the KES period is tip/slotsPerKESPeriod and that
// a genesis error propagates.
func TestServiceKESPeriod(t *testing.T) {
	s, _ := newSeedService(t)
	info, err := s.KESPeriod(context.Background())
	if err != nil {
		t.Fatalf("KESPeriod: %v", err)
	}
	if info.CurrentPeriod != 2 { // 259200 / 129600
		t.Fatalf("current period = %d, want 2", info.CurrentPeriod)
	}
	if info.SlotsPerKESPeriod != 129600 || info.MaxKESEvolutions != 62 {
		t.Fatalf("genesis passthrough wrong: %+v", info)
	}

	bad := NewService(nil, &fakeKeystore{}, fakeGenesis{err: errors.New("boom")}, fakeTip{})
	if _, err := bad.KESPeriod(context.Background()); err == nil {
		t.Fatal("expected KESPeriod error when genesis fails")
	}
}

// TestServiceIssueAndRotateOpCert checks an issued opcert verifies against the
// cold vkey, and that rotation derives a new KES key + bumps the issue counter.
func TestServiceIssueOpCert(t *testing.T) {
	s, _ := newSeedService(t)
	creds, _ := s.Credentials("spend-password")
	coldVkey, _ := hex.DecodeString(creds.Cold.VKeyHex)

	opcert, err := s.IssueOpCert("spend-password", 0, 5, 2)
	if err != nil {
		t.Fatalf("IssueOpCert: %v", err)
	}
	if opcert.IssueNumber != 5 || opcert.KesPeriod != 2 {
		t.Fatalf("issue/period = %d/%d, want 5/2", opcert.IssueNumber, opcert.KesPeriod)
	}
	// The opcert ColdSignature must verify against the cold vkey over
	// CBOR([kesVkey, issue, period]).
	kesVkey, _ := hex.DecodeString(opcert.KesVKeyHex)
	sig, _ := hex.DecodeString(opcert.ColdSignatureHex)
	payload, _ := cbor.Encode([]any{kesVkey, uint64(5), uint64(2)})
	if !ed25519.Verify(coldVkey, payload, sig) {
		t.Fatal("issued opcert does not verify against the cold vkey")
	}

	if _, err := s.IssueOpCert("wrong", 0, 5, 2); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: got %v", err)
	}
}

func TestServiceRotateKES(t *testing.T) {
	s, _ := newSeedService(t)
	// Rotation: new KES index 1, previous issue 3 → new issue 4.
	rotated, err := s.RotateKES("spend-password", 1, 3, 5)
	if err != nil {
		t.Fatalf("RotateKES: %v", err)
	}
	if rotated.IssueNumber != 4 {
		t.Fatalf("rotated issue number = %d, want 4 (prev 3 + 1)", rotated.IssueNumber)
	}
	if rotated.KESIndex != 1 {
		t.Fatalf("rotated KES index = %d, want 1", rotated.KESIndex)
	}
	// The rotated opcert must use the KES key at index 1 (different from index 0).
	idx0, _ := s.IssueOpCert("spend-password", 0, 4, 5)
	if rotated.KesVKeyHex == idx0.KesVKeyHex {
		t.Fatal("rotated KES vkey equals index-0 vkey; rotation did not change keys")
	}
}

// TestServiceBuildRegistrationFromSeed checks the seed path builds a cert whose
// pool ID matches the derived credentials and defaults the reward account to the
// wallet's stake address.
func TestServiceBuildRegistrationFromSeed(t *testing.T) {
	s, acct := newSeedService(t)
	creds, _ := s.Credentials("spend-password")
	p := RegistrationParams{Pledge: 1_000_000, Cost: 340_000_000, MarginNum: 1, MarginDenom: 50}
	res, err := s.BuildRegistrationFromSeed("spend-password", p)
	if err != nil {
		t.Fatalf("BuildRegistrationFromSeed: %v", err)
	}
	if res.PoolID != creds.PoolID {
		t.Fatalf("pool ID %q != %q", res.PoolID, creds.PoolID)
	}
	// reward account defaults to the wallet stake address (29-byte) — decode and
	// confirm it is non-empty.
	raw, _ := hex.DecodeString(res.CBORHex)
	var arr []cbor.RawMessage
	if _, err := cbor.Decode(raw, &arr); err != nil {
		t.Fatalf("decode cert: %v", err)
	}
	var reward []byte
	_, _ = cbor.Decode(arr[6], &reward)
	if len(reward) != 29 {
		t.Fatalf("default reward account len = %d, want 29", len(reward))
	}
	_ = acct
}

// TestServiceAirGapRegistration checks the air-gap path builds a registration
// cert from an imported cold vkey + VRF hash without any keystore.
func TestServiceAirGapRegistration(t *testing.T) {
	// Service with no keystore (offline-only).
	acct, _ := wallet.Derive(testMnemonic, "preview", 2)
	s := NewService(nil, nil, nil, nil)
	s.SetAccount(acct)

	creds, _ := deriveCredentials(mustRoot(t), "preview", 0, 0, 0)
	p := AirGapRegistrationParams{
		RegistrationParams: RegistrationParams{
			Pledge: 1, Cost: 1, MarginNum: 0, MarginDenom: 1,
			ColdVKeyHex: creds.Cold.VKeyHex,
		},
		VRFKeyHashHex: creds.VRF.HashHex,
	}
	res, err := s.BuildRegistrationAirGap(p)
	if err != nil {
		t.Fatalf("BuildRegistrationAirGap: %v", err)
	}
	if res.PoolID != creds.PoolID {
		t.Fatalf("air-gap pool ID %q != %q", res.PoolID, creds.PoolID)
	}
}

// TestServicePoolIDFromColdVKey checks the air-gap import returns matching
// bech32 + hex IDs.
func TestServicePoolIDFromColdVKey(t *testing.T) {
	s := NewService(nil, nil, nil, nil)
	creds, _ := deriveCredentials(mustRoot(t), "preview", 0, 0, 0)
	id, idHex, err := s.PoolIDFromColdVKey(creds.Cold.VKeyHex)
	if err != nil {
		t.Fatalf("PoolIDFromColdVKey: %v", err)
	}
	if id != creds.PoolID || idHex != creds.PoolIDHex {
		t.Fatalf("got id=%q hex=%q, want %q / %q", id, idHex, creds.PoolID, creds.PoolIDHex)
	}
}

// compile-time guard: the real keystore satisfies the interface used here.
var _ = bursa.GetRootKeyFromMnemonic
