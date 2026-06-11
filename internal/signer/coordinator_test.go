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

package signer

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/operation"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// --- fakes ---

type fakeCardano struct {
	insp      *bursa.TxInspection
	txid      []byte
	assembled []byte
}

func (f fakeCardano) Inspect([]byte) (*bursa.TxInspection, error) { return f.insp, nil }
func (f fakeCardano) TxID([]byte) ([]byte, error)                 { return f.txid, nil }
func (f fakeCardano) Assemble([]byte, []lcommon.VkeyWitness) ([]byte, error) {
	return f.assembled, nil
}

// Verify fakeCardano implements operation.Cardano.
var _ operation.Cardano = fakeCardano{}

type fakeKey struct {
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	hash    backend.KeyHash
	signErr error
}

func (k *fakeKey) Hash() backend.KeyHash        { return k.hash }
func (k *fakeKey) PublicKey() ed25519.PublicKey { return k.pub }
func (k *fakeKey) Type() backend.KeyType        { return backend.KeyTypePayment }
func (k *fakeKey) Extended() bool               { return false }
func (k *fakeKey) Backend() string              { return "fake" }
func (k *fakeKey) Sign(_ context.Context, d []byte) ([]byte, error) {
	if k.signErr != nil {
		return nil, k.signErr
	}
	return ed25519.Sign(k.priv, d), nil
}

type fakeBackend struct{ key *fakeKey }

func (b fakeBackend) Name() string { return "fake" }
func (b fakeBackend) ListKeys(context.Context) ([]backend.KeyRef, error) {
	return []backend.KeyRef{b.key}, nil
}
func (b fakeBackend) GetKey(_ context.Context, h backend.KeyHash) (backend.KeyRef, error) {
	if h == b.key.hash {
		return b.key, nil
	}
	return nil, backend.ErrKeyNotFound
}

func newFakeKey(t *testing.T) *fakeKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return &fakeKey{pub: pub, priv: priv, hash: backend.HashPublicKey(pub)}
}

func newCoordinator(t *testing.T, k *fakeKey, pol policy.KeyPolicy, wm watermark.Watermark, card operation.Cardano) *Coordinator {
	t.Helper()
	pol.Hash = k.hash.String()
	eng, err := policy.NewEngine([]policy.KeyPolicy{pol})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return New(Deps{
		Resolver:  backend.NewResolver(fakeBackend{key: k}),
		Policy:    eng,
		Watermark: wm,
		WMMode:    watermark.ModeEnforce,
		Cardano:   card,
	})
}

func TestSignTx_HappyPath(t *testing.T) {
	k := newFakeKey(t)
	card := fakeCardano{
		insp:      &bursa.TxInspection{TxId: "abc", TTL: 10, Outputs: []bursa.TxOutput{{Address: "addr1ok", Lovelace: "1000000"}}},
		txid:      make([]byte, 32),
		assembled: []byte{0x01, 0x02},
	}
	c := newCoordinator(t, k,
		policy.KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &policy.TxPolicy{}},
		watermark.NewMemWatermark(), card)

	res, perr, err := c.SignTx(context.Background(), []byte("11"), []string{k.hash.String()})
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}
	if len(perr) != 0 {
		t.Fatalf("unexpected per-signer errors: %+v", perr)
	}
	if len(res.Witnesses) != 1 {
		t.Fatalf("expected 1 witness, got %d", len(res.Witnesses))
	}
}

func TestSignTx_PolicyDeny(t *testing.T) {
	k := newFakeKey(t)
	card := fakeCardano{insp: &bursa.TxInspection{CertificateCount: 1}, txid: make([]byte, 32)}
	c := newCoordinator(t, k,
		policy.KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &policy.TxPolicy{}}, // certs not allowed
		watermark.NewMemWatermark(), card)

	res, perr, err := c.SignTx(context.Background(), []byte("11"), []string{k.hash.String()})
	if err != nil {
		t.Fatalf("SignTx returned hard error: %v", err)
	}
	if len(res.Witnesses) != 0 || len(perr) != 1 || perr[0].Code != CodeDenied {
		t.Fatalf("expected one denied signer, got res=%+v perr=%+v", res, perr)
	}
}

func TestSignTx_UnknownKey(t *testing.T) {
	k := newFakeKey(t)
	card := fakeCardano{insp: &bursa.TxInspection{}, txid: make([]byte, 32)}
	c := newCoordinator(t, k,
		policy.KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &policy.TxPolicy{}},
		watermark.NewMemWatermark(), card)

	other := newFakeKey(t)
	_, perr, _ := c.SignTx(context.Background(), []byte("11"), []string{other.hash.String()})
	if len(perr) != 1 || perr[0].Code != CodeNotFound {
		t.Fatalf("expected not-found, got %+v", perr)
	}
}

func TestSignTx_ExtendedOnUnsupportedBackend(t *testing.T) {
	k := newFakeKey(t)
	k.signErr = backend.ErrUnsupportedExtended
	card := fakeCardano{insp: &bursa.TxInspection{}, txid: make([]byte, 32)}
	c := newCoordinator(t, k,
		policy.KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &policy.TxPolicy{}},
		watermark.NewMemWatermark(), card)
	_, perr, _ := c.SignTx(context.Background(), []byte("11"), []string{k.hash.String()})
	if len(perr) != 1 || perr[0].Code != CodeUnsupported {
		t.Fatalf("expected unsupported, got %+v", perr)
	}
}

type conflictWatermark struct{}

func (conflictWatermark) Check(context.Context, backend.KeyHash, string, []byte) error {
	return watermark.ErrConflict
}
func (conflictWatermark) CheckAndCommit(context.Context, backend.KeyHash, string, []byte) error {
	return watermark.ErrConflict
}
func (conflictWatermark) Commit(context.Context, backend.KeyHash, string, []byte) error { return nil }

func TestSignTx_WatermarkConflict(t *testing.T) {
	k := newFakeKey(t)
	card := fakeCardano{insp: &bursa.TxInspection{}, txid: make([]byte, 32)}
	c := newCoordinator(t, k,
		policy.KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &policy.TxPolicy{}},
		conflictWatermark{}, card)
	_, perr, _ := c.SignTx(context.Background(), []byte("11"), []string{k.hash.String()})
	if len(perr) != 1 || perr[0].Code != CodeConflict {
		t.Fatalf("expected conflict, got %+v", perr)
	}
}

// --- Fix 9: new tests ---

// paymentAddrForKey builds a mainnet enterprise (key/none) address from pub.
func paymentAddrForKey(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	h := backend.HashPublicKey(pub)
	addr, err := lcommon.NewAddressFromParts(
		lcommon.AddressTypeKeyNone,
		lcommon.AddressNetworkMainnet,
		h[:],
		nil,
	)
	if err != nil {
		t.Fatalf("paymentAddrForKey: %v", err)
	}
	return addr.String()
}

// stakeAddrForKey builds a mainnet stake address (none/key) from pub.
func stakeAddrForKey(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	h := backend.HashPublicKey(pub)
	addr, err := lcommon.NewAddressFromParts(
		lcommon.AddressTypeNoneKey,
		lcommon.AddressNetworkMainnet,
		nil,
		h[:],
	)
	if err != nil {
		t.Fatalf("stakeAddrForKey: %v", err)
	}
	return addr.String()
}

// TestResolveSigner_Address verifies that resolveSigner accepts payment addresses,
// stake addresses, and rejects garbage strings.
func TestResolveSigner_Address(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := backend.HashPublicKey(pub)

	t.Run("payment address", func(t *testing.T) {
		addr := paymentAddrForKey(t, pub)
		got, err := resolveSigner(addr)
		if err != nil {
			t.Fatalf("resolveSigner(%q): %v", addr, err)
		}
		if got != wantHash {
			t.Fatalf("payment addr: want %s, got %s", wantHash, got)
		}
	})

	t.Run("stake address", func(t *testing.T) {
		addr := stakeAddrForKey(t, pub)
		got, err := resolveSigner(addr)
		if err != nil {
			t.Fatalf("resolveSigner(%q): %v", addr, err)
		}
		if got != wantHash {
			t.Fatalf("stake addr: want %s, got %s", wantHash, got)
		}
	})

	t.Run("garbage string", func(t *testing.T) {
		_, err := resolveSigner("not-a-valid-anything")
		if err == nil {
			t.Fatal("expected error for garbage signer string, got nil")
		}
	})
}

// TestSignTx_WatermarkModes verifies ModeOff (watermark never consulted) and
// ModeWarn (conflict logged, signing proceeds).
func TestSignTx_WatermarkModes(t *testing.T) {
	baseCard := fakeCardano{
		insp:      &bursa.TxInspection{},
		txid:      make([]byte, 32),
		assembled: []byte{0x99},
	}

	t.Run("ModeOff", func(t *testing.T) {
		k := newFakeKey(t)
		pol := policy.KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &policy.TxPolicy{}}
		pol.Hash = k.hash.String()
		eng, _ := policy.NewEngine([]policy.KeyPolicy{pol})
		c := New(Deps{
			Resolver:  backend.NewResolver(fakeBackend{key: k}),
			Policy:    eng,
			Watermark: conflictWatermark{}, // would fail if consulted
			WMMode:    watermark.ModeOff,
			Cardano:   baseCard,
		})
		res, perr, err := c.SignTx(context.Background(), []byte("11"), []string{k.hash.String()})
		if err != nil {
			t.Fatalf("SignTx (ModeOff): %v", err)
		}
		if len(perr) != 0 {
			t.Fatalf("ModeOff: unexpected per-signer errors: %+v", perr)
		}
		if len(res.Witnesses) != 1 {
			t.Fatalf("ModeOff: expected 1 witness, got %d", len(res.Witnesses))
		}
	})

	t.Run("ModeWarn", func(t *testing.T) {
		k := newFakeKey(t)
		pol := policy.KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &policy.TxPolicy{}}
		pol.Hash = k.hash.String()
		eng, _ := policy.NewEngine([]policy.KeyPolicy{pol})
		c := New(Deps{
			Resolver:  backend.NewResolver(fakeBackend{key: k}),
			Policy:    eng,
			Watermark: conflictWatermark{}, // returns ErrConflict but mode=warn
			WMMode:    watermark.ModeWarn,
			Cardano:   baseCard,
		})
		res, perr, err := c.SignTx(context.Background(), []byte("11"), []string{k.hash.String()})
		if err != nil {
			t.Fatalf("SignTx (ModeWarn): %v", err)
		}
		if len(perr) != 0 {
			t.Fatalf("ModeWarn: unexpected per-signer errors: %+v", perr)
		}
		if len(res.Witnesses) != 1 {
			t.Fatalf("ModeWarn: expected 1 witness (conflict warned, not blocked), got %d", len(res.Witnesses))
		}
	})
}

// badSigKey signs a fixed wrong 64-byte buffer instead of the real payload.
type badSigKey struct{ *fakeKey }

func (b *badSigKey) Sign(_ context.Context, _ []byte) ([]byte, error) {
	return make([]byte, 64), nil // correct length, wrong bytes → Verify must fail
}

// TestSignTx_VerifyFailure ensures a backend that returns a wrong (but
// correctly-sized) signature yields CodeInternal and no witness.
func TestSignTx_VerifyFailure(t *testing.T) {
	base := newFakeKey(t)
	k := &badSigKey{fakeKey: base}
	pol := policy.KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &policy.TxPolicy{}}
	pol.Hash = k.hash.String()
	eng, _ := policy.NewEngine([]policy.KeyPolicy{pol})
	card := fakeCardano{insp: &bursa.TxInspection{}, txid: make([]byte, 32)}

	c := New(Deps{
		Resolver:  backend.NewResolver(badKeyBackend{k: k}),
		Policy:    eng,
		Watermark: watermark.NewMemWatermark(),
		WMMode:    watermark.ModeEnforce,
		Cardano:   card,
	})
	_, perr, err := c.SignTx(context.Background(), []byte("11"), []string{k.hash.String()})
	if err != nil {
		t.Fatalf("SignTx: unexpected hard error: %v", err)
	}
	if len(perr) != 1 || perr[0].Code != CodeInternal {
		t.Fatalf("expected CodeInternal for bad sig, got %+v", perr)
	}
}

// badKeyBackend is a minimal Backend returning a badSigKey.
type badKeyBackend struct{ k *badSigKey }

func (b badKeyBackend) Name() string { return "bad-sig" }
func (b badKeyBackend) ListKeys(_ context.Context) ([]backend.KeyRef, error) {
	return []backend.KeyRef{b.k}, nil
}
func (b badKeyBackend) GetKey(_ context.Context, h backend.KeyHash) (backend.KeyRef, error) {
	if h == b.k.hash {
		return b.k, nil
	}
	return nil, backend.ErrKeyNotFound
}

// TestSignTx_PartialSuccess: two signers, one resolvable + one unknown.
func TestSignTx_PartialSuccess(t *testing.T) {
	k := newFakeKey(t)
	other := newFakeKey(t) // resolvable key not in this coordinator's backend
	card := fakeCardano{
		insp:      &bursa.TxInspection{},
		txid:      make([]byte, 32),
		assembled: []byte{0xAB},
	}
	c := newCoordinator(t, k,
		policy.KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &policy.TxPolicy{}},
		watermark.NewMemWatermark(), card)

	res, perr, err := c.SignTx(context.Background(), []byte("11"),
		[]string{k.hash.String(), other.hash.String()})
	if err != nil {
		t.Fatalf("SignTx: unexpected hard error: %v", err)
	}
	if len(res.Witnesses) != 1 {
		t.Fatalf("expected 1 witness, got %d", len(res.Witnesses))
	}
	if len(perr) != 1 || perr[0].Code != CodeNotFound {
		t.Fatalf("expected 1 not_found error, got %+v", perr)
	}
}

// TestSignTx_NoSigners: empty signers slice must return a bad_request hard error.
func TestSignTx_NoSigners(t *testing.T) {
	k := newFakeKey(t)
	card := fakeCardano{insp: &bursa.TxInspection{}, txid: make([]byte, 32)}
	c := newCoordinator(t, k,
		policy.KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &policy.TxPolicy{}},
		watermark.NewMemWatermark(), card)

	_, _, err := c.SignTx(context.Background(), []byte("11"), []string{})
	if err == nil {
		t.Fatal("expected hard error for empty signers, got nil")
	}
	if !IsBadRequest(err) {
		t.Fatalf("expected IsBadRequest true, got false; err=%v", err)
	}
}
