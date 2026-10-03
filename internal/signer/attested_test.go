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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// stubEnclave holds one key. When forge is set it signs with that key instead,
// modelling an enclave (or a tampering host proxy) returning a signature that
// does not belong to the attested public key.
type stubEnclave struct {
	mu    sync.Mutex
	priv  ed25519.PrivateKey
	role  backend.KeyType
	forge ed25519.PrivateKey
	calls []backend.AttestedRequest
}

func (e *stubEnclave) Inventory(_ context.Context, nonce []byte) (backend.AttestedInventory, error) {
	keys := []backend.AttestedKeyInfo{{Role: e.role, PublicKey: e.priv.Public().(ed25519.PublicKey)}}
	return backend.AttestedInventory{
		Version:     backend.AttestedProtocol,
		Keys:        keys,
		Attestation: backend.InventoryBinding(nonce, keys),
	}, nil
}

func (e *stubEnclave) Sign(_ context.Context, req backend.AttestedRequest) (backend.AttestedResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, req)
	key := e.priv
	if e.forge != nil {
		key = e.forge
	}
	return backend.AttestedResponse{
		Version: backend.AttestedProtocol, Nonce: req.Nonce, Signature: ed25519.Sign(key, req.Payload),
	}, nil
}

func (e *stubEnclave) purposes() []backend.Purpose {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []backend.Purpose
	for _, c := range e.calls {
		out = append(out, c.Purpose)
	}
	return out
}

// evidenceIsBinding accepts evidence equal to the binding.
type evidenceIsBinding struct{}

func (evidenceIsBinding) Verify(_ context.Context, evidence, binding []byte) error {
	if !bytes.Equal(evidence, binding) {
		return backend.ErrAttestation
	}
	return nil
}

func newAttestedCoordinator(t *testing.T, role backend.KeyType, allowed string, card fakeCardano) (*Coordinator, *stubEnclave, backend.KeyHash, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	enc := &stubEnclave{priv: priv, role: role}
	b := backend.NewAttestedBackend("enclave", enc, evidenceIsBinding{})
	if err := b.Load(t.Context()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	hash := backend.HashPublicKey(pub)
	eng, err := policy.NewEngine([]policy.KeyPolicy{{
		Hash:            hash.String(),
		AllowedRequests: []string{allowed},
		Tx:              &policy.TxPolicy{},
		CIP8:            &policy.CIP8Policy{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return New(Deps{
		Resolver:  backend.NewResolver(b),
		Policy:    eng,
		Watermark: watermark.NewMemWatermark(),
		WMMode:    watermark.ModeEnforce,
		Cardano:   card,
	}), enc, hash, pub
}

func TestAttestedKeySignsTransaction(t *testing.T) {
	t.Parallel()
	card := fakeCardano{
		insp:      &bursa.TxInspection{TxId: "abc", Outputs: []bursa.TxOutput{{Address: "addr1ok", Lovelace: "1"}}},
		txid:      bytes.Repeat([]byte{7}, 32),
		assembled: []byte{1},
	}
	c, enc, hash, _ := newAttestedCoordinator(t, backend.KeyTypePayment, "tx", card)

	res, perr, err := c.SignTx(t.Context(), []byte("11"), []string{hash.String()})
	if err != nil || len(perr) != 0 || len(res.Witnesses) != 1 {
		t.Fatalf("SignTx: res=%+v perr=%+v err=%v", res, perr, err)
	}
	if got := enc.purposes(); len(got) != 1 || got[0] != backend.PurposeTxHash {
		t.Fatalf("enclave purposes = %v, want [tx-hash]", got)
	}
	if !bytes.Equal(enc.calls[0].Payload, card.txid) {
		t.Fatal("enclave was not asked to sign the tx id")
	}

	// A signature that does not verify under the attested key is not a witness.
	_, forged, _ := ed25519.GenerateKey(nil)
	enc.forge = forged
	res, perr, err = c.SignTx(t.Context(), []byte("11"), []string{hash.String()})
	if err != nil || len(perr) != 1 || perr[0].Code != CodeInternal {
		t.Fatalf("forged signature: res=%+v perr=%+v err=%v", res, perr, err)
	}
}

func TestAttestedKeySignsOpCert(t *testing.T) {
	t.Parallel()
	c, enc, hash, pub := newAttestedCoordinator(t, backend.KeyTypePool, "opcert", fakeCardano{})
	kes := bytes.Repeat([]byte{9}, kesVkeySize)

	res, code, err := c.SignOpCert(t.Context(), kes, 5, 100, hash.String())
	if err != nil {
		t.Fatalf("SignOpCert: code=%s err=%v", code, err)
	}
	sig, _ := hex.DecodeString(res.SignatureHex)
	want := append(append(append([]byte{}, kes...), 0, 0, 0, 0, 0, 0, 0, 5), 0, 0, 0, 0, 0, 0, 0, 100)
	if !ed25519.Verify(pub, want, sig) {
		t.Fatal("opcert signature does not verify over the OCertSignable bytes")
	}
	if got := enc.purposes(); len(got) != 1 || got[0] != backend.PurposeOpCert {
		t.Fatalf("enclave purposes = %v, want [opcert]", got)
	}

	// The durable counter watermark still gates the enclave: a repeated counter
	// is refused without a second enclave call.
	if _, code, err := c.SignOpCert(t.Context(), kes, 5, 101, hash.String()); err == nil || code != CodeConflict {
		t.Fatalf("repeated counter: code=%s err=%v, want conflict", code, err)
	}
	if len(enc.calls) != 1 {
		t.Fatalf("enclave contacted %d times, want 1", len(enc.calls))
	}

	// A signature not made by the attested key is discarded.
	_, forged, _ := ed25519.GenerateKey(nil)
	enc.forge = forged
	if res, code, err := c.SignOpCert(t.Context(), kes, 6, 100, hash.String()); err == nil || code != CodeInternal || res != nil {
		t.Fatalf("forged signature: code=%s err=%v", code, err)
	}
}

func TestAttestedKeyOpCertRequiresPoolRole(t *testing.T) {
	t.Parallel()
	c, enc, hash, _ := newAttestedCoordinator(t, backend.KeyTypePayment, "opcert", fakeCardano{})
	if _, code, err := c.SignOpCert(t.Context(), make([]byte, kesVkeySize), 1, 1, hash.String()); err == nil || code != CodeBadRequest {
		t.Fatalf("code=%s err=%v, want bad_request", code, err)
	}
	if len(enc.calls) != 0 {
		t.Fatal("enclave contacted for a non-pool key")
	}
}

func TestAttestedKeySignsCIP8(t *testing.T) {
	t.Parallel()
	c, enc, hash, pub := newAttestedCoordinator(t, backend.KeyTypePayment, "cip8", fakeCardano{})
	addr := addrForKey(t, pub)

	res, code, err := c.SignCIP8(t.Context(), []byte("hello"), addr, hash.String())
	if err != nil {
		t.Fatalf("SignCIP8: code=%s err=%v", code, err)
	}
	ok, err := bursa.VerifyData(res.SignatureHex, res.KeyHex, []byte("hello"))
	if err != nil || !ok {
		t.Fatalf("COSE_Sign1 does not verify: ok=%v err=%v", ok, err)
	}
	if got := enc.purposes(); len(got) != 1 || got[0] != backend.PurposeCIP8 {
		t.Fatalf("enclave purposes = %v, want [cip8]", got)
	}

	_, forged, _ := ed25519.GenerateKey(nil)
	enc.forge = forged
	if res, code, err := c.SignCIP8(t.Context(), []byte("hello"), addr, hash.String()); err == nil || res != nil || code != CodeBackend {
		t.Fatalf("forged signature: code=%s err=%v", code, err)
	}
}

// TestBuildBackendsConfidentialSpace boots the backend from config against a
// fake workload and a fake key set, then checks that boot fails closed.
func TestBuildBackendsConfidentialSpace(t *testing.T) {
	t.Parallel()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &rsaKey.PublicKey, KeyID: "k1", Algorithm: "RS256"}}})
	}))
	t.Cleanup(jwks.Close)

	_, priv, _ := ed25519.GenerateKey(nil)
	pub := priv.Public().(ed25519.PublicKey)
	digest := "sha256:aaaa"
	workload := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Nonce []byte `json:"nonce"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		keys := []backend.AttestedKeyInfo{{Role: backend.KeyTypePool, PublicKey: pub}}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": backend.ConfidentialSpaceIssuer, "aud": "https://signer.example",
			"exp":       time.Now().Add(time.Hour).Unix(),
			"eat_nonce": []string{hex.EncodeToString(backend.InventoryBinding(in.Nonce, keys))},
			"dbgstat":   "disabled-since-boot", "swname": "CONFIDENTIAL_SPACE", "secboot": true,
			"submods": map[string]any{"container": map[string]any{"image_digest": digest}},
		})
		tok.Header["kid"] = "k1"
		s, _ := tok.SignedString(rsaKey)
		_ = json.NewEncoder(w).Encode(backend.AttestedInventory{Version: backend.AttestedProtocol, Keys: keys, Attestation: []byte(s)})
	}))
	t.Cleanup(workload.Close)

	cfg := config.SignerBackendConfig{
		Name: "gcp", Type: "confidential-space", Address: workload.URL,
		Audience: "https://signer.example", ImageDigest: digest, JWKSURL: jwks.URL,
	}
	bs, err := BuildBackends(t.Context(), []config.SignerBackendConfig{cfg})
	if err != nil {
		t.Fatalf("BuildBackends: %v", err)
	}
	if _, err := bs[0].GetKey(t.Context(), backend.HashPublicKey(pub)); err != nil {
		t.Fatalf("attested key not resolvable after boot: %v", err)
	}

	// A different approved image digest fails attestation, so boot fails.
	bad := cfg
	bad.ImageDigest = "sha256:bbbb"
	if _, err := BuildBackends(t.Context(), []config.SignerBackendConfig{bad}); err == nil {
		t.Fatal("boot succeeded with a mismatched image digest")
	}
}

// writeRootPEM writes a self-signed certificate and returns its path.
func writeRootPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBuildAttestedBackendsRejectBadConfig(t *testing.T) {
	t.Parallel()
	root := writeRootPEM(t)
	goodPCR := strings.Repeat("ab", 48)
	for _, tc := range []struct {
		name string
		cfg  config.SignerBackendConfig
		want string
	}{
		{"nitro without root", config.SignerBackendConfig{Type: "nitro", Address: "http://127.0.0.1:1"}, "root_ca_file"},
		{"nitro unreadable root", config.SignerBackendConfig{Type: "nitro", Address: "http://127.0.0.1:1", RootCAFile: "/nonexistent/root.pem"}, "root_ca_file"},
		{"nitro without PCR0", config.SignerBackendConfig{Type: "nitro", Address: "http://127.0.0.1:1", RootCAFile: root}, "PCR0"},
		{"nitro non-hex PCR", config.SignerBackendConfig{Type: "nitro", Address: "http://127.0.0.1:1", RootCAFile: root, PCRs: map[uint]string{0: "zz"}}, "pcrs[0]"},
		{"nitro zero PCR0", config.SignerBackendConfig{Type: "nitro", Address: "http://127.0.0.1:1", RootCAFile: root, PCRs: map[uint]string{0: strings.Repeat("00", 48)}}, "all zeros"},
		{"nitro without address", config.SignerBackendConfig{Type: "nitro", RootCAFile: root, PCRs: map[uint]string{0: goodPCR}}, "address"},
		{"confidential-space without audience", config.SignerBackendConfig{Type: "confidential-space", Address: "http://127.0.0.1:1", ImageDigest: "sha256:aa"}, "audience"},
		{"confidential-space cleartext jwks", config.SignerBackendConfig{
			Type: "confidential-space", Address: "http://127.0.0.1:1", Audience: "a", ImageDigest: "sha256:aa", JWKSURL: "http://example.com/jwks",
		}, "https"},
		{"confidential-space without address", config.SignerBackendConfig{
			Type: "confidential-space", Audience: "a", ImageDigest: "sha256:aa", JWKSURL: "http://127.0.0.1:1/jwks",
		}, "address"},
	} {
		tc.cfg.Name = "x"
		_, err := BuildBackends(t.Context(), []config.SignerBackendConfig{tc.cfg})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want error containing %q", tc.name, err, tc.want)
		}
	}
}
