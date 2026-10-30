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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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
	"github.com/blinklabs-io/gouroboros/ledger"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/blake2b"
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
	// issueSkew is added to the opcert-next issue number, and omitIssue
	// leaves it out, modelling custody that misreports the counter.
	issueSkew uint64
	omitIssue bool
}

func (e *stubEnclave) Inventory(
	_ context.Context,
	nonce []byte,
) (backend.AttestedInventory, error) {
	keys := []backend.AttestedKeyInfo{
		{Role: e.role, PublicKey: e.priv.Public().(ed25519.PublicKey)},
	}
	return backend.AttestedInventory{
		Version:     backend.AttestedProtocol,
		Keys:        keys,
		Attestation: backend.InventoryBinding(nonce, keys),
	}, nil
}

func (e *stubEnclave) Sign(
	_ context.Context,
	req backend.AttestedRequest,
) (backend.AttestedResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, req)
	key := e.priv
	if e.forge != nil {
		key = e.forge
	}
	payload := req.Payload
	var issue *uint64
	switch req.Purpose {
	case backend.PurposeTxBody:
		hash := blake2b.Sum256(req.Payload)
		payload = hash[:]
	case backend.PurposeOpCertNext:
		n := binary.BigEndian.Uint64(req.Payload[kesVkeySize:]) + 1 + e.issueSkew
		payload = binary.BigEndian.AppendUint64(append([]byte(nil), req.Payload[:kesVkeySize]...), n)
		payload = append(payload, req.Payload[kesVkeySize+8:]...)
		if !e.omitIssue {
			issue = &n
		}
	}
	return backend.AttestedResponse{
		Version: backend.AttestedProtocol, Nonce: req.Nonce, Signature: ed25519.Sign(key, payload), IssueCounter: issue,
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

func (evidenceIsBinding) Verify(
	_ context.Context,
	evidence, binding []byte,
) error {
	if !bytes.Equal(evidence, binding) {
		return backend.ErrAttestation
	}
	return nil
}

func newAttestedCoordinator(
	t *testing.T,
	role backend.KeyType,
	allowed string,
	card fakeCardano,
) (*Coordinator, *stubEnclave, backend.KeyHash, ed25519.PublicKey) {
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
	// An indefinite map is semantically equivalent to the usual definite map,
	// but re-encoding it changes the body hash.
	txCBOR := "84bf008001800200ffa0f5f6"
	body, err := hex.DecodeString("bf008001800200ff")
	if err != nil {
		t.Fatal(err)
	}
	txid := blake2b.Sum256(body)
	card := fakeCardano{
		insp:      &bursa.TxInspection{TxId: "abc", Outputs: []bursa.TxOutput{{Address: "addr1ok", Lovelace: "1"}}},
		txid:      txid[:],
		assembled: []byte{1},
	}
	c, enc, hash, _ := newAttestedCoordinator(
		t,
		backend.KeyTypePayment,
		"tx",
		card,
	)

	res, perr, err := c.SignTx(t.Context(), []byte(txCBOR), testTxEra, []string{hash.String()})
	if err != nil || len(perr) != 0 || len(res.Witnesses) != 1 {
		t.Fatalf("SignTx: res=%+v perr=%+v err=%v", res, perr, err)
	}
	if got := enc.purposes(); len(got) != 1 || got[0] != backend.PurposeTxBody {
		t.Fatalf("enclave purposes = %v, want [tx-body]", got)
	}
	if !bytes.Equal(enc.calls[0].Payload, body) {
		t.Fatalf("enclave payload = %x, want raw body %x", enc.calls[0].Payload, body)
	}
	if enc.calls[0].Era == nil || *enc.calls[0].Era != ledger.TxTypeBabbage {
		t.Fatalf("enclave era = %v, want %d", enc.calls[0].Era, ledger.TxTypeBabbage)
	}

	// A signature that does not verify under the attested key is not a witness.
	_, forged, _ := ed25519.GenerateKey(nil)
	enc.forge = forged
	res, perr, err = c.SignTx(t.Context(), []byte(txCBOR), testTxEra, []string{hash.String()})
	if err != nil || len(perr) != 1 || perr[0].Code != CodeInternal {
		t.Fatalf("forged signature: res=%+v perr=%+v err=%v", res, perr, err)
	}
}

func TestAttestedKeySignsOpCert(t *testing.T) {
	t.Parallel()
	c, enc, hash, pub := newAttestedCoordinator(
		t,
		backend.KeyTypePool,
		"opcert",
		fakeCardano{},
	)
	kes := bytes.Repeat([]byte{9}, kesVkeySize)

	res, code, err := c.SignOpCert(t.Context(), kes, 5, 100, hash.String())
	if err != nil {
		t.Fatalf("SignOpCert: code=%s err=%v", code, err)
	}
	sig, _ := hex.DecodeString(res.SignatureHex)
	want := append(
		append(append([]byte{}, kes...), 0, 0, 0, 0, 0, 0, 0, 5),
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		100,
	)
	if !ed25519.Verify(pub, want, sig) {
		t.Fatal("opcert signature does not verify over the OCertSignable bytes")
	}
	if got := enc.purposes(); len(got) != 1 || got[0] != backend.PurposeOpCert {
		t.Fatalf("enclave purposes = %v, want [opcert]", got)
	}

	// The counter watermark still gates the enclave: a repeated counter
	// is refused without a second enclave call.
	if _, code, err := c.SignOpCert(t.Context(), kes, 5, 101, hash.String()); err == nil ||
		code != CodeConflict {
		t.Fatalf("repeated counter: code=%s err=%v, want conflict", code, err)
	}
	if len(enc.calls) != 1 {
		t.Fatalf("enclave contacted %d times, want 1", len(enc.calls))
	}

	// A signature not made by the attested key is discarded.
	_, forged, _ := ed25519.GenerateKey(nil)
	enc.forge = forged
	if res, code, err := c.SignOpCert(t.Context(), kes, 6, 100, hash.String()); err == nil ||
		code != CodeInternal ||
		res != nil {
		t.Fatalf("forged signature: code=%s err=%v", code, err)
	}
}

// TestAttestedKeySignsOpCertFromChain: an attested key issues opcerts from the
// on-chain counter through opcert-next, so custody chooses the issue number,
// and Bursa accepts only chain counter + 1 under a verified signature.
func TestAttestedKeySignsOpCertFromChain(t *testing.T) {
	t.Parallel()
	c, enc, hash, pub := newAttestedCoordinator(t, backend.KeyTypePool, "opcert", fakeCardano{})
	kes := bytes.Repeat([]byte{9}, kesVkeySize)
	signable := func(issue, period uint64) []byte {
		b := binary.BigEndian.AppendUint64(append([]byte(nil), kes...), issue)
		return binary.BigEndian.AppendUint64(b, period)
	}

	res, code, err := c.SignOpCertFromChain(t.Context(), kes, 4, 100, hash.String())
	if err != nil {
		t.Fatalf("SignOpCertFromChain: code=%s err=%v", code, err)
	}
	sig, _ := hex.DecodeString(res.SignatureHex)
	if res.IssueCounter != 5 || !ed25519.Verify(pub, signable(5, 100), sig) {
		t.Fatalf("result %+v does not verify at issue 5", res)
	}
	if got := enc.purposes(); len(got) != 1 || got[0] != backend.PurposeOpCertNext {
		t.Fatalf("enclave purposes = %v, want [opcert-next]", got)
	}
	if !bytes.Equal(enc.calls[0].Payload, signable(4, 100)) {
		t.Fatalf("enclave payload = %x, want kes || chain 4 || period 100", enc.calls[0].Payload)
	}

	// a chain counter below the recorded floor never reaches custody
	if _, code, err := c.SignOpCertFromChain(t.Context(), kes, 3, 100, hash.String()); err == nil || code != CodeConflict {
		t.Fatalf("stale chain counter: code=%s err=%v, want conflict", code, err)
	}
	if len(enc.calls) != 1 {
		t.Fatalf("enclave contacted %d times, want 1", len(enc.calls))
	}

	for name, misbehave := range map[string]func(){
		"issue above chain + 1": func() { enc.issueSkew = 2 },
		"no issue counter":      func() { enc.omitIssue = true },
		"forged signature":      func() { _, enc.forge, _ = ed25519.GenerateKey(nil) },
	} {
		enc.issueSkew, enc.omitIssue, enc.forge = 0, false, nil
		misbehave()
		if res, _, err := c.SignOpCertFromChain(t.Context(), kes, 6, 100, hash.String()); err == nil || res != nil {
			t.Fatalf("%s: accepted %+v", name, res)
		}
	}

	// refusals did not raise the floor past chain counter 4
	enc.issueSkew, enc.omitIssue, enc.forge = 0, false, nil
	if _, code, err := c.SignOpCertFromChain(t.Context(), kes, 5, 100, hash.String()); err != nil {
		t.Fatalf("after refusals: code=%s err=%v", code, err)
	}
}

func TestAttestedKeyOpCertRequiresPoolRole(t *testing.T) {
	t.Parallel()
	c, enc, hash, _ := newAttestedCoordinator(
		t,
		backend.KeyTypePayment,
		"opcert",
		fakeCardano{},
	)
	if _, code, err := c.SignOpCert(t.Context(), make([]byte, kesVkeySize), 1, 1, hash.String()); err == nil ||
		code != CodeBadRequest {
		t.Fatalf("code=%s err=%v, want bad_request", code, err)
	}
	if len(enc.calls) != 0 {
		t.Fatal("enclave contacted for a non-pool key")
	}
}

func TestAttestedKeySignsCIP8(t *testing.T) {
	t.Parallel()
	c, enc, hash, pub := newAttestedCoordinator(
		t,
		backend.KeyTypePayment,
		"cip8",
		fakeCardano{},
	)
	addr := addrForKey(t, pub)

	res, code, err := c.SignCIP8(
		t.Context(),
		[]byte("hello"),
		addr,
		hash.String(),
	)
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
	if res, code, err := c.SignCIP8(t.Context(), []byte("hello"), addr, hash.String()); err == nil ||
		res != nil ||
		code != CodeBackend {
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
	jwks := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).
				Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &rsaKey.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
		}),
	)
	t.Cleanup(jwks.Close)

	_, priv, _ := ed25519.GenerateKey(nil)
	pub := priv.Public().(ed25519.PublicKey)
	digest := "sha256:" + strings.Repeat("a", 64)
	profiles := make(chan string, 2)
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "signer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(
		rand.Reader,
		clientTemplate,
		clientTemplate,
		&clientKey.PublicKey,
		clientKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	clientCertFile := filepath.Join(dir, "client.crt")
	clientKeyFile := filepath.Join(dir, "client.key")
	clientCertPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: clientDER,
	})
	if err := os.WriteFile(clientCertFile, clientCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientKeyFile, pem.EncodeToMemory(&pem.Block{
		Type: "EC PRIVATE KEY", Bytes: clientKeyDER,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(clientCertPEM)
	workload := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var in struct {
				Nonce   []byte `json:"nonce"`
				Profile string `json:"profile"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			profiles <- in.Profile
			keys := []backend.AttestedKeyInfo{
				{Role: backend.KeyTypePool, PublicKey: pub},
			}
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": backend.ConfidentialSpaceIssuer, "aud": "https://signer.example",
				"iat": time.Now().
					Add(-time.Minute).
					Unix(),
				"nbf": time.Now().Add(-time.Minute).Unix(),
				"exp": time.Now().
					Add(time.Hour).
					Unix(),
				"hwmodel": "GCP_AMD_SEV",
				"eat_nonce": []string{
					hex.EncodeToString(
						backend.InventoryBinding(in.Nonce, keys),
					),
				},
				"dbgstat": "disabled-since-boot", "swname": "CONFIDENTIAL_SPACE", "secboot": true,
				"submods": map[string]any{
					"container": map[string]any{"image_digest": digest},
					"confidential_space": map[string]any{
						"support_attributes": []string{"STABLE"},
					},
				},
			})
			tok.Header["kid"] = "k1"
			s, _ := tok.SignedString(rsaKey)
			_ = json.NewEncoder(w).
				Encode(backend.AttestedInventory{Version: backend.AttestedProtocol, Keys: keys, Attestation: []byte(s)})
		}),
	)
	workload.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientCAs:  clientCAs,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	workload.StartTLS()
	t.Cleanup(workload.Close)
	serverCAFile := filepath.Join(dir, "server-ca.crt")
	if err := os.WriteFile(serverCAFile, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: workload.Certificate().Raw,
	}), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.SignerBackendConfig{
		Name: "gcp", Type: "confidential-space", Address: workload.URL,
		Audience: "https://signer.example", ImageDigest: digest, JWKSURL: jwks.URL,
		TLSCAFile: serverCAFile, TLSClientCertFile: clientCertFile, TLSClientKeyFile: clientKeyFile,
		Profile: "pool@mainnet",
	}
	bs, err := BuildBackends(t.Context(), []config.SignerBackendConfig{cfg})
	if err != nil {
		t.Fatalf("BuildBackends: %v", err)
	}
	if _, err := bs[0].GetKey(t.Context(), backend.HashPublicKey(pub)); err != nil {
		t.Fatalf("attested key not resolvable after boot: %v", err)
	}
	if got := <-profiles; got != cfg.Profile {
		t.Fatalf("inventory profile = %q, want %q", got, cfg.Profile)
	}

	// A different approved image digest fails attestation, so boot fails.
	bad := cfg
	bad.ImageDigest = "sha256:" + strings.Repeat("b", 64)
	if _, err := BuildBackends(t.Context(), []config.SignerBackendConfig{bad}); err == nil {
		t.Fatal("boot succeeded with a mismatched image digest")
	}
}

func TestBuildBackendsArmory(t *testing.T) {
	t.Parallel()
	identity, identityPriv, _ := ed25519.GenerateKey(nil)
	pool, _, _ := ed25519.GenerateKey(nil)
	stake, _, _ := ed25519.GenerateKey(nil)
	profiles := make(chan string, 2)
	device := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Nonce   []byte `json:"nonce"`
			Profile string `json:"profile"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		profiles <- in.Profile
		keys := []backend.AttestedKeyInfo{{Role: backend.KeyTypePool, PublicKey: pool}, {Role: backend.KeyTypeStake, PublicKey: stake}}
		att := ed25519.Sign(identityPriv, backend.InventoryBinding(in.Nonce, keys))
		_ = json.NewEncoder(w).Encode(backend.AttestedInventory{Version: backend.AttestedProtocol, Keys: keys, Attestation: att})
	}))
	t.Cleanup(device.Close)

	cfg := config.SignerBackendConfig{
		Name: "armory", Type: "armory", Address: device.URL,
		Profile: "pool@preview", IdentityPublicKey: hex.EncodeToString(identity),
	}
	bs, err := BuildBackends(t.Context(), []config.SignerBackendConfig{cfg})
	if err != nil {
		t.Fatalf("BuildBackends: %v", err)
	}
	for _, k := range []ed25519.PublicKey{pool, stake} {
		if _, err := bs[0].GetKey(t.Context(), backend.HashPublicKey(k)); err != nil {
			t.Fatalf("armory key not resolvable after boot: %v", err)
		}
	}
	if got := <-profiles; got != cfg.Profile {
		t.Fatalf("inventory profile = %q, want %q", got, cfg.Profile)
	}

	// Evidence from a device whose identity key is not the pinned one fails
	// attestation, so boot fails.
	other, _, _ := ed25519.GenerateKey(nil)
	bad := cfg
	bad.IdentityPublicKey = hex.EncodeToString(other)
	if _, err := BuildBackends(t.Context(), []config.SignerBackendConfig{bad}); err == nil {
		t.Fatal("boot succeeded with another identity key pinned")
	}
}

// writeHostKeyFile writes an armory-pool host key envelope with mode.
func writeHostKeyFile(t *testing.T, typ, cborHex string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "host.skey")
	body := fmt.Sprintf("{\n    \"type\": %q,\n    \"description\": \"\",\n    \"cborHex\": %q\n}\n", typ, cborHex)
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestBuildBackendsArmoryHostKey: with host_key_file set, every signing
// request carries a challenge from the device and a host signature over it.
func TestBuildBackendsArmoryHostKey(t *testing.T) {
	t.Parallel()
	identity, identityPriv, _ := ed25519.GenerateKey(nil)
	pool, poolPriv, _ := ed25519.GenerateKey(nil)
	host, hostPriv, _ := ed25519.GenerateKey(nil)
	var mu sync.Mutex
	var challenges [][]byte
	device := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/inventory":
			var in struct {
				Nonce   []byte `json:"nonce"`
				Profile string `json:"profile"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			keys := []backend.AttestedKeyInfo{{Role: backend.KeyTypePool, PublicKey: pool}}
			att := ed25519.Sign(identityPriv, backend.InventoryBinding(in.Nonce, keys))
			_ = json.NewEncoder(w).Encode(backend.AttestedInventory{Version: backend.AttestedProtocol, Keys: keys, Attestation: att})
		case "/v1/challenge":
			c := bytes.Repeat([]byte{byte(len(challenges) + 1)}, 32)
			challenges = append(challenges, c)
			_ = json.NewEncoder(w).Encode(map[string]any{"version": backend.AttestedProtocol, "challenge": c})
		case "/v1/sign":
			var req backend.AttestedRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			resp := backend.AttestedResponse{Version: backend.AttestedProtocol, Nonce: req.Nonce}
			if !bytes.Equal(req.HostKey, host) || len(challenges) == 0 ||
				!bytes.Equal(req.Challenge, challenges[len(challenges)-1]) ||
				!ed25519.Verify(host, backend.AttestedRequestBinding(req), req.HostSignature) {
				resp.Error = "host authentication failed"
			} else {
				hash := blake2b.Sum256(req.Payload)
				resp.Signature = ed25519.Sign(poolPriv, hash[:])
				resp.BindingSignature = ed25519.Sign(poolPriv, backend.AttestedResponseBinding(req, resp.Signature, ""))
			}
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	t.Cleanup(device.Close)

	cfg := config.SignerBackendConfig{
		Name: "armory", Type: "armory", Address: device.URL, Profile: "pool@preview",
		IdentityPublicKey: hex.EncodeToString(identity),
		HostKeyFile:       writeHostKeyFile(t, "ArmoryHostSigningKey_ed25519", "5820"+hex.EncodeToString(hostPriv.Seed()), 0o600),
	}
	bs, err := BuildBackends(t.Context(), []config.SignerBackendConfig{cfg})
	if err != nil {
		t.Fatalf("BuildBackends: %v", err)
	}
	ref, err := bs[0].GetKey(t.Context(), backend.HashPublicKey(pool))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte{0xa0}
	if _, err := backend.SignTxFor(t.Context(), ref, body, 6, nil); err != nil {
		t.Fatalf("authenticated sign: %v", err)
	}
	if len(challenges) != 1 {
		t.Fatalf("challenges = %d, want 1", len(challenges))
	}

	seed := hex.EncodeToString(hostPriv.Seed())
	for name, path := range map[string]string{
		"missing file":       filepath.Join(t.TempDir(), "none"),
		"readable by others": writeHostKeyFile(t, "ArmoryHostSigningKey_ed25519", "5820"+seed, 0o644),
		"other key type":     writeHostKeyFile(t, "PaymentSigningKeyShelley_ed25519", "5820"+seed, 0o600),
		"short key":          writeHostKeyFile(t, "ArmoryHostSigningKey_ed25519", "581f"+seed[:62], 0o600),
	} {
		bad := cfg
		bad.HostKeyFile = path
		if _, err := BuildBackends(t.Context(), []config.SignerBackendConfig{bad}); err == nil || !strings.Contains(err.Error(), "host_key_file") {
			t.Errorf("%s: got %v, want a host_key_file error", name, err)
		}
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
		SerialNumber: big.NewInt(
			1,
		), Subject: pkix.Name{CommonName: "test-root"},
		NotBefore: time.Now().
			Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour),
		IsCA:     true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		tmpl,
		tmpl,
		&key.PublicKey,
		key,
	)
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
	goodDigest := "sha256:" + strings.Repeat("a", 64)
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
			Type: "confidential-space", Address: "http://127.0.0.1:1", Audience: "a", ImageDigest: goodDigest, JWKSURL: "http://example.com/jwks",
		}, "https"},
		{"confidential-space without address", config.SignerBackendConfig{
			Type: "confidential-space", Audience: "a", ImageDigest: goodDigest, JWKSURL: "http://127.0.0.1:1/jwks",
		}, "address"},
		{"confidential-space without mTLS identity", config.SignerBackendConfig{
			Type: "confidential-space", Address: "https://127.0.0.1:1", Audience: "a", ImageDigest: goodDigest, JWKSURL: "http://127.0.0.1:1/jwks",
		}, "tls_client_cert_file"},
		{"armory without identity key", config.SignerBackendConfig{Type: "armory", Address: "http://127.0.0.1:1", Profile: "p@preview"}, "identity_public_key"},
		{"armory non-hex identity key", config.SignerBackendConfig{
			Type: "armory", Address: "http://127.0.0.1:1", Profile: "p@preview", IdentityPublicKey: strings.Repeat("zz", 32),
		}, "identity_public_key"},
		{"armory short identity key", config.SignerBackendConfig{
			Type: "armory", Address: "http://127.0.0.1:1", Profile: "p@preview", IdentityPublicKey: strings.Repeat("ab", 31),
		}, "identity_public_key"},
		{"armory without profile", config.SignerBackendConfig{
			Type: "armory", Address: "http://127.0.0.1:1", IdentityPublicKey: strings.Repeat("ab", 32),
		}, "profile"},
		{"armory without address", config.SignerBackendConfig{
			Type: "armory", Profile: "p@preview", IdentityPublicKey: strings.Repeat("ab", 32),
		}, "address"},
	} {
		tc.cfg.Name = "x"
		_, err := BuildBackends(
			t.Context(),
			[]config.SignerBackendConfig{tc.cfg},
		)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf(
				"%s: got %v, want error containing %q",
				tc.name,
				err,
				tc.want,
			)
		}
	}
}

// A JWKS endpoint that passes the URL policy must not hand the fetch to one
// that does not: a redirect to cleartext would let the keys be substituted.
func TestFetchJWKSRefusesRedirectToCleartext(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(
		http.RedirectHandler("http://192.0.2.1/jwks", http.StatusFound),
	)
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if _, err := fetchJWKS(ctx, srv.URL); !errors.Is(err, errJWKSURLPolicy) {
		t.Fatalf("got %v, want errJWKSURLPolicy", err)
	}
}
