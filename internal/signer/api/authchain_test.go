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

package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/operation"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
)

// newACLServer builds a tx-signable server whose ACL grants only "alice" the
// test key. It attaches mTLS and request-signing authenticators registering
// "alice" and "bob" so ACL enforcement can be checked per caller source.
func newACLServer(t *testing.T) (*Server, backend.KeyHash, map[string]ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	b := backend.NewSoftwareBackend("software")
	h, err := b.AddKey(&bursa.LoadedKey{SKey: []byte(priv), VKey: pub}, backend.KeyTypePayment)
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	pol := policy.KeyPolicy{Hash: h.String(), AllowedRequests: []string{"tx"}, Tx: &policy.TxPolicy{}}
	eng, _ := policy.NewEngine([]policy.KeyPolicy{pol})
	coord := signer.New(signer.Deps{
		Resolver:  backend.NewResolver(b),
		Policy:    eng,
		Watermark: watermark.NewMemWatermark(),
		Cardano:   operation.Cardano(fakeCardano{pub: pub}),
	})
	acl := NewCallerACL(map[string][]backend.KeyHash{"alice": {h}})
	// No JWT validator: exercise only the mTLS and request-signing chain entries.
	srv := NewServer(coord, backend.NewResolver(b), eng, acl, nil)

	alicePub, alicePriv, _ := ed25519.GenerateKey(rand.Reader)
	bobPub, bobPriv, _ := ed25519.GenerateKey(rand.Reader)
	srv.SetRequestSigningAuthenticator(NewRequestSigningAuthenticator(
		map[string]ed25519.PublicKey{"alice": alicePub, "bob": bobPub}, 60*time.Second))
	srv.SetMTLSAuthenticator(NewMTLSAuthenticator())

	return srv, h, map[string]ed25519.PrivateKey{"alice": alicePriv, "bob": bobPriv}
}

func certWithCN(cn string) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}}}
}

// signTxBody returns the /v1/sign body for a tx signed by the test key.
func signTxBody(t *testing.T, h backend.KeyHash) []byte {
	t.Helper()
	body, err := json.Marshal(SignRequest{Type: "tx", Cbor: "83a0a0f5f6", Signers: []string{h.String()}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// TestACL_MTLSCaller verifies the ACL applies to a caller derived from a client
// certificate, not just a JWT subject.
func TestACL_MTLSCaller(t *testing.T) {
	srv, h, _ := newACLServer(t)
	handler := srv.Handler()
	body := signTxBody(t, h)

	t.Run("alice allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
		req.TLS = certWithCN("alice")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for alice, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("bob denied by ACL", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
		req.TLS = certWithCN("bob")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for bob, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// TestACL_RequestSigningCaller verifies the ACL applies to a caller derived
// from an authorized-keys request signature.
func TestACL_RequestSigningCaller(t *testing.T) {
	srv, h, keys := newACLServer(t)
	handler := srv.Handler()
	body := signTxBody(t, h)

	send := func(caller, nonce string) int {
		bodyHash := sha256.Sum256(body)
		tsStr := strconv.FormatInt(time.Now().Unix(), 10)
		canonical := strings.Join([]string{http.MethodPost, "/v1/sign", hex.EncodeToString(bodyHash[:]), tsStr, nonce}, "|")
		sig := ed25519.Sign(keys[caller], []byte(canonical))
		req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
		req.Header.Set(HeaderKey, caller)
		req.Header.Set(HeaderTimestamp, tsStr)
		req.Header.Set(HeaderNonce, nonce)
		req.Header.Set(HeaderSignature, hex.EncodeToString(sig))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	if code := send("alice", "a1"); code != http.StatusOK {
		t.Fatalf("expected 200 for alice, got %d", code)
	}
	if code := send("bob", "b1"); code != http.StatusForbidden {
		t.Fatalf("expected 403 for bob (ACL), got %d", code)
	}
}

// TestAuthChain_NoCredentials fails closed when no scheme presents a credential.
func TestAuthChain_NoCredentials(t *testing.T) {
	srv, _, _ := newACLServer(t)
	handler := srv.Handler()
	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no credentials, got %d", rr.Code)
	}
}

// TestAuthChain_MTLSPrecedence confirms a verified client cert wins even when a
// request-signing credential is also present.
func TestAuthChain_MTLSPrecedence(t *testing.T) {
	srv, h, keys := newACLServer(t)
	handler := srv.Handler()
	body := signTxBody(t, h)

	// Signed request as "bob" (denied by ACL) but presenting an mTLS cert for
	// "alice" (allowed). mTLS precedence -> alice -> 200.
	bodyHash := sha256.Sum256(body)
	tsStr := strconv.FormatInt(time.Now().Unix(), 10)
	canonical := strings.Join([]string{http.MethodPost, "/v1/sign", hex.EncodeToString(bodyHash[:]), tsStr, "p1"}, "|")
	sig := ed25519.Sign(keys["bob"], []byte(canonical))
	req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
	req.Header.Set(HeaderKey, "bob")
	req.Header.Set(HeaderTimestamp, tsStr)
	req.Header.Set(HeaderNonce, "p1")
	req.Header.Set(HeaderSignature, hex.EncodeToString(sig))
	req.TLS = certWithCN("alice")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected mTLS identity (alice) to win -> 200, got %d: %s", rr.Code, rr.Body.String())
	}
}
