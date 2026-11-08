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

package kesagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newIdentityKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func TestIdentityKeyAttestationRoundTrip(t *testing.T) {
	t.Parallel()
	a, cold, _ := newHeaderAgent(t)
	pub, priv := newIdentityKey(t)
	attester, err := NewIdentityKeyAttester(priv)
	if err != nil {
		t.Fatalf("NewIdentityKeyAttester: %v", err)
	}
	verifier, err := NewIdentityKeyVerifier(pub)
	if err != nil {
		t.Fatalf("NewIdentityKeyVerifier: %v", err)
	}
	server, client := tcpConnPair(t)
	go func() {
		defer server.Close()
		a.serveAttestedConn(t.Context(), server, AttestedServiceConfig{
			Provider: IdentityKeyProvider,
			Attester: attester,
		})
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	var hello Hello
	if err := readFrame(client, &hello); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	req, err := NewAttestationRequest()
	if err != nil {
		t.Fatalf("NewAttestationRequest: %v", err)
	}
	if err := writeFrame(client, req); err != nil {
		t.Fatalf("write challenge: %v", err)
	}
	var resp AttestationResponse
	if err := readFrame(client, &resp); err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	if resp.Error != "" || len(resp.Attestation) == 0 {
		t.Fatalf("server refused or sent empty evidence: %q", resp.Error)
	}
	if err := VerifyAttestation(
		t.Context(), req, resp, IdentityKeyProvider, cold.pub, resp.OpCert, verifier,
	); err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}

	otherPub, _ := newIdentityKey(t)
	wrongKey, err := NewIdentityKeyVerifier(otherPub)
	if err != nil {
		t.Fatalf("NewIdentityKeyVerifier: %v", err)
	}
	if err := VerifyAttestation(
		t.Context(), req, resp, IdentityKeyProvider, cold.pub, resp.OpCert, wrongKey,
	); err == nil {
		t.Fatal("attestation verified under the wrong identity key")
	}

	badNonce := req
	badNonce.Nonce = append([]byte(nil), req.Nonce...)
	badNonce.Nonce[0] ^= 1
	if err := VerifyAttestation(
		t.Context(), badNonce, resp, IdentityKeyProvider, cold.pub, resp.OpCert, verifier,
	); err == nil {
		t.Fatal("attestation verified for a different nonce")
	}

	tampered := resp
	tampered.Period++
	if err := VerifyAttestation(
		t.Context(), req, tampered, IdentityKeyProvider, cold.pub, resp.OpCert, verifier,
	); err == nil {
		t.Fatal("attestation verified after the binding changed")
	}

	empty := resp
	empty.Attestation = nil
	if err := VerifyAttestation(
		t.Context(), req, empty, IdentityKeyProvider, cold.pub, resp.OpCert, verifier,
	); err == nil {
		t.Fatal("empty evidence verified")
	}
}

func TestIdentityKeyVerifierRejectsBadEvidence(t *testing.T) {
	t.Parallel()
	pub, priv := newIdentityKey(t)
	attester, err := NewIdentityKeyAttester(priv)
	if err != nil {
		t.Fatalf("NewIdentityKeyAttester: %v", err)
	}
	verifier, err := NewIdentityKeyVerifier(pub)
	if err != nil {
		t.Fatalf("NewIdentityKeyVerifier: %v", err)
	}
	binding := AttestationBinding([]byte("n"), []byte("c"), []byte("k"), []byte("o"), 1)
	ev, err := attester.Evidence(t.Context(), binding)
	if err != nil {
		t.Fatalf("Evidence: %v", err)
	}
	if len(ev) != ed25519.SignatureSize {
		t.Fatalf("evidence length = %d, want %d", len(ev), ed25519.SignatureSize)
	}
	if err := verifier.Verify(t.Context(), ev, binding); err != nil {
		t.Fatalf("valid evidence refused: %v", err)
	}
	other := AttestationBinding([]byte("n"), []byte("c"), []byte("k"), []byte("o"), 2)
	if err := verifier.Verify(t.Context(), ev, other); err == nil {
		t.Fatal("evidence verified against a different binding")
	}
	if err := verifier.Verify(t.Context(), nil, binding); err == nil {
		t.Fatal("empty evidence verified")
	}
	if err := verifier.Verify(t.Context(), ev[:10], binding); err == nil {
		t.Fatal("truncated evidence verified")
	}
	if _, err := attester.Evidence(t.Context(), []byte("short")); err == nil {
		t.Fatal("attester signed a value that is not a binding digest")
	}
}

func TestIdentityKeyConstructorsRejectBadKeys(t *testing.T) {
	t.Parallel()
	if _, err := NewIdentityKeyAttester(make([]byte, 10)); err == nil {
		t.Fatal("short private key accepted")
	}
	if _, err := NewIdentityKeyVerifier(make([]byte, 10)); err == nil {
		t.Fatal("short public key accepted")
	}
	if _, err := NewIdentityKeyVerifier(make([]byte, ed25519.PublicKeySize)); err == nil {
		t.Fatal("all-zero public key accepted")
	}
}

func TestLoadIdentityKey(t *testing.T) {
	t.Parallel()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("id.skey", `{"type":"`+IdentityKeyFileType+`","cborHex":"5820`+hex.EncodeToString(seed)+`"}`)
	key, err := LoadIdentityKey(good)
	if err != nil {
		t.Fatalf("LoadIdentityKey: %v", err)
	}
	if !key.Public().(ed25519.PublicKey).Equal(ed25519.NewKeyFromSeed(seed).Public()) {
		t.Fatal("loaded key does not match the seed")
	}
	for name, content := range map[string]string{
		"wrong type": `{"type":"Other","cborHex":"5820` + hex.EncodeToString(seed) + `"}`,
		"short seed": `{"type":"` + IdentityKeyFileType + `","cborHex":"5820abcd"}`,
		"not json":   "nope",
	} {
		if _, err := LoadIdentityKey(write("bad.skey", content)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := LoadIdentityKey(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
}
