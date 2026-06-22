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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

// fakeVault emulates the two Transit endpoints buildVaultBackend uses:
// GET /v1/<mount>/keys/<name> and PUT /v1/<mount>/sign/<name>.
func fakeVault(t *testing.T, priv ed25519.PrivateKey, keyName string) *httptest.Server {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/transit/keys/"+keyName, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, `{"data":{"type":"ed25519","latest_version":1,"keys":{"1":{"public_key":"%s"}}}}`,
			base64.StdEncoding.EncodeToString(pub))
	})
	mux.HandleFunc("PUT /v1/transit/sign/"+keyName, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var body struct {
			Input string `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		msg, err := base64.StdEncoding.DecodeString(body.Input)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sig := ed25519.Sign(priv, msg)
		fmt.Fprintf(w, `{"data":{"signature":"vault:v1:%s"}}`, base64.StdEncoding.EncodeToString(sig))
	})
	return httptest.NewServer(mux)
}

func TestBuildVaultBackend_SignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := fakeVault(t, priv, "payment-1")
	defer ts.Close()
	t.Setenv("VAULT_TOKEN", "test-token")

	b, err := buildVaultBackend(context.Background(), config.SignerBackendConfig{
		Name:    "vault",
		Type:    "vault",
		Address: ts.URL,
		Keys:    []config.SignerBackendKeyConfig{{Name: "payment-1", Type: "payment"}},
	})
	if err != nil {
		t.Fatalf("buildVaultBackend: %v", err)
	}

	hash := backend.HashPublicKey(pub)
	ref, err := b.GetKey(context.Background(), hash)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}
	sig, err := ref.Sign(context.Background(), digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(pub, digest, sig) {
		t.Fatal("vault signature failed ed25519 verification")
	}
}

func TestBuildVaultBackend_RejectsNonEd25519(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/transit/keys/rsa-1", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"data":{"type":"rsa-2048","latest_version":1,"keys":{"1":{"public_key":"x"}}}}`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	t.Setenv("VAULT_TOKEN", "test-token")

	_, err := buildVaultBackend(context.Background(), config.SignerBackendConfig{
		Name: "vault", Type: "vault", Address: ts.URL,
		Keys: []config.SignerBackendKeyConfig{{Name: "rsa-1", Type: "payment"}},
	})
	if err == nil {
		t.Fatal("expected error for non-ed25519 transit key")
	}
}

func TestBuildVaultBackend_RequiresKeysAndToken(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "test-token")
	_, err := buildVaultBackend(context.Background(), config.SignerBackendConfig{
		Name: "vault", Type: "vault", Address: "http://127.0.0.1:1",
	})
	if err == nil {
		t.Fatal("expected error for missing keys list")
	}

	t.Setenv("VAULT_TOKEN", "")
	_, err = buildVaultBackend(context.Background(), config.SignerBackendConfig{
		Name: "vault", Type: "vault", Address: "http://127.0.0.1:1",
		Keys: []config.SignerBackendKeyConfig{{Name: "k", Type: "payment"}},
	})
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestBuildVaultBackend_InvalidKeyType(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "test-token")
	_, err := buildVaultBackend(context.Background(), config.SignerBackendConfig{
		Name: "vault", Type: "vault", Address: "http://127.0.0.1:1",
		Keys: []config.SignerBackendKeyConfig{{Name: "k", Type: "bogus"}},
	})
	if err == nil {
		t.Fatal("expected error for invalid key type")
	}
}

func TestBuildVaultBackend_RejectsPlainHTTPNonLoopback(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "test-token")
	_, err := buildVaultBackend(context.Background(), config.SignerBackendConfig{
		Name: "vault", Type: "vault", Address: "http://vault.internal:8200",
		Keys: []config.SignerBackendKeyConfig{{Name: "k", Type: "payment"}},
	})
	if err == nil {
		t.Fatal("expected error for plain http vault address on non-loopback host")
	}
}
