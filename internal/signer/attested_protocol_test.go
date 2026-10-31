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
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"golang.org/x/crypto/blake2b"
)

// armoryProtocolDevice is a fake armory. With v1Only it refuses any sign
// version but 1 the way the version 1 firmware does.
type armoryProtocolDevice struct {
	mu       sync.Mutex
	v1Only   bool
	versions []string
}

func newArmoryProtocolDevice(t *testing.T, v1Only bool) (config.SignerBackendConfig, ed25519.PublicKey, *armoryProtocolDevice) {
	t.Helper()
	identity, identityPriv, _ := ed25519.GenerateKey(nil)
	pool, poolPriv, _ := ed25519.GenerateKey(nil)
	dev := &armoryProtocolDevice{v1Only: v1Only}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dev.mu.Lock()
		defer dev.mu.Unlock()
		switch r.URL.Path {
		case "/v1/inventory":
			var in struct {
				Nonce []byte `json:"nonce"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			keys := []backend.AttestedKeyInfo{{Role: backend.KeyTypePool, PublicKey: pool}}
			_ = json.NewEncoder(w).Encode(backend.AttestedInventory{
				Version: backend.AttestedProtocol, Keys: keys,
				Attestation: ed25519.Sign(identityPriv, backend.InventoryBinding(in.Nonce, keys)),
			})
		case "/v1/sign":
			var req backend.AttestedRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			dev.versions = append(dev.versions, req.Version)
			resp := backend.AttestedResponse{Version: backend.AttestedProtocol, Nonce: req.Nonce}
			switch {
			case req.Version == backend.AttestedProtocol || (req.Version == backend.AttestedProtocolSummary && !dev.v1Only):
				resp.Version = req.Version
				hash := blake2b.Sum256(req.Payload)
				resp.Signature = ed25519.Sign(poolPriv, hash[:])
				if req.Version == backend.AttestedProtocolSummary {
					resp.Summary = "custody summary"
				}
				resp.BindingSignature = ed25519.Sign(poolPriv, backend.AttestedSummaryResponseBinding(req, resp.Signature, resp.Summary))
			default:
				resp.Error = "unsupported protocol version"
			}
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	t.Cleanup(srv.Close)
	return config.SignerBackendConfig{
		Name: "armory", Type: "armory", Address: srv.URL, Profile: "pool@preview",
		IdentityPublicKey: hex.EncodeToString(identity),
	}, pool, dev
}

func (d *armoryProtocolDevice) seen() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return strings.Join(d.versions, ",")
}

const (
	wantV1      = backend.AttestedProtocol
	wantV2      = backend.AttestedProtocolSummary
	wantV2ThenV = backend.AttestedProtocolSummary + "," + backend.AttestedProtocol
)

func TestBuildBackendsArmoryProtocol(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		protocol    string
		v1Only      bool
		wantSeen    string
		wantSummary string
		wantErr     bool
	}{
		"default sends version 1":             {protocol: "", wantSeen: wantV1},
		"explicit 1 sends version 1":          {protocol: "1", wantSeen: wantV1},
		"negotiate with version 2 device":     {protocol: "negotiate", wantSeen: wantV2, wantSummary: "custody summary"},
		"negotiate falls back on v1 firmware": {protocol: "negotiate", v1Only: true, wantSeen: wantV2ThenV},
		"2 with version 2 device":             {protocol: "2", wantSeen: wantV2, wantSummary: "custody summary"},
		"2 refuses version 1 firmware":        {protocol: "2", v1Only: true, wantSeen: wantV2, wantErr: true},
		"default works against v1 firmware":   {protocol: "", v1Only: true, wantSeen: wantV1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg, pool, dev := newArmoryProtocolDevice(t, tc.v1Only)
			cfg.Protocol = tc.protocol
			bs, err := BuildBackends(t.Context(), []config.SignerBackendConfig{cfg})
			if err != nil {
				t.Fatalf("BuildBackends: %v", err)
			}
			ref, err := bs[0].GetKey(t.Context(), backend.HashPublicKey(pool))
			if err != nil {
				t.Fatal(err)
			}
			_, summary, err := backend.SignTxSummaryFor(t.Context(), ref, []byte{0xa0}, 6, nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("sign error = %v, want error %v", err, tc.wantErr)
			}
			if summary != tc.wantSummary {
				t.Fatalf("summary = %q, want %q", summary, tc.wantSummary)
			}
			if got := dev.seen(); got != tc.wantSeen {
				t.Fatalf("sign requests at %q, want %q", got, tc.wantSeen)
			}
		})
	}
}

func TestBuildBackendsProtocolValidation(t *testing.T) {
	t.Parallel()
	cfg, _, _ := newArmoryProtocolDevice(t, false)
	cfg.Protocol = "3"
	if _, err := BuildBackends(t.Context(), []config.SignerBackendConfig{cfg}); err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("armory protocol 3: got %v, want a protocol error", err)
	}

	soft := config.SignerBackendConfig{Name: "soft", Type: "software", Path: t.TempDir(), Protocol: "negotiate"}
	if _, err := BuildBackends(t.Context(), []config.SignerBackendConfig{soft}); err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("software with protocol: got %v, want a protocol error", err)
	}
}
