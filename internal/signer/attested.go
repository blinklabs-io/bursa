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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/go-jose/go-jose/v4"
)

// attestedLoadTimeout bounds the boot-time attestation of an enclave.
const attestedLoadTimeout = 60 * time.Second

// buildNitroBackend wires an AWS Nitro Enclaves custody backend. Boot fails if
// attestation does not succeed: an unattested enclave serves no keys.
func buildNitroBackend(ctx context.Context, c config.SignerBackendConfig) (backend.Backend, error) {
	if c.RootCAFile == "" {
		return nil, errors.New("nitro backend requires root_ca_file")
	}
	root, err := os.ReadFile(c.RootCAFile)
	if err != nil {
		return nil, fmt.Errorf("read root_ca_file: %w", err)
	}
	pcrs := make(map[uint][]byte, len(c.PCRs))
	for idx, h := range c.PCRs {
		v, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("pcrs[%d]: %w", idx, err)
		}
		pcrs[idx] = v
	}
	verifier, err := backend.NewNitroVerifier(root, pcrs)
	if err != nil {
		return nil, err
	}
	return loadAttestedBackend(ctx, c, verifier)
}

// buildConfidentialSpaceBackend wires a GCP Confidential Space custody
// backend, with the same fail-closed boot as buildNitroBackend.
func buildConfidentialSpaceBackend(ctx context.Context, c config.SignerBackendConfig) (backend.Backend, error) {
	jwksURL := c.JWKSURL
	if jwksURL == "" {
		jwksURL = backend.ConfidentialSpaceJWKSURL
	}
	u, err := url.Parse(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("invalid jwks_url: %w", err)
	}
	// Keys fetched over cleartext could be substituted in transit, which would
	// let a forged attestation token verify.
	if u.Scheme != "https" && (u.Scheme != "http" || !backend.IsLoopbackHost(u.Hostname())) {
		return nil, errors.New("jwks_url must use https; plain http is allowed only for loopback addresses")
	}
	verifier, err := backend.NewConfidentialSpaceVerifier(
		func(ctx context.Context) (jose.JSONWebKeySet, error) { return fetchJWKS(ctx, jwksURL) },
		c.Audience, c.ImageDigest,
	)
	if err != nil {
		return nil, err
	}
	return loadAttestedBackend(ctx, c, verifier)
}

func loadAttestedBackend(ctx context.Context, c config.SignerBackendConfig, verifier backend.AttestationVerifier) (backend.Backend, error) {
	if c.Address == "" {
		return nil, fmt.Errorf("%s backend requires address", c.Type)
	}
	enclave, err := backend.NewHTTPEnclave(c.Address)
	if err != nil {
		return nil, err
	}
	b := backend.NewAttestedBackend(c.Name, enclave, verifier)
	loadCtx, cancel := context.WithTimeout(ctx, attestedLoadTimeout)
	defer cancel()
	if err := b.Load(loadCtx); err != nil {
		return nil, err
	}
	return b, nil
}

// fetchJWKS downloads a JSON Web Key Set over HTTPS.
func fetchJWKS(ctx context.Context, url string) (jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return set, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return set, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return set, fmt.Errorf("jwks fetch: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return set, err
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return set, fmt.Errorf("jwks decode: %w", err)
	}
	return set, nil
}
