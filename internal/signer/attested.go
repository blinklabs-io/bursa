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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/blinklabs-io/bursa"
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
	if err := checkJWKSURL(u); err != nil {
		return nil, err
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

// buildArmoryBackend wires a USB armory custody backend. The device answers
// for one profile and signs its inventory with an identity key pinned here,
// with the same fail-closed boot as buildNitroBackend.
func buildArmoryBackend(ctx context.Context, c config.SignerBackendConfig) (backend.Backend, error) {
	if c.IdentityPublicKey == "" {
		return nil, errors.New("armory backend requires identity_public_key")
	}
	identity, err := hex.DecodeString(c.IdentityPublicKey)
	if err != nil {
		return nil, fmt.Errorf("identity_public_key: %w", err)
	}
	verifier, err := backend.NewArmoryVerifier(identity)
	if err != nil {
		return nil, fmt.Errorf("identity_public_key: %w", err)
	}
	if c.Profile == "" {
		return nil, errors.New("armory backend requires profile")
	}
	if c.HostKeyFile == "" {
		return loadAttestedBackend(ctx, c, verifier)
	}
	hostKey, err := readArmoryHostKey(c.HostKeyFile)
	if err != nil {
		return nil, fmt.Errorf("host_key_file: %w", err)
	}
	if c.Address == "" {
		return nil, fmt.Errorf("%s backend requires address", c.Type)
	}
	enclave, err := backend.NewHostKeyHTTPEnclave(c.Address, c.Profile, hostKey)
	if err != nil {
		return nil, err
	}
	return loadAttestedEnclave(ctx, c, enclave, verifier)
}

// armoryHostKeyType is the envelope type armory-pool host-key writes.
const armoryHostKeyType = "ArmoryHostSigningKey_ed25519"

// readArmoryHostKey reads a host signing key file written by armory-pool
// host-key: a text envelope whose cborHex is a CBOR byte string holding the
// 32-byte Ed25519 seed. The file must not be readable by others.
func readArmoryHostKey(path string) (ed25519.PrivateKey, error) {
	data, err := bursa.ReadSecretKeyFile(path)
	if err != nil {
		return nil, err
	}
	var env struct {
		Type    string `json:"type"`
		CborHex string `json:"cborHex"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("not a text envelope: %w", err)
	}
	if env.Type != armoryHostKeyType {
		return nil, fmt.Errorf("envelope type %q, want %q", env.Type, armoryHostKeyType)
	}
	raw, err := hex.DecodeString(env.CborHex)
	if err != nil || len(raw) != 2+ed25519.SeedSize || raw[0] != 0x58 || raw[1] != ed25519.SeedSize {
		return nil, errors.New("cborHex is not a 32-byte seed")
	}
	return ed25519.NewKeyFromSeed(raw[2:]), nil
}

func loadAttestedBackend(ctx context.Context, c config.SignerBackendConfig, verifier backend.AttestationVerifier) (backend.Backend, error) {
	if c.Address == "" {
		return nil, fmt.Errorf("%s backend requires address", c.Type)
	}
	var (
		enclave *backend.HTTPEnclave
		err     error
	)
	if c.Type == "confidential-space" {
		if c.TLSCAFile == "" || c.TLSClientCertFile == "" ||
			c.TLSClientKeyFile == "" {
			return nil, errors.New(
				"confidential-space backend requires tls_ca_file, tls_client_cert_file, and tls_client_key_file",
			)
		}
		enclave, err = backend.NewProfiledMTLSHTTPEnclave(
			c.Address,
			c.Profile,
			c.TLSCAFile,
			c.TLSClientCertFile,
			c.TLSClientKeyFile,
		)
	} else {
		enclave, err = backend.NewProfiledHTTPEnclave(c.Address, c.Profile)
	}
	if err != nil {
		return nil, err
	}
	return loadAttestedEnclave(ctx, c, enclave, verifier)
}

func loadAttestedEnclave(ctx context.Context, c config.SignerBackendConfig, enclave backend.Enclave, verifier backend.AttestationVerifier) (backend.Backend, error) {
	b := backend.NewProfiledAttestedBackend(c.Name, c.Profile, enclave, verifier)
	loadCtx, cancel := context.WithTimeout(ctx, attestedLoadTimeout)
	defer cancel()
	if err := b.Load(loadCtx); err != nil {
		return nil, err
	}
	return b, nil
}

// errJWKSURLPolicy is returned for a JWKS location that is neither HTTPS nor
// loopback HTTP.
var errJWKSURLPolicy = errors.New("jwks_url must use https; plain http is allowed only for loopback addresses")

// checkJWKSURL applies the JWKS location policy. Keys fetched over cleartext
// could be substituted in transit, which would let a forged attestation token
// verify.
func checkJWKSURL(u *url.URL) error {
	if u.Scheme != "https" && (u.Scheme != "http" || !backend.IsLoopbackHost(u.Hostname())) {
		return errJWKSURLPolicy
	}
	return nil
}

// jwksClient applies the JWKS location policy to every redirect hop, not only
// to the configured URL.
var jwksClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("jwks fetch: stopped after 10 redirects")
		}
		return checkJWKSURL(req.URL)
	},
}

// fetchJWKS downloads a JSON Web Key Set over HTTPS or loopback HTTP.
func fetchJWKS(ctx context.Context, url string) (jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return set, err
	}
	resp, err := jwksClient.Do(req)
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
