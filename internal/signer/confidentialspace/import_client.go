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

package confidentialspace

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// maxImportResponse bounds a challenge response: an attestation token of at
// most maxTokenSize, which JSON carries base64-encoded, and a few small fields.
const maxImportResponse = (maxTokenSize+2)/3*4 + 4<<10

// ImportParams is what the operator seals to the workload.
type ImportParams struct {
	// KMSKey is the workload's Cloud KMS key, which the binding covers.
	KMSKey string
	// Seed is the 32-byte Ed25519 seed of the pool cold key.
	Seed []byte
	// VKey is the pool's registered cold verification key, taken from an
	// input independent of Seed.
	VKey     []byte
	Profiles []ImportProfile
	// Authority is the provisioning authority's signing key.
	Authority ed25519.PrivateKey
}

// VerifyImportChallenge checks that the attestation token vouches for this
// challenge and this channel key. The verifier checks Google's signature, the
// audience, the image digest and the production and debug claims, and that
// the token carries the one nonce it is asked for; both nonces are asked for.
func VerifyImportChallenge(
	ctx context.Context,
	verifier backend.AttestationVerifier,
	ch ImportChallenge,
) error {
	if verifier == nil {
		return errors.New("import requires an attestation verifier")
	}
	if ch.Version != ImportProtocol ||
		len(ch.Challenge) != importChallengeSize ||
		len(ch.PublicKey) != curve25519.PointSize ||
		len(ch.Attestation) == 0 {
		return errors.New("import challenge is malformed")
	}
	if err := verifier.Verify(ctx, ch.Attestation, ch.Challenge); err != nil {
		return fmt.Errorf("attestation does not cover the challenge: %w", err)
	}
	if err := verifier.Verify(
		ctx, ch.Attestation, tokenNonceOf(ch.PublicKey),
	); err != nil {
		return fmt.Errorf(
			"attestation does not cover the workload's channel key: %w", err,
		)
	}
	return nil
}

// BuildImportRequest verifies ch, then seals the key to the workload it
// attests and has the provisioning authority sign the binding and the
// ciphertext.
func BuildImportRequest(
	ctx context.Context,
	verifier backend.AttestationVerifier,
	ch ImportChallenge,
	p ImportParams,
) (ImportRequest, error) {
	if err := VerifyImportChallenge(ctx, verifier, ch); err != nil {
		return ImportRequest{}, err
	}
	return buildImportRequest(ImportRoute, ch, p)
}

// buildImportRequest binds the request to route. Only ImportRoute is served;
// tests build for another to show the binding refuses it.
func buildImportRequest(
	route string,
	ch ImportChallenge,
	p ImportParams,
) (ImportRequest, error) {
	if len(p.Seed) != ed25519.SeedSize ||
		len(p.VKey) != ed25519.PublicKeySize ||
		len(p.Authority) != ed25519.PrivateKeySize ||
		p.KMSKey == "" {
		return ImportRequest{}, errors.New("import parameters are incomplete")
	}
	entries := slices.Clone(p.Profiles)
	slices.SortFunc(entries, func(a, b ImportProfile) int {
		return strings.Compare(a.Profile, b.Profile)
	})
	names := make([]string, len(entries))
	for n, e := range entries {
		if e.NextIssueNumber >= math.MaxUint64-1 {
			return ImportRequest{}, ErrCounterRegression
		}
		names[n] = e.Profile
	}
	if err := validateImportProfiles(names); err != nil {
		return ImportRequest{}, err
	}
	counters, err := json.Marshal(entries)
	if err != nil {
		return ImportRequest{}, err
	}
	// Validated profiles keep this far below the bound; the bound makes the
	// capacity below provably small. The capacity is exact so the seed is
	// never copied by a reallocation that wipe would miss.
	if len(counters) > maxRequestBody {
		return ImportRequest{}, errors.New("import profiles exceed size limit")
	}
	body := make([]byte, 0, importBodyFixedSize+len(counters))
	body = append(body, p.Seed...)
	body = append(body, p.VKey...)
	body = append(body, counters...)
	defer wipe(body)

	clientSeed := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(clientSeed); err != nil {
		return ImportRequest{}, fmt.Errorf("generate channel key: %w", err)
	}
	defer wipe(clientSeed)
	clientKey, err := curve25519.X25519(clientSeed, curve25519.Basepoint)
	if err != nil {
		return ImportRequest{}, fmt.Errorf("derive channel key: %w", err)
	}
	shared, err := curve25519.X25519(clientSeed, ch.PublicKey)
	if err != nil {
		return ImportRequest{}, errors.New("workload channel key is invalid")
	}
	defer wipe(shared)
	binding := importBinding(
		route, ch.Challenge, tokenNonceOf(ch.PublicKey), ch.PublicKey,
		clientKey, p.KMSKey, names,
	)
	key, err := importChannelKey(shared, binding)
	if err != nil {
		return ImportRequest{}, err
	}
	defer wipe(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return ImportRequest{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return ImportRequest{}, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, body, binding)
	return ImportRequest{
		Version:         ImportProtocol,
		Challenge:       bytes.Clone(ch.Challenge),
		Profiles:        names,
		ClientPublicKey: clientKey,
		Nonce:           nonce,
		Ciphertext:      ciphertext,
		Authorization: ed25519.Sign(
			p.Authority, importAuthorizationDigest(binding, ciphertext),
		),
	}, nil
}

// ImportClient talks to an import-mode workload over mutual TLS.
type ImportClient struct {
	base   *url.URL
	client *http.Client
}

// NewImportClient creates a client for the workload at address, which must be
// https. It refuses a client certificate whose key is the provisioning
// authority's: the two identities must differ.
func NewImportClient(
	address, caFile, certFile, keyFile string,
	authority ed25519.PublicKey,
) (*ImportClient, error) {
	rootPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read tls ca file: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, errors.New("tls ca file contains no certificates")
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read TLS client certificate: %w", err)
	}
	keyPEM, err := bursa.ReadSecretKeyFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read TLS client private key: %w", err)
	}
	defer clear(keyPEM)
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load TLS client certificate: %w", err)
	}
	return newImportClient(address, authority, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		Certificates: []tls.Certificate{certificate},
	})
}

func newImportClient(
	address string,
	authority ed25519.PublicKey,
	tlsConfig *tls.Config,
) (*ImportClient, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("import address must use https")
	}
	for _, cert := range tlsConfig.Certificates {
		if len(cert.Certificate) == 0 {
			continue
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse TLS client certificate: %w", err)
		}
		if key, ok := leaf.PublicKey.(ed25519.PublicKey); ok &&
			key.Equal(authority) {
			return nil, errors.New(
				"the provisioning authority must not be the TLS client identity",
			)
		}
	}
	return &ImportClient{
		base: u,
		client: &http.Client{
			Timeout:   60 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Challenge requests a challenge. The caller must verify it with
// VerifyImportChallenge, which BuildImportRequest does.
func (c *ImportClient) Challenge(ctx context.Context) (ImportChallenge, error) {
	var ch ImportChallenge
	if err := c.post(ctx, ImportChallengeRoute, struct{}{}, &ch); err != nil {
		return ImportChallenge{}, err
	}
	return ch, nil
}

// Import sends the request and returns once the workload has written the key.
func (c *ImportClient) Import(ctx context.Context, req ImportRequest) error {
	var out struct {
		Version string `json:"version"`
	}
	if err := c.post(ctx, ImportRoute, req, &out); err != nil {
		return err
	}
	if out.Version != ImportProtocol {
		return errors.New("import response has an unexpected version")
	}
	return nil
}

func (c *ImportClient) post(
	ctx context.Context,
	route string,
	in, out any,
) error {
	data, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, c.base.JoinPath(route).String(),
		bytes.NewReader(data),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", route, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxImportResponse+1))
	if err != nil {
		return fmt.Errorf("read %s response: %w", route, err)
	}
	if len(body) > maxImportResponse {
		return fmt.Errorf("%s response exceeds size limit", route)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"POST %s returned HTTP %d: %s",
			route, resp.StatusCode, strings.TrimSpace(string(body)),
		)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decode %s response: %w", route, err)
	}
	return requireJSONEOF(dec)
}
