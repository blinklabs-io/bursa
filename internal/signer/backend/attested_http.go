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

package backend

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/blinklabs-io/bursa"
)

const (
	// attestedMaxResponse bounds an enclave response body.
	attestedMaxResponse = 1 << 20
	// attestedRequestTimeout bounds one enclave round trip.
	attestedRequestTimeout = 30 * time.Second
)

// HTTPEnclave carries attested-signer messages as JSON over HTTP:
//
//	POST /v1/inventory  {"nonce": <b64>}  ->  AttestedInventory
//	POST /v1/sign       AttestedRequest   ->  AttestedResponse
//
// Attestation and signature verification protect protocol integrity. Callers
// that rely on the transport for authorization must use a constructor that
// configures authenticated TLS.
type HTTPEnclave struct {
	client  *http.Client
	base    string
	profile string
}

// NewHTTPEnclave connects to address: an http:// or https:// URL, or
// unix:///path/to/socket.
func NewHTTPEnclave(address string) (*HTTPEnclave, error) {
	return newHTTPEnclave(address, "", nil)
}

// NewProfiledHTTPEnclave connects to an enclave and selects profile for its
// inventory requests. The same profile is placed on signing requests by the
// profiled attested backend.
func NewProfiledHTTPEnclave(address, profile string) (*HTTPEnclave, error) {
	return newHTTPEnclave(address, profile, nil)
}

// NewMTLSHTTPEnclave connects to an HTTPS workload using TLS 1.3, a pinned
// server CA, and a mandatory client certificate.
func NewMTLSHTTPEnclave(
	address, caFile, certFile, keyFile string,
) (*HTTPEnclave, error) {
	return NewProfiledMTLSHTTPEnclave(address, "", caFile, certFile, keyFile)
}

// NewProfiledMTLSHTTPEnclave is NewMTLSHTTPEnclave with a workload profile,
// as NewProfiledHTTPEnclave is to NewHTTPEnclave.
func NewProfiledMTLSHTTPEnclave(
	address, profile, caFile, certFile, keyFile string,
) (*HTTPEnclave, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("authenticated enclave address must use https")
	}
	rootPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read tls_ca_file: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, errors.New("tls_ca_file contains no certificates")
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
	return newHTTPEnclave(address, profile, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		Certificates: []tls.Certificate{certificate},
	})
}

func newHTTPEnclave(
	address, profile string,
	tlsConfig *tls.Config,
) (*HTTPEnclave, error) {
	u, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("invalid enclave address: %w", err)
	}
	client := &http.Client{
		Timeout: attestedRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	switch u.Scheme {
	case "http", "https":
		if u.Host == "" {
			return nil, errors.New("enclave address has no host")
		}
		if tlsConfig != nil {
			if u.Scheme != "https" {
				return nil, errors.New("authenticated enclave address must use https")
			}
			client.Transport = &http.Transport{TLSClientConfig: tlsConfig.Clone()}
		}
		return &HTTPEnclave{client: client, base: u.Scheme + "://" + u.Host, profile: profile}, nil
	case "unix":
		if tlsConfig != nil {
			return nil, errors.New("authenticated enclave address must use https")
		}
		if u.Path == "" {
			return nil, errors.New("enclave unix address has no socket path")
		}
		path := u.Path
		client.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		}
		return &HTTPEnclave{client: client, base: "http://enclave", profile: profile}, nil
	default:
		return nil, fmt.Errorf("enclave address scheme %q is not http, https, or unix", u.Scheme)
	}
}

func (e *HTTPEnclave) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, attestedMaxResponse+1))
	if err != nil {
		return err
	}
	if len(data) > attestedMaxResponse {
		return fmt.Errorf("%w: response exceeds %d bytes", ErrAttestedProtocol, attestedMaxResponse)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enclave returned HTTP %d", resp.StatusCode)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%w: %w", ErrAttestedProtocol, err)
	}
	// Decoder.More does not see a stray closing bracket or brace at the top
	// level, so require the stream to end.
	if err := dec.Decode(&json.RawMessage{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing data after response", ErrAttestedProtocol)
	}
	return nil
}

// Inventory implements Enclave.
func (e *HTTPEnclave) Inventory(ctx context.Context, nonce []byte) (AttestedInventory, error) {
	var inv AttestedInventory
	err := e.post(ctx, "/v1/inventory", struct {
		Nonce   []byte `json:"nonce"`
		Profile string `json:"profile,omitempty"`
	}{Nonce: nonce, Profile: e.profile}, &inv)
	return inv, err
}

// Sign implements Enclave.
func (e *HTTPEnclave) Sign(ctx context.Context, req AttestedRequest) (AttestedResponse, error) {
	var resp AttestedResponse
	err := e.post(ctx, "/v1/sign", req, &resp)
	return resp, err
}
