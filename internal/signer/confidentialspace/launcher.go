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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"time"
)

const (
	// LauncherSocket is the Confidential Space launcher's attestation socket.
	LauncherSocket = "/run/container_launcher/teeserver.sock"
	launcherURL    = "http://localhost/v1/token"
	maxTokenSize   = 64 << 10
)

// LauncherTokenSource requests Google Cloud Attestation OIDC tokens over the
// Confidential Space launcher socket.
type LauncherTokenSource struct {
	client *http.Client
}

// NewLauncherTokenSource creates a source using socketPath. Production should
// use LauncherSocket; the parameter permits faithful Unix-socket tests.
func NewLauncherTokenSource(socketPath string) (*LauncherTokenSource, error) {
	if socketPath == "" || !filepath.IsAbs(socketPath) {
		return nil, errors.New("launcher socket path must be absolute")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	return &LauncherTokenSource{client: &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}, nil
}

// Token obtains a custom token whose audience and nonces are echoed in the
// signed claims. Google Cloud Attestation accepts at most six nonces, each 8
// through 88 bytes.
func (s *LauncherTokenSource) Token(
	ctx context.Context,
	audience string,
	nonces []string,
) ([]byte, error) {
	if audience == "" || len(audience) > 512 {
		return nil, errors.New("attestation audience has invalid length")
	}
	if len(nonces) == 0 || len(nonces) > 6 {
		return nil, errors.New(
			"attestation request must contain one through six nonces",
		)
	}
	for _, nonce := range nonces {
		if len(nonce) < 8 || len(nonce) > 88 {
			return nil, errors.New("attestation nonce has invalid length")
		}
	}
	body, err := json.Marshal(struct {
		Audience  string   `json:"audience"`
		Nonces    []string `json:"nonces"`
		TokenType string   `json:"token_type"`
	}{Audience: audience, Nonces: nonces, TokenType: "OIDC"})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		launcherURL,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("launcher token request: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenSize+1))
	if err != nil {
		return nil, fmt.Errorf("read launcher token: %w", err)
	}
	if len(data) > maxTokenSize {
		return nil, errors.New("launcher token exceeds size limit")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"launcher token request returned HTTP %d",
			resp.StatusCode,
		)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("launcher returned an empty token")
	}
	return bytes.TrimSpace(data), nil
}
