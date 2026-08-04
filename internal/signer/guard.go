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
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/blinklabs-io/bursa/internal/config"
)

// IsLoopbackListenAddress reports whether addr binds only the loopback
// interface (localhost / 127.0.0.0-8 / ::1). An empty address binds all
// interfaces and is therefore NOT loopback.
func IsLoopbackListenAddress(addr string) bool {
	host := strings.TrimSpace(addr)
	if host == "" {
		return false
	}
	if splitHost, _, err := net.SplitHostPort(host); err == nil {
		host = splitHost
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	parsed, err := netip.ParseAddr(host)
	return err == nil && parsed.IsLoopback()
}

// isSoftwareFileBackend reports whether c is the plaintext, in-process
// software/file key backend.
func isSoftwareFileBackend(c config.SignerBackendConfig) bool {
	switch c.Type {
	case "software", "file":
		return true
	default:
		return false
	}
}

// CheckFileBackendGuard enforces the production posture for the plaintext
// software/file key backend. That backend loads private key material into
// process memory (see internal/signer/backend/software.go) and is intended for
// development only; production deployments should custody keys in Vault or SOPS.
//
// The returned warning string is non-empty whenever a software/file backend is
// configured; the caller should log it loudly. The returned error is non-nil
// when such a backend is configured while the signer binds a non-loopback
// address (including the all-interfaces empty address) and the operator has not
// explicitly opted in via allowInsecure (signer.allow_insecure_file_backend).
// On a loopback address, or with the opt-in set, boot proceeds and only the
// warning is returned.
func CheckFileBackendGuard(backends []config.SignerBackendConfig, listenAddress string, allowInsecure bool) (string, error) {
	var names []string
	for _, c := range backends {
		if isSoftwareFileBackend(c) {
			names = append(names, c.Name)
		}
	}
	if len(names) == 0 {
		return "", nil
	}
	warn := fmt.Sprintf(
		"software/file key backend(s) %v load plaintext private key material into process memory (development only); prefer a vault or sops backend in production",
		names,
	)
	if IsLoopbackListenAddress(listenAddress) || allowInsecure {
		return warn, nil
	}
	return warn, fmt.Errorf(
		"refusing to start: software/file key backend(s) %v hold plaintext key material and signer.listen_address %q is not loopback; use a vault/sops backend or set signer.allow_insecure_file_backend: true to override (development only)",
		names, listenAddress,
	)
}
