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
	"strconv"
	"strings"

	"github.com/blinklabs-io/bursa/internal/config"
)

// LoopbackBindAddress joins host and port into a listen address that binds
// only the loopback interface. host must be a bare host name or IP literal,
// optionally bracketed. A host that already carries a port is rejected rather
// than combined with port into an address that cannot bind.
func LoopbackBindAddress(host string, port uint) (string, error) {
	trimmed := strings.TrimSpace(host)
	if _, _, err := net.SplitHostPort(trimmed); err == nil {
		return "", fmt.Errorf(
			"listen address %q must be a host without a port; set the port separately",
			host,
		)
	}
	if !IsLoopbackListenAddress(trimmed) {
		return "", fmt.Errorf(
			"refusing listener on non-loopback address %q",
			host,
		)
	}
	if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
		trimmed = strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]")
	}
	return net.JoinHostPort(trimmed, strconv.FormatUint(uint64(port), 10)), nil
}

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

// isSoftwareFileBackend reports whether c is the in-process
// software/file key backend. The only key-backend types BuildBackends accepts
// are "software", "sops", and "vault" (config.SignerBackendConfig.Type); a
// literal Type of "file" is not a valid key backend (it is only a watermark
// store type) and would never reach here in a functioning configuration, so
// it is intentionally not matched.
func isSoftwareFileBackend(c config.SignerBackendConfig) bool {
	return c.Type == "software"
}

// CheckFileBackendGuard applies the default for the software key backend,
// which holds key material in process memory (see
// internal/signer/backend/software.go).
//
// The returned message is non-empty whenever a software backend is configured;
// the caller logs it at INFO. The returned error is non-nil when such a
// backend is configured while the signer binds a non-loopback address
// (including the all-interfaces empty address) and allowFileBackend
// (signer.allow_insecure_file_backend) is not set.
func CheckFileBackendGuard(
	backends []config.SignerBackendConfig,
	listenAddress string,
	allowFileBackend bool,
) (string, error) {
	var names []string
	for _, c := range backends {
		if isSoftwareFileBackend(c) {
			names = append(names, c.Name)
		}
	}
	if len(names) == 0 {
		return "", nil
	}
	msg := fmt.Sprintf(
		"signer key custody: software backend(s) %v hold key material in process memory",
		names,
	)
	if IsLoopbackListenAddress(listenAddress) || allowFileBackend {
		return msg, nil
	}
	return msg, fmt.Errorf(
		"software key backend(s) %v with non-loopback signer.listen_address %q: set signer.allow_insecure_file_backend: true to permit this, or use a vault, sops, pkcs11, or attested backend",
		names,
		listenAddress,
	)
}
