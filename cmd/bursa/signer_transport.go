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

package main

import (
	"errors"
	"net/url"
	"strings"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer"
)

// checkSignerAuth validates the request authentication settings and returns
// the INFO line naming the modes in use.
//
// Without any mode configured the signer refuses to start unless
// signer.auth_none is set. require_client_cert without client_ca_cert is
// refused because there is nothing to verify a client certificate against.
func checkSignerAuth(cfg config.SignerConfig) (string, error) {
	var modes []string
	switch {
	case cfg.JWKSURL != "":
		modes = append(modes, "jwt (jwks)")
	case cfg.JWTSecret != "":
		modes = append(modes, "jwt (shared secret)")
	}
	if cfg.ClientCACert != "" {
		if cfg.RequireClientCert {
			modes = append(modes, "client certificate (required)")
		} else {
			modes = append(modes, "client certificate (when presented)")
		}
	} else if cfg.RequireClientCert {
		return "", errors.New(
			"signer.require_client_cert requires signer.client_ca_cert",
		)
	}
	if len(cfg.AuthorizedKeys) > 0 {
		modes = append(modes, "request signing")
	}
	if cfg.AuthNone {
		modes = append(
			modes,
			"none (requests without credentials use caller \"anonymous\")",
		)
	}
	if len(modes) == 0 {
		return "", errors.New(
			"no signer request auth configured: set signer.jwt_secret, signer.jwks_url, signer.client_ca_cert, or signer.authorized_keys, or set signer.auth_none: true",
		)
	}
	return "signer request auth: " + strings.Join(modes, ", "), nil
}

// checkSignerListener validates the listener transport settings and returns
// the INFO line naming the transport in use.
//
// A plain TCP listener on a non-loopback address is refused unless
// signer.plaintext is set. A TLS certificate without its key (or the reverse)
// and a client CA without server TLS cannot work and are always refused.
func checkSignerListener(cfg config.SignerConfig) (string, error) {
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return "", errors.New(
			"signer TLS requires both tls_cert_file and tls_key_file",
		)
	}
	if cfg.TLSCertFile != "" {
		switch {
		case cfg.ClientCACert == "":
			return "signer listener: TLS", nil
		case cfg.RequireClientCert:
			return "signer listener: TLS, client certificate required", nil
		default:
			return "signer listener: TLS, client certificate verified when presented", nil
		}
	}
	// mTLS verifies client certs during the TLS handshake, so it needs server
	// TLS enabled.
	if cfg.ClientCACert != "" {
		return "", errors.New(
			"signer.client_ca_cert requires server TLS (signer.tls_cert_file and signer.tls_key_file)",
		)
	}
	if !cfg.Plaintext &&
		!signer.IsLoopbackListenAddress(cfg.ListenAddress) {
		return "", errors.New(
			"signer.listen_address is not loopback and no TLS is configured: set signer.tls_cert_file and signer.tls_key_file, bind a loopback address, or set signer.plaintext: true",
		)
	}
	return "signer listener: plain TCP", nil
}

// describeSignerJWKS returns the INFO line naming the JWKS transport, or ""
// when signer.jwks_url is unset.
func describeSignerJWKS(cfg config.SignerConfig) string {
	if cfg.JWKSURL == "" {
		return ""
	}
	u, err := url.Parse(cfg.JWKSURL)
	if err == nil && u.Scheme == "http" {
		return "signer jwks: plain http"
	}
	return "signer jwks: https"
}
