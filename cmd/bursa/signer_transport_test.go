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
	"regexp"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
)

// neutralWording matches words the transport policy keeps out of logs and
// errors: a component cannot see what the deployment provides around it.
var neutralWording = regexp.MustCompile(
	`(?i)insecure|unsafe|risk|danger|development only|dev-only|cleartext`,
)

func TestCheckSignerAuth(t *testing.T) {
	t.Parallel()
	keys := []config.SignerAuthorizedKeyConfig{
		{Caller: "a", Ed25519PubkeyHex: strings.Repeat("ab", 32)},
	}
	for _, tc := range []struct {
		name    string
		cfg     config.SignerConfig
		want    string
		wantErr string
	}{
		{
			name:    "no auth refused by default",
			cfg:     config.SignerConfig{},
			wantErr: "signer.auth_none",
		},
		{
			name: "auth_none",
			cfg:  config.SignerConfig{AuthNone: true},
			want: `signer request auth: none (requests without credentials use caller "anonymous")`,
		},
		{
			name: "jwt secret",
			cfg:  config.SignerConfig{JWTSecret: "s"},
			want: "signer request auth: jwt (shared secret)",
		},
		{
			name: "jwks",
			cfg:  config.SignerConfig{JWKSURL: "https://idp/jwks"},
			want: "signer request auth: jwt (jwks)",
		},
		{
			name: "client certificate optional",
			cfg:  config.SignerConfig{ClientCACert: "/ca.pem"},
			want: "signer request auth: client certificate (when presented)",
		},
		{
			name: "client certificate required",
			cfg: config.SignerConfig{
				ClientCACert:      "/ca.pem",
				RequireClientCert: true,
			},
			want: "signer request auth: client certificate (required)",
		},
		{
			name: "request signing",
			cfg:  config.SignerConfig{AuthorizedKeys: keys},
			want: "signer request auth: request signing",
		},
		{
			name: "auth_none alongside a mode",
			cfg: config.SignerConfig{
				JWTSecret: "s",
				AuthNone:  true,
			},
			want: `signer request auth: jwt (shared secret), none (requests without credentials use caller "anonymous")`,
		},
		{
			name:    "require_client_cert without client CA refused",
			cfg:     config.SignerConfig{RequireClientCert: true},
			wantErr: "signer.client_ca_cert",
		},
		{
			name: "require_client_cert without client CA refused with auth_none",
			cfg: config.SignerConfig{
				RequireClientCert: true,
				AuthNone:          true,
			},
			wantErr: "signer.client_ca_cert",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := checkSignerAuth(tc.cfg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one naming %q", err, tc.wantErr)
				}
				if neutralWording.MatchString(err.Error()) {
					t.Errorf("error wording: %q", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkSignerAuth: %v", err)
			}
			if got != tc.want {
				t.Fatalf("mode = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCheckSignerListener(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		cfg     config.SignerConfig
		want    string
		wantErr string
	}{
		{
			name: "loopback plain TCP",
			cfg:  config.SignerConfig{ListenAddress: "127.0.0.1"},
			want: "signer listener: plain TCP",
		},
		{
			name:    "non-loopback plain TCP refused by default",
			cfg:     config.SignerConfig{ListenAddress: "0.0.0.0"},
			wantErr: "signer.plaintext",
		},
		{
			name:    "all interfaces plain TCP refused by default",
			cfg:     config.SignerConfig{},
			wantErr: "signer.plaintext",
		},
		{
			name: "non-loopback plain TCP with plaintext",
			cfg: config.SignerConfig{
				ListenAddress: "0.0.0.0",
				Plaintext:     true,
			},
			want: "signer listener: plain TCP",
		},
		{
			name: "all interfaces plain TCP with plaintext",
			cfg:  config.SignerConfig{Plaintext: true},
			want: "signer listener: plain TCP",
		},
		{
			name: "TLS",
			cfg: config.SignerConfig{
				ListenAddress: "0.0.0.0",
				TLSCertFile:   "/c.pem",
				TLSKeyFile:    "/k.pem",
			},
			want: "signer listener: TLS",
		},
		{
			name: "TLS takes effect over plaintext",
			cfg: config.SignerConfig{
				ListenAddress: "0.0.0.0",
				TLSCertFile:   "/c.pem",
				TLSKeyFile:    "/k.pem",
				Plaintext:     true,
			},
			want: "signer listener: TLS",
		},
		{
			name: "TLS with optional client certificate",
			cfg: config.SignerConfig{
				TLSCertFile:  "/c.pem",
				TLSKeyFile:   "/k.pem",
				ClientCACert: "/ca.pem",
			},
			want: "signer listener: TLS, client certificate verified when presented",
		},
		{
			name: "TLS with required client certificate",
			cfg: config.SignerConfig{
				TLSCertFile:       "/c.pem",
				TLSKeyFile:        "/k.pem",
				ClientCACert:      "/ca.pem",
				RequireClientCert: true,
			},
			want: "signer listener: TLS, client certificate required",
		},
		{
			name: "cert without key refused",
			cfg: config.SignerConfig{
				ListenAddress: "127.0.0.1",
				TLSCertFile:   "/c.pem",
			},
			wantErr: "tls_key_file",
		},
		{
			name: "key without cert refused",
			cfg: config.SignerConfig{
				ListenAddress: "127.0.0.1",
				TLSKeyFile:    "/k.pem",
				Plaintext:     true,
			},
			wantErr: "tls_cert_file",
		},
		{
			name: "client CA without server TLS refused",
			cfg: config.SignerConfig{
				ListenAddress: "127.0.0.1",
				ClientCACert:  "/ca.pem",
			},
			wantErr: "requires server TLS",
		},
		{
			name: "client CA without server TLS refused with plaintext",
			cfg: config.SignerConfig{
				ListenAddress: "0.0.0.0",
				ClientCACert:  "/ca.pem",
				Plaintext:     true,
			},
			wantErr: "requires server TLS",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := checkSignerListener(tc.cfg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one naming %q", err, tc.wantErr)
				}
				if neutralWording.MatchString(err.Error()) {
					t.Errorf("error wording: %q", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkSignerListener: %v", err)
			}
			if got != tc.want {
				t.Fatalf("mode = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSignerJWKSHint(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		cfg  config.SignerConfig
		hint bool
	}{
		{config.SignerConfig{JWKSURL: "http://idp/jwks"}, true},
		{config.SignerConfig{JWKSURL: "http://idp/jwks", JWKSPlaintext: true}, false},
		{config.SignerConfig{JWKSURL: "https://idp/jwks"}, false},
	} {
		got := signerJWKSHint(tc.cfg)
		if (got != "") != tc.hint ||
			(got != "" && !strings.Contains(got, "signer.jwks_plaintext")) {
			t.Errorf("%+v: hint = %q", tc.cfg, got)
		}
	}
}

func TestDescribeSignerJWKS(t *testing.T) {
	t.Parallel()
	for url, want := range map[string]string{
		"":                      "",
		"https://idp/jwks":      "signer jwks: https",
		"http://127.0.0.1/jwks": "signer jwks: plain http",
		"http://idp/jwks":       "signer jwks: plain http",
	} {
		got := describeSignerJWKS(config.SignerConfig{JWKSURL: url})
		if got != want {
			t.Errorf("%q: got %q, want %q", url, got, want)
		}
	}
}
