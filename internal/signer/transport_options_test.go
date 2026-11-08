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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

// neutralWording matches words the transport policy keeps out of logs and
// errors: a component cannot see what the deployment provides around it.
var neutralWording = regexp.MustCompile(
	`(?i)insecure|unsafe|risk|danger|development only|dev-only|cleartext`,
)

// writeClientIdentity writes a self-signed client certificate and its key,
// returning their paths and a pool trusting the certificate.
func writeClientIdentity(
	t *testing.T,
) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "signer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		tmpl,
		tmpl,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "client.crt")
	keyFile = filepath.Join(dir, "client.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{
		Type: "EC PRIVATE KEY", Bytes: keyDER,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return certFile, keyFile, pool
}

// writeServerCA writes the certificate of a TLS test server as a CA file.
func writeServerCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server-ca.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: srv.Certificate().Raw,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// inventoryServer answers /v1/inventory with an empty inventory and counts
// the requests it received.
func inventoryServer(t *testing.T) (http.Handler, func() int) {
	t.Helper()
	calls := make(chan struct{}, 16)
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls <- struct{}{}
			_ = json.NewEncoder(w).Encode(
				backend.AttestedInventory{Version: backend.AttestedProtocol},
			)
		}), func() int {
			return len(calls)
		}
}

// TestBuildBackendsArmoryHTTPS: an armory device behind https with a private
// CA that requires a client certificate, plus host-key signed requests.
func TestBuildBackendsArmoryHTTPS(t *testing.T) {
	t.Parallel()
	identity, identityPriv, _ := ed25519.GenerateKey(nil)
	pool, poolPriv, _ := ed25519.GenerateKey(nil)
	host, hostPriv, _ := ed25519.GenerateKey(nil)
	device, challenges := hostKeyDevice(
		t, pool, poolPriv, host,
		func(nonce []byte, keys []backend.AttestedKeyInfo) []byte {
			return ed25519.Sign(
				identityPriv,
				backend.InventoryBinding(nonce, keys),
			)
		},
	)
	deviceURL, err := url.Parse(device.URL)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile, clientCAs := writeClientIdentity(t)
	front := httptest.NewUnstartedServer(
		httputil.NewSingleHostReverseProxy(deviceURL),
	)
	front.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientCAs:  clientCAs,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	front.StartTLS()
	t.Cleanup(front.Close)

	cfg := config.SignerBackendConfig{
		Name: "armory", Type: "armory", Address: front.URL,
		Profile:           "pool@preview",
		IdentityPublicKey: hex.EncodeToString(identity),
		TLSCAFile:         writeServerCA(t, front),
		TLSClientCertFile: certFile,
		TLSClientKeyFile:  keyFile,
		HostKeyFile: writeHostKeyFile(
			t,
			"ArmoryHostSigningKey_ed25519",
			"5820"+hex.EncodeToString(hostPriv.Seed()),
			0o600,
		),
	}
	bs, err := BuildBackends(t.Context(), []config.SignerBackendConfig{cfg})
	if err != nil {
		t.Fatalf("BuildBackends: %v", err)
	}
	ref, err := bs[0].GetKey(t.Context(), backend.HashPublicKey(pool))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := backend.SignTxFor(t.Context(), ref, []byte{0xa0}, 6, nil); err != nil {
		t.Fatalf("sign over https: %v", err)
	}
	if n := challenges(); n != 1 {
		t.Fatalf("challenges = %d, want 1", n)
	}

	// Without the client certificate the device's TLS front refuses the
	// connection, so boot fails.
	noCert := cfg
	noCert.TLSClientCertFile, noCert.TLSClientKeyFile = "", ""
	if _, err := BuildBackends(t.Context(), []config.SignerBackendConfig{noCert}); err == nil {
		t.Fatal(
			"boot succeeded without the client certificate the device requires",
		)
	}
}

// TestBuildBackendsNitroWithoutHostKey: host_key_file is optional. Without it
// requests are not host-key signed and the device decides whether to accept
// them; this device requires them, so the signature request fails.
func TestBuildBackendsNitroWithoutHostKey(t *testing.T) {
	t.Parallel()
	pool, poolPriv, _ := ed25519.GenerateKey(nil)
	host, _, _ := ed25519.GenerateKey(nil)
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	rootPEM, document := nitroAttester(t, pcr0)
	rootFile := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(rootFile, rootPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	device, challenges := hostKeyDevice(
		t, pool, poolPriv, host,
		func(nonce []byte, keys []backend.AttestedKeyInfo) []byte {
			return document(backend.InventoryBinding(nonce, keys))
		},
	)
	cfg := config.SignerBackendConfig{
		Name: "nitro", Type: "nitro", Address: device.URL, Profile: "pool@preview",
		RootCAFile: rootFile,
		PCRs:       map[uint]string{0: hex.EncodeToString(pcr0)},
	}
	bs, err := BuildBackends(t.Context(), []config.SignerBackendConfig{cfg})
	if err != nil {
		t.Fatalf("BuildBackends without host_key_file: %v", err)
	}
	ref, err := bs[0].GetKey(t.Context(), backend.HashPublicKey(pool))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := backend.SignTxFor(t.Context(), ref, []byte{0xa0}, 6, nil); err == nil {
		t.Fatal(
			"device that requires host signatures accepted an unsigned request",
		)
	}
	if n := challenges(); n != 0 {
		t.Fatalf("challenges = %d, want 0 without a host key", n)
	}
}

// TestConfidentialSpaceTransport covers the confidential-space address
// settings: https by default with optional CA and client certificate, and
// plain http only with plaintext.
func TestConfidentialSpaceTransport(t *testing.T) {
	t.Parallel()
	handler, calls := inventoryServer(t)
	tlsSrv := httptest.NewTLSServer(handler)
	t.Cleanup(tlsSrv.Close)
	plainSrv := httptest.NewServer(handler)
	t.Cleanup(plainSrv.Close)
	ca := writeServerCA(t, tlsSrv)
	certFile, keyFile, _ := writeClientIdentity(t)
	cs := func(addr string) config.SignerBackendConfig {
		return config.SignerBackendConfig{
			Name: "cs", Type: "confidential-space", Address: addr,
		}
	}

	reach := func(c config.SignerBackendConfig) error {
		t.Helper()
		e, err := newAttestedEnclave(c)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		_, err = e.Inventory(ctx, make([]byte, 32))
		return err
	}

	withCA := cs(tlsSrv.URL)
	withCA.TLSCAFile = ca
	if err := reach(withCA); err != nil {
		t.Fatalf("https with tls_ca_file and no client certificate: %v", err)
	}
	withCert := withCA
	withCert.TLSClientCertFile, withCert.TLSClientKeyFile = certFile, keyFile
	if err := reach(withCert); err != nil {
		t.Fatalf("https with tls_ca_file and client certificate: %v", err)
	}
	// Without tls_ca_file the system roots verify the server, and they do not
	// trust the test server's certificate.
	err := reach(cs(tlsSrv.URL))
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("https with system roots: got %v, want unknown authority", err)
	}

	if _, err := newAttestedEnclave(cs(plainSrv.URL)); err == nil ||
		!strings.Contains(err.Error(), "plaintext: true") {
		t.Fatalf("plain http by default: got %v, want refusal", err)
	}
	plain := cs(plainSrv.URL)
	plain.Plaintext = true
	if err := reach(plain); err != nil {
		t.Fatalf("plain http with plaintext: %v", err)
	}
	if got := calls(); got != 3 {
		t.Fatalf("inventory requests = %d, want 3", got)
	}
}

func TestConfidentialSpaceJWKSPlaintext(t *testing.T) {
	t.Parallel()
	c := config.SignerBackendConfig{
		Name: "cs", Type: "confidential-space", Address: "https://127.0.0.1:1",
		Audience:    "a",
		ImageDigest: "sha256:" + strings.Repeat("a", 64),
		JWKSURL:     "http://idp.invalid/jwks",
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := buildConfidentialSpaceBackend(ctx, c); !errors.Is(
		err,
		errJWKSURLPolicy,
	) {
		t.Fatalf("default: got %v, want errJWKSURLPolicy", err)
	}
	c.JWKSPlaintext = true
	if _, err := buildConfidentialSpaceBackend(ctx, c); err == nil ||
		errors.Is(err, errJWKSURLPolicy) {
		t.Fatalf("jwks_plaintext: got %v, want a later error", err)
	}

	redirect := httptest.NewServer(
		http.RedirectHandler("http://idp.invalid/jwks", http.StatusFound),
	)
	t.Cleanup(redirect.Close)
	if _, err := fetchJWKS(ctx, redirect.URL, true); err == nil ||
		errors.Is(err, errJWKSURLPolicy) {
		t.Fatalf(
			"redirect with jwks_plaintext: got %v, want a fetch error",
			err,
		)
	}
}

func TestBuildVaultBackendPlaintext(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "test-token")
	c := config.SignerBackendConfig{
		Name: "vault", Type: "vault", Address: "http://vault.invalid:8200",
		Keys: []config.SignerBackendKeyConfig{{Name: "k", Type: "payment"}},
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	_, err := buildVaultBackend(ctx, c)
	if err == nil || !strings.Contains(err.Error(), "plaintext: true") {
		t.Fatalf("default: got %v, want the https refusal", err)
	}
	if neutralWording.MatchString(err.Error()) {
		t.Errorf("error wording: %q", err)
	}
	c.Plaintext = true
	_, err = buildVaultBackend(ctx, c)
	if err == nil || strings.Contains(err.Error(), "plaintext: true") {
		t.Fatalf("plaintext: got %v, want a connection error", err)
	}
}

func TestDescribeBackendTransport(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		cfg  config.SignerBackendConfig
		want string
	}{
		{config.SignerBackendConfig{Type: "software"}, ""},
		{config.SignerBackendConfig{Type: "vault", Address: "https://v:8200"}, "https"},
		{config.SignerBackendConfig{Type: "vault", Address: "http://v:8200"}, "plain http"},
		{
			config.SignerBackendConfig{Type: "confidential-space", Address: "https://w"},
			"https, system roots; jwks: https",
		},
		{
			config.SignerBackendConfig{
				Type: "confidential-space", Address: "https://w",
				TLSCAFile: "/ca", TLSClientCertFile: "/c", TLSClientKeyFile: "/k",
				JWKSURL: "http://idp/jwks",
			},
			"https, tls_ca_file, client certificate; jwks: plain http",
		},
		{
			config.SignerBackendConfig{Type: "armory", Address: "http://d"},
			"plain http; host key: none",
		},
		{
			config.SignerBackendConfig{
				Type: "armory", Address: "https://d", TLSCAFile: "/ca",
				HostKeyFile: "/h",
			},
			"https, tls_ca_file; host key: signed requests",
		},
		{
			config.SignerBackendConfig{
				Type: "nitro", Address: "unix:///run/e.sock", HostKeyFile: "/h",
			},
			"unix socket; host key: signed requests",
		},
	} {
		if got := DescribeBackendTransport(tc.cfg); got != tc.want {
			t.Errorf("%+v: got %q, want %q", tc.cfg, got, tc.want)
		}
		if neutralWording.MatchString(DescribeBackendTransport(tc.cfg)) {
			t.Errorf("wording: %q", DescribeBackendTransport(tc.cfg))
		}
	}
}

// The software backend default keeps its refusal; the message and error name
// the option without judging the deployment.
func TestCheckFileBackendGuardWording(t *testing.T) {
	t.Parallel()
	msg, err := CheckFileBackendGuard(
		[]config.SignerBackendConfig{softwareBackend()},
		"0.0.0.0",
		false,
	)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"signer.allow_insecure_file_backend: true",
		) {
		t.Fatalf("got %v, want a refusal naming the option", err)
	}
	// The option's key name is kept for compatibility; only the surrounding
	// wording is checked.
	rest := strings.ReplaceAll(
		err.Error(),
		"signer.allow_insecure_file_backend",
		"",
	)
	for _, s := range []string{msg, rest} {
		if neutralWording.MatchString(s) {
			t.Errorf("wording: %q", s)
		}
	}
	if !strings.HasPrefix(msg, "signer key custody: ") {
		t.Errorf("message = %q", msg)
	}
}
