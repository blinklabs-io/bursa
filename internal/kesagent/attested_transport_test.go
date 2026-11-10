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

package kesagent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"
	"time"
)

// attestAndSign runs the attested exchange on conn with the none provider and
// then one sign request.
func attestAndSign(
	t *testing.T,
	conn net.Conn,
	cold coldKeyPair,
	spec headerSpec,
) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var hello Hello
	if err := readFrame(conn, &hello); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if hello.Protocol != AttestedProtocolID {
		t.Fatalf("hello protocol = %q", hello.Protocol)
	}
	req, err := NewAttestationRequest()
	if err != nil {
		t.Fatalf("NewAttestationRequest: %v", err)
	}
	if err := writeFrame(conn, req); err != nil {
		t.Fatalf("write challenge: %v", err)
	}
	var resp AttestationResponse
	if err := readFrame(conn, &resp); err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	if resp.Error != "" || resp.Provider != NoEvidenceProvider {
		t.Fatalf("attestation = %q provider %q", resp.Error, resp.Provider)
	}
	if err := VerifyAttestation(
		t.Context(), req, resp, NoEvidenceProvider, cold.pub, resp.OpCert, nil,
	); err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}
	if err := writeFrame(conn, SignRequest{
		Type: "sign_request", Period: 5, Message: spec.encode(t),
	}); err != nil {
		t.Fatalf("write sign request: %v", err)
	}
	var signed SignResponse
	if err := readFrame(conn, &signed); err != nil {
		t.Fatalf("read sign response: %v", err)
	}
	if signed.Error != "" || len(signed.Signature) == 0 {
		t.Fatalf("signing refused: %q", signed.Error)
	}
}

func serveAttested(
	t *testing.T,
	a *Agent,
	ln net.Listener,
	cfg AttestedServiceConfig,
) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.ServeAttestedService(ctx, ln, cfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("ServeAttestedService did not stop")
		}
	})
}

func TestAttestedPlaintextRoundTrip(t *testing.T) {
	t.Parallel()
	a, cold, spec := newHeaderAgent(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveAttested(t, a, ln, AttestedServiceConfig{
		Provider:  NoEvidenceProvider,
		Plaintext: true,
	})
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	attestAndSign(t, conn, cold, spec)
}

// A non-plaintext service still refuses a plain TCP connection.
func TestAttestedNonPlaintextRefusesPlainTCP(t *testing.T) {
	t.Parallel()
	a, _, _ := newHeaderAgent(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveAttested(t, a, ln, AttestedServiceConfig{Provider: NoEvidenceProvider})
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var hello Hello
	if err := readFrame(conn, &hello); err == nil {
		t.Fatal("plain TCP connection received a hello without plaintext mode")
	}
}

// tlsServerSetup starts the attested service over TLS. With caPool nil the
// listener requests no client certificate.
func tlsServerSetup(
	t *testing.T,
	optional bool,
	withCA bool,
) (*Agent, coldKeyPair, headerSpec, string, tls.Certificate) {
	t.Helper()
	a, cold, spec := newHeaderAgent(t)
	ca, caKey, _ := tlsTestCert(t, nil, nil, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "test ca"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	})
	_, _, serverCert := tlsTestCert(t, ca, caKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "server"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	_, _, clientCert := tlsTestCert(t, ca, caKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "client"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	serverCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
	}
	if withCA {
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		serverCfg.ClientCAs = pool
		serverCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveAttested(t, a, ln, AttestedServiceConfig{
		Provider:           NoEvidenceProvider,
		ClientCertOptional: optional,
	})
	return a, cold, spec, ln.Addr().String(), clientCert
}

func dialNoClientCert(t *testing.T, addr string) (*tls.Conn, error) {
	t.Helper()
	return tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
		&tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, //nolint:gosec // test server uses a throwaway CA
		},
	)
}

func TestAttestedTLSWithoutClientCAAcceptsNoClientCert(t *testing.T) {
	t.Parallel()
	_, cold, spec, addr, _ := tlsServerSetup(t, true, false)
	conn, err := dialNoClientCert(t, addr)
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	attestAndSign(t, conn, cold, spec)
}

func TestAttestedTLSWithClientCARefusesNoClientCert(t *testing.T) {
	t.Parallel()
	_, _, _, addr, _ := tlsServerSetup(t, false, true)
	conn, err := dialNoClientCert(t, addr)
	if err != nil {
		// TLS 1.3 clients may see the refusal at dial time.
		return
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var hello Hello
	if err := readFrame(conn, &hello); err == nil {
		t.Fatal("client without a certificate received a hello")
	}
}

// Without a client CA the agent must not demand peer certificates, but a
// service that was not told so still requires them.
func TestAttestedTLSDefaultRequiresVerifiedClientCert(t *testing.T) {
	t.Parallel()
	_, _, _, addr, _ := tlsServerSetup(t, false, false)
	conn, err := dialNoClientCert(t, addr)
	if err != nil {
		return
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var hello Hello
	if err := readFrame(conn, &hello); err == nil {
		t.Fatal("anonymous client served without ClientCertOptional")
	}
}
