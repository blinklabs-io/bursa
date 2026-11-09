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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"os"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/kesagent"
)

func TestAttestedListenerPlaintextRefusesTLSFiles(t *testing.T) {
	t.Parallel()
	certFile, keyFile := writeConfidentialSpaceTLSFixture(t)
	cases := map[string]config.KESAgentConfig{
		"cert": {AttestedTLSCertFile: certFile},
		"key":  {AttestedTLSKeyFile: keyFile},
		"ca":   {AttestedClientCAFile: certFile},
	}
	for name, kc := range cases {
		kc.AttestedListenAddress = "127.0.0.1:0"
		kc.AttestedPlaintext = true
		ln, _, err := attestedListener(kc)
		if err == nil {
			_ = ln.Close()
			t.Fatalf("%s: plaintext with a TLS file was accepted", name)
		}
	}
}

func TestAttestedListenerPlaintextServesPlainTCP(t *testing.T) {
	t.Parallel()
	ln, _, err := attestedListener(config.KESAgentConfig{
		AttestedListenAddress: "127.0.0.1:0",
		AttestedPlaintext:     true,
	})
	if err != nil {
		t.Fatalf("attestedListener: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	select {
	case c := <-accepted:
		defer c.Close()
		if _, isTLS := c.(*tls.Conn); isTLS {
			t.Fatal("plaintext listener accepted a TLS connection type")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no connection accepted")
	}
}

func TestAttestedListenerTLSRequiresCertAndKey(t *testing.T) {
	t.Parallel()
	certFile, _ := writeConfidentialSpaceTLSFixture(t)
	ln, _, err := attestedListener(config.KESAgentConfig{
		AttestedListenAddress: "127.0.0.1:0",
		AttestedTLSCertFile:   certFile,
	})
	if err == nil {
		_ = ln.Close()
		t.Fatal("TLS listener without a key was accepted")
	}
}

// acceptHandshake dials the listener without a client certificate and returns
// the server-side handshake error and peer certificate count.
func acceptHandshake(t *testing.T, ln net.Listener) (error, int) {
	t.Helper()
	type result struct {
		err   error
		peers int
	}
	out := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			out <- result{err: err}
			return
		}
		defer c.Close()
		tc := c.(*tls.Conn)
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		err = tc.Handshake()
		out <- result{err: err, peers: len(tc.ConnectionState().PeerCertificates)}
	}()
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second}, "tcp", ln.Addr().String(),
		&tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, //nolint:gosec // throwaway test certificate
		},
	)
	if err == nil {
		defer conn.Close()
	}
	select {
	case r := <-out:
		return r.err, r.peers
	case <-time.After(10 * time.Second):
		t.Fatal("server handshake did not finish")
		return nil, 0
	}
}

func TestAttestedListenerTLSWithoutClientCAAcceptsNoCert(t *testing.T) {
	t.Parallel()
	certFile, keyFile := writeConfidentialSpaceTLSFixture(t)
	ln, _, err := attestedListener(config.KESAgentConfig{
		AttestedListenAddress: "127.0.0.1:0",
		AttestedTLSCertFile:   certFile,
		AttestedTLSKeyFile:    keyFile,
	})
	if err != nil {
		t.Fatalf("TLS listener without a client CA refused: %v", err)
	}
	defer ln.Close()
	if err, peers := acceptHandshake(t, ln); err != nil || peers != 0 {
		t.Fatalf("handshake without client cert: err=%v peers=%d", err, peers)
	}
}

func TestAttestedListenerTLSWithClientCARefusesNoCert(t *testing.T) {
	t.Parallel()
	certFile, keyFile := writeConfidentialSpaceTLSFixture(t)
	ln, _, err := attestedListener(config.KESAgentConfig{
		AttestedListenAddress: "127.0.0.1:0",
		AttestedTLSCertFile:   certFile,
		AttestedTLSKeyFile:    keyFile,
		AttestedClientCAFile:  certFile,
	})
	if err != nil {
		t.Fatalf("attestedListener: %v", err)
	}
	defer ln.Close()
	if err, _ := acceptHandshake(t, ln); err == nil {
		t.Fatal("handshake without a client cert succeeded with a client CA set")
	}
}

// TestAttestedListenerPinMatchesServedCert checks that the reported pin is the
// SHA-256 SPKI of the certificate the listener serves, even when the
// certificate file changes after the listener has loaded it.
func TestAttestedListenerPinMatchesServedCert(t *testing.T) {
	t.Parallel()
	certFile, keyFile := writeConfidentialSpaceTLSFixture(t)
	ln, pin, err := attestedListener(config.KESAgentConfig{
		AttestedListenAddress: "127.0.0.1:0",
		AttestedTLSCertFile:   certFile,
		AttestedTLSKeyFile:    keyFile,
	})
	if err != nil {
		t.Fatalf("attestedListener: %v", err)
	}
	defer ln.Close()
	otherCert, _ := writeConfidentialSpaceTLSFixture(t)
	other, err := os.ReadFile(otherCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, other, 0o600); err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.(*tls.Conn).Handshake()
	}()
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second}, "tcp", ln.Addr().String(),
		&tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, //nolint:gosec // throwaway test certificate
		},
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	served := conn.ConnectionState().PeerCertificates[0]
	der, err := x509.MarshalPKIXPublicKey(served.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	if want := hex.EncodeToString(sum[:]); pin != want {
		t.Fatalf("pin = %q, want served certificate SPKI %q", pin, want)
	}
}

func TestAttestedListenerPlaintextHasNoPin(t *testing.T) {
	t.Parallel()
	ln, pin, err := attestedListener(config.KESAgentConfig{
		AttestedListenAddress: "127.0.0.1:0",
		AttestedPlaintext:     true,
	})
	if err != nil {
		t.Fatalf("attestedListener: %v", err)
	}
	defer ln.Close()
	if pin != "" {
		t.Fatalf("plaintext listener reported pin %q", pin)
	}
}

func TestAttestedServiceConfigTransport(t *testing.T) {
	t.Parallel()
	base := config.KESAgentConfig{AttestationProvider: kesagent.NoEvidenceProvider}
	cases := []struct {
		name             string
		plaintext        bool
		ca               string
		wantPlaintext    bool
		wantCertOptional bool
	}{
		{"tls with ca", false, "ca.pem", false, false},
		{"tls without ca", false, "", false, true},
		{"plaintext", true, "", true, false},
	}
	for _, tc := range cases {
		kc := base
		kc.AttestedPlaintext = tc.plaintext
		kc.AttestedClientCAFile = tc.ca
		cfg, err := attestedServiceConfig(kc)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if cfg.Plaintext != tc.wantPlaintext ||
			cfg.ClientCertOptional != tc.wantCertOptional {
			t.Fatalf("%s: plaintext=%v optional=%v", tc.name, cfg.Plaintext, cfg.ClientCertOptional)
		}
	}
}
