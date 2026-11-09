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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"
)

// attestedTLSConfigs returns mTLS server and client configurations that trust
// one throwaway CA, matching the attested listener's TLS policy.
func attestedTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	leaf := func(serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "leaf"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	server := &tls.Config{
		Certificates: []tls.Certificate{leaf(2, x509.ExtKeyUsageServerAuth)},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	client := &tls.Config{
		Certificates: []tls.Certificate{leaf(3, x509.ExtKeyUsageClientAuth)},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}
	return server, client
}

// TestAttestedServiceServesPeerDuringHandshakeFlood covers a remote client
// that opens TCP connections and never completes the TLS handshake. Those
// connections must not take the slots an authenticated block producer needs.
func TestAttestedServiceServesPeerDuringHandshakeFlood(t *testing.T) {
	// The flood needs a second loopback source address. Linux routes all of
	// 127.0.0.0/8 to lo, but macOS assigns only 127.0.0.1 to lo0 by default.
	probe, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("127.0.0.2 is not a usable loopback address here: %v", err)
	}
	_ = probe.Close()
	a, _, _ := newHeaderAgent(t)
	serverCfg, clientCfg := attestedTLSConfigs(t)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := raw.Addr().String()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- a.ServeAttestedService(
			ctx,
			tls.NewListener(raw, serverCfg),
			AttestedServiceConfig{Provider: "nitro", Attester: bindingAttester{}},
		)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("ServeAttestedService did not stop")
		}
	})

	flood := net.Dialer{
		Timeout:   2 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)},
	}
	for range maxTrackedConns {
		c, err := flood.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("flood dial: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{
			Timeout:   3 * time.Second,
			LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
		},
		"tcp",
		addr,
		clientCfg,
	)
	if err != nil {
		t.Fatalf("authenticated peer refused during handshake flood: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	var hello Hello
	if err := readFrame(conn, &hello); err != nil {
		t.Fatalf("authenticated peer got no hello during handshake flood: %v", err)
	}
	if hello.Protocol != AttestedProtocolID {
		t.Fatalf("hello = %+v", hello)
	}
}

func TestHandshakeGateBudgets(t *testing.T) {
	tcp := func(ip string) net.Addr {
		return &net.TCPAddr{IP: net.ParseIP(ip), Port: 1}
	}
	g := newHandshakeGate()
	var held []string
	for range maxPendingHandshakesPerHost {
		host, ok := g.acquire(tcp("192.0.2.1"))
		if !ok {
			t.Fatal("per-host budget refused too early")
		}
		held = append(held, host)
	}
	if _, ok := g.acquire(tcp("192.0.2.1")); ok {
		t.Fatal("per-host budget exceeded")
	}
	if _, ok := g.acquire(tcp("2001:db8::1")); !ok {
		t.Fatal("another host refused while one host is at its budget")
	}
	for i := 2; i <= maxPendingHandshakesPerHost; i++ {
		if _, ok := g.acquire(tcp(fmt.Sprintf("2001:db8::%d", i))); !ok {
			t.Fatal("IPv6 /64 refused before its budget")
		}
	}
	if _, ok := g.acquire(tcp("2001:db8::ffff")); ok {
		t.Fatal("addresses in one IPv6 /64 escaped the per-host budget")
	}
	g.release(held[0])
	if _, ok := g.acquire(tcp("192.0.2.1")); !ok {
		t.Fatal("released slot was not reusable")
	}

	g = newHandshakeGate()
	pipe, other := net.Pipe()
	defer pipe.Close()
	defer other.Close()
	for i := range maxPendingHandshakes {
		if _, ok := g.acquire(pipe.RemoteAddr()); !ok {
			t.Fatalf("non-IP peer %d refused below the global budget", i)
		}
	}
	if _, ok := g.acquire(tcp("192.0.2.9")); ok {
		t.Fatal("global handshake budget exceeded")
	}
	g.release("")
	if _, ok := g.acquire(tcp("192.0.2.9")); !ok {
		t.Fatal("released global slot was not reusable")
	}
}
