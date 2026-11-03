// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package nitro

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
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const testRPCServerName = "nitro-enclave.test"

type rpcTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

type rpcTestTLSFiles struct {
	ca         string
	serverCert string
	serverKey  string
	clientCert string
	clientKey  string
}

func newRPCTestCA(t *testing.T) rpcTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nitro-rpc-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return rpcTestCA{
		cert: cert,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func writeRPCTestLeaf(t *testing.T, dir, name string, ca rpcTestCA, usage x509.ExtKeyUsage, dnsName string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	if dnsName != "" {
		template.DNSNames = []string{dnsName}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	certPath := filepath.Join(dir, name+".pem")
	keyPath := filepath.Join(dir, name+"-key.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

func newRPCTestTLSFiles(t *testing.T) rpcTestTLSFiles {
	t.Helper()
	dir := t.TempDir()
	ca := newRPCTestCA(t)
	caPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, ca.pem, 0o600))
	serverCert, serverKey := writeRPCTestLeaf(t, dir, "server", ca, x509.ExtKeyUsageServerAuth, testRPCServerName)
	clientCert, clientKey := writeRPCTestLeaf(t, dir, "client", ca, x509.ExtKeyUsageClientAuth, "")
	return rpcTestTLSFiles{
		ca: caPath, serverCert: serverCert, serverKey: serverKey,
		clientCert: clientCert, clientKey: clientKey,
	}
}

func startTestRPCServer(t *testing.T, service *Service, files rpcTestTLSFiles) *bufconn.Listener {
	t.Helper()
	options, err := RPCServerOptions(RPCServerTLSConfig{
		CertificateFile: files.serverCert,
		KeyFile:         files.serverKey,
		ClientCAFile:    files.ca,
	})
	require.NoError(t, err)
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(options...)
	RegisterRPCServer(server, service)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return listener
}

func testRPCDialer(listener *bufconn.Listener) grpc.DialOption {
	return grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	})
}

func authorizedTestRPCClient(t *testing.T, listener *bufconn.Listener, files rpcTestTLSFiles) (*rpcClient, *grpc.ClientConn) {
	t.Helper()
	options, err := RPCDialOptions(RPCClientTLSConfig{
		CertificateFile: files.clientCert,
		KeyFile:         files.clientKey,
		RootCAFile:      files.ca,
		ServerName:      testRPCServerName,
	})
	require.NoError(t, err)
	options = append(options, testRPCDialer(listener))
	conn, err := grpc.NewClient("passthrough:///test", options...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return NewRPCClient(conn), conn
}

func unauthorizedTestRPCClient(t *testing.T, listener *bufconn.Listener, files rpcTestTLSFiles) *rpcClient {
	t.Helper()
	roots, err := loadRPCCertPool(files.ca)
	require.NoError(t, err)
	options := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    roots,
			ServerName: testRPCServerName,
		})),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(nitroCodec)),
		testRPCDialer(listener),
	}
	conn, err := grpc.NewClient("passthrough:///unauthorized", options...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return NewRPCClient(conn)
}

func testRPCClient(t *testing.T, service *Service) (*rpcClient, *grpc.ClientConn) {
	t.Helper()
	files := newRPCTestTLSFiles(t)
	return authorizedTestRPCClient(t, startTestRPCServer(t, service, files), files)
}

func TestRPCRejectsGroupReadablePrivateKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file modes do not express Unix group access")
	}
	files := newRPCTestTLSFiles(t)
	require.NoError(t, os.Chmod(files.clientKey, 0o640))
	_, err := RPCDialOptions(RPCClientTLSConfig{
		CertificateFile: files.clientCert,
		KeyFile:         files.clientKey,
		RootCAFile:      files.ca,
		ServerName:      testRPCServerName,
	})
	require.ErrorContains(t, err, "grants group or other access")
}

func TestRPCRejectsUntrustedClientCertificate(t *testing.T) {
	service, _, _ := newTestService(t, testEvidence(t, 10))
	files := newRPCTestTLSFiles(t)
	listener := startTestRPCServer(t, service, files)
	rogueCA := newRPCTestCA(t)
	rogueCert, rogueKey := writeRPCTestLeaf(
		t,
		t.TempDir(),
		"rogue-client",
		rogueCA,
		x509.ExtKeyUsageClientAuth,
		"",
	)
	options, err := RPCDialOptions(RPCClientTLSConfig{
		CertificateFile: rogueCert,
		KeyFile:         rogueKey,
		RootCAFile:      files.ca,
		ServerName:      testRPCServerName,
	})
	require.NoError(t, err)
	options = append(options, testRPCDialer(listener))
	conn, err := grpc.NewClient("passthrough:///untrusted-client", options...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = NewRPCClient(conn).Provision(ctx, testProvisionRequest())
	requireRPCDenied(t, "provision with untrusted client certificate", err)
}

func testProvisionRequest() ProvisionRequest {
	request := ProvisionRequest{
		Version: Protocol, Region: "us-east-1", Credentials: testCredentials,
		KMSKeyID: testKMSKey, Role: backend.KeyTypePool,
	}
	request.Authorization = ed25519.Sign(testProvisionAuthority, ProvisionAuthorizationBinding(request))
	return request
}

func testSignRequest(publicKey ed25519.PublicKey) backend.AttestedRequest {
	payload := make([]byte, 48)
	binary.BigEndian.PutUint64(payload[32:40], 1)
	return backend.AttestedRequest{
		Version: backend.AttestedProtocol, Purpose: backend.PurposeOpCert,
		KeyHash: backend.HashPublicKey(publicKey).String(), Role: backend.KeyTypePool,
		Nonce: bytes.Repeat([]byte{9}, requestNonceSize), Payload: payload,
	}
}

func requireRPCDenied(t *testing.T, operation string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("unauthorized %s reached the enclave service", operation)
	}
}

func TestRPCRejectsUnauthorizedCallsBeforeStateMutation(t *testing.T) {
	service, _, _ := newTestService(t, testEvidence(t, 8))
	files := newRPCTestTLSFiles(t)
	listener := startTestRPCServer(t, service, files)
	authorized, _ := authorizedTestRPCClient(t, listener, files)
	unauthorized := unauthorizedTestRPCClient(t, listener, files)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := unauthorized.Provision(ctx, testProvisionRequest())
	requireRPCDenied(t, "provision", err)
	_, err = authorized.Inventory(ctx, bytes.Repeat([]byte{1}, requestNonceSize))
	require.ErrorContains(t, err, ErrNotLoaded.Error())

	provisioned, err := authorized.Provision(ctx, testProvisionRequest())
	require.NoError(t, err)
	_, err = unauthorized.Inventory(ctx, bytes.Repeat([]byte{2}, requestNonceSize))
	requireRPCDenied(t, "inventory", err)

	malformedProvision := testProvisionRequest()
	malformedProvision.Version = "invalid"
	_, err = unauthorized.Provision(ctx, malformedProvision)
	requireRPCDenied(t, "malformed provision", err)
	_, err = authorized.Inventory(ctx, bytes.Repeat([]byte{3}, requestNonceSize))
	require.NoError(t, err, "unauthorized provision changed loaded state")

	_, err = unauthorized.Reload(ctx, ReloadRequest{Version: "invalid"})
	requireRPCDenied(t, "reload", err)
	_, err = authorized.Inventory(ctx, bytes.Repeat([]byte{4}, requestNonceSize))
	require.NoError(t, err, "unauthorized reload changed loaded state")

	request := testSignRequest(provisioned.Envelope.PublicKey)
	_, err = unauthorized.Sign(ctx, request)
	requireRPCDenied(t, "sign", err)
	signed, err := authorized.Sign(ctx, request)
	require.NoError(t, err, "unauthorized sign consumed nonce or counter state")
	require.True(t, ed25519.Verify(provisioned.Envelope.PublicKey, request.Payload, signed.Signature))
}

func TestRPCAuthorizedProxyRoundTrip(t *testing.T) {
	service, _, _ := newTestService(t, testEvidence(t, 9))
	client, _ := testRPCClient(t, service)
	provisioned, err := client.Provision(context.Background(), testProvisionRequest())
	require.NoError(t, err)
	handler, err := NewProxyHandler(client)
	require.NoError(t, err)

	inventoryBody, err := json.Marshal(map[string][]byte{"nonce": bytes.Repeat([]byte{5}, requestNonceSize)})
	require.NoError(t, err)
	inventoryRequest := httptest.NewRequest(http.MethodPost, "/v1/inventory", bytes.NewReader(inventoryBody))
	inventoryResponse := httptest.NewRecorder()
	handler.ServeHTTP(inventoryResponse, inventoryRequest)
	require.Equal(t, http.StatusOK, inventoryResponse.Code)

	signRequest := testSignRequest(provisioned.Envelope.PublicKey)
	signBody, err := json.Marshal(signRequest)
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(signBody))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)
	var signed backend.AttestedResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &signed))
	require.True(t, ed25519.Verify(provisioned.Envelope.PublicKey, signRequest.Payload, signed.Signature))
}

func TestRPCServerBoundsReceivedMessageSize(t *testing.T) {
	service, kms, _ := newTestService(t, testEvidence(t, 11))
	client, _ := testRPCClient(t, service)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	provisioned, err := client.Provision(ctx, testProvisionRequest())
	require.NoError(t, err)

	atLimit := provisioned.Envelope
	atLimit.EncryptedDataKey = bytes.Repeat([]byte{1}, maxEnvelopeSize)
	atLimit.Ciphertext = bytes.Repeat([]byte{2}, maxEnvelopeSize)
	_, err = client.Reload(ctx, ReloadRequest{
		Version: Protocol, Region: "us-east-1", Credentials: testCredentials, Envelope: atLimit,
	})
	require.NotEqual(t, codes.ResourceExhausted, status.Code(err), "largest valid envelope was refused by the transport")
	require.ErrorContains(t, err, "KMS decrypt data key", "largest valid envelope did not reach KMS")

	oversized := provisioned.Envelope
	oversized.Ciphertext = make([]byte, 1<<20)
	kms.calls = 0
	_, err = client.Reload(ctx, ReloadRequest{
		Version: Protocol, Region: "us-east-1", Credentials: testCredentials, Envelope: oversized,
	})
	require.Equal(t, codes.ResourceExhausted, status.Code(err), "oversized message was decoded: %v", err)
	require.Zero(t, kms.calls)
}
