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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfidentialSpaceTLSConfigRequiresVerifiedClients(t *testing.T) {
	t.Parallel()
	certFile, keyFile := writeConfidentialSpaceTLSFixture(t)

	config, err := confidentialSpaceTLSConfig(certFile, keyFile, certFile)
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 ||
		config.ClientAuth != tls.RequireAndVerifyClientCert ||
		config.ClientCAs == nil || len(config.Certificates) != 1 {
		t.Fatalf("TLS config does not require TLS 1.3 mTLS: %+v", config)
	}
}

func TestConfidentialSpaceStorageModes(t *testing.T) {
	t.Parallel()
	const secret = "projects/p/secrets/s"
	tests := []struct {
		name                        string
		secret, file, bucket, name2 string
		wantErr                     string
	}{
		{name: "state secret", secret: secret},
		{
			name: "gcs", file: "/state/w", bucket: "b", name2: "o",
		},
		{
			name:    "neither",
			wantErr: "one of --state-secret or --wrapped-key-file",
		},
		{
			name: "secret with file", secret: secret, file: "/state/w",
			wantErr: "--state-secret excludes --wrapped-key-file",
		},
		{
			name: "secret with bucket", secret: secret, bucket: "b",
			wantErr: "--state-secret excludes --counter-bucket",
		},
		{
			name: "secret with object", secret: secret, name2: "o",
			wantErr: "--state-secret excludes --counter-object",
		},
		{
			name: "gcs without file", bucket: "b", name2: "o",
			wantErr: "--wrapped-key-file required without --state-secret",
		},
		{
			name: "gcs without bucket", file: "/state/w", name2: "o",
			wantErr: "--counter-bucket required without --state-secret",
		},
		{
			name: "gcs without object", file: "/state/w", bucket: "b",
			wantErr: "--counter-object required without --state-secret",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateConfidentialSpaceStorage(
				tt.secret, tt.file, tt.bucket, tt.name2,
			)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil ||
				!strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("error %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// TestConfidentialSpaceCommandChecksStorageFlags runs the command itself: the
// storage mode is validated before any file or service is touched, and the
// three object flags are no longer required by cobra.
func TestConfidentialSpaceCommandChecksStorageFlags(t *testing.T) {
	t.Parallel()
	base := []string{
		"--audience", "a",
		"--kms-key", "k",
		"--wif-credentials", "/nonexistent/wif.json",
		"--tls-cert-file", "/nonexistent/cert.pem",
		"--tls-key-file", "/nonexistent/key.pem",
		"--client-ca-file", "/nonexistent/ca.pem",
	}
	tests := []struct {
		name    string
		extra   []string
		wantErr string
	}{
		{
			"no storage flag", nil,
			"one of --state-secret or --wrapped-key-file",
		},
		{
			"both modes",
			[]string{
				"--state-secret",
				"projects/p/secrets/s",
				"--counter-bucket",
				"b",
			},
			"--state-secret excludes --counter-bucket",
		},
		{
			"gcs missing the object",
			[]string{"--wrapped-key-file", "/w", "--counter-bucket", "b"},
			"--counter-object required without --state-secret",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cmd := confidentialSpaceCommand()
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(append(append([]string{}, base...), tt.extra...))
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %v, want %q", err, tt.wantErr)
			}
		})
	}
	// cobra requires none of the three object flags, so a state secret alone
	// is a complete command line. Execute is not used: it would configure the
	// process-wide logger.
	cmd := confidentialSpaceCommand()
	if err := cmd.ParseFlags(append(
		append([]string{}, base...), "--state-secret", "projects/p/secrets/s",
	)); err != nil {
		t.Fatal(err)
	}
	if err := cmd.ValidateRequiredFlags(); err != nil {
		t.Fatalf("a state secret alone is not accepted: %v", err)
	}
}

func TestConfidentialSpaceTLSSources(t *testing.T) {
	t.Parallel()
	const secret = "projects/p/secrets/tls"
	tests := []struct {
		name              string
		secret, cert, key string
		wantErr           string
	}{
		{name: "secret", secret: secret},
		{name: "files", cert: "/c", key: "/k"},
		{
			name: "both sources", secret: secret, cert: "/c", key: "/k",
			wantErr: "--tls-secret excludes --tls-cert-file",
		},
		{
			name: "secret with key file", secret: secret, key: "/k",
			wantErr: "--tls-secret excludes --tls-key-file",
		},
		{
			name:    "neither",
			wantErr: "one of --tls-secret or --tls-cert-file with --tls-key-file is required",
		},
		{
			name: "certificate without key", cert: "/c",
			wantErr: "--tls-key-file required without --tls-secret",
		},
		{
			name: "key without certificate", key: "/k",
			wantErr: "--tls-cert-file required without --tls-secret",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateConfidentialSpaceTLS(tt.secret, tt.cert, tt.key)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" &&
				(err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("error %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// TestConfidentialSpaceCommandChecksTLSFlags runs the command: the TLS source
// is validated before any file or service is touched.
func TestConfidentialSpaceCommandChecksTLSFlags(t *testing.T) {
	t.Parallel()
	base := []string{
		"--audience", "a",
		"--kms-key", "k",
		"--wif-credentials", "/nonexistent/wif.json",
		"--client-ca-file", "/nonexistent/ca.pem",
		"--state-secret", "projects/p/secrets/s",
	}
	tests := []struct {
		name    string
		extra   []string
		wantErr string
	}{
		{
			"both sources",
			[]string{
				"--tls-secret", "projects/p/secrets/tls",
				"--tls-cert-file", "/c", "--tls-key-file", "/k",
			},
			"--tls-secret excludes --tls-cert-file",
		},
		{"neither", nil, "one of --tls-secret or --tls-cert-file"},
		{
			"partial file pair", []string{"--tls-cert-file", "/c"},
			"--tls-key-file required without --tls-secret",
		},
		{
			"malformed secret", []string{"--tls-secret", "tls"},
			"must be projects/<project>/secrets/<secret>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cmd := confidentialSpaceCommand()
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(append(append([]string{}, base...), tt.extra...))
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %v, want %q", err, tt.wantErr)
			}
		})
	}
	// Neither file flag is required by cobra, so a TLS secret alone is a
	// complete command line. Execute is not used: it would configure the
	// process-wide logger.
	cmd := confidentialSpaceCommand()
	if err := cmd.ParseFlags(append(
		append([]string{}, base...), "--tls-secret", "projects/p/secrets/tls",
	)); err != nil {
		t.Fatal(err)
	}
	if err := cmd.ValidateRequiredFlags(); err != nil {
		t.Fatalf("a TLS secret alone is not accepted: %v", err)
	}
}

func TestConfidentialSpaceTLSConfigForCertificateRequiresVerifiedClients(
	t *testing.T,
) {
	t.Parallel()
	certFile, keyFile := writeConfidentialSpaceTLSFixture(t)
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	config, err := confidentialSpaceTLSConfigFor(certificate, certFile)
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 ||
		config.ClientAuth != tls.RequireAndVerifyClientCert ||
		config.ClientCAs == nil || len(config.Certificates) != 1 {
		t.Fatalf("TLS config does not require TLS 1.3 mTLS: %+v", config)
	}
	if _, err := confidentialSpaceTLSConfigFor(
		certificate, "/nonexistent/ca.pem",
	); err == nil {
		t.Fatal("a missing client CA was accepted")
	}
}

func writeConfidentialSpaceTLSFixture(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "workload-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
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
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: der,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{
		Type: "EC PRIVATE KEY", Bytes: keyDER,
	}), 0o600); err != nil {
		t.Fatal(err)
	}

	return certFile, keyFile
}
