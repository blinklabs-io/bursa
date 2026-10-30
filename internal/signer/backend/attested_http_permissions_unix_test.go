//go:build unix

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

package backend

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa"
)

func TestNewMTLSHTTPEnclaveRejectsPermissiveKey(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o644} {
		t.Run(mode.String(), func(t *testing.T) {
			certFile, keyFile := writeHTTPEnclaveTLSFixture(t)
			if err := os.Chmod(keyFile, mode); err != nil {
				t.Fatal(err)
			}
			_, err := NewMTLSHTTPEnclave(
				"https://workload.example",
				certFile,
				certFile,
				keyFile,
			)
			if !errors.Is(err, bursa.ErrInsecureFileMode) {
				t.Fatalf("NewMTLSHTTPEnclave error = %v, want ErrInsecureFileMode", err)
			}
		})
	}
}

func writeHTTPEnclaveTLSFixture(t *testing.T) (string, string) {
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
