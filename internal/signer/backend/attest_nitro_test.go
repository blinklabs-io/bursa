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
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// nitroFixture is a miniature Nitro PKI: a root, a leaf signed by it, and the
// image measurement the enclave reports.
type nitroFixture struct {
	rootPEM []byte
	rootDER []byte
	leafDER []byte
	leafKey *ecdsa.PrivateKey
	pcr0    []byte
	now     time.Time
}

func newNitroFixture(t *testing.T) *nitroFixture {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-nitro-root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test-enclave"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	pcr0 := make([]byte, nitroPCRSize)
	pcr0[0] = 0xaa
	return &nitroFixture{
		rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		rootDER: rootDER, leafDER: leafDER, leafKey: leafKey, pcr0: pcr0, now: now,
	}
}

// document builds a COSE_Sign1 attestation document. mutate may alter the
// payload fields before signing.
func (f *nitroFixture) document(t *testing.T, userData []byte, mutate func(d map[string]any)) []byte {
	t.Helper()
	d := map[string]any{
		"module_id": "i-test", "digest": "SHA384", "timestamp": uint64(f.now.UnixMilli()),
		"pcrs":        map[uint][]byte{0: f.pcr0},
		"certificate": f.leafDER, "cabundle": [][]byte{f.rootDER},
		"user_data": userData,
	}
	if mutate != nil {
		mutate(d)
	}
	payload, err := cbor.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := cbor.Marshal(map[int]int{1: coseAlgES384})
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := cbor.Marshal([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384(tbs)
	r, s, err := ecdsa.Sign(rand.Reader, f.leafKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])
	doc, err := cbor.Marshal([]any{protected, map[any]any{}, payload, sig})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func (f *nitroFixture) verifier(t *testing.T) *NitroVerifier {
	t.Helper()
	v, err := NewNitroVerifier(f.rootPEM, map[uint][]byte{0: f.pcr0})
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return f.now }
	return v
}

func TestNitroVerifier(t *testing.T) {
	t.Parallel()
	binding := []byte("binding-0123456789abcdef01234567")
	other := newNitroFixture(t)

	tests := []struct {
		name    string
		doc     func(f *nitroFixture, t *testing.T) []byte
		verify  func(v *NitroVerifier, f *nitroFixture)
		wantErr bool
	}{
		{"valid", func(f *nitroFixture, t *testing.T) []byte { return f.document(t, binding, nil) }, nil, false},
		{"tagged COSE_Sign1", func(f *nitroFixture, t *testing.T) []byte {
			return append([]byte{coseTagSign1}, f.document(t, binding, nil)...)
		}, nil, false},
		{"debug enclave reports zero PCR0", func(f *nitroFixture, t *testing.T) []byte {
			return f.document(t, binding, func(d map[string]any) { d["pcrs"] = map[uint][]byte{0: make([]byte, nitroPCRSize)} })
		}, nil, true},
		{"different image measurement", func(f *nitroFixture, t *testing.T) []byte {
			pcr := append([]byte(nil), f.pcr0...)
			pcr[1] = 0xbb
			return f.document(t, binding, func(d map[string]any) { d["pcrs"] = map[uint][]byte{0: pcr} })
		}, nil, true},
		{"missing PCR0", func(f *nitroFixture, t *testing.T) []byte {
			return f.document(t, binding, func(d map[string]any) { d["pcrs"] = map[uint][]byte{} })
		}, nil, true},
		{"binding mismatch", func(f *nitroFixture, t *testing.T) []byte { return f.document(t, []byte("another-binding"), nil) }, nil, true},
		{"missing user_data", func(f *nitroFixture, t *testing.T) []byte { return f.document(t, nil, nil) }, nil, true},
		{"expired certificate", func(f *nitroFixture, t *testing.T) []byte { return f.document(t, binding, nil) },
			func(v *NitroVerifier, f *nitroFixture) { v.now = func() time.Time { return f.now.Add(2 * time.Hour) } }, true},
		{"untrusted root", func(f *nitroFixture, t *testing.T) []byte { return f.document(t, binding, nil) },
			func(v *NitroVerifier, f *nitroFixture) {
				v.roots = x509.NewCertPool()
				c, _ := x509.ParseCertificate(other.rootDER)
				v.roots.AddCert(c)
			}, true},
		{"unsupported digest", func(f *nitroFixture, t *testing.T) []byte {
			return f.document(t, binding, func(d map[string]any) { d["digest"] = "SHA256" })
		}, nil, true},
		{"expected PCR1 not reported", func(f *nitroFixture, t *testing.T) []byte { return f.document(t, binding, nil) },
			func(v *NitroVerifier, f *nitroFixture) { v.pcrs[1] = make([]byte, nitroPCRSize) }, true},
		{"signature over a different payload", func(f *nitroFixture, t *testing.T) []byte {
			var msg coseSign1Msg
			if err := cbor.Unmarshal(f.document(t, binding, nil), &msg); err != nil {
				t.Fatal(err)
			}
			// Same binding, different payload: only the signature check can
			// tell this document from the genuine one.
			forged := f.document(t, binding, func(d map[string]any) { d["module_id"] = "i-other" })
			var fm coseSign1Msg
			if err := cbor.Unmarshal(forged, &fm); err != nil {
				t.Fatal(err)
			}
			fm.Signature = msg.Signature
			out, _ := cbor.Marshal(fm)
			return out
		}, nil, true},
		{"not CBOR", func(*nitroFixture, *testing.T) []byte { return []byte("not a document") }, nil, true},
		{"empty", func(*nitroFixture, *testing.T) []byte { return nil }, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newNitroFixture(t)
			v := f.verifier(t)
			if tc.verify != nil {
				tc.verify(v, f)
			}
			err := v.Verify(t.Context(), tc.doc(f, t), binding)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Verify error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestNewNitroVerifierValidatesConfig(t *testing.T) {
	t.Parallel()
	f := newNitroFixture(t)
	good := map[uint][]byte{0: f.pcr0}
	for _, tc := range []struct {
		name string
		root []byte
		pcrs map[uint][]byte
	}{
		{"no root", []byte("junk"), good},
		{"no PCR0", f.rootPEM, map[uint][]byte{1: f.pcr0}},
		{"zero PCR0", f.rootPEM, map[uint][]byte{0: make([]byte, nitroPCRSize)}},
		{"short PCR", f.rootPEM, map[uint][]byte{0: f.pcr0, 1: {1}}},
	} {
		if _, err := NewNitroVerifier(tc.root, tc.pcrs); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
	if _, err := NewNitroVerifier(f.rootPEM, good); err != nil {
		t.Fatalf("valid config: %v", err)
	}
}
