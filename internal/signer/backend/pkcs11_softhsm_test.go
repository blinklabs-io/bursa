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

//go:build pkcs11

package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/asn1"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/miekg/pkcs11"
)

// CKM_EC_EDWARDS_KEY_PAIR_GEN, only used when provisioning the test token.
const ckmECEdwardsKeyPairGen = 0x00001055

// ed25519OID is the DER-encoded CKA_EC_PARAMS for edwards25519 (OID 1.3.101.112).
func ed25519OID(t *testing.T) []byte {
	t.Helper()
	b, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 101, 112})
	if err != nil {
		t.Fatalf("marshal ed25519 OID: %v", err)
	}
	return b
}

// findSoftHSMModule locates libsofthsm2.so, or returns "" to signal a skip.
func findSoftHSMModule() string {
	if m := os.Getenv("SOFTHSM2_MODULE"); m != "" {
		if _, err := os.Stat(m); err == nil {
			return m
		}
	}
	candidates := []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/opt/homebrew/lib/softhsm/libsofthsm2.so",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// setupSoftHSMToken initializes a fresh SoftHSM token in a temp dir and returns
// the module path, token label, and PIN. The token is isolated via
// SOFTHSM2_CONF so it never touches the host's real token store.
func setupSoftHSMToken(t *testing.T) (module, label, pin string) {
	t.Helper()
	module = findSoftHSMModule()
	if module == "" {
		t.Skip("SoftHSM2 module not found; skipping PKCS#11 runtime test")
	}
	util, err := exec.LookPath("softhsm2-util")
	if err != nil {
		t.Skip("softhsm2-util not found; skipping PKCS#11 runtime test")
	}

	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatalf("mkdir tokens: %v", err)
	}
	conf := filepath.Join(dir, "softhsm2.conf")
	cfg := "directories.tokendir = " + tokenDir + "\n" +
		"objectstore.backend = file\n" +
		"log.level = ERROR\n"
	if err := os.WriteFile(conf, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write softhsm2.conf: %v", err)
	}
	t.Setenv("SOFTHSM2_CONF", conf)

	label, pin = "bursa-test", "1234"
	out, err := exec.Command(util,
		"--init-token", "--free",
		"--label", label,
		"--pin", pin,
		"--so-pin", "5678",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("softhsm2-util init-token: %v\n%s", err, out)
	}
	return module, label, pin
}

// importEd25519Key writes a known Ed25519 key pair into the token (matching
// CKA_ID on both objects) so the backend can enumerate it and so the signature
// can be checked byte-for-byte against the software implementation.
func importEd25519Key(t *testing.T, module, label, pin string, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	p := pkcs11.New(module)
	if p == nil {
		t.Fatalf("load module %q", module)
	}
	if err := p.Initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer func() {
		_ = p.Finalize()
		p.Destroy()
	}()

	slot, err := findSlotByLabel(p, label)
	if err != nil {
		t.Fatalf("find slot: %v", err)
	}
	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	defer func() { _ = p.CloseSession(session) }()
	if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = p.Logout(session) }()

	oid := ed25519OID(t)
	id := []byte{0x01}
	ecPoint, err := asn1.Marshal([]byte(pub)) // DER OCTET STRING wrapping the 32-byte key
	if err != nil {
		t.Fatalf("marshal EC_POINT: %v", err)
	}

	pubTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, uint(ckkECEdwards)),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, oid),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPoint),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "bursa-key"),
	}
	if _, err := p.CreateObject(session, pubTmpl); err != nil {
		t.Fatalf("create public key object: %v", err)
	}

	privTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, uint(ckkECEdwards)),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, oid),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, priv.Seed()), // 32-byte Ed25519 seed
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "bursa-key"),
	}
	if _, err := p.CreateObject(session, privTmpl); err != nil {
		t.Fatalf("create private key object: %v", err)
	}
}

func findSlotByLabel(p *pkcs11.Ctx, label string) (uint, error) {
	cfg := PKCS11Config{TokenLabel: label}
	return selectSlot(p, cfg)
}

// TestPKCS11Backend_SoftHSM imports a known Ed25519 key, then asserts that the
// backend derives the correct KeyHash, produces a valid signature, and that the
// signature is byte-for-byte identical to the software (ed25519.Sign) output.
func TestPKCS11Backend_SoftHSM(t *testing.T) {
	module, label, pin := setupSoftHSMToken(t)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	importEd25519Key(t, module, label, pin, pub, priv)

	b, err := NewPKCS11Backend(PKCS11Config{
		Name:       "hsm",
		Module:     module,
		TokenLabel: label,
		PIN:        pin,
	})
	if err != nil {
		t.Fatalf("NewPKCS11Backend: %v", err)
	}
	defer func() {
		if c, ok := b.(*PKCS11Backend); ok {
			_ = c.Close()
		}
	}()

	ctx := context.Background()
	want := HashPublicKey(pub)
	ref, err := b.GetKey(ctx, want)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if ref.Hash() != want {
		t.Fatalf("hash mismatch: got %s want %s", ref.Hash(), want)
	}
	if !bytes.Equal(ref.PublicKey(), pub) {
		t.Fatalf("public key mismatch")
	}
	if ref.Extended() {
		t.Fatal("pkcs11 key must not report as extended")
	}
	if _, ok := ref.(LoadedKeyProvider); ok {
		t.Fatal("pkcs11 key must not expose an in-process LoadedKey")
	}

	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}
	sig, err := ref.Sign(ctx, digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(pub, digest, sig) {
		t.Fatal("HSM signature failed ed25519 verification")
	}

	// Byte-for-byte parity with the software backend: CKM_EDDSA PureEdDSA over
	// the same message is deterministic and must match ed25519.Sign exactly.
	soft := ed25519.Sign(priv, digest)
	if !bytes.Equal(sig, soft) {
		t.Fatalf("HSM signature != software signature\n hsm:  %x\n soft: %x", sig, soft)
	}
}
