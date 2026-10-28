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
	"bytes"
	"crypto/ed25519"
	"fmt"
	"slices"
	"strings"
	"sync"

	usbarmory "github.com/usbarmory/tamago/board/usbarmory/mk2"

	"github.com/blinklabs-io/bursa/armory/se050"
)

// Bring-up test objects, all transient and deleted after use.
const (
	generatedID uint32 = 0x20e50001
	importedID  uint32 = 0x20e50002
)

var bringupMessage = []byte("armory-signer se050 bring-up")

// Report accumulates bring-up output for the HTTP endpoint.
type Report struct {
	sync.Mutex
	lines []string
	done  bool
}

func (r *Report) Logf(format string, args ...any) {
	r.Lock()
	defer r.Unlock()

	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}

func (r *Report) String() string {
	r.Lock()
	defer r.Unlock()

	s := strings.Join(r.lines, "\n") + "\n"

	if !r.done {
		s += "(running)\n"
	}

	return s
}

func (r *Report) finish(pass bool) {
	if pass {
		r.Logf("RESULT: PASS")
	} else {
		r.Logf("RESULT: FAIL")
	}

	r.Lock()
	r.done = true
	r.Unlock()
}

// diagnoseSignature reports which byte order, if any, makes an SE050
// signature verify, to pin down the device's Ed25519 encoding.
func diagnoseSignature(r *Report, pub ed25519.PublicKey, sig []byte) {
	rev := func(b []byte) []byte {
		c := slices.Clone(b)
		slices.Reverse(c)
		return c
	}

	pubs := map[string][]byte{"pub": pub, "pub-reversed": rev(pub)}
	sigs := map[string][]byte{
		"sig":                 sig,
		"sig-halves-reversed": append(rev(sig[:32]), rev(sig[32:])...),
		"sig-reversed":        rev(sig),
	}

	for pn, p := range pubs {
		for sn, s := range sigs {
			if ed25519.Verify(p, bringupMessage, s) {
				r.Logf("  diagnosis: verifies with %s + %s", pn, sn)
			}
		}
	}
}

// clearObject removes a leftover test object from an interrupted run.
func clearObject(r *Report, se *se050.SE050, id uint32) error {
	exists, err := se.Exists(id)

	if err != nil || !exists {
		return err
	}

	r.Logf("  removing leftover test object %#08x", id)

	return se.Delete(id)
}

func testGenerated(r *Report, se *se050.SE050) bool {
	r.Logf("generated key test (object %#08x, transient)", generatedID)

	if err := clearObject(r, se, generatedID); err != nil {
		r.Logf("  exist check: %v", err)
		return false
	}

	if err := se.GenerateEd25519(generatedID, true); err != nil {
		r.Logf("  generate: %v", err)
		return false
	}

	defer func() {
		if err := se.Delete(generatedID); err != nil {
			r.Logf("  delete: %v", err)
		}
	}()

	pub, err := se.PublicKeyEd25519(generatedID)

	if err != nil {
		r.Logf("  read public key: %v", err)
		return false
	}

	r.Logf("  public key %x", []byte(pub))

	sig, err := se.SignEd25519(generatedID, bringupMessage)

	if err != nil {
		r.Logf("  sign: %v", err)
		return false
	}

	if !ed25519.Verify(pub, bringupMessage, sig) {
		r.Logf("  signature does not verify: %x", sig)
		diagnoseSignature(r, pub, sig)
		return false
	}

	r.Logf("  signature verifies")

	return true
}

// testImported proves byte-exact compatibility with crypto/ed25519 using a
// throwaway seed from the SE050 RNG.
func testImported(r *Report, se *se050.SE050) bool {
	r.Logf("imported key test (object %#08x, transient)", importedID)

	seed, err := se.Random(ed25519.SeedSize)

	if err != nil {
		r.Logf("  random: %v", err)
		return false
	}

	key := ed25519.NewKeyFromSeed(seed)
	wantPub := key.Public().(ed25519.PublicKey)
	wantSig := ed25519.Sign(key, bringupMessage)

	if err := clearObject(r, se, importedID); err != nil {
		r.Logf("  exist check: %v", err)
		return false
	}

	if err := se.ImportEd25519(importedID, seed, true); err != nil {
		r.Logf("  import: %v", err)
		return false
	}

	defer func() {
		if err := se.Delete(importedID); err != nil {
			r.Logf("  delete: %v", err)
		}
	}()

	pub, err := se.PublicKeyEd25519(importedID)

	if err != nil {
		r.Logf("  read public key: %v", err)
		return false
	}

	if !bytes.Equal(pub, wantPub) {
		r.Logf("  public key mismatch: se %x want %x", []byte(pub), []byte(wantPub))
		return false
	}

	r.Logf("  public key matches crypto/ed25519")

	sig, err := se.SignEd25519(importedID, bringupMessage)

	if err != nil {
		r.Logf("  sign: %v", err)
		return false
	}

	if !bytes.Equal(sig, wantSig) {
		r.Logf("  signature mismatch: se %x want %x", sig, wantSig)
		diagnoseSignature(r, wantPub, sig)
		return false
	}

	r.Logf("  signature is byte-identical to crypto/ed25519")

	return true
}

func runBringup(r *Report, s *signer) {
	_, model := usbarmory.Model()
	r.Logf("board: %s", model)

	if err := enableSE050(); err != nil {
		r.Logf("enable: %v", err)
		r.finish(false)
		return
	}

	se, err := se050.Open(newSE050Bus())

	if err != nil {
		r.Logf("open: %v", err)
		r.finish(false)
		return
	}

	r.Logf("ATR: bwt %v ifsc %d mpot %v segt %v wut %v historical %q",
		se.ATR.BWT, se.ATR.IFSC, se.ATR.MPOT, se.ATR.SEGT, se.ATR.WUT, se.ATR.Historical)
	r.Logf("applet: %s", se.Version)

	if !se.Version.EdDSA() {
		r.Logf("this SE050 variant does not support EdDSA")
		r.finish(false)
		return
	}

	r.Logf("EdDSA supported")

	rnd, err := se.Random(16)

	if err != nil {
		r.Logf("random: %v", err)
		r.finish(false)
		return
	}

	r.Logf("random: %x", rnd)

	pass := testGenerated(r, se)
	pass = testImported(r, se) && pass
	pass = selfTestLedger(r) && pass

	if exists, err := se.Exists(coldKeyID); err == nil {
		r.Logf("cold key %#08x provisioned: %v", coldKeyID, exists)
	}

	// endpoints only get the session once bring-up is done with it
	s.set(se)

	r.finish(pass)
}
