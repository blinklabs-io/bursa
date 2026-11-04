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
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/armory/profile"
	"github.com/blinklabs-io/bursa/armory/signlog"
)

func TestLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:1", "[::1]:1"} {
		if err := loopback(addr); err != nil {
			t.Errorf("loopback(%q): %v", addr, err)
		}
	}

	for _, addr := range []string{"0.0.0.0:1", ":1", "10.0.0.1:80", "localhost:1", "127.0.0.1"} {
		if err := loopback(addr); err == nil {
			t.Errorf("loopback(%q) accepted a non-loopback address", addr)
		}
	}
}

func TestScope(t *testing.T) {
	cases := []struct {
		network, chain string
		id             uint8
		label          string
		ok             bool
	}{
		{"testnet", "", 0, "", true},
		{"mainnet", "cardano", 1, "cardano-mainnet", true},
		{"mainnet", "prime", 1, "prime-mainnet", true},
		{"mainnet", "", 0, "", false},
		{"mainnet", "other", 0, "", false},
		{"testnet", "prime", 0, "", false},
		{"preview", "", 0, "", false},
	}

	for _, c := range cases {
		id, label, err := scope(c.network, c.chain)
		if (err == nil) != c.ok || id != c.id || label != c.label {
			t.Errorf("scope(%q, %q) = %d, %q, %v", c.network, c.chain, id, label, err)
		}
	}
}

// TestChipPersists checks that a second open sees the first one's objects,
// as the signing image sees what the provisioning image wrote.
func TestChipPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chip.json")

	c, err := openChip(path)
	if err != nil {
		t.Fatal(err)
	}

	seed := bytes.Repeat([]byte{9}, ed25519.SeedSize)
	if err := c.ImportEd25519(0x20e50010, seed, false); err != nil {
		t.Fatal(err)
	}

	if err := c.ImportEd25519(0x20e50010, seed, false); err == nil {
		t.Fatal("import over an existing object succeeded")
	}

	if err := c.ImportEd25519(0x20e50001, seed, true); err != nil {
		t.Fatal(err)
	}

	if err := c.WriteBinary(0x20e50000, []byte("record")); err != nil {
		t.Fatal(err)
	}

	if err := c.WriteBinary(0x20e50010, []byte("x")); err == nil {
		t.Fatal("binary write over a key succeeded")
	}

	c2, err := openChip(path)
	if err != nil {
		t.Fatal(err)
	}

	pub, err := c2.PublicKeyEd25519(0x20e50010)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pub, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)) {
		t.Fatal("reopened chip returned a different key")
	}

	sig, err := c2.SignEd25519(0x20e50010, []byte("m"))
	if err != nil || !ed25519.Verify(pub, []byte("m"), sig) {
		t.Fatalf("reopened chip signature: %v", err)
	}

	if ok, _ := c2.Exists(0x20e50001); ok {
		t.Fatal("a transient key persisted")
	}

	b, err := c2.ReadBinary(0x20e50000)
	if err != nil || string(b) != "record" {
		t.Fatalf("binary = %q, %v", b, err)
	}

	if err := c2.Delete(0x20e50000); err != nil {
		t.Fatal(err)
	}

	c3, err := openChip(path)
	if err != nil {
		t.Fatal(err)
	}

	if ok, _ := c3.Exists(0x20e50000); ok {
		t.Fatal("a deleted object came back")
	}
}

func TestCardBounds(t *testing.T) {
	c, err := openCard(filepath.Join(t.TempDir(), "card.img"), 8)
	if err != nil {
		t.Fatal(err)
	}

	if bs, n := c.Geometry(); bs != signlog.BlockSize || n != 8 {
		t.Fatalf("geometry %d x %d", bs, n)
	}

	buf := bytes.Repeat([]byte{1}, 2*signlog.BlockSize)
	if err := c.WriteBlocks(6, buf); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, len(buf))
	if err := c.ReadBlocks(6, got); err != nil || !bytes.Equal(got, buf) {
		t.Fatalf("read back: %v", err)
	}

	if err := c.WriteBlocks(7, buf); err == nil {
		t.Fatal("write past the end succeeded")
	}

	if err := c.ReadBlocks(0, make([]byte, 100)); err == nil {
		t.Fatal("partial block read succeeded")
	}
}

// TestBuildImages checks each image serves its own routes on any Host, and
// that a signing image without an identity key refuses to sign.
func TestBuildImages(t *testing.T) {
	cases := []struct {
		image, path string
		want        int
	}{
		{"provision", "/v1/challenge", http.StatusOK},
		{"provision", "/v1/sign", http.StatusNotFound},
		{"wipe", "/v1/challenge", http.StatusOK},
		{"wipe", "/provision/identity", http.StatusNotFound},
		{"sign", "/v1/challenge", http.StatusOK},
		{"sign", "/provision/identity", http.StatusNotFound},
	}

	for _, c := range cases {
		h, err := build(options{
			listen: "127.0.0.1:0", state: t.TempDir(), image: c.image,
			network: "testnet", cardBlocks: 1 << 10,
		}, t.Logf)
		if err != nil {
			t.Fatalf("%s: %v", c.image, err)
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18080"+c.path, strings.NewReader("{}"))
		r.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(w, r)

		if w.Code != c.want {
			t.Errorf("%s %s: %d %s, want %d", c.image, c.path, w.Code, w.Body, c.want)
		}
	}

	if _, err := build(options{listen: "127.0.0.1:0", state: t.TempDir(), image: "other", network: "testnet"}, t.Logf); err == nil {
		t.Fatal("unknown image accepted")
	}
}

// TestSigningLogNeedsIdentity checks that a signing image whose chip has no
// identity key leaves the log closed rather than failing to start.
func TestSigningLogNeedsIdentity(t *testing.T) {
	dir := t.TempDir()

	chip, err := openChip(filepath.Join(dir, "chip.json"))
	if err != nil {
		t.Fatal(err)
	}

	if ok, _ := chip.Exists(profile.IdentityKeyID); ok {
		t.Fatal("new chip has an identity key")
	}

	if _, err := build(options{listen: "127.0.0.1:0", state: dir, image: "sign", network: "testnet", cardBlocks: 1 << 10}, t.Logf); err != nil {
		t.Fatalf("signing image without identity: %v", err)
	}
}

// TestSigningLogOpens builds a signing image whose chip holds an identity
// key, so the log opens on a new card image. Opening the log must not hold
// the service lock while installing the log, which takes that lock too.
func TestSigningLogOpens(t *testing.T) {
	dir := t.TempDir()

	chip, err := openChip(filepath.Join(dir, "chip.json"))
	if err != nil {
		t.Fatal(err)
	}

	if err := chip.GenerateEd25519(profile.IdentityKeyID, false); err != nil {
		t.Fatal(err)
	}

	var logged []string

	done := make(chan error, 1)

	go func() {
		_, err := build(options{listen: "127.0.0.1:0", state: dir, image: "sign", network: "testnet", cardBlocks: 1 << 10},
			func(f string, a ...any) { logged = append(logged, f) })
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("building the signing image blocked")
	}

	for _, l := range logged {
		if strings.Contains(l, "NOT OPEN") {
			t.Fatalf("signing log did not open: %v", logged)
		}
	}
}

// TestChipSaveFailureRollsBack checks that a change the chip cannot save is
// not kept in memory either.
func TestChipSaveFailureRollsBack(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}

	dir := t.TempDir()

	c, err := openChip(filepath.Join(dir, "chip.json"))
	if err != nil {
		t.Fatal(err)
	}

	if err := c.WriteBinary(1, []byte("old")); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := c.ImportEd25519(2, bytes.Repeat([]byte{1}, ed25519.SeedSize), false); err == nil {
		t.Fatal("import saved into a read-only directory")
	}

	if ok, _ := c.Exists(2); ok {
		t.Fatal("a key whose save failed is still in the chip")
	}

	if err := c.WriteBinary(1, []byte("new")); err == nil {
		t.Fatal("write saved into a read-only directory")
	}

	if b, _ := c.ReadBinary(1); string(b) != "old" {
		t.Fatalf("binary = %q after a failed write, want the old content", b)
	}

	if err := c.Delete(1); err == nil {
		t.Fatal("delete saved into a read-only directory")
	}

	if ok, _ := c.Exists(1); !ok {
		t.Fatal("an object whose delete failed is gone from the chip")
	}
}

func TestCardSizeBounds(t *testing.T) {
	// 1<<55+8 blocks is 1<<64+4096 bytes, which wraps to a 4096-byte image
	for _, n := range []uint64{0, math.MaxInt64/signlog.BlockSize + 1, 1<<55 + 8, math.MaxUint64} {
		if _, err := openCard(filepath.Join(t.TempDir(), "card.img"), n); err == nil {
			t.Errorf("openCard accepted %d blocks", n)
		}
	}
}

func TestOpenChipRejectsKeyAndBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chip.json")
	// a valid 32-byte seed, so only the overlap can make the load fail
	seed := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	state := `{"keys":{"0x20e50010":"` + seed + `"},"bins":{"0x20e50010":"eA=="}}`

	if err := os.WriteFile(path, []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := openChip(path); err == nil {
		t.Fatal("openChip accepted an object that is both a key and a binary")
	}
}

// TestStateLocked checks that a second simulator cannot use a state
// directory another one holds.
func TestStateLocked(t *testing.T) {
	dir := t.TempDir()
	o := options{listen: "127.0.0.1:0", state: dir, image: "provision", network: "testnet"}

	if _, err := build(o, t.Logf); err != nil {
		t.Fatal(err)
	}

	if _, err := build(o, t.Logf); err == nil {
		t.Fatal("a second simulator opened a state directory in use")
	}

	// the lock must outlive garbage collection: a dropped *os.File is
	// closed by its finalizer, which would release the lock
	for range 5 {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)

		if _, err := build(o, t.Logf); err == nil {
			t.Fatal("the state lock was released after garbage collection")
		}
	}
}
