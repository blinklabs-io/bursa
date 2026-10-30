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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/armory/device"
	"github.com/blinklabs-io/bursa/armory/hostkey"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"
)

const (
	coldID      uint32 = 0x20e50011
	profileName        = "otg@preview"
	chainCtr           = uint64(3)
	kesPeriod          = uint64(7)
)

// fakeChip is a minimal software SE050 (the device package's own fake is in
// its tests).
type fakeChip struct {
	keys map[uint32]ed25519.PrivateKey
	bins map[uint32][]byte
}

func (c *fakeChip) Exists(id uint32) (bool, error) {
	_, k := c.keys[id]
	_, b := c.bins[id]

	return k || b, nil
}

func (c *fakeChip) GenerateEd25519(id uint32, _ bool) error {
	_, priv, _ := ed25519.GenerateKey(nil)
	c.keys[id] = priv

	return nil
}

func (c *fakeChip) ImportEd25519(id uint32, seed []byte, _ bool) error {
	c.keys[id] = ed25519.NewKeyFromSeed(seed)

	return nil
}

func (c *fakeChip) PublicKeyEd25519(id uint32) (ed25519.PublicKey, error) {
	k, ok := c.keys[id]
	if !ok {
		return nil, errors.New("no key")
	}

	return k.Public().(ed25519.PublicKey), nil
}

func (c *fakeChip) SignEd25519(id uint32, msg []byte) ([]byte, error) {
	k, ok := c.keys[id]
	if !ok {
		return nil, errors.New("no key")
	}

	return ed25519.Sign(k, msg), nil
}

func (c *fakeChip) WriteBinary(id uint32, data []byte) error {
	c.bins[id] = bytes.Clone(data)

	return nil
}

func (c *fakeChip) Delete(id uint32) error {
	delete(c.bins, id)
	delete(c.keys, id)

	return nil
}

func (c *fakeChip) ReadBinary(id uint32) ([]byte, error) {
	b, ok := c.bins[id]
	if !ok {
		return nil, errors.New("no object")
	}

	return bytes.Clone(b), nil
}

func devicePost(t *testing.T, srv *httptest.Server, path string, req, resp any) {
	t.Helper()

	b, _ := json.Marshal(req)

	res, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}

	defer res.Body.Close()

	var buf bytes.Buffer

	_, _ = buf.ReadFrom(res.Body)

	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: %s %s", path, res.Status, buf.String())
	}

	if err := json.Unmarshal(buf.Bytes(), resp); err != nil {
		t.Fatal(err)
	}
}

// rig is a provisioned device with a pool cold key whose chain counter is 3,
// and the public inputs opcert-check takes for the certificate issue 4.
type rig struct {
	srv      *httptest.Server
	vkeyHex  string
	certHex  string
	poolHex  string
	hostFile string
}

func writeHostKey(t *testing.T, seed byte, mode os.FileMode) (string, ed25519.PrivateKey) {
	t.Helper()

	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	file := filepath.Join(t.TempDir(), "host.skey")
	body := fmt.Sprintf("{\n    \"type\": %q,\n    \"description\": %q,\n    \"cborHex\": \"5820%x\"\n}\n",
		hostkey.Type, hostkey.Description, priv.Seed())

	if err := os.WriteFile(file, []byte(body), mode); err != nil {
		t.Fatal(err)
	}

	// WriteFile is subject to the umask
	if err := os.Chmod(file, mode); err != nil {
		t.Fatal(err)
	}

	return file, priv
}

// newRig serves a real device.Service on a fake chip and registers
// registered as a host key, when it is not nil.
func newRig(t *testing.T, registered ed25519.PrivateKey) *rig {
	t.Helper()

	svc := device.New(&sync.Mutex{}, t.Logf)

	if err := svc.SetChip(&fakeChip{keys: map[uint32]ed25519.PrivateKey{}, bins: map[uint32][]byte{}}); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(svc.Handler())
	t.Cleanup(srv.Close)

	var id device.IdentityResponse

	devicePost(t, srv, "/provision/identity", struct{}{}, &id)

	coldSeed := bytes.Repeat([]byte{0x42}, 32)

	var cold device.ColdResponse

	devicePost(t, srv, "/provision/cold", device.ColdRequest{
		ColdKeyID: coldID, SigningKey: "5820" + hex.EncodeToString(coldSeed),
	}, &cold)

	chain := chainCtr

	var prov device.ProvisionResponse

	devicePost(t, srv, "/provision/profile", device.ProvisionRequest{
		Name: profileName, Slot: 0, ColdKeyID: coldID, ChainCounter: &chain,
		RewardAccount: "e0" + strings.Repeat("ee", 28),
	}, &prov)

	if registered != nil {
		var keys device.HostKeyResponse

		devicePost(t, srv, "/provision/host-key",
			device.HostKeyRequest{PublicKey: registered.Public().(ed25519.PublicKey)}, &keys)
	}

	coldPriv := ed25519.NewKeyFromSeed(coldSeed)
	vkey := coldPriv.Public().(ed25519.PublicKey)

	h, _ := blake2b.New(28, nil)
	h.Write(vkey)

	body := opCertBody{KESKey: bytes.Repeat([]byte{0x5a}, 32), IssueNumber: chainCtr + 1, KESPeriod: kesPeriod}
	body.ColdSig = ed25519.Sign(coldPriv, body.signable())

	cert, err := cbor.Marshal(opCert{Body: body, ColdKey: vkey})
	if err != nil {
		t.Fatal(err)
	}

	return &rig{
		srv:     srv,
		vkeyHex: "5820" + hex.EncodeToString(vkey),
		certHex: hex.EncodeToString(cert),
		poolHex: hex.EncodeToString(h.Sum(nil)),
	}
}

func (r *rig) check(extra ...string) (string, error) {
	var out bytes.Buffer

	args := append([]string{
		"-vkey", r.vkeyHex, "-cert", r.certHex, "-pool", r.poolHex, "-profile", profileName,
		"-signer", r.srv.URL, "-source", "",
	}, extra...)
	err := run(args, &out)

	return out.String(), err
}

func TestNoHostKeyUnchanged(t *testing.T) {
	t.Parallel()

	out, err := newRig(t, nil).check()
	if err != nil {
		t.Fatalf("device without host keys: %v", err)
	}

	if !strings.Contains(out, "ok   binding signature covers the request under node.vkey") {
		t.Fatalf("output %q", out)
	}
}

func TestRegisteredHostKeyRefusesUnauthenticated(t *testing.T) {
	t.Parallel()

	_, priv := writeHostKey(t, 0x48, 0o600)

	if _, err := newRig(t, priv).check(); err == nil || !strings.Contains(err.Error(), "host key not registered") {
		t.Fatalf("unauthenticated request: err = %v, want host key not registered", err)
	}
}

func TestHostKeyAuthenticatesRequest(t *testing.T) {
	t.Parallel()

	file, priv := writeHostKey(t, 0x48, 0o600)

	out, err := newRig(t, priv).check("-host-key", file)
	if err != nil {
		t.Fatalf("authenticated request: %v", err)
	}

	for _, want := range []string{
		"ok   device reproduces node.cert signature (issue 4, KES period 7)",
		"ok   binding signature covers the request under node.vkey",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q lacks %q", out, want)
		}
	}
}

func TestWrongHostKeyRefused(t *testing.T) {
	t.Parallel()

	_, registered := writeHostKey(t, 0x48, 0o600)
	other, _ := writeHostKey(t, 0x49, 0o600)

	if _, err := newRig(t, registered).check("-host-key", other); err == nil ||
		!strings.Contains(err.Error(), "host key not registered") {
		t.Fatalf("unregistered host key: err = %v, want host key not registered", err)
	}
}

func TestHostKeyFileReadableByOthersRejected(t *testing.T) {
	t.Parallel()

	for _, mode := range []os.FileMode{0o640, 0o604, 0o644} {
		file, priv := writeHostKey(t, 0x48, mode)

		_, err := newRig(t, priv).check("-host-key", file)
		if err == nil || !strings.Contains(err.Error(), "readable by others") {
			t.Fatalf("mode %o: err = %v, want readable by others", mode, err)
		}
	}
}

func TestHostKeyWrongEnvelopeRejected(t *testing.T) {
	t.Parallel()

	file := filepath.Join(t.TempDir(), "other.skey")
	body := fmt.Sprintf("{\"type\": \"PaymentSigningKeyShelley_ed25519\", \"description\": \"\", \"cborHex\": \"5820%x\"}",
		binary.BigEndian.AppendUint64(nil, 1))

	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := newRig(t, nil).check("-host-key", file); err == nil || !strings.Contains(err.Error(), "envelope type") {
		t.Fatalf("err = %v, want envelope type error", err)
	}
}
