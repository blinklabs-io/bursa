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
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/armory/device"
)

func TestHostKeyFile(t *testing.T) {
	t.Parallel()

	file := filepath.Join(t.TempDir(), "host.skey")

	var out bytes.Buffer

	if err := run([]string{"host-key", "-out", file}, &out); err != nil {
		t.Fatal(err)
	}

	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("host key file mode %v %v", fi, err)
	}

	key, err := readHostKey(file)
	if err != nil {
		t.Fatal(err)
	}

	// the printed line is the /provision/host-key request body, as is
	var req device.HostKeyRequest

	if err := json.Unmarshal(out.Bytes(), &req); err != nil || !bytes.Equal(req.PublicKey, key.Public().(ed25519.PublicKey)) {
		t.Fatalf("printed %q, not the host-key request for the public key: %v", out.String(), err)
	}

	if err := run([]string{"host-key", "-out", file}, &out); err == nil {
		t.Fatal("existing host key file overwritten")
	}

	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := readHostKey(file); err == nil {
		t.Fatal("host key file readable by others accepted")
	}
}

func TestHostKeyAuthenticatesSigning(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	dir := t.TempDir()
	hostFile := filepath.Join(dir, "host.skey")

	var out bytes.Buffer

	if err := run([]string{"host-key", "-out", hostFile}, &out); err != nil {
		t.Fatal(err)
	}

	var keys device.HostKeyResponse

	// the printed request registers the key unchanged
	devicePost(t, r.srv, "/provision/host-key", json.RawMessage(out.Bytes()), &keys)

	if len(keys.HostKeys) != 1 {
		t.Fatalf("host keys after registering the printed request: %d", len(keys.HostKeys))
	}

	kesFile := filepath.Join(dir, "kes.vkey")
	if err := os.WriteFile(kesFile, marshalEnvelope("KesVerificationKey_ed25519_kes_2^6", "", vkeyCBOR(bytes.Repeat([]byte{0x5a}, 32))), 0o600); err != nil {
		t.Fatal(err)
	}

	opcert := func(extra ...string) error {
		args := append([]string{
			"-signer", r.srv.URL, "-source", "", "-identity", hex.EncodeToString(r.identity), "-profile", profile,
		}, extra...)

		return run(append(args, "opcert", "-kes-vkey", kesFile, "-kes-period", "7", "-chain-counter", "3",
			"-out", filepath.Join(dir, "node.cert")), &bytes.Buffer{})
	}

	if err := opcert(); err == nil || !strings.Contains(err.Error(), "device refused") {
		t.Fatalf("unauthenticated opcert: err = %v, want a refusal", err)
	}

	if err := opcert("-host-key", hostFile); err != nil {
		t.Fatalf("authenticated opcert: %v", err)
	}
}
