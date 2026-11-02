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
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/armory/device"
)

// adminServer serves a device with the provisioning, signing and wipe
// endpoints on one address.
func adminServer(t *testing.T) *httptest.Server {
	t.Helper()

	svc := device.New(&sync.Mutex{}, t.Logf)

	if err := svc.SetChip(&fakeChip{keys: map[uint32]ed25519.PrivateKey{}, bins: map[uint32][]byte{}}); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/wipe/", svc.WipeHandler())
	mux.Handle("/", svc.Handler())

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv
}

func adminRun(srv *httptest.Server, in string, args ...string) (string, error) {
	var out bytes.Buffer

	err := runIO(append([]string{"-signer", srv.URL, "-source", ""}, args...), strings.NewReader(in), &out)

	return out.String(), err
}

// With a host key registered the provisioning and wipe subcommands sign their
// requests with the host key; without one the device refuses them.
func TestProvisionAndWipeSubcommandsSign(t *testing.T) {
	t.Parallel()

	srv := adminServer(t)
	hostFile := filepath.Join(t.TempDir(), "host.skey")

	var keyReq bytes.Buffer
	if err := run([]string{"host-key", "-out", hostFile}, &keyReq); err != nil {
		t.Fatal(err)
	}

	// a fresh device takes its first host key unsigned
	if out, err := adminRun(srv, keyReq.String(), "provision", "host-key"); err != nil {
		t.Fatalf("first host key: %v %s", err, out)
	}

	out, err := adminRun(srv, "", "provision", "identity")
	if err == nil {
		t.Fatalf("unsigned provisioning accepted: %s", out)
	}

	out, err = adminRun(srv, "", "-host-key", hostFile, "provision", "identity")
	if err != nil {
		t.Fatalf("signed provisioning: %v", err)
	}

	var id device.IdentityResponse
	if err = json.Unmarshal([]byte(out), &id); err != nil || len(id.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("identity answer %q: %v", out, err)
	}

	idHex := hex.EncodeToString(id.PublicKey)
	wipe := `{"identity_public_key":"` + idHex + `"}`

	if out, err = adminRun(srv, wipe, "wipe", "signlog"); err == nil {
		t.Fatalf("unsigned signing log wipe accepted: %s", out)
	}

	if out, err = adminRun(srv, wipe, "-host-key", hostFile, "wipe", "signlog"); err != nil {
		t.Fatalf("signed signing log wipe: %v", err)
	}

	// the device wipe is never signed, even when a host key is given
	if out, err = adminRun(srv, wipe, "-host-key", hostFile, "wipe", "device"); err != nil {
		t.Fatalf("device wipe: %v %s", err, out)
	}

	if _, err = adminRun(srv, "", "provision", "nonsense"); err == nil {
		t.Fatal("unknown route accepted")
	}
}

// failReader fails the test if it is read.
type failReader struct{ t *testing.T }

func (r failReader) Read([]byte) (int, error) {
	r.t.Fatal("request read before the route was checked")
	return 0, nil
}

// An unknown route is refused before the request is read, so it does not
// wait on standard input.
func TestAdminRequestChecksRouteFirst(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer

	err := adminRequest(&client{}, "/provision/nonsense", "", failReader{t}, &out)
	if err == nil || !strings.Contains(err.Error(), "unknown route") {
		t.Fatalf("err = %v", err)
	}
}
