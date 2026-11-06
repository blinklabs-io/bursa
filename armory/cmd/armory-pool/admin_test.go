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
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

	// the device answers only to its own address, not the loopback one
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Host = device.Address
			mux.ServeHTTP(w, r)
		}),
	)
	t.Cleanup(srv.Close)

	return srv
}

func adminRun(srv *httptest.Server, in string, args ...string) (string, error) {
	var out bytes.Buffer

	err := runIO(
		append([]string{"-signer", srv.URL, "-source", ""}, args...),
		strings.NewReader(in),
		&out,
	)

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
	if err = json.Unmarshal([]byte(out), &id); err != nil ||
		len(id.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("identity answer %q: %v", out, err)
	}

	idHex := hex.EncodeToString(id.PublicKey)
	wipe := `{"identity_public_key":"` + idHex + `"}`
	cold := `{"cold_key_id":551878672,"signing_key":"5820` + strings.Repeat(
		"42",
		ed25519.SeedSize,
	) + `"}`

	if out, err = adminRun(srv, cold, "-identity", idHex, "-host-key", hostFile, "provision", "cold"); err != nil {
		t.Fatalf("authenticated cold import: %v %s", err, out)
	}

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

type countingReader struct {
	reads atomic.Int64
	r     io.Reader
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.reads.Add(1)

	return r.r.Read(p)
}

// A substituted endpoint cannot make armory-pool read or send a private key:
// it must first prove possession of the pinned device identity key.
func TestPrivateKeyProvisioningAuthenticatesDeviceBeforeReading(t *testing.T) {
	t.Parallel()

	pinned := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x51}, ed25519.SeedSize),
	)
	attacker := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x52}, ed25519.SeedSize),
	)

	for _, tc := range []struct {
		name, route, body string
	}{
		{"cold", "cold", `{"cold_key_id":551878672,"signing_key":"5820` + strings.Repeat("53", ed25519.SeedSize) + `"}`},
		{"profile owner", "profile", `{"name":"pool@preview","network_id":0,"slot":0,"cold_key_id":551878672,"owner_signing_key":"5820` + strings.Repeat("54", ed25519.SeedSize) + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var secretRequests atomic.Int64
			srv := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case device.RouteIdentityProof:
						var req device.IdentityProofRequest
						if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
							t.Error(err)
							return
						}

						pub := attacker.Public().(ed25519.PublicKey)
						_ = json.NewEncoder(w).
							Encode(device.IdentityProofResponse{
								Version:   device.Protocol,
								PublicKey: pub,
								Attestation: ed25519.Sign(
									attacker,
									device.IdentityBinding(req.Nonce, pub),
								),
							})
					case "/provision/" + tc.route:
						secretRequests.Add(1)
						_ = json.NewEncoder(w).Encode(struct{}{})
					default:
						http.NotFound(w, r)
					}
				}),
			)
			t.Cleanup(srv.Close)

			in := &countingReader{r: strings.NewReader(tc.body)}
			var out bytes.Buffer

			err := runIO([]string{
				"-signer", srv.URL,
				"-source", "",
				"-identity", hex.EncodeToString(pinned.Public().(ed25519.PublicKey)),
				"provision", tc.route,
			}, in, &out)
			if err == nil ||
				!strings.Contains(err.Error(), "device identity proof") {
				t.Fatalf("err = %v, want device identity proof refusal", err)
			}

			if got := in.reads.Load(); got != 0 {
				t.Errorf(
					"private request input read %d times before device authentication",
					got,
				)
			}

			if got := secretRequests.Load(); got != 0 {
				t.Errorf(
					"private request sent %d times to unauthenticated endpoint",
					got,
				)
			}
		})
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

	err := adminRequest(
		&client{},
		"/provision/nonsense",
		"",
		"",
		failReader{t},
		&out,
	)
	if err == nil || !strings.Contains(err.Error(), "unknown route") {
		t.Fatalf("err = %v", err)
	}
}
