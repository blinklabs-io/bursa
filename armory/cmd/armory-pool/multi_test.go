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

// multiServer serves a multi provisioning image, with its signing and wipe
// endpoints, on a fake chip.
func multiServer(t *testing.T) *httptest.Server {
	t.Helper()

	svc := device.New(&sync.Mutex{}, t.Logf)
	svc.SetScopes(device.MultiScopes())
	svc.AllowFirstHostKey()

	if err := svc.SetChip(&fakeChip{keys: map[uint32]ed25519.PrivateKey{}, bins: map[uint32][]byte{}}); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/wipe/", svc.WipeHandler())
	mux.Handle("/", svc.Handler())

	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Host = device.Address
			mux.ServeHTTP(w, r)
		}),
	)
	t.Cleanup(srv.Close)

	return srv
}

func TestMultiImageWithScopedHostKeys(t *testing.T) {
	t.Parallel()

	srv := multiServer(t)
	dir := t.TempDir()
	scopes := []string{"cardano-mainnet", "testnet", "prime-mainnet"}

	// each key is made for its scope and its printed request registers it:
	// the device's first key unsigned, then the others signed by that
	// mainnet key, picked from the directory with -scope
	for i, sc := range scopes {
		var out bytes.Buffer

		if err := run([]string{"host-key", "-scope", sc, "-out", filepath.Join(dir, sc+".key")}, &out); err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(out.String(), `"scope":"`+sc+`"`) {
			t.Fatalf("host-key request does not name %s: %s", sc, out.String())
		}

		args := []string{"provision", "host-key"}
		if i > 0 {
			args = append(
				[]string{"-host-key-dir", dir, "-scope", scopes[0]},
				args...)
		}

		if _, err := adminRun(srv, out.String(), args...); err != nil {
			t.Fatalf("first %s key: %v", sc, err)
		}
	}

	keys := []string{"-host-key-dir", dir}

	// device-wide and cold requests name no profile: -scope picks the key
	var ident device.IdentityResponse

	out, err := adminRun(
		srv,
		"{}",
		append(
			append([]string{}, keys...),
			"-scope",
			"cardano-mainnet",
			"provision",
			"identity",
		)...)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	if err = json.Unmarshal([]byte(out), &ident); err != nil {
		t.Fatal(err)
	}

	if _, err = adminRun(srv, "{}", append(append([]string{}, keys...), "provision", "identity")...); err == nil {
		t.Fatal("a device-wide request picked a key with no scope named")
	}

	seed := hex.EncodeToString(bytes.Repeat([]byte{0x61}, 32))
	cold := `{"cold_key_id":` + "551878673" + `,"signing_key":"5820` + seed + `"}`

	if _, err = adminRun(srv, cold, append(append([]string{}, keys...), "-scope", "testnet", "provision", "cold")...); err != nil {
		t.Fatalf("cold: %v", err)
	}

	// the profile's name picks the key: a testnet profile by the testnet key
	profileReq := `{"name":"otg@preview","network_id":0,"slot":0,"cold_key_id":551878673,"chain_counter":3}`

	if _, err = adminRun(srv, profileReq, append(append([]string{}, keys...), "provision", "profile")...); err != nil {
		t.Fatalf("profile: %v", err)
	}

	// a mainnet profile by the key of its chain, named by profile or by name
	seed2 := hex.EncodeToString(bytes.Repeat([]byte{0x62}, 32))
	cold2 := `{"cold_key_id":551878684,"signing_key":"5820` + seed2 + `"}`

	// a prime key does not import into an object the testnet key owns
	outside := `{"cold_key_id":551878673,"signing_key":"5820` + seed2 + `"}`
	if _, err = adminRun(srv, outside, append(append([]string{}, keys...), "-scope", "prime-mainnet", "provision", "cold")...); err == nil ||
		!strings.Contains(err.Error(), "belongs to another scope") {
		t.Fatalf("prime cold into the testnet's object: %v", err)
	}

	if _, err = adminRun(srv, cold2, append(append([]string{}, keys...), "-scope", "prime-mainnet", "provision", "cold")...); err != nil {
		t.Fatalf("prime cold: %v", err)
	}

	primeReq := `{"name":"pool@prime-mainnet","network_id":1,"slot":1,"cold_key_id":551878684,"chain_counter":3}`

	if _, err = adminRun(srv, primeReq, append(append([]string{}, keys...), "provision", "profile")...); err != nil {
		t.Fatalf("prime profile: %v", err)
	}

	if _, err = adminRun(srv, `{"profile":"pool@prime-mainnet","chain_counter":4}`, append(append([]string{}, keys...), "provision", "floor")...); err != nil {
		t.Fatalf("prime floor: %v", err)
	}

	// with the key of another scope the device refuses it
	_, err = adminRun(
		srv,
		strings.Replace(profileReq, "otg@preview", "x@preview", 1),
		"-host-key",
		filepath.Join(dir, "prime-mainnet.key"),
		"provision",
		"profile",
	)
	if err == nil || !strings.Contains(err.Error(), "not of the scope") {
		t.Fatalf("a prime key provisioned a testnet profile: %v", err)
	}

	// inventory is signed by the key of the profile's scope; the device
	// refuses the other keys
	args := func(extra ...string) []string {
		return append([]string{
			"-signer", srv.URL, "-source", "", "-identity", hex.EncodeToString(ident.PublicKey), "-profile", "otg@preview",
		}, append(extra, "keys", "-out-dir", t.TempDir())...)
	}

	if err = run(args("-host-key-dir", dir), &bytes.Buffer{}); err != nil {
		t.Fatalf("keys with the scope's key: %v", err)
	}

	err = run(
		args("-host-key", filepath.Join(dir, "prime-mainnet.key")),
		&bytes.Buffer{},
	)
	if err == nil || !strings.Contains(err.Error(), "not of the scope") {
		t.Fatalf("keys with a prime key: %v", err)
	}

	if err = run(args(), &bytes.Buffer{}); err == nil {
		t.Fatal("keys without a host key on a multi image")
	}
}

func TestScopeOfProfileName(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]string{
		"otg@preview":          "testnet",
		"musashi@preprod":      "testnet",
		"plain":                "testnet",
		"pool@cardano-mainnet": "cardano-mainnet",
		"pool@prime-mainnet":   "prime-mainnet",
		"a@b@prime-mainnet":    "prime-mainnet",
		// a label no multi image serves is no mainnet scope
		"x@other-mainnet": "testnet",
	} {
		if got := profileScope(name); got != want {
			t.Errorf("profileScope(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestHostKeyDirRefusesPathScope(t *testing.T) {
	t.Parallel()

	for _, sc := range []string{"", "../x", "a/b", "Testnet", "other-mainnet"} {
		if _, err := scopedHostKeyFile(t.TempDir(), sc); err == nil {
			t.Errorf("scope %q picked a key file", sc)
		}
	}
}

// When the challenge for the signed inventory retry fails, that failure is
// reported alongside the refusal of the unsigned request.
func TestInventoryRetryReportsChallengeFailure(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/challenge" {
				http.Error(
					w,
					"challenge table full",
					http.StatusServiceUnavailable,
				)
				return
			}

			http.Error(w, "host key not registered", http.StatusBadRequest)
		}),
	)
	t.Cleanup(srv.Close)

	s := &session{
		c:       newClient(srv.URL, ""),
		profile: "otg@preview",
		hostKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)),
	}

	_, err := s.inventory()
	if err == nil ||
		!strings.Contains(err.Error(), "host key not registered") ||
		!strings.Contains(err.Error(), "challenge table full") {
		t.Fatalf(
			"err = %v, want both the refusal and the challenge failure",
			err,
		)
	}
}

// The -scope help names each scope and says cold key objects are owned, not
// assigned to a range.
func TestScopeHelpDescribesColdKeyOwnership(t *testing.T) {
	t.Parallel()

	help := scopeHelp()
	for _, want := range []string{"testnet", "cardano-mainnet", "prime-mainnet", "free cold key object", "belongs to the scope"} {
		if !strings.Contains(help, want) {
			t.Errorf("scope help %q lacks %q", help, want)
		}
	}

	if strings.Contains(help, "0x20e5") {
		t.Errorf("scope help %q still names object ranges", help)
	}
}
