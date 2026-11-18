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
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/confidentialspace"
)

var importKeyProfiles = []confidentialspace.ImportProfile{
	{Profile: "pool@mainnet", NextIssueNumber: 4},
	{Profile: "pool@preview", NextIssueNumber: 0},
}

func TestLoadImportKeysSharedKey(t *testing.T) {
	t.Parallel()
	f := newImportFixture(t)
	keys, err := loadImportKeys(
		[]string{f.signingKey}, []string{f.vkeyFile}, importKeyProfiles,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.wipe()
	if keys.byProfile != nil || !bytes.Equal(keys.seed, f.seed) ||
		!bytes.Equal(keys.vkey, f.vkey) {
		t.Fatalf("shared key not loaded as one key: %+v", keys)
	}
}

func TestLoadImportKeysPerProfile(t *testing.T) {
	t.Parallel()
	a, b := newImportFixture(t), newImportFixture(t)
	keys, err := loadImportKeys(
		[]string{"pool@mainnet=" + a.signingKey, "pool@preview=" + b.signingKey},
		[]string{"pool@preview=" + b.vkeyFile, "pool@mainnet=" + a.vkeyFile},
		importKeyProfiles,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.wipe()
	if keys.seed != nil || len(keys.byProfile) != 2 ||
		!bytes.Equal(keys.byProfile["pool@mainnet"].Seed, a.seed) ||
		!bytes.Equal(keys.byProfile["pool@mainnet"].VKey, a.vkey) ||
		!bytes.Equal(keys.byProfile["pool@preview"].Seed, b.seed) ||
		!bytes.Equal(keys.byProfile["pool@preview"].VKey, b.vkey) {
		t.Fatalf("each profile does not hold its own key: %+v", keys)
	}
}

func TestLoadImportKeysRefusals(t *testing.T) {
	t.Parallel()
	a, b := newImportFixture(t), newImportFixture(t)
	mainnetSK, previewSK := "pool@mainnet="+a.signingKey, "pool@preview="+b.signingKey
	mainnetVK, previewVK := "pool@mainnet="+a.vkeyFile, "pool@preview="+b.vkeyFile
	for name, tc := range map[string]struct{ sk, vk []string }{
		"mixed shared and per-profile": {
			[]string{a.signingKey, previewSK}, []string{a.vkeyFile, previewVK},
		},
		"two shared keys": {
			[]string{a.signingKey, b.signingKey}, []string{a.vkeyFile, b.vkeyFile},
		},
		"profile without a key": {
			[]string{mainnetSK}, []string{mainnetVK},
		},
		"key for an unnamed profile": {
			[]string{mainnetSK, previewSK, "pool@sancho=" + b.signingKey},
			[]string{mainnetVK, previewVK, "pool@sancho=" + b.vkeyFile},
		},
		"signing key without its vkey": {
			[]string{mainnetSK, previewSK}, []string{mainnetVK},
		},
		"vkey of another profile's key": {
			[]string{mainnetSK, previewSK},
			[]string{"pool@mainnet=" + b.vkeyFile, previewVK},
		},
		"profile keyed twice": {
			[]string{mainnetSK, mainnetSK, previewSK},
			[]string{mainnetVK, mainnetVK, previewVK},
		},
		"one key under two profiles": {
			[]string{mainnetSK, "pool@preview=" + a.signingKey},
			[]string{mainnetVK, "pool@preview=" + a.vkeyFile},
		},
	} {
		keys, err := loadImportKeys(tc.sk, tc.vk, importKeyProfiles)
		if err == nil {
			keys.wipe()
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRunConfidentialSpaceImportPerProfileKeys(t *testing.T) {
	t.Parallel()
	a, b := newImportFixture(t), newImportFixture(t)
	keys, err := loadImportKeys(
		[]string{"pool@mainnet=" + a.signingKey, "pool@preview=" + b.signingKey},
		[]string{"pool@mainnet=" + a.vkeyFile, "pool@preview=" + b.vkeyFile},
		importKeyProfiles,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.wipe()
	authorityPub, authority, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryImportStore{}
	importer, err := confidentialspace.NewImporter(confidentialspace.ImportConfig{
		Audience: "a", KMSKey: "k", Tokens: staticTokens{},
		Wrapper: identityWrapper{}, Store: store, Authority: authorityPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = importer.Close() })
	var imports int
	if err := runConfidentialSpaceImport(
		t.Context(),
		directTransport{importer: importer, imports: &imports},
		fakeVerifier{},
		keys.params("k", importKeyProfiles, authority),
	); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, vkey := range [][]byte{a.vkey, b.vkey} {
		if !bytes.Contains(
			store.envelope, []byte(base64.StdEncoding.EncodeToString(vkey)),
		) {
			t.Fatalf("envelope lacks an imported public key: %s", store.envelope)
		}
	}
	if store.nextIssue["pool@mainnet"] != 4 || store.nextIssue["pool@preview"] != 0 ||
		len(store.nextIssue) != 2 {
		t.Fatalf("starting counters %v", store.nextIssue)
	}
}
