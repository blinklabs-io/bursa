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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

const (
	testAudience = "https://signer.example"
	testDigest   = "sha256:aaaa"
)

type gcpFixture struct {
	key     *rsa.PrivateKey
	now     time.Time
	binding []byte
}

func newGCPFixture(t *testing.T) *gcpFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &gcpFixture{key: key, now: time.Now(), binding: []byte("binding-0123456789abcdef01234567")}
}

func (f *gcpFixture) jwks(context.Context) (jose.JSONWebKeySet, error) {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256"}}}, nil
}

func (f *gcpFixture) verifier(t *testing.T) *ConfidentialSpaceVerifier {
	t.Helper()
	v, err := NewConfidentialSpaceVerifier(f.jwks, testAudience, testDigest)
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return f.now }
	return v
}

// token mints an attestation token that passes verification; mutate may spoil
// a claim, and kid names the signing key id.
func (f *gcpFixture) token(t *testing.T, kid string, mutate func(c jwt.MapClaims)) string {
	t.Helper()
	c := jwt.MapClaims{
		"iss": ConfidentialSpaceIssuer, "aud": testAudience,
		"iat": f.now.Add(-time.Minute).Unix(), "exp": f.now.Add(time.Hour).Unix(),
		"eat_nonce": []string{hex.EncodeToString(f.binding)},
		"dbgstat":   "disabled-since-boot", "swname": "CONFIDENTIAL_SPACE", "secboot": true,
		"submods": map[string]any{"container": map[string]any{"image_digest": testDigest}},
	}
	if mutate != nil {
		mutate(c)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestConfidentialSpaceVerifier(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		kid     string
		mutate  func(c jwt.MapClaims)
		wantErr bool
	}{
		{"valid", "k1", nil, false},
		{"wrong audience", "k1", func(c jwt.MapClaims) { c["aud"] = "https://other.example" }, true},
		{"expired", "k1", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, true},
		{"no expiry", "k1", func(c jwt.MapClaims) { delete(c, "exp") }, true},
		{"wrong issuer", "k1", func(c jwt.MapClaims) { c["iss"] = "https://evil.example" }, true},
		{"unapproved image digest", "k1", func(c jwt.MapClaims) {
			c["submods"] = map[string]any{"container": map[string]any{"image_digest": "sha256:bbbb"}}
		}, true},
		{"missing image digest", "k1", func(c jwt.MapClaims) { delete(c, "submods") }, true},
		{"debug workload", "k1", func(c jwt.MapClaims) { c["dbgstat"] = "enabled" }, true},
		{"not confidential space", "k1", func(c jwt.MapClaims) { c["swname"] = "OTHER" }, true},
		{"no secure boot", "k1", func(c jwt.MapClaims) { c["secboot"] = false }, true},
		{"nonce for another binding", "k1", func(c jwt.MapClaims) { c["eat_nonce"] = []string{"00"} }, true},
		{"missing nonce", "k1", func(c jwt.MapClaims) { delete(c, "eat_nonce") }, true},
		{"unknown signing key", "other", nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newGCPFixture(t)
			err := f.verifier(t).Verify(t.Context(), []byte(f.token(t, tc.kid, tc.mutate)), f.binding)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Verify error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestConfidentialSpaceVerifierRejectsUnattested(t *testing.T) {
	t.Parallel()
	f := newGCPFixture(t)
	v := f.verifier(t)

	if err := v.Verify(t.Context(), nil, f.binding); err == nil {
		t.Error("empty token accepted")
	}
	// A token signed with a key the verifier does not trust.
	rogue := newGCPFixture(t)
	if err := v.Verify(t.Context(), []byte(rogue.token(t, "k1", nil)), f.binding); err == nil {
		t.Error("token signed by an untrusted key accepted")
	}
	// An HMAC token keyed with the public key bytes must not pass for RS256.
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iss": ConfidentialSpaceIssuer, "aud": testAudience, "exp": f.now.Add(time.Hour).Unix()})
	hs.Header["kid"] = "k1"
	s, _ := hs.SignedString([]byte("secret"))
	if err := v.Verify(t.Context(), []byte(s), f.binding); err == nil {
		t.Error("HS256 token accepted")
	}
	// A token signed with an RSA algorithm other than RS256.
	rs512 := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"iss": ConfidentialSpaceIssuer, "aud": testAudience, "exp": f.now.Add(time.Hour).Unix(),
		"eat_nonce": []string{hex.EncodeToString(f.binding)}, "dbgstat": "disabled-since-boot",
		"swname": "CONFIDENTIAL_SPACE", "secboot": true,
		"submods": map[string]any{"container": map[string]any{"image_digest": testDigest}},
	})
	rs512.Header["kid"] = "k1"
	s, _ = rs512.SignedString(f.key)
	if err := v.Verify(t.Context(), []byte(s), f.binding); err == nil {
		t.Error("RS512 token accepted")
	}
	// An unsigned token.
	none := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"iss": ConfidentialSpaceIssuer, "aud": testAudience, "exp": f.now.Add(time.Hour).Unix()})
	s, _ = none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err := v.Verify(t.Context(), []byte(s), f.binding); err == nil {
		t.Error("unsigned token accepted")
	}
	// A key-source failure fails closed.
	failing, _ := NewConfidentialSpaceVerifier(func(context.Context) (jose.JSONWebKeySet, error) {
		return jose.JSONWebKeySet{}, errors.New("jwks unreachable")
	}, testAudience, testDigest)
	if err := failing.Verify(t.Context(), []byte(f.token(t, "k1", nil)), f.binding); err == nil {
		t.Error("token accepted while key source was down")
	}
}

func TestNewConfidentialSpaceVerifierValidatesConfig(t *testing.T) {
	t.Parallel()
	f := newGCPFixture(t)
	for name, args := range map[string]struct {
		jwks     JWKSFunc
		aud, dig string
	}{
		"no key source": {nil, testAudience, testDigest},
		"no audience":   {f.jwks, "", testDigest},
		"no digest":     {f.jwks, testAudience, ""},
	} {
		if _, err := NewConfidentialSpaceVerifier(args.jwks, args.aud, args.dig); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
