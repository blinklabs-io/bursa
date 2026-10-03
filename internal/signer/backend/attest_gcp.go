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
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// ConfidentialSpaceIssuer is the issuer of Confidential Space attestation
	// tokens.
	ConfidentialSpaceIssuer = "https://confidentialcomputing.googleapis.com"
	// ConfidentialSpaceJWKSURL publishes the keys that sign those tokens.
	ConfidentialSpaceJWKSURL = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"

	confidentialSpaceSoftware = "CONFIDENTIAL_SPACE"
	// dbgstatDisabled is the only debug state a production workload may report.
	dbgstatDisabled = "disabled-since-boot"
)

// JWKSFunc returns the current signing keys for attestation tokens. Production
// fetches ConfidentialSpaceJWKSURL; tests inject a fixed set.
type JWKSFunc func(ctx context.Context) (jose.JSONWebKeySet, error)

// ConfidentialSpaceVerifier validates Google Cloud Attestation OIDC tokens for
// a Confidential Space workload.
type ConfidentialSpaceVerifier struct {
	jwks        JWKSFunc
	audience    string
	imageDigest string
	now         func() time.Time
}

// NewConfidentialSpaceVerifier builds a verifier that accepts only tokens
// issued for audience from a non-debug Confidential Space workload running the
// container image imageDigest (for example "sha256:...").
func NewConfidentialSpaceVerifier(jwks JWKSFunc, audience, imageDigest string) (*ConfidentialSpaceVerifier, error) {
	if jwks == nil {
		return nil, errors.New("confidential space verifier requires a key source")
	}
	if audience == "" {
		return nil, errors.New("confidential space verifier requires an audience")
	}
	if imageDigest == "" {
		return nil, errors.New("confidential space verifier requires an image digest")
	}
	return &ConfidentialSpaceVerifier{jwks: jwks, audience: audience, imageDigest: imageDigest, now: time.Now}, nil
}

type confidentialSpaceClaims struct {
	jwt.RegisteredClaims
	EATNonce jwt.ClaimStrings `json:"eat_nonce"`
	DbgStat  string           `json:"dbgstat"`
	SWName   string           `json:"swname"`
	SecBoot  bool             `json:"secboot"`
	Submods  struct {
		Container struct {
			ImageDigest string `json:"image_digest"`
		} `json:"container"`
	} `json:"submods"`
}

// Verify implements AttestationVerifier. The token must carry hex(binding) in
// eat_nonce.
func (v *ConfidentialSpaceVerifier) Verify(ctx context.Context, evidence, binding []byte) error {
	set, err := v.jwks(ctx)
	if err != nil {
		return fmt.Errorf("confidential space keys: %w", err)
	}
	var claims confidentialSpaceClaims
	_, err = jwt.ParseWithClaims(string(evidence), &claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		keys := set.Key(kid)
		if kid == "" || len(keys) == 0 {
			return nil, fmt.Errorf("no signing key for kid %q", kid)
		}
		return keys[0].Key, nil
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(ConfidentialSpaceIssuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.now),
	)
	if err != nil {
		return fmt.Errorf("confidential space token: %w", err)
	}
	if claims.DbgStat != dbgstatDisabled {
		return fmt.Errorf("confidential space workload is in debug state %q", claims.DbgStat)
	}
	if claims.SWName != confidentialSpaceSoftware {
		return fmt.Errorf("confidential space token swname is %q", claims.SWName)
	}
	if !claims.SecBoot {
		return errors.New("confidential space workload did not boot with secure boot")
	}
	if subtle.ConstantTimeCompare([]byte(claims.Submods.Container.ImageDigest), []byte(v.imageDigest)) != 1 {
		return errors.New("confidential space container image digest does not match")
	}
	want := hex.EncodeToString(binding)
	for _, n := range claims.EATNonce {
		if subtle.ConstantTimeCompare([]byte(n), []byte(want)) == 1 {
			return nil
		}
	}
	return errors.New("confidential space token eat_nonce does not match the attestation binding")
}
