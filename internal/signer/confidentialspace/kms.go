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

package confidentialspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"regexp"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	googleSTSURL   = "https://sts.googleapis.com/v1/token"
	jwtSubjectType = "urn:ietf:params:oauth:token-type:jwt"
	wifTokenFile   = "/run/container_launcher/attestation_verifier_claims_token"
)

var kmsKeyPattern = regexp.MustCompile(
	`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`,
)

var wifAudiencePattern = regexp.MustCompile(
	`^//iam\.googleapis\.com/projects/[0-9]+/locations/global/workloadIdentityPools/[^/]+/providers/[^/]+$`,
)

type kmsClient interface {
	Encrypt(
		context.Context,
		*kmspb.EncryptRequest,
		...gax.CallOption,
	) (*kmspb.EncryptResponse, error)
	Decrypt(
		context.Context,
		*kmspb.DecryptRequest,
		...gax.CallOption,
	) (*kmspb.DecryptResponse, error)
	Close() error
}

// CloudKMS wraps DEKs with one configured Cloud KMS key. Its credentials are
// restricted to a WIF external-account configuration sourced from the
// launcher's attestation token file.
type CloudKMS struct {
	key    string
	client kmsClient
}

// NewCloudKMS creates a KMS wrapper after validating the external-account
// credential file and key resource.
func NewCloudKMS(
	ctx context.Context,
	key, credentialFile string,
) (*CloudKMS, error) {
	if !kmsKeyPattern.MatchString(key) {
		return nil, errors.New("invalid Cloud KMS key resource")
	}
	if err := validateWIFCredentials(credentialFile); err != nil {
		return nil, err
	}
	client, err := kms.NewKeyManagementClient(
		ctx,
		option.WithAuthCredentialsFile(option.ExternalAccount, credentialFile),
	)
	if err != nil {
		return nil, fmt.Errorf("create Cloud KMS client: %w", err)
	}
	return &CloudKMS{key: key, client: client}, nil
}

type externalAccountConfig struct {
	Type                           string `json:"type"`
	Audience                       string `json:"audience"`
	SubjectTokenType               string `json:"subject_token_type"`
	TokenURL                       string `json:"token_url"`
	ServiceAccountImpersonationURL string `json:"service_account_impersonation_url"`
	CredentialSource               struct {
		File                        string          `json:"file"`
		URL                         string          `json:"url"`
		EnvironmentID               string          `json:"environment_id"`
		Executable                  json.RawMessage `json:"executable"`
		Certificate                 json.RawMessage `json:"certificate"`
		RegionURL                   string          `json:"region_url"`
		RegionalCredentialVerifyURL string          `json:"regional_cred_verification_url"`
		CredentialVerificationURL   string          `json:"cred_verification_url"`
		IMDSv2SessionTokenURL       string          `json:"imdsv2_session_token_url"`
		Format                      *struct {
			Type string `json:"type"`
		} `json:"format"`
	} `json:"credential_source"`
}

func validateWIFCredentials(path string) error {
	if path == "" {
		return errors.New("WIF credential file is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open WIF credential file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxRequestBody+1))
	if err != nil {
		return fmt.Errorf("read WIF credential file: %w", err)
	}
	if len(data) > maxRequestBody {
		return errors.New("WIF credential file exceeds size limit")
	}
	var cfg externalAccountConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("decode WIF credential file: %w", err)
	}
	if cfg.Type != "external_account" || cfg.SubjectTokenType != jwtSubjectType ||
		cfg.TokenURL != googleSTSURL {
		return errors.New(
			"credential file is not a Google STS external-account configuration",
		)
	}
	if cfg.ServiceAccountImpersonationURL != "" {
		return errors.New(
			"service account impersonation is not permitted for the workload",
		)
	}
	if !wifAudiencePattern.MatchString(cfg.Audience) {
		return errors.New(
			"credential file has an invalid workload identity provider audience",
		)
	}
	if cfg.CredentialSource.File != wifTokenFile ||
		cfg.CredentialSource.URL != "" ||
		cfg.CredentialSource.EnvironmentID != "" ||
		len(cfg.CredentialSource.Executable) != 0 ||
		len(cfg.CredentialSource.Certificate) != 0 ||
		cfg.CredentialSource.RegionURL != "" ||
		cfg.CredentialSource.RegionalCredentialVerifyURL != "" ||
		cfg.CredentialSource.CredentialVerificationURL != "" ||
		cfg.CredentialSource.IMDSv2SessionTokenURL != "" {
		return errors.New(
			"credential source must be the Confidential Space attestation token file",
		)
	}
	if cfg.CredentialSource.Format != nil &&
		cfg.CredentialSource.Format.Type != "text" {
		return errors.New("credential source token format must be text")
	}
	return nil
}

// Wrap encrypts a DEK and verifies Cloud KMS request and response integrity.
func (k *CloudKMS) Wrap(
	ctx context.Context,
	plaintext, aad []byte,
) ([]byte, error) {
	resp, err := k.client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:                              k.key,
		Plaintext:                         plaintext,
		AdditionalAuthenticatedData:       aad,
		PlaintextCrc32C:                   checksum(plaintext),
		AdditionalAuthenticatedDataCrc32C: checksum(aad),
	})
	if err != nil {
		return nil, err
	}
	if !resp.GetVerifiedPlaintextCrc32C() ||
		!resp.GetVerifiedAdditionalAuthenticatedDataCrc32C() {
		return nil, errors.New("cloud KMS did not verify request integrity")
	}
	if resp.GetCiphertextCrc32C() == nil ||
		resp.GetCiphertextCrc32C().GetValue() != checksumValue(resp.GetCiphertext()) {
		return nil, errors.New(
			"cloud KMS encrypt response failed integrity check",
		)
	}
	if !strings.HasPrefix(resp.GetName(), k.key+"/cryptoKeyVersions/") {
		return nil, errors.New("cloud KMS encrypted with an unexpected key")
	}
	return append([]byte(nil), resp.GetCiphertext()...), nil
}

// Unwrap decrypts a DEK and verifies Cloud KMS request and response integrity.
func (k *CloudKMS) Unwrap(
	ctx context.Context,
	ciphertext, aad []byte,
) ([]byte, error) {
	resp, err := k.client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:                              k.key,
		Ciphertext:                        ciphertext,
		AdditionalAuthenticatedData:       aad,
		CiphertextCrc32C:                  checksum(ciphertext),
		AdditionalAuthenticatedDataCrc32C: checksum(aad),
	})
	if err != nil {
		return nil, err
	}
	if resp.GetPlaintextCrc32C() == nil ||
		resp.GetPlaintextCrc32C().GetValue() != checksumValue(resp.GetPlaintext()) {
		wipe(resp.GetPlaintext())
		return nil, errors.New(
			"cloud KMS decrypt response failed integrity check",
		)
	}
	plaintext := append([]byte(nil), resp.GetPlaintext()...)
	wipe(resp.GetPlaintext())
	return plaintext, nil
}

// Close releases the Cloud KMS client.
func (k *CloudKMS) Close() error { return k.client.Close() }

func checksum(data []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(checksumValue(data))
}

func checksumValue(data []byte) int64 {
	return int64(crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)))
}
