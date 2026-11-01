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
	"os"
	"path/filepath"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type fakeKMSClient struct {
	encrypt func(*kmspb.EncryptRequest) (*kmspb.EncryptResponse, error)
	decrypt func(*kmspb.DecryptRequest) (*kmspb.DecryptResponse, error)
}

func (f *fakeKMSClient) Encrypt(
	_ context.Context,
	req *kmspb.EncryptRequest,
	_ ...gax.CallOption,
) (*kmspb.EncryptResponse, error) {
	return f.encrypt(req)
}

func (f *fakeKMSClient) Decrypt(
	_ context.Context,
	req *kmspb.DecryptRequest,
	_ ...gax.CallOption,
) (*kmspb.DecryptResponse, error) {
	return f.decrypt(req)
}

func (*fakeKMSClient) Close() error { return nil }

func TestCloudKMSIntegrity(t *testing.T) {
	t.Parallel()
	plain := []byte("01234567890123456789012345678901")
	aad := []byte("bound metadata")
	ciphertext := []byte("kms ciphertext")
	client := &fakeKMSClient{}
	client.encrypt = func(req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
		if req.Name != testKMSKey ||
			req.PlaintextCrc32C.Value != checksumValue(plain) ||
			req.AdditionalAuthenticatedDataCrc32C.Value != checksumValue(aad) {
			t.Fatalf("encrypt request = %+v", req)
		}
		return &kmspb.EncryptResponse{
			Name:       testKMSKey + "/cryptoKeyVersions/1",
			Ciphertext: ciphertext,
			CiphertextCrc32C: wrapperspb.Int64(
				checksumValue(ciphertext),
			),
			VerifiedPlaintextCrc32C:                   true,
			VerifiedAdditionalAuthenticatedDataCrc32C: true,
		}, nil
	}
	client.decrypt = func(req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
		if req.Name != testKMSKey ||
			req.CiphertextCrc32C.Value != checksumValue(ciphertext) ||
			req.AdditionalAuthenticatedDataCrc32C.Value != checksumValue(aad) {
			t.Fatalf("decrypt request = %+v", req)
		}
		return &kmspb.DecryptResponse{
			Plaintext:       append([]byte(nil), plain...),
			PlaintextCrc32C: wrapperspb.Int64(checksumValue(plain)),
		}, nil
	}
	k := &CloudKMS{key: testKMSKey, client: client}
	gotCiphertext, err := k.Wrap(t.Context(), plain, aad)
	if err != nil || string(gotCiphertext) != string(ciphertext) {
		t.Fatalf("Wrap = %q, %v", gotCiphertext, err)
	}
	gotPlain, err := k.Unwrap(t.Context(), ciphertext, aad)
	if err != nil || string(gotPlain) != string(plain) {
		t.Fatalf("Unwrap = %q, %v", gotPlain, err)
	}
}

func TestCloudKMSFailsClosed(t *testing.T) {
	t.Parallel()
	client := &fakeKMSClient{
		encrypt: func(*kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
			return &kmspb.EncryptResponse{Ciphertext: []byte("x")}, nil
		},
		decrypt: func(*kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
			return nil, errors.New("permission denied")
		},
	}
	k := &CloudKMS{key: testKMSKey, client: client}
	if _, err := k.Wrap(t.Context(), []byte("dek"), []byte("aad")); err == nil {
		t.Fatal("unverified KMS encrypt response accepted")
	}
	if _, err := k.Unwrap(t.Context(), []byte("wrapped"), []byte("aad")); err == nil {
		t.Fatal("KMS denial ignored")
	}
}

func TestValidateWIFCredentials(t *testing.T) {
	t.Parallel()
	valid := map[string]any{
		"type":               "external_account",
		"audience":           "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
		"subject_token_type": jwtSubjectType,
		"token_url":          googleSTSURL,
		"credential_source": map[string]any{
			"file":   wifTokenFile,
			"format": map[string]any{"type": "text"},
		},
	}
	write := func(t *testing.T, cfg map[string]any) string {
		t.Helper()
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "wif.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if err := validateWIFCredentials(write(t, valid)); err != nil {
		t.Fatalf("valid config: %v", err)
	}

	for name, mutate := range map[string]func(map[string]any){
		"service account": func(c map[string]any) { c["type"] = "service_account" },
		"wrong token URL": func(c map[string]any) { c["token_url"] = "https://evil.example" },
		"impersonation": func(c map[string]any) {
			c["service_account_impersonation_url"] = "https://iamcredentials.googleapis.com/x"
		},
		"URL source": func(c map[string]any) { c["credential_source"] = map[string]any{"url": "http://localhost/token"} },
		"other file": func(c map[string]any) { c["credential_source"] = map[string]any{"file": "/tmp/token"} },
		"AWS source override": func(c map[string]any) {
			c["credential_source"] = map[string]any{
				"file":           wifTokenFile,
				"environment_id": "aws1",
			}
		},
		"executable source": func(c map[string]any) {
			c["credential_source"] = map[string]any{
				"file":       wifTokenFile,
				"executable": map[string]any{"command": "/bin/false"},
			}
		},
		"malformed provider audience": func(c map[string]any) {
			c["audience"] = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider/extra"
		},
	} {
		t.Run(name, func(t *testing.T) {
			copyCfg := make(map[string]any, len(valid))
			for k, v := range valid {
				copyCfg[k] = v
			}
			mutate(copyCfg)
			if err := validateWIFCredentials(write(t, copyCfg)); err == nil {
				t.Fatal("unsafe credential configuration accepted")
			}
		})
	}
}
