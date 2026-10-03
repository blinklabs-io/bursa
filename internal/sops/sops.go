// Copyright 2025 Blink Labs Software
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

package sops

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/blinklabs-io/bursa/internal/config"
	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/age"
	scommon "github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/decrypt"
	"github.com/getsops/sops/v3/gcpkms"
	skeys "github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/kms"
	json "github.com/getsops/sops/v3/stores/json"
	"github.com/getsops/sops/v3/version"
)

func Decrypt(data []byte) ([]byte, error) {
	ret, err := decrypt.Data(data, "json")
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// ErrNoMasterKey is returned when no SOPS master key resource is configured.
var ErrNoMasterKey = errors.New(
	"no SOPS master key configured: set a google kms resource id, an aws kms key arn or age recipients",
)

// Configured reports whether any SOPS master key resource is set.
func Configured(cfg *config.Config) bool {
	return cfg.Google.ResourceId != "" ||
		cfg.Aws.KMSKeyARN != "" ||
		cfg.Age.Recipients != ""
}

// masterKeys builds the master keys for every configured resource. Any one of
// them can decrypt the result. It fails when none is configured or when a
// configured value is malformed.
func masterKeys(cfg *config.Config) ([]skeys.MasterKey, error) {
	if !Configured(cfg) {
		return nil, ErrNoMasterKey
	}
	keys := []skeys.MasterKey{}
	for _, k := range gcpkms.MasterKeysFromResourceIDString(
		cfg.Google.ResourceId,
	) {
		keys = append(keys, k)
	}
	if cfg.Aws.KMSKeyARN != "" {
		for _, v := range strings.Split(cfg.Aws.KMSKeyARN, ",") {
			parsed, err := arn.Parse(strings.TrimSpace(v))
			if err != nil || parsed.Service != "kms" {
				return nil, fmt.Errorf("invalid aws kms key arn %q", v)
			}
		}
		for _, k := range kms.MasterKeysFromArnString(cfg.Aws.KMSKeyARN, nil, "") {
			keys = append(keys, k)
		}
	}
	if cfg.Age.Recipients != "" {
		ageKeys, err := age.MasterKeysFromRecipients(cfg.Age.Recipients)
		if err != nil {
			return nil, fmt.Errorf("invalid age recipients: %w", err)
		}
		for _, k := range ageKeys {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func Encrypt(data []byte) ([]byte, error) {
	input := &json.Store{}
	output := &json.Store{}

	// prevent double encryption
	branches, err := input.LoadPlainFile(data)
	if err != nil {
		return nil, fmt.Errorf("error loading data: %w", err)
	}
	for _, branch := range branches {
		for _, b := range branch {
			if b.Key == "sops" {
				return nil, errors.New("already encrypted")
			}
		}
	}

	// Resolve and validate the master keys before touching the data so a
	// missing or malformed resource is reported as such, not as a tree error.
	keys, err := masterKeys(config.GetConfig())
	if err != nil {
		return nil, err
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{keys},
			Version:   version.Version,
		},
	}
	dataKey, errs := tree.GenerateDataKey()
	if len(errs) > 0 {
		return nil, fmt.Errorf("failed generating data key: %v", errs)
	}
	err = scommon.EncryptTree(scommon.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  aes.NewCipher(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed encrypt: %w", err)
	}
	encryptData, err := output.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("failed output: %w", err)
	}
	return encryptData, nil
}
