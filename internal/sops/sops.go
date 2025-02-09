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
	"fmt"

	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	scommon "github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/decrypt"
	"github.com/getsops/sops/v3/gcpkms"
	skeys "github.com/getsops/sops/v3/keys"
	json "github.com/getsops/sops/v3/stores/json"
	"github.com/getsops/sops/v3/version"

	"github.com/blinklabs-io/bursa/internal/config"
)

func Decrypt(data []byte) ([]byte, error) {
	ret, err := decrypt.Data(data, "json")
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func Encrypt(data []byte) ([]byte, error) {
	input := &json.Store{}
	output := &json.Store{}

	// prevent double encryption
	branches, err := input.LoadPlainFile(data)
	if err != nil {
		return nil, fmt.Errorf("error loading data: %v", err)
	}
	for _, branch := range branches {
		for _, b := range branch {
			if b.Key == "sops" {
				return nil, fmt.Errorf("already encrypted")
			}
		}
	}

	cfg := config.GetConfig()

	// create tree and encrypt
	tree := sops.Tree{Branches: branches}
	// configure Google KMS to encrypt
	if cfg.Google.ResourceId != "" {
		keys := []skeys.MasterKey{}
		for _, k := range gcpkms.MasterKeysFromResourceIDString(
			cfg.Google.ResourceId,
		) {
			keys = append(keys, k)
		}
		keyGroups := []sops.KeyGroup{keys}
		tree.Metadata = sops.Metadata{
			KeyGroups: keyGroups,
			Version:   version.Version,
		}
	}
	dataKey, errors := tree.GenerateDataKey()
	if len(errors) > 0 {
		return nil, fmt.Errorf("failed generating data key: %v", errors)
	}
	err = scommon.EncryptTree(scommon.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  aes.NewCipher(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed encrypt: %v", err)
	}
	encryptData, err := output.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("failed output: %v", err)
	}
	return encryptData, nil
}
