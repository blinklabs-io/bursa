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

package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/sops"
)

func RunKeyEncrypt(inFile, outFile, passphrase string) error {
	if passphrase == "" {
		return errors.New("--passphrase is required")
	}
	data, err := os.ReadFile(inFile)
	if err != nil {
		return err
	}
	enc, err := sops.EncryptWithPassphrase(data, passphrase)
	if err != nil {
		return err
	}
	target := outFile
	if target == "" {
		target = inFile
	}
	return writeSecretFileAtomic(target, append(enc, '\n'))
}

func RunKeyDecrypt(inFile, outFile, passphrase string) error {
	if passphrase == "" {
		return errors.New("--passphrase is required")
	}
	data, err := os.ReadFile(inFile)
	if err != nil {
		return err
	}
	dec, err := sops.DecryptWithPassphrase(data, passphrase)
	if err != nil {
		return err
	}
	if outFile == "" {
		fmt.Print(string(dec))
		return nil
	}
	return writeSecretFileAtomic(outFile, dec)
}

func writeSecretFileAtomic(path string, data []byte) error {
	return bursa.WriteSecretKeyFile(path, data)
}
