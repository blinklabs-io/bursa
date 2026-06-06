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
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/blinklabs-io/bursa/internal/cli"
	"github.com/blinklabs-io/bursa/internal/logging"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func keyEncryptCommand() *cobra.Command {
	var inFile, outFile, passphraseFile string
	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a key file with a passphrase (scrypt + AES-256-GCM)",
		Run: func(cmd *cobra.Command, args []string) {
			passphrase, err := readPassphrase(cmd, passphraseFile, "Encryption passphrase: ")
			if err != nil {
				logging.GetLogger().Error("failed to read passphrase", "error", err)
				os.Exit(1)
			}
			if err := cli.RunKeyEncrypt(inFile, outFile, passphrase); err != nil {
				logging.GetLogger().Error("failed to encrypt key file", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&inFile, "in-file", "", "File to encrypt")
	cmd.Flags().StringVar(&outFile, "out-file", "", "Output file (default: overwrite in-file)")
	cmd.Flags().StringVar(&passphraseFile, "passphrase-file", "", "File containing encryption passphrase (use - for stdin)")
	_ = cmd.MarkFlagRequired("in-file")
	return cmd
}

func keyDecryptCommand() *cobra.Command {
	var inFile, outFile, passphraseFile string
	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt a passphrase-encrypted key file",
		Run: func(cmd *cobra.Command, args []string) {
			passphrase, err := readPassphrase(cmd, passphraseFile, "Decryption passphrase: ")
			if err != nil {
				logging.GetLogger().Error("failed to read passphrase", "error", err)
				os.Exit(1)
			}
			if err := cli.RunKeyDecrypt(inFile, outFile, passphrase); err != nil {
				logging.GetLogger().Error("failed to decrypt key file", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&inFile, "in-file", "", "File to decrypt")
	cmd.Flags().StringVar(&outFile, "out-file", "", "Output file (default: stdout)")
	cmd.Flags().StringVar(&passphraseFile, "passphrase-file", "", "File containing decryption passphrase (use - for stdin)")
	_ = cmd.MarkFlagRequired("in-file")
	return cmd
}

func readPassphrase(cmd *cobra.Command, passphraseFile, prompt string) (string, error) {
	var passphrase string
	if passphraseFile != "" {
		var data []byte
		var err error
		if passphraseFile == "-" {
			data, err = io.ReadAll(cmd.InOrStdin())
		} else {
			data, err = os.ReadFile(passphraseFile)
		}
		if err != nil {
			return "", err
		}
		passphrase = strings.TrimRight(string(data), "\r\n")
	} else {
		fd := int(os.Stdin.Fd())
		if !term.IsTerminal(fd) {
			return "", errors.New("passphrase is required via terminal prompt or --passphrase-file")
		}
		fmt.Fprint(cmd.ErrOrStderr(), prompt)
		data, err := term.ReadPassword(fd)
		fmt.Fprintln(cmd.ErrOrStderr())
		if err != nil {
			return "", err
		}
		passphrase = string(data)
	}
	if passphrase == "" {
		return "", errors.New("passphrase must not be empty")
	}
	return passphrase, nil
}
