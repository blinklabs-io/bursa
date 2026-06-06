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
	"os"

	"github.com/blinklabs-io/bursa/internal/cli"
	"github.com/blinklabs-io/bursa/internal/logging"
	"github.com/spf13/cobra"
)

func signCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "sign", Short: "CIP-8/CIP-30 message signing"}
	cmd.AddCommand(signDataCommand(), signVerifyCommand())
	return cmd
}

func signDataCommand() *cobra.Command {
	var address, payload, payloadHex, signingKeyFile string
	cmd := &cobra.Command{
		Use:   "data",
		Short: "Sign a payload (CIP-30 signData / COSE_Sign1)",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunSignData(address, payload, payloadHex, signingKeyFile); err != nil {
				logging.GetLogger().Error("failed to sign data", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&address, "address", "", "Hex-encoded address bytes for the protected header")
	cmd.Flags().StringVar(&payload, "payload", "", "Payload as UTF-8 text")
	cmd.Flags().StringVar(&payloadHex, "payload-hex", "", "Payload as hex")
	cmd.Flags().StringVar(&signingKeyFile, "signing-key-file", "", "Signing key file")
	_ = cmd.MarkFlagRequired("address")
	_ = cmd.MarkFlagRequired("signing-key-file")
	cmd.MarkFlagsMutuallyExclusive("payload", "payload-hex")
	return cmd
}

func signVerifyCommand() *cobra.Command {
	var signature, key, payload, payloadHex string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a CIP-30 signData signature",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.RunVerifyData(signature, key, payload, payloadHex); err != nil {
				logging.GetLogger().Error("verification failed", "error", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&signature, "signature", "", "Hex COSE_Sign1 signature")
	cmd.Flags().StringVar(&key, "key", "", "Hex COSE_Key")
	cmd.Flags().StringVar(&payload, "payload", "", "Expected payload as UTF-8 text")
	cmd.Flags().StringVar(&payloadHex, "payload-hex", "", "Expected payload as hex")
	_ = cmd.MarkFlagRequired("signature")
	_ = cmd.MarkFlagRequired("key")
	cmd.MarkFlagsMutuallyExclusive("payload", "payload-hex")
	return cmd
}
