// Copyright 2023 Blink Labs Software
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

	"github.com/blinklabs-io/bursa/internal/logging"
	"github.com/spf13/cobra"
)

const (
	programName = "bursa"
)

func main() {
	// Configure logging
	logging.Setup()
	logger := logging.GetLogger()
	defer func() {
		if err := logger.Sync(); err != nil {
			// ignore error
			return
		}
	}()

	rootCmd := &cobra.Command{
		Use: programName,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	rootCmd.AddCommand(
		walletCommand(),
		apiCommand(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
