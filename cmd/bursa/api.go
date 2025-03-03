// Copyright 2024 Blink Labs Software
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
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/blinklabs-io/bursa/internal/api"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/logging"
	"github.com/spf13/cobra"
)

func apiCommand() *cobra.Command {
	apiCommand := cobra.Command{
		Use:   "api",
		Short: "Runs the api",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.LoadConfig()
			if err != nil {
				logging.GetLogger().Error("failed to load config", "error", err)
				os.Exit(1)
			}

			// Create a context that can be canceled for graceful shutdown
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Handle interrupt signals for graceful shutdown
			go func() {
				sigChan := make(chan os.Signal, 1)
				signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
				<-sigChan
				cancel()
			}()

			// Start API listener
			if err := api.Start(ctx, cfg, nil, nil); err != nil {
				logging.GetLogger().Error("failed to start API:", "error", err)
				os.Exit(1)
			}
		},
	}
	return &apiCommand
}
