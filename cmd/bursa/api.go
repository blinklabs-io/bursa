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
	"errors"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof" // #nosec G108
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/blinklabs-io/bursa/internal/api"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/logging"
	"github.com/spf13/cobra"
)

// startDebugListener serves the pprof endpoints on a loopback address. It
// returns nil when the listener is disabled (port 0) and refuses any address
// other hosts could reach, since the endpoints are unauthenticated.
func startDebugListener(cfg config.DebugConfig) (*http.Server, error) {
	if cfg.ListenPort == 0 {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(cfg.ListenAddress, strconv.FormatUint(uint64(cfg.ListenPort), 10))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	slog.Info("starting debug listener on " + addr)
	debugger := &http.Server{ReadHeaderTimeout: 60 * time.Second}
	go func() {
		if err := debugger.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("debug listener stopped", "error", err)
		}
	}()
	return debugger, nil
}

func apiCommand() *cobra.Command {
	apiCommand := cobra.Command{
		Use:   "api",
		Short: "Runs the api",
		Run: func(cmd *cobra.Command, args []string) {
			logging.ConfigureJSON()

			cfg, err := config.LoadConfig()
			if err != nil {
				logging.GetLogger().Error("failed to load config", "error", err)
				os.Exit(1)
			}
			logging.ConfigureJSON()

			if _, err := startDebugListener(cfg.Debug); err != nil {
				logging.GetLogger().Error("failed to start debug listener", "error", err)
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
