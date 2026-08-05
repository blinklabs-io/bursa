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
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	bursa "github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/kesagent"
	"github.com/blinklabs-io/bursa/internal/logging"
	"github.com/blinklabs-io/bursa/internal/version"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
)

func kesAgentCommand() *cobra.Command {
	var configFile string

	cmd := &cobra.Command{
		Use:   "kes-agent",
		Short: "Run the KES agent daemon for a Cardano block producer",
		Long: `Run the KES agent daemon.

The KES agent holds the block-production KES signing key in locked secure
memory, evolves it forward-securely each KES period, and serves it to a Go
block producer (dingo) over a Unix socket. It runs in one of two modes:

  serve-key  push the current KES signing key (with its opcert) to the producer
  sign       sign block headers on the producer's behalf; the key never leaves

The pool cold signing key never touches the agent: it only holds the cold
verification key and consumes the operational certificate the cold signer
issued. Manage keys over the control socket: gen-staged-key, install-key,
drop-key, info.`,
		Run: func(cmd *cobra.Command, args []string) {
			logging.ConfigureJSON()
			logger := logging.GetLogger()

			if configFile == "" {
				configFile = os.Getenv("BURSA_CONFIG")
			}
			cfg, err := config.LoadConfigFile(configFile)
			if err != nil {
				logger.Error("failed to load config", "error", err)
				os.Exit(1)
			}
			logging.ConfigureJSON()
			logger = logging.GetLogger()

			kc := cfg.KESAgent
			if kc.Mode != kesagent.ModeServeKey && kc.Mode != kesagent.ModeSign {
				logger.Error("kes_agent.mode must be \"serve-key\" or \"sign\"", "mode", kc.Mode)
				os.Exit(1)
			}
			if kc.ServiceSocket == "" || kc.ControlSocket == "" {
				logger.Error("kes_agent.service_socket and kes_agent.control_socket are required")
				os.Exit(1)
			}
			if kc.SlotsPerKESPeriod == 0 {
				logger.Error("kes_agent.slots_per_kes_period must be set")
				os.Exit(1)
			}
			systemStart, err := time.Parse(time.RFC3339, kc.SystemStart)
			if err != nil {
				logger.Error("kes_agent.system_start must be RFC3339", "error", err)
				os.Exit(1)
			}
			coldVKey, err := loadColdVKey(kc.ColdVKeyHex, kc.ColdVKeyFile)
			if err != nil {
				logger.Error("failed to load cold verification key", "error", err)
				os.Exit(1)
			}
			socketMode, err := parseSocketMode(kc.SocketMode)
			if err != nil {
				logger.Error("invalid kes_agent.socket_mode", "error", err)
				os.Exit(1)
			}
			evolveInterval := time.Minute
			if kc.EvolveInterval != "" {
				evolveInterval, err = time.ParseDuration(kc.EvolveInterval)
				if err != nil {
					logger.Error("invalid kes_agent.evolve_interval", "error", err)
					os.Exit(1)
				}
			}
			slotLen := kc.SlotLength
			if slotLen <= 0 {
				slotLen = 1
			}

			metrics := kesagent.NewMetrics()
			metrics.Register(prometheus.DefaultRegisterer)

			agent, err := kesagent.New(kesagent.Config{
				Mode:              kc.Mode,
				SystemStart:       systemStart,
				SlotLength:        time.Duration(slotLen * float64(time.Second)),
				SlotsPerKESPeriod: kc.SlotsPerKESPeriod,
				MaxKESEvolutions:  kc.MaxKESEvolutions,
				ColdVKey:          coldVKey,
				EvolveInterval:    evolveInterval,
				GuardPath:         kc.GuardFile,
				Version:           version.GetVersionString(),
			}, logger, metrics)
			if err != nil {
				logger.Error("failed to create KES agent", "error", err)
				os.Exit(1)
			}
			defer agent.Close()

			serviceLn, err := kesagent.ListenUnix(kc.ServiceSocket, socketMode)
			if err != nil {
				logger.Error("failed to open service socket", "error", err)
				os.Exit(1)
			}
			controlLn, err := kesagent.ListenUnix(kc.ControlSocket, socketMode)
			if err != nil {
				logger.Error("failed to open control socket", "error", err)
				os.Exit(1)
			}

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			// Optional metrics HTTP endpoint.
			var metricsSrv *http.Server
			if cfg.Metrics.ListenPort != 0 {
				addr := fmt.Sprintf("%s:%d", cfg.Metrics.ListenAddress, cfg.Metrics.ListenPort)
				mux := http.NewServeMux()
				mux.Handle("/metrics", promhttp.Handler())
				metricsSrv = &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
				go func() {
					if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
						logger.Error("metrics server exited", "error", err)
					}
				}()
			}

			errCh := make(chan error, 2)
			go func() { errCh <- agent.ServeService(ctx, serviceLn) }()
			go func() { errCh <- agent.ServeControl(ctx, controlLn) }()
			go agent.Run(ctx)

			logger.Info("starting bursa kes-agent",
				"mode", kc.Mode,
				"service_socket", kc.ServiceSocket,
				"control_socket", kc.ControlSocket,
				"cold_vkey", hex.EncodeToString(coldVKey),
			)

			select {
			case err := <-errCh:
				if err != nil {
					logger.Error("kes-agent listener exited", "error", err)
					os.Exit(1)
				}
			case <-ctx.Done():
				logger.Info("shutdown signal received")
			}
			if metricsSrv != nil {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = metricsSrv.Shutdown(shutdownCtx)
			}
			_ = os.Remove(kc.ServiceSocket)
			_ = os.Remove(kc.ControlSocket)
			logger.Info("kes-agent shutdown complete")
		},
	}
	cmd.Flags().StringVar(&configFile, "config", "", "path to YAML config file (env: BURSA_CONFIG)")
	return cmd
}

// loadColdVKey resolves the pool cold verification key from an inline hex value
// or a file (cardano-cli text envelope or raw/hex), returning the raw 32 bytes.
func loadColdVKey(hexStr, filePath string) ([]byte, error) {
	if hexStr != "" {
		raw, err := hex.DecodeString(strings.TrimSpace(hexStr))
		if err != nil {
			return nil, fmt.Errorf("cold_vkey_hex: %w", err)
		}
		return unwrapVKey(raw)
	}
	if filePath == "" {
		return nil, errors.New("one of kes_agent.cold_vkey_hex or kes_agent.cold_vkey_file is required")
	}
	raw, err := bursa.ReadCborInputFile(filePath)
	if err != nil {
		return nil, err
	}
	return unwrapVKey(raw)
}

// unwrapVKey returns the raw 32-byte key from either a bare 32-byte value or a
// CBOR bytestring wrapping it.
func unwrapVKey(b []byte) ([]byte, error) {
	if len(b) == 32 {
		return b, nil
	}
	var inner []byte
	if _, err := cbor.Decode(b, &inner); err != nil {
		return nil, fmt.Errorf("cold vkey is neither 32 raw bytes nor CBOR bytes: %w", err)
	}
	if len(inner) != 32 {
		return nil, fmt.Errorf("cold vkey must be 32 bytes, got %d", len(inner))
	}
	return inner, nil
}

// parseSocketMode parses an octal file-mode string (e.g. "0600"), defaulting to
// 0600 when empty.
func parseSocketMode(s string) (os.FileMode, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0o600, nil
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("socket mode %q: %w", s, err)
	}
	return os.FileMode(v), nil
}
