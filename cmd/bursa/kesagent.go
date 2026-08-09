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
			os.Exit(runKesAgent(configFile))
		},
	}
	cmd.Flags().StringVar(&configFile, "config", "", "path to YAML config file (env: BURSA_CONFIG)")
	return cmd
}

// runKesAgent runs the KES agent daemon to completion and returns the process
// exit code. It is a plain function (rather than logic inlined in cobra's
// Run) so that every exit path -- validation failure, listener setup
// failure, or a listener error at runtime -- returns normally and lets
// deferred cleanup (agent.Close(), which wipes the locked secure-memory KES
// buffer, and socket removal) run. os.Exit skips deferred functions, so it
// must only be called once, by the caller, after this function returns.
func runKesAgent(configFile string) int {
	logging.ConfigureJSON()
	logger := logging.GetLogger()

	if configFile == "" {
		configFile = os.Getenv("BURSA_CONFIG")
	}
	cfg, err := config.LoadConfigFile(configFile)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		return 1
	}
	logging.ConfigureJSON()
	logger = logging.GetLogger()

	kc := cfg.KESAgent
	if kc.Mode != kesagent.ModeServeKey && kc.Mode != kesagent.ModeSign {
		logger.Error("kes_agent.mode must be \"serve-key\" or \"sign\"", "mode", kc.Mode)
		return 1
	}
	if kc.ServiceSocket == "" || kc.ControlSocket == "" {
		logger.Error("kes_agent.service_socket and kes_agent.control_socket are required")
		return 1
	}
	if kc.ServiceSocket == kc.ControlSocket {
		logger.Error("kes_agent.service_socket and kes_agent.control_socket must be different paths",
			"path", kc.ServiceSocket)
		return 1
	}
	if kc.SlotsPerKESPeriod == 0 {
		logger.Error("kes_agent.slots_per_kes_period must be set")
		return 1
	}
	if kc.SlotLength <= 0 {
		logger.Error("kes_agent.slot_length must be positive", "slot_length", kc.SlotLength)
		return 1
	}
	systemStart, err := time.Parse(time.RFC3339, kc.SystemStart)
	if err != nil {
		logger.Error("kes_agent.system_start must be RFC3339", "error", err)
		return 1
	}
	coldVKey, err := loadColdVKey(kc.ColdVKeyHex, kc.ColdVKeyFile)
	if err != nil {
		logger.Error("failed to load cold verification key", "error", err)
		return 1
	}
	serviceSocketMode, err := parseSocketMode(kc.ServiceSocketMode)
	if err != nil {
		logger.Error("invalid kes_agent.service_socket_mode", "error", err)
		return 1
	}
	controlSocketMode, err := parseSocketMode(kc.ControlSocketMode)
	if err != nil {
		logger.Error("invalid kes_agent.control_socket_mode", "error", err)
		return 1
	}
	if err := validateControlSocketMode(controlSocketMode); err != nil {
		logger.Error("invalid kes_agent.control_socket_mode", "error", err)
		return 1
	}
	evolveInterval := time.Minute
	if kc.EvolveInterval != "" {
		evolveInterval, err = time.ParseDuration(kc.EvolveInterval)
		if err != nil {
			logger.Error("invalid kes_agent.evolve_interval", "error", err)
			return 1
		}
	}

	metrics := kesagent.NewMetrics()
	metrics.Register(prometheus.DefaultRegisterer)

	agent, err := kesagent.New(kesagent.Config{
		Mode:              kc.Mode,
		SystemStart:       systemStart,
		SlotLength:        time.Duration(kc.SlotLength * float64(time.Second)),
		SlotsPerKESPeriod: kc.SlotsPerKESPeriod,
		MaxKESEvolutions:  kc.MaxKESEvolutions,
		ColdVKey:          coldVKey,
		EvolveInterval:    evolveInterval,
		GuardPath:         kc.GuardFile,
		Version:           version.GetVersionString(),
	}, logger, metrics)
	if err != nil {
		logger.Error("failed to create KES agent", "error", err)
		return 1
	}
	defer agent.Close()

	serviceLn, err := kesagent.ListenUnix(kc.ServiceSocket, serviceSocketMode)
	if err != nil {
		logger.Error("failed to open service socket", "error", err)
		return 1
	}

	controlLn, err := kesagent.ListenUnix(kc.ControlSocket, controlSocketMode)
	if err != nil {
		logger.Error("failed to open control socket", "error", err)
		_ = serviceLn.Close()
		_ = os.Remove(kc.ServiceSocket)
		return 1
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

	exitCode := 0
	select {
	case err := <-errCh:
		if err != nil {
			logger.Error("kes-agent listener exited", "error", err)
			exitCode = 1
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
	return exitCode
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
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %w", filePath, err)
	}
	// A raw 32-byte binary file (one of the documented formats) is not valid
	// hex or JSON text, so it must be detected before routing through
	// ReadCborInput, which only understands hex-encoded or envelope text.
	// Guard the heuristic with looksLikeText: raw key material is random
	// bytes and vanishingly unlikely to be all printable text, so a 32-byte
	// file that IS text-shaped (e.g. malformed/truncated hex or JSON that
	// happens to be 32 bytes long) still falls through to the decode path
	// below and surfaces a clear error instead of being silently accepted.
	if len(fileBytes) == 32 && !looksLikeText(fileBytes) {
		return unwrapVKey(fileBytes)
	}
	raw, err := bursa.ReadCborInput(fileBytes)
	if err != nil {
		return nil, err
	}
	return unwrapVKey(raw)
}

// looksLikeText reports whether b consists entirely of printable ASCII and
// common whitespace (spaces, tabs, newlines) -- the shape of hex-encoded or
// JSON-envelope key files. Raw 32-byte key material is random and
// vanishingly unlikely to satisfy this.
func looksLikeText(b []byte) bool {
	for _, c := range b {
		switch {
		case c == '\n' || c == '\r' || c == '\t':
			continue
		case c < 0x20 || c > 0x7e:
			return false
		}
	}
	return true
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

// validateControlSocketMode rejects a control-socket mode that grants group
// or other write access. The control socket accepts gen-staged-key,
// install-key, and drop-key commands, so a group/other-writable peer could
// install or drop KES keys; unlike the service socket, it must never be
// widened beyond owner-only write access.
func validateControlSocketMode(mode os.FileMode) error {
	if mode.Perm()&0o022 != 0 {
		return fmt.Errorf(
			"control socket mode %04o must not grant group or other write access",
			mode.Perm(),
		)
	}
	return nil
}
