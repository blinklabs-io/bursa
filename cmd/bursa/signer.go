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
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/logging"
	"github.com/blinklabs-io/bursa/internal/signer"
	"github.com/blinklabs-io/bursa/internal/signer/api"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/operation"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
)

// maxRequestSignSkewSeconds bounds signer.request_sign_skew_seconds. It also
// caps the nonce cache TTL (2x skew), so a very large skew is rejected at boot
// rather than silently widening the replay window and shortening how long the
// bounded nonce cache can absorb traffic before failing closed.
const maxRequestSignSkewSeconds = 300

func signerCommand() *cobra.Command {
	var configFile string

	cmd := &cobra.Command{
		Use:   "signer",
		Short: "Run the Cardano remote signing service",
		Long: `Run the Cardano remote signing service.

Authentication (at least one mode must be configured; modes are composable and
resolve to a single caller identity fed to the signer.callers ACL):

  JWT bearer          at most one of signer.jwt_secret (HS256, dev/simple) or
                      signer.jwks_url (RS256/ES256/EdDSA via JWKS, production);
                      optional signer.jwt_issuer / signer.jwt_audience are
                      enforced when set. Caller is the token subject.
  mTLS client cert    signer.client_ca_cert (PEM) + signer.require_client_cert.
                      Caller is derived from the verified client certificate
                      (first URI SAN, else first DNS SAN, else CN). Requires
                      server TLS. Takes precedence over the other modes.
  Request signing     signer.authorized_keys (caller + ed25519_pubkey_hex). The
                      client signs METHOD|PATH|sha256(body)|timestamp|nonce and
                      sends X-Bursa-{Signature,Timestamp,Nonce,Key}. Rejected
                      outside signer.request_sign_skew_seconds (default 60) or on
                      a reused (key,nonce). Caller is the named key.

Without a signer.callers ACL, any authenticated caller may use any configured
key.`,
		Run: func(cmd *cobra.Command, args []string) {
			logging.ConfigureJSON()

			logger := logging.GetLogger()

			// Honor BURSA_CONFIG env if --config was not provided.
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

			// Cheap config validation before any expensive I/O.
			hasSecret := cfg.Signer.JWTSecret != ""
			hasJWKS := cfg.Signer.JWKSURL != ""
			if hasSecret && hasJWKS {
				logger.Error("at most one of signer.jwt_secret and signer.jwks_url may be set")
				os.Exit(1)
			}
			hasJWT := hasSecret || hasJWKS
			hasMTLS := cfg.Signer.ClientCACert != ""
			hasReqSign := len(cfg.Signer.AuthorizedKeys) > 0
			if !hasJWT && !hasMTLS && !hasReqSign {
				logger.Error("at least one auth mode must be configured (signer.jwt_secret, signer.jwks_url, signer.client_ca_cert, or signer.authorized_keys)")
				os.Exit(1)
			}
			if cfg.Signer.RequireClientCert && !hasMTLS {
				logger.Error("signer.require_client_cert requires signer.client_ca_cert")
				os.Exit(1)
			}
			authorizedKeys, err := signer.BuildAuthorizedKeys(cfg.Signer.AuthorizedKeys)
			if err != nil {
				logger.Error("invalid signer.authorized_keys", "error", err)
				os.Exit(1)
			}
			aclMap, err := signer.BuildCallerACL(cfg.Signer.Callers)
			if err != nil {
				logger.Error("invalid signer.callers", "error", err)
				os.Exit(1)
			}
			acl := api.NewCallerACL(aclMap)
			if !acl.Restricted() {
				logger.Warn("no signer.callers configured; any valid token may use any configured key")
			}

			// Signal-cancellable root context for graceful shutdown.
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			backends, err := signer.BuildBackends(ctx, cfg.Signer.Backends)
			if err != nil {
				logger.Error("failed to build backends", "error", err)
				os.Exit(1)
			}
			if len(backends) == 0 {
				logger.Error("no signer backends configured")
				os.Exit(1)
			}
			resolver := backend.NewResolver(backends...)

			// Fix 5: ambiguous duplicate-hash check — same key hash in multiple
			// backends is a config error; fail at boot rather than silently
			// routing to whichever backend happens to be first.
			if err := resolver.CheckAmbiguous(ctx); err != nil {
				logger.Error("ambiguous key configuration", "error", err)
				os.Exit(1)
			}

			pols, err := signer.BuildPolicies(cfg.Signer.Keys)
			if err != nil {
				logger.Error("failed to build policies", "error", err)
				os.Exit(1)
			}
			eng, err := policy.NewEngine(pols)
			if err != nil {
				logger.Error("invalid policy", "error", err)
				os.Exit(1)
			}
			wm, mode, err := signer.BuildWatermark(cfg.Signer.Watermark)
			if err != nil {
				logger.Error("failed to build watermark", "error", err)
				os.Exit(1)
			}

			m := signer.NewMetrics()
			m.Register(prometheus.DefaultRegisterer)

			coord := signer.New(signer.Deps{
				Resolver:  resolver,
				Policy:    eng,
				Watermark: wm,
				WMMode:    mode,
				Cardano:   operation.BursaCardano{},
				Logger:    logger,
				Metrics:   m,
			})

			var validate api.Validator
			switch {
			case hasJWKS:
				validate, err = api.JWKSValidator(ctx, cfg.Signer.JWKSURL, cfg.Signer.JWTIssuer, cfg.Signer.JWTAudience)
				if err != nil {
					logger.Error("failed to initialize JWKS validator", "error", err)
					os.Exit(1)
				}
			case hasSecret:
				// Require a minimum of 32 bytes so the shared secret is not
				// trivially brute-forceable.
				if len(cfg.Signer.JWTSecret) < 32 {
					logger.Error("signer.jwt_secret must be at least 32 bytes")
					os.Exit(1)
				}
				validate = api.HS256Validator([]byte(cfg.Signer.JWTSecret), cfg.Signer.JWTIssuer, cfg.Signer.JWTAudience)
			}
			// Both JWT modes enforce jwt_issuer/jwt_audience when set; warn when
			// either is unset so operators know any-issuer / any-audience tokens
			// are accepted.
			if hasJWT && cfg.Signer.JWTIssuer == "" {
				logger.Warn("signer.jwt_issuer is not set; tokens from any issuer signed by a trusted key will be accepted")
			}
			if hasJWT && cfg.Signer.JWTAudience == "" {
				logger.Warn("signer.jwt_audience is not set; tokens for any audience signed by a trusted key will be accepted")
			}
			srv := api.NewServer(coord, resolver, eng, acl, validate)
			if hasReqSign {
				// Reject an out-of-range skew rather than silently falling back
				// to the 60s default inside NewRequestSigningAuthenticator: an
				// operator who deliberately tightens or misconfigures this
				// value should get a boot-time error, not a quietly different
				// security posture.
				if cfg.Signer.RequestSignSkewSeconds < 0 || cfg.Signer.RequestSignSkewSeconds > maxRequestSignSkewSeconds {
					logger.Error(
						"signer.request_sign_skew_seconds must be between 0 and "+strconv.Itoa(maxRequestSignSkewSeconds),
						"value", cfg.Signer.RequestSignSkewSeconds,
					)
					os.Exit(1)
				}
				skew := time.Duration(cfg.Signer.RequestSignSkewSeconds) * time.Second
				srv.SetRequestSigningAuthenticator(api.NewRequestSigningAuthenticator(authorizedKeys, skew))
			}

			mux := http.NewServeMux()
			mux.Handle("/v1/", srv.Handler())
			mux.Handle("/", api.HealthHandler())
			mux.Handle("/metrics", promhttp.Handler())

			addr := fmt.Sprintf("%s:%d", cfg.Signer.ListenAddress, cfg.Signer.ListenPort)
			tlsConfigured := cfg.Signer.TLSCertFile != "" || cfg.Signer.TLSKeyFile != ""
			if (cfg.Signer.TLSCertFile == "") != (cfg.Signer.TLSKeyFile == "") {
				logger.Error("signer TLS requires both tls_cert_file and tls_key_file")
				os.Exit(1)
			}
			// mTLS verifies client certs during the TLS handshake, so it needs
			// server TLS enabled.
			if hasMTLS && !tlsConfigured {
				logger.Error("signer.client_ca_cert requires server TLS (signer.tls_cert_file and signer.tls_key_file)")
				os.Exit(1)
			}
			if !tlsConfigured && !isLocalListenAddress(cfg.Signer.ListenAddress) {
				logger.Error("refusing plaintext signer listener on non-loopback address",
					"listen_address", cfg.Signer.ListenAddress,
					"hint", "configure signer.tls_cert_file and signer.tls_key_file or bind signer.listen_address to localhost/127.0.0.1",
				)
				os.Exit(1)
			}
			httpServer := &http.Server{
				Addr:              addr,
				Handler:           mux,
				ReadHeaderTimeout: 10 * time.Second,
			}
			if tlsConfigured {
				tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
				if hasMTLS {
					pool, err := api.LoadClientCAPool(cfg.Signer.ClientCACert)
					if err != nil {
						logger.Error("failed to load signer.client_ca_cert", "error", err)
						os.Exit(1)
					}
					tlsCfg.ClientCAs = pool
					if cfg.Signer.RequireClientCert {
						tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
					} else {
						tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
					}
					srv.SetMTLSAuthenticator(api.NewMTLSAuthenticator())
				}
				httpServer.TLSConfig = tlsCfg
			}
			logger.Info("starting bursa signer", "address", addr, "tls", tlsConfigured)

			// Serve in a goroutine so we can listen for shutdown signals.
			serveErr := make(chan error, 1)
			go func() {
				if tlsConfigured {
					serveErr <- httpServer.ListenAndServeTLS(cfg.Signer.TLSCertFile, cfg.Signer.TLSKeyFile)
					return
				}
				serveErr <- httpServer.ListenAndServe()
			}()

			select {
			case err := <-serveErr:
				if !errors.Is(err, http.ErrServerClosed) {
					logger.Error("signer server exited", "error", err)
					os.Exit(1)
				}
			case <-ctx.Done():
				logger.Info("shutdown signal received; draining connections")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := httpServer.Shutdown(shutdownCtx); err != nil {
					logger.Error("graceful shutdown failed", "error", err)
					os.Exit(1)
				}
				logger.Info("signer shutdown complete")
			}
		},
	}
	cmd.Flags().StringVar(
		&configFile, "config", "",
		"path to YAML config file (env: BURSA_CONFIG)",
	)
	return cmd
}

func isLocalListenAddress(addr string) bool {
	host := strings.TrimSpace(addr)
	if host == "" {
		return false
	}
	if splitHost, _, err := net.SplitHostPort(host); err == nil {
		host = splitHost
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	parsed, err := netip.ParseAddr(host)
	return err == nil && parsed.IsLoopback()
}
