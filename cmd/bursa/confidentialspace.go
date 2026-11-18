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
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	bursa "github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/logging"
	signerapi "github.com/blinklabs-io/bursa/internal/signer/api"
	"github.com/blinklabs-io/bursa/internal/signer/confidentialspace"
	"github.com/spf13/cobra"
)

func confidentialSpaceCommand() *cobra.Command {
	var (
		listenAddress  string
		audience       string
		kmsKey         string
		stateSecret    string
		wrappedKeyFile string
		counterBucket  string
		counterObject  string
		wifCredentials string
		tlsSecret      string
		tlsCertFile    string
		tlsKeyFile     string
		clientCAFile   string
		profiles       []string
		createProfiles []string
	)
	cmd := &cobra.Command{
		Use:   "confidential-space-workload",
		Short: "Run pool cold-key custody inside GCP Confidential Space",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := validateConfidentialSpaceStorage(
				stateSecret,
				wrappedKeyFile,
				counterBucket,
				counterObject,
			); err != nil {
				return err
			}
			if err := validateConfidentialSpaceTLS(
				tlsSecret,
				tlsCertFile,
				tlsKeyFile,
			); err != nil {
				return err
			}
			logging.ConfigureJSON()
			ctx, stop := signal.NotifyContext(
				context.Background(),
				syscall.SIGINT,
				syscall.SIGTERM,
			)
			defer stop()
			tlsConfig, err := confidentialSpaceTLSConfigFromSource(
				ctx,
				tlsSecret,
				tlsCertFile,
				tlsKeyFile,
				clientCAFile,
				wifCredentials,
			)
			if err != nil {
				return err
			}

			tokens, err := confidentialspace.NewLauncherTokenSource(
				confidentialspace.LauncherSocket,
			)
			if err != nil {
				return err
			}
			wrapper, err := confidentialspace.NewCloudKMS(
				ctx,
				kmsKey,
				wifCredentials,
			)
			if err != nil {
				return err
			}
			defer wrapper.Close()
			cfg := confidentialspace.Config{
				Audience:              audience,
				KMSKey:                kmsKey,
				Tokens:                tokens,
				Wrapper:               wrapper,
				CreateProfileCounters: createProfiles,
			}
			if len(createProfiles) > 0 && len(profiles) == 0 {
				return errors.New(
					"--create-profile-counter requires --profile",
				)
			}
			if stateSecret != "" {
				state, err := confidentialspace.NewSecretStateStore(
					ctx,
					stateSecret,
					kmsKey,
					wrapper,
					wifCredentials,
				)
				if err != nil {
					return err
				}
				defer state.Close()
				cfg.Store = state
				if len(profiles) == 0 {
					counter, err := state.Counter("")
					if err != nil {
						return err
					}
					cfg.Counter = counter
				} else {
					cfg.Profiles = make(
						map[string]confidentialspace.CounterStore,
						len(profiles),
					)
					for _, profile := range profiles {
						if _, dup := cfg.Profiles[profile]; dup {
							return fmt.Errorf("duplicate --profile %q", profile)
						}
						counter, err := state.Counter(profile)
						if err != nil {
							return err
						}
						cfg.Profiles[profile] = counter
					}
				}
			} else {
				if len(profiles) == 0 {
					counter, err := confidentialspace.NewCloudCounterStore(
						ctx,
						counterBucket,
						counterObject,
						wifCredentials,
					)
					if err != nil {
						return err
					}
					defer counter.Close()
					cfg.Counter = counter
				} else {
					cfg.Profiles = make(
						map[string]confidentialspace.CounterStore,
						len(profiles),
					)
					for _, profile := range profiles {
						if _, dup := cfg.Profiles[profile]; dup {
							return fmt.Errorf("duplicate --profile %q", profile)
						}
						counter, err := confidentialspace.NewProfiledCloudCounterStore(
							ctx,
							counterBucket,
							counterObject,
							profile,
							wifCredentials,
						)
						if err != nil {
							return err
						}
						defer counter.Close()
						cfg.Profiles[profile] = counter
					}
				}
				store, err := confidentialspace.NewFileEnvelopeStore(wrappedKeyFile)
				if err != nil {
					return err
				}
				cfg.Store = store
			}
			workload, err := confidentialspace.New(ctx, cfg)
			if err != nil {
				return err
			}
			defer workload.Close()

			server := &http.Server{
				Addr:              listenAddress,
				Handler:           workload.Handler(),
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       15 * time.Second,
				WriteTimeout:      30 * time.Second,
				IdleTimeout:       60 * time.Second,
				MaxHeaderBytes:    16 << 10,
				TLSConfig:         tlsConfig,
			}
			errCh := make(chan error, 1)
			go func() {
				errCh <- server.ListenAndServeTLS("", "")
			}()
			select {
			case err := <-errCh:
				if !errors.Is(err, http.ErrServerClosed) {
					return fmt.Errorf("confidential space workload: %w", err)
				}
				return nil
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(
					context.Background(),
					10*time.Second,
				)
				defer cancel()
				if err := server.Shutdown(shutdownCtx); err != nil {
					return fmt.Errorf(
						"stop confidential space workload: %w",
						err,
					)
				}
				return nil
			}
		},
	}
	cmd.Flags().
		StringVar(&listenAddress, "listen", ":8080", "HTTP listen address inside the Confidential Space workload")
	cmd.Flags().
		StringVar(&audience, "audience", "", "signer-specific attestation token audience")
	cmd.Flags().
		StringVar(&kmsKey, "kms-key", "", "Cloud KMS CryptoKey resource used to wrap the pool key")
	cmd.Flags().
		StringVar(&stateSecret, "state-secret", "", "existing Secret Manager secret, projects/<project>/secrets/<secret>, holding the wrapped pool key and every issue counter; replaces --wrapped-key-file, --counter-bucket and --counter-object")
	cmd.Flags().
		StringVar(&wrappedKeyFile, "wrapped-key-file", "", "absolute path for the persistent wrapped pool key")
	cmd.Flags().
		StringVar(&counterBucket, "counter-bucket", "", "Cloud Storage bucket for the pool issue counter")
	cmd.Flags().
		StringVar(&counterObject, "counter-object", "", "Cloud Storage object for the pool issue counter; with --profile, the base name of each profile's counter object")
	cmd.Flags().
		StringArrayVar(&profiles, "profile", nil, "serve the key under this profile, repeatable; each profile has its own counter object <counter-object>/profiles/<profile>, which does not take over the --counter-object state, and requests without a profile are refused")
	cmd.Flags().
		StringArrayVar(&createProfiles, "create-profile-counter", nil, "create the missing counter object of this --profile, repeatable, for the one start that adds it; a missing counter object of any other profile still stops startup")
	cmd.Flags().
		StringVar(&wifCredentials, "wif-credentials", "", "validated external-account credential configuration")
	cmd.Flags().
		StringVar(&tlsSecret, "tls-secret", "", "existing Secret Manager secret, projects/<project>/secrets/<secret>, whose most recently created version, which must be enabled, holds one PEM bundle of the workload HTTPS certificate chain and its private key; replaces --tls-cert-file and --tls-key-file")
	cmd.Flags().
		StringVar(&tlsCertFile, "tls-cert-file", "", "PEM workload HTTPS certificate")
	cmd.Flags().
		StringVar(&tlsKeyFile, "tls-key-file", "", "PEM private key for the workload HTTPS certificate")
	cmd.Flags().
		StringVar(&clientCAFile, "client-ca-file", "", "PEM CA trusted to authenticate the signer client")
	_ = cmd.MarkFlagRequired("audience")
	_ = cmd.MarkFlagRequired("kms-key")
	_ = cmd.MarkFlagRequired("wif-credentials")
	_ = cmd.MarkFlagRequired("client-ca-file")
	return cmd
}

// validateConfidentialSpaceStorage requires exactly one storage mode: the
// state secret, or the wrapped-key file with the counter bucket and object.
func validateConfidentialSpaceStorage(
	stateSecret, wrappedKeyFile, counterBucket, counterObject string,
) error {
	gcs := []struct{ name, value string }{
		{"--wrapped-key-file", wrappedKeyFile},
		{"--counter-bucket", counterBucket},
		{"--counter-object", counterObject},
	}
	var missing []string
	for _, f := range gcs {
		if stateSecret != "" && f.value != "" {
			return fmt.Errorf("--state-secret excludes %s", f.name)
		}
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	switch {
	case stateSecret != "" || len(missing) == 0:
		return nil
	case len(missing) == len(gcs):
		return errors.New(
			"one of --state-secret or --wrapped-key-file with --counter-bucket and --counter-object is required",
		)
	default:
		return fmt.Errorf(
			"%s required without --state-secret",
			strings.Join(missing, ", "),
		)
	}
}

// validateConfidentialSpaceTLS requires exactly one TLS source: a well-formed
// secret name, or the certificate and key files together.
func validateConfidentialSpaceTLS(secret, certFile, keyFile string) error {
	files := []struct{ name, value string }{
		{"--tls-cert-file", certFile},
		{"--tls-key-file", keyFile},
	}
	var missing []string
	for _, f := range files {
		if secret != "" && f.value != "" {
			return fmt.Errorf("--tls-secret excludes %s", f.name)
		}
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	switch {
	case secret != "":
		return confidentialspace.ValidateTLSSecret(secret)
	case len(missing) == 0:
		return nil
	case len(missing) == len(files):
		return errors.New(
			"one of --tls-secret or --tls-cert-file with --tls-key-file is required",
		)
	default:
		return fmt.Errorf(
			"%s required without --tls-secret",
			strings.Join(missing, ", "),
		)
	}
}

// confidentialSpaceTLSConfigFromSource builds the TLS configuration from the
// secret when one is named, and from the files otherwise.
func confidentialSpaceTLSConfigFromSource(
	ctx context.Context,
	secret, certFile, keyFile, clientCAFile, wifCredentials string,
) (*tls.Config, error) {
	if secret == "" {
		return confidentialSpaceTLSConfig(certFile, keyFile, clientCAFile)
	}
	certificate, err := confidentialspace.LoadTLSCertificate(
		ctx,
		secret,
		wifCredentials,
	)
	if err != nil {
		return nil, fmt.Errorf("load workload TLS secret: %w", err)
	}
	return confidentialSpaceTLSConfigFor(certificate, clientCAFile)
}

func confidentialSpaceTLSConfig(
	certFile, keyFile, clientCAFile string,
) (*tls.Config, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read workload TLS certificate: %w", err)
	}
	keyPEM, err := bursa.ReadSecretKeyFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read workload TLS private key: %w", err)
	}
	defer clear(keyPEM)
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load workload TLS certificate: %w", err)
	}
	return confidentialSpaceTLSConfigFor(certificate, clientCAFile)
}

func confidentialSpaceTLSConfigFor(
	certificate tls.Certificate, clientCAFile string,
) (*tls.Config, error) {
	clientCAs, err := signerapi.LoadClientCAPool(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("load workload client CA: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}
