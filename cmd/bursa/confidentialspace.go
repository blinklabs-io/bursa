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
	"os/signal"
	"syscall"
	"time"

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
		wrappedKeyFile string
		counterBucket  string
		counterObject  string
		wifCredentials string
		tlsCertFile    string
		tlsKeyFile     string
		clientCAFile   string
	)
	cmd := &cobra.Command{
		Use:   "confidential-space-workload",
		Short: "Run pool cold-key custody inside GCP Confidential Space",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			logging.ConfigureJSON()
			tlsConfig, err := confidentialSpaceTLSConfig(
				tlsCertFile,
				tlsKeyFile,
				clientCAFile,
			)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(
				context.Background(),
				syscall.SIGINT,
				syscall.SIGTERM,
			)
			defer stop()

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
			store, err := confidentialspace.NewFileEnvelopeStore(wrappedKeyFile)
			if err != nil {
				return err
			}
			workload, err := confidentialspace.New(
				ctx,
				confidentialspace.Config{
					Audience: audience,
					KMSKey:   kmsKey,
					Tokens:   tokens,
					Wrapper:  wrapper,
					Store:    store,
					Counter:  counter,
				},
			)
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
		StringVar(&wrappedKeyFile, "wrapped-key-file", "", "absolute path for the persistent wrapped pool key")
	cmd.Flags().
		StringVar(&counterBucket, "counter-bucket", "", "Cloud Storage bucket for the pool issue counter")
	cmd.Flags().
		StringVar(&counterObject, "counter-object", "", "Cloud Storage object for the pool issue counter")
	cmd.Flags().
		StringVar(&wifCredentials, "wif-credentials", "", "validated external-account credential configuration")
	cmd.Flags().
		StringVar(&tlsCertFile, "tls-cert-file", "", "PEM workload HTTPS certificate")
	cmd.Flags().
		StringVar(&tlsKeyFile, "tls-key-file", "", "PEM private key for the workload HTTPS certificate")
	cmd.Flags().
		StringVar(&clientCAFile, "client-ca-file", "", "PEM CA trusted to authenticate the signer client")
	_ = cmd.MarkFlagRequired("audience")
	_ = cmd.MarkFlagRequired("kms-key")
	_ = cmd.MarkFlagRequired("wrapped-key-file")
	_ = cmd.MarkFlagRequired("counter-bucket")
	_ = cmd.MarkFlagRequired("counter-object")
	_ = cmd.MarkFlagRequired("wif-credentials")
	_ = cmd.MarkFlagRequired("tls-cert-file")
	_ = cmd.MarkFlagRequired("tls-key-file")
	_ = cmd.MarkFlagRequired("client-ca-file")
	return cmd
}

func confidentialSpaceTLSConfig(
	certFile, keyFile, clientCAFile string,
) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load workload TLS certificate: %w", err)
	}
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
