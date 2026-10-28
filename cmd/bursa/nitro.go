// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/nitro"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func nitroCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "nitro",
		Short: "Run AWS Nitro Enclave signer components",
	}
	command.AddCommand(nitroEnclaveCommand(), nitroProxyCommand())
	return command
}

func nitroEnclaveCommand() *cobra.Command {
	var signerPort, kmsProxyPort uint32
	command := &cobra.Command{
		Use:   "enclave",
		Short: "Run the measured pool-cold signing workload",
		RunE: func(command *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(command.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			recipient, err := nitro.NewNSMRecipient()
			if err != nil {
				return err
			}
			service, err := nitro.NewService(recipient, nitro.NewAWSKMSFactory(nitro.NewKMSProxyHTTPClient(kmsProxyPort)))
			if err != nil {
				return err
			}
			listener, err := nitro.ListenVsock(signerPort)
			if err != nil {
				return fmt.Errorf("listen for signer RPC: %w", err)
			}
			defer listener.Close() //nolint:errcheck // Serve reports listener failures
			server := grpc.NewServer(nitro.RPCServerOptions()...)
			nitro.RegisterRPCServer(server, service)
			errCh := make(chan error, 1)
			go func() { errCh <- server.Serve(listener) }()
			select {
			case <-ctx.Done():
				server.GracefulStop()
				return nil
			case err := <-errCh:
				return err
			}
		},
	}
	command.Flags().Uint32Var(&signerPort, "signer-port", nitro.DefaultSignerPort, "enclave gRPC vsock port")
	command.Flags().Uint32Var(&kmsProxyPort, "kms-proxy-port", nitro.DefaultKMSProxyPort, "parent KMS proxy vsock port")
	return command
}

func nitroProxyCommand() *cobra.Command {
	var (
		socket                               string
		region, kmsKeyID, secretID           string
		enclaveCID, signerPort, kmsProxyPort uint32
		provision                            bool
	)
	command := &cobra.Command{
		Use:   "proxy",
		Short: "Run the untrusted host proxy for a Nitro enclave",
		RunE: func(command *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(command.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			if !filepath.IsAbs(socket) || region == "" || secretID == "" || enclaveCID == 0 || (provision && kmsKeyID == "") {
				return errors.New("absolute --socket, --region, --secret-id, and provisioning --kms-key-id are required")
			}
			awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
			if err != nil {
				return fmt.Errorf("load AWS configuration: %w", err)
			}
			awsCredentials, err := awsCfg.Credentials.Retrieve(ctx)
			if err != nil {
				return fmt.Errorf("retrieve temporary AWS credentials: %w", err)
			}
			credentials := nitro.Credentials{
				AccessKeyID:     awsCredentials.AccessKeyID,
				SecretAccessKey: awsCredentials.SecretAccessKey,
				SessionToken:    awsCredentials.SessionToken,
			}

			kmsListener, err := nitro.ListenVsock(kmsProxyPort)
			if err != nil {
				return fmt.Errorf("listen for enclave KMS traffic: %w", err)
			}
			defer kmsListener.Close() //nolint:errcheck // proxy shutdown owns the listener
			proxyErr := make(chan error, 1)
			go func() { proxyErr <- nitro.RunKMSProxy(ctx, kmsListener, region) }()

			dialOptions := append([]grpc.DialOption{
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
					return nitro.DialVsockContext(ctx, enclaveCID, signerPort)
				}),
			}, nitro.RPCDialOptions()...)
			conn, err := grpc.NewClient("passthrough:///nitro-enclave", dialOptions...)
			if err != nil {
				return fmt.Errorf("create enclave client: %w", err)
			}
			defer conn.Close() //nolint:errcheck // command shutdown is already in progress
			client := nitro.NewRPCClient(conn)
			store, err := nitro.NewSecretStore(secretsmanager.NewFromConfig(awsCfg), secretID)
			if err != nil {
				return err
			}
			if provision {
				if _, err := store.Load(ctx); err == nil {
					return errors.New("refusing to replace an existing wrapped pool-cold key")
				} else if !errors.Is(err, nitro.ErrNoEnvelope) {
					return err
				}
				response, err := client.Provision(ctx, nitro.ProvisionRequest{
					Version: nitro.Protocol, Region: region, Credentials: credentials,
					KMSKeyID: kmsKeyID, Role: backend.KeyTypePool,
				})
				if err != nil {
					return fmt.Errorf("provision enclave key: %w", err)
				}
				if response.Version != nitro.Protocol {
					return errors.New("enclave returned an unsupported provision version")
				}
				if err := store.Save(ctx, response.Envelope); err != nil {
					return err
				}
			} else {
				envelope, err := store.Load(ctx)
				if err != nil {
					return err
				}
				response, err := client.Reload(ctx, nitro.ReloadRequest{
					Version: nitro.Protocol, Region: region, Credentials: credentials, Envelope: envelope,
				})
				if err != nil {
					return fmt.Errorf("reload enclave key: %w", err)
				}
				if response.Version != nitro.Protocol || !bytes.Equal(response.PublicKey, envelope.PublicKey) {
					return errors.New("enclave reload response does not match stored envelope")
				}
			}

			handler, err := nitro.NewProxyHandler(client)
			if err != nil {
				return err
			}
			listener, err := listenPrivateUnix(ctx, socket)
			if err != nil {
				return err
			}
			defer func() {
				_ = listener.Close()
				_ = os.Remove(socket)
			}()
			server := &http.Server{
				Handler:           handler,
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      30 * time.Second,
				IdleTimeout:       30 * time.Second,
			}
			httpErr := make(chan error, 1)
			go func() { httpErr <- server.Serve(listener) }()
			select {
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				return server.Shutdown(shutdownCtx)
			case err := <-proxyErr:
				return err
			case err := <-httpErr:
				if errors.Is(err, http.ErrServerClosed) {
					return nil
				}
				return err
			}
		},
	}
	command.Flags().StringVar(&socket, "socket", "/run/bursa/nitro.sock", "private Unix socket exposed to bursa signer")
	command.Flags().StringVar(&region, "region", "", "AWS region")
	command.Flags().StringVar(&secretID, "secret-id", "", "existing Secrets Manager secret containing the wrapped envelope")
	command.Flags().StringVar(&kmsKeyID, "kms-key-id", "", "KMS key ARN used only with --provision")
	command.Flags().Uint32Var(&enclaveCID, "enclave-cid", 0, "running enclave CID")
	command.Flags().Uint32Var(&signerPort, "signer-port", nitro.DefaultSignerPort, "enclave gRPC vsock port")
	command.Flags().Uint32Var(&kmsProxyPort, "kms-proxy-port", nitro.DefaultKMSProxyPort, "host KMS proxy vsock port")
	command.Flags().BoolVar(&provision, "provision", false, "generate a new key in an existing empty secret")
	_ = command.MarkFlagRequired("enclave-cid")
	return command
}

func listenPrivateUnix(ctx context.Context, path string) (net.Listener, error) {
	if _, err := os.Lstat(path); err == nil {
		return nil, errors.New("refusing to replace an existing Nitro proxy socket")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on Nitro proxy socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("protect Nitro proxy socket: %w", err)
	}
	return listener, nil
}
