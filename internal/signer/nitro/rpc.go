// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package nitro

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
)

const rpcServiceName = "bursa.signer.nitro.v1.Custody"

// maxRPCMessageSize caps what the enclave decodes before validation. The
// largest valid message is a Reload carrying two maxEnvelopeSize fields, which
// JSON base64 expands by 4/3 to about 175 KiB; gRPC's 4 MiB default would let
// the host force allocations well past the envelope bounds.
const maxRPCMessageSize = 4 * maxEnvelopeSize

type strictJSONCodec struct{}

func (strictJSONCodec) Name() string                      { return "bursa-nitro-json" }
func (strictJSONCodec) Marshal(value any) ([]byte, error) { return json.Marshal(value) }
func (strictJSONCodec) Unmarshal(data []byte, value any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return err
	}
	if err := dec.Decode(&json.RawMessage{}); !errors.Is(err, io.EOF) {
		return ErrProtocol
	}
	return nil
}

var nitroCodec = strictJSONCodec{}

func init() {
	encoding.RegisterCodec(nitroCodec)
}

// RPCServerTLSConfig identifies the enclave server certificate and the
// dedicated CA authorized to issue proxy client certificates.
type RPCServerTLSConfig struct {
	CertificateFile string
	KeyFile         string
	ClientCAFile    string
}

// RPCClientTLSConfig identifies the proxy client certificate and the CA and
// DNS name used to authenticate the enclave server.
type RPCClientTLSConfig struct {
	CertificateFile string
	KeyFile         string
	RootCAFile      string
	ServerName      string
}

func loadRPCKeyPair(certFile, keyFile string) (tls.Certificate, error) {
	if certFile == "" || keyFile == "" {
		return tls.Certificate{}, errors.New("RPC certificate and key files are required")
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("stat RPC private key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return tls.Certificate{}, errors.New("RPC private key must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return tls.Certificate{}, fmt.Errorf("RPC private key mode %04o grants group or other access", info.Mode().Perm())
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load RPC certificate: %w", err)
	}
	return cert, nil
}

func loadRPCCertPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, errors.New("RPC CA file is required")
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read RPC CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("RPC CA file contains no certificates")
	}
	return pool, nil
}

// RPCServerOptions returns fail-closed mutual-TLS and codec options for the
// enclave server. Only certificates from ClientCAFile may invoke any RPC.
func RPCServerOptions(config RPCServerTLSConfig) ([]grpc.ServerOption, error) {
	cert, err := loadRPCKeyPair(config.CertificateFile, config.KeyFile)
	if err != nil {
		return nil, err
	}
	clientCAs, err := loadRPCCertPool(config.ClientCAFile)
	if err != nil {
		return nil, err
	}
	transport := credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	return []grpc.ServerOption{
		grpc.Creds(transport),
		grpc.ForceServerCodec(nitroCodec),
		grpc.MaxRecvMsgSize(maxRPCMessageSize),
	}, nil
}

// RPCDialOptions returns fail-closed mutual-TLS and codec options for the host
// proxy. ServerName must match the enclave certificate.
func RPCDialOptions(config RPCClientTLSConfig) ([]grpc.DialOption, error) {
	if config.ServerName == "" {
		return nil, errors.New("RPC server name is required")
	}
	cert, err := loadRPCKeyPair(config.CertificateFile, config.KeyFile)
	if err != nil {
		return nil, err
	}
	roots, err := loadRPCCertPool(config.RootCAFile)
	if err != nil {
		return nil, err
	}
	transport := credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		ServerName:   config.ServerName,
	})
	return []grpc.DialOption{
		grpc.WithTransportCredentials(transport),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(nitroCodec)),
	}, nil
}

// RegisterRPCServer exposes service over a gRPC server.
func RegisterRPCServer(server *grpc.Server, service *Service) {
	server.RegisterService(&custodyServiceDesc, service)
}

type rpcClient struct {
	conn grpc.ClientConnInterface
}

// NewRPCClient creates a typed client for the versioned enclave service.
func NewRPCClient(conn grpc.ClientConnInterface) *rpcClient {
	return &rpcClient{conn: conn}
}

func (c *rpcClient) Provision(ctx context.Context, req ProvisionRequest) (ProvisionResponse, error) {
	var response ProvisionResponse
	err := c.conn.Invoke(ctx, "/"+rpcServiceName+"/Provision", &req, &response)
	return response, err
}

func (c *rpcClient) Reload(ctx context.Context, req ReloadRequest) (ReloadResponse, error) {
	var response ReloadResponse
	err := c.conn.Invoke(ctx, "/"+rpcServiceName+"/Reload", &req, &response)
	return response, err
}

// Inventory implements backend.Enclave over gRPC.
func (c *rpcClient) Inventory(ctx context.Context, nonce []byte) (backend.AttestedInventory, error) {
	var response backend.AttestedInventory
	err := c.conn.Invoke(ctx, "/"+rpcServiceName+"/Inventory", &InventoryRequest{
		Version: Protocol,
		Nonce:   bytes.Clone(nonce),
	}, &response)
	return response, err
}

// Sign implements backend.Enclave over gRPC.
func (c *rpcClient) Sign(ctx context.Context, req backend.AttestedRequest) (backend.AttestedResponse, error) {
	var response backend.AttestedResponse
	err := c.conn.Invoke(ctx, "/"+rpcServiceName+"/Sign", &req, &response)
	return response, err
}

var custodyServiceDesc = grpc.ServiceDesc{
	ServiceName: rpcServiceName,
	HandlerType: (*custodyRPC)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Provision", Handler: provisionHandler},
		{MethodName: "Reload", Handler: reloadHandler},
		{MethodName: "Inventory", Handler: inventoryHandler},
		{MethodName: "Sign", Handler: signHandler},
	},
}

type custodyRPC interface {
	Provision(context.Context, *ProvisionRequest) (*ProvisionResponse, error)
	Reload(context.Context, *ReloadRequest) (*ReloadResponse, error)
	Inventory(context.Context, *InventoryRequest) (*backend.AttestedInventory, error)
	Sign(context.Context, *backend.AttestedRequest) (*backend.AttestedResponse, error)
}

func invokeRPC(
	service any,
	ctx context.Context,
	request any,
	method string,
	interceptor grpc.UnaryServerInterceptor,
	call func(custodyRPC, context.Context, any) (any, error),
) (any, error) {
	rpc := service.(custodyRPC)
	if interceptor == nil {
		return call(rpc, ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: service, FullMethod: "/" + rpcServiceName + "/" + method}
	return interceptor(ctx, request, info, func(ctx context.Context, request any) (any, error) {
		return call(rpc, ctx, request)
	})
}

func provisionHandler(service any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	request := new(ProvisionRequest)
	if err := decode(request); err != nil {
		return nil, err
	}
	return invokeRPC(service, ctx, request, "Provision", interceptor, func(rpc custodyRPC, ctx context.Context, request any) (any, error) {
		return rpc.Provision(ctx, request.(*ProvisionRequest))
	})
}

func reloadHandler(service any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	request := new(ReloadRequest)
	if err := decode(request); err != nil {
		return nil, err
	}
	return invokeRPC(service, ctx, request, "Reload", interceptor, func(rpc custodyRPC, ctx context.Context, request any) (any, error) {
		return rpc.Reload(ctx, request.(*ReloadRequest))
	})
}

func inventoryHandler(service any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	request := new(InventoryRequest)
	if err := decode(request); err != nil {
		return nil, err
	}
	return invokeRPC(service, ctx, request, "Inventory", interceptor, func(rpc custodyRPC, ctx context.Context, request any) (any, error) {
		return rpc.Inventory(ctx, request.(*InventoryRequest))
	})
}

func signHandler(service any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	request := new(backend.AttestedRequest)
	if err := decode(request); err != nil {
		return nil, err
	}
	return invokeRPC(service, ctx, request, "Sign", interceptor, func(rpc custodyRPC, ctx context.Context, request any) (any, error) {
		return rpc.Sign(ctx, request.(*backend.AttestedRequest))
	})
}
