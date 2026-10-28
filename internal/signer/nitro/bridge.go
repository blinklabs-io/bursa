// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package nitro

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	parentCID           = 3
	maxProxyConnections = 128
	kmsDialTimeout      = 10 * time.Second
	proxyIdleTimeout    = 2 * time.Minute
)

var awsRegionPattern = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]?$`)

// KMSEndpoint returns the fixed AWS commercial KMS endpoint for region.
func KMSEndpoint(region string) (string, error) {
	if !awsRegionPattern.MatchString(region) || len(region) > 32 ||
		strings.HasPrefix(region, "cn-") || strings.Contains(region, "-gov-") {
		return "", errors.New("invalid AWS region")
	}
	return net.JoinHostPort("kms."+region+".amazonaws.com", "443"), nil
}

// NewKMSProxyHTTPClient routes enclave-side AWS SDK connections to the parent
// vsock proxy. TLS still terminates at AWS KMS.
func NewKMSProxyHTTPClient(port uint32) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return DialVsockContext(ctx, parentCID, port)
	}
	transport.DisableKeepAlives = true
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}

// RunKMSProxy forwards opaque, end-to-end TLS bytes from an enclave vsock
// listener to one fixed regional KMS endpoint.
func RunKMSProxy(ctx context.Context, listener net.Listener, region string) error {
	if listener == nil {
		return errors.New("KMS proxy listener is required")
	}
	endpoint, err := KMSEndpoint(region)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	limit := make(chan struct{}, maxProxyConnections)
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		inbound, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept KMS proxy connection: %w", err)
		}
		select {
		case limit <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-limit }()
				defer inbound.Close() //nolint:errcheck // the copy result is authoritative
				bridgeKMS(ctx, inbound, endpoint)
			}()
		default:
			_ = inbound.Close()
		}
	}
}

func bridgeKMS(ctx context.Context, inbound net.Conn, endpoint string) {
	dialer := net.Dialer{Timeout: kmsDialTimeout, KeepAlive: 30 * time.Second}
	upstream, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return
	}
	defer upstream.Close() //nolint:errcheck // the byte stream is best effort after either side closes
	deadline := time.Now().Add(proxyIdleTimeout)
	_ = inbound.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	done := make(chan struct{}, 2)
	copyStream := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyStream(upstream, inbound)
	go copyStream(inbound, upstream)
	select {
	case <-ctx.Done():
	case <-done:
	}
}
