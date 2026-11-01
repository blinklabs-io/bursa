// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//go:build linux

package nitro

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/mdlayher/vsock"
)

const vsockDialTimeout = 5 * time.Second

// ListenVsock listens on a Nitro vsock port.
func ListenVsock(port uint32) (net.Listener, error) {
	return vsock.Listen(port, nil)
}

// DialVsockContext dials a CID/port while bounding a driver call that lacks a
// context-aware API. A connection that arrives after cancellation is closed.
func DialVsockContext(ctx context.Context, cid, port uint32) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, vsockDialTimeout)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		conn, err := vsock.Dial(cid, port, nil)
		resultCh <- result{conn: conn, err: err}
	}()
	select {
	case <-ctx.Done():
		go func() {
			result := <-resultCh
			if result.conn != nil {
				_ = result.conn.Close()
			}
		}()
		return nil, fmt.Errorf("dial vsock: %w", ctx.Err())
	case result := <-resultCh:
		return result.conn, result.err
	}
}
