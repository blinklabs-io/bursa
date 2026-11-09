// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//go:build !linux

package nitro

import (
	"context"
	"errors"
	"net"
)

func ListenVsock(uint32) (net.Listener, error) {
	return nil, errors.New("AWS Nitro vsock is available only on Linux")
}

func DialVsockContext(context.Context, uint32, uint32) (net.Conn, error) {
	return nil, errors.New("AWS Nitro vsock is available only on Linux")
}
