// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWaitReachableReturnsWhenURLAnswers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if err := waitReachable(context.Background(), server.URL, time.Second, make(chan error)); err != nil {
		t.Fatalf("waitReachable() error = %v", err)
	}
}

func TestWaitReachableReturnsStartupErrorDuringPoll(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	srvErr := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		srvErr <- errors.New("listen failed")
	}()

	start := time.Now()
	err = waitReachable(context.Background(), url, 5*time.Second, srvErr)
	if err == nil {
		t.Fatal("waitReachable() error = nil, want startup error")
	}
	if !strings.Contains(err.Error(), "control surface: listen failed") {
		t.Fatalf("waitReachable() error = %q, want control surface startup error", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("waitReachable() took %s, want prompt return after startup error", elapsed)
	}
}
