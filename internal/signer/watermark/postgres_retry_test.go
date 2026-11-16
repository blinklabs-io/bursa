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

package watermark

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func refusedErr() error {
	return fmt.Errorf("begin schema: %w", &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: &netSyscallErr{syscall.ECONNREFUSED},
	})
}

// netSyscallErr mimics os.SyscallError's unwrap chain.
type netSyscallErr struct{ errno syscall.Errno }

func (e *netSyscallErr) Error() string { return "connect: " + e.errno.Error() }
func (e *netSyscallErr) Unwrap() error { return e.errno }

var fastPolicy = dialRetryPolicy{
	Total:   2 * time.Second,
	Initial: time.Millisecond,
	Max:     5 * time.Millisecond,
}

func TestRetryTransientDial_RefusedThenSuccess(t *testing.T) {
	t.Parallel()
	calls := 0
	err := retryTransientDial(
		context.Background(),
		fastPolicy,
		func(context.Context) error {
			calls++
			if calls < 3 {
				return refusedErr()
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("want success after retries, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("want 3 attempts, got %d", calls)
	}
}

func TestRetryTransientDial_PersistentRefusalGivesUp(t *testing.T) {
	t.Parallel()
	calls := 0
	policy := dialRetryPolicy{
		Total:   50 * time.Millisecond,
		Initial: time.Millisecond,
		Max:     5 * time.Millisecond,
	}
	err := retryTransientDial(
		context.Background(),
		policy,
		func(context.Context) error {
			calls++
			return refusedErr()
		},
	)
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("want last refused error, got %v", err)
	}
	if calls < 2 {
		t.Fatalf("want retries before giving up, got %d attempts", calls)
	}
}

func TestRetryTransientDial_NonTransientFailsFast(t *testing.T) {
	t.Parallel()
	cases := map[string]error{
		"auth": &pgconn.PgError{Code: "28P01", Message: "bad password"},
		"missing database": &pgconn.PgError{
			Code: "3D000", Message: "database does not exist",
		},
		"schema": &pgconn.PgError{Code: "42601", Message: "syntax"},
		"plain":  errors.New("parse postgres watermark dsn"),
		"dns not found": &net.DNSError{
			Err: "no such host", Name: "db", IsNotFound: true,
		},
	}
	for name, cause := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			err := retryTransientDial(
				context.Background(),
				fastPolicy,
				func(context.Context) error {
					calls++
					return fmt.Errorf("create schema: %w", cause)
				},
			)
			if !errors.Is(err, cause) {
				t.Fatalf("want original error, got %v", err)
			}
			if calls != 1 {
				t.Fatalf("want 1 attempt, got %d", calls)
			}
		})
	}
}

func TestRetryTransientDial_ServerStartingIsTransient(t *testing.T) {
	t.Parallel()
	if !isTransientDialError(&pgconn.PgError{Code: "57P03"}) {
		t.Fatal("57P03 should be transient")
	}
}

func TestRetryTransientDial_CancelStopsWaiting(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	// Buffered so the first attempt is recorded even before the receive
	// below is ready; an unbuffered nonblocking send could drop it.
	attempted := make(chan struct{}, 1)
	done := make(chan error, 1)
	policy := dialRetryPolicy{
		Total:   time.Hour,
		Initial: time.Hour,
		Max:     time.Hour,
	}
	go func() {
		done <- retryTransientDial(ctx, policy, func(context.Context) error {
			select {
			case attempted <- struct{}{}:
			default:
			}
			return refusedErr()
		})
	}()
	select {
	case <-attempted:
	case <-time.After(10 * time.Second):
		t.Fatal("op never ran")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("want last error, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("retry did not stop after cancel")
	}
}
