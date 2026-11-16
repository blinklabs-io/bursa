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
	"log/slog"
	"net"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// dialRetryPolicy bounds how long startup waits for Postgres to become
// reachable. The wait is capped by Total and by the caller context.
type dialRetryPolicy struct {
	// Total is the longest the retries may run, measured from the first try.
	Total time.Duration
	// Initial is the first backoff; it doubles after each attempt.
	Initial time.Duration
	// Max caps a single backoff.
	Max time.Duration
}

// defaultDialRetryPolicy covers a network that admits a new process a few
// seconds after it starts. It stays below the KES agent's 30 s store open
// timeout so the schema step still has time to run.
var defaultDialRetryPolicy = dialRetryPolicy{
	Total:   20 * time.Second,
	Initial: 250 * time.Millisecond,
	Max:     2 * time.Second,
}

// retryTransientDial runs op until it succeeds, fails with an error that is
// not a transient dial failure, the policy bound is spent, or ctx ends. It
// returns the last error from op. Each retry logs one warning that carries the
// underlying network error only, never the connection string.
func retryTransientDial(
	ctx context.Context,
	policy dialRetryPolicy,
	op func(context.Context) error,
) error {
	deadline := time.Now().Add(policy.Total)
	backoff := policy.Initial
	for attempt := 1; ; attempt++ {
		err := op(ctx)
		if err == nil || !isTransientDialError(err) || ctx.Err() != nil {
			return err
		}
		// The next attempt would start at or after the deadline: the budget
		// is spent.
		if backoff >= time.Until(deadline) {
			return err
		}
		slog.Warn(
			"postgres not reachable yet, retrying",
			"attempt", attempt,
			"retry_in", backoff.String(),
			"cause", dialCause(err),
		)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return err
		case <-timer.C:
		}
		// A late wakeup can still land past the deadline.
		if !time.Now().Before(deadline) {
			return err
		}
		backoff = min(backoff*2, policy.Max)
	}
}

// dialCause returns the network error inside err, which names the address and
// the OS error but not the user, database, or password that pgx prints in its
// own wrapper.
func dialCause(err error) string {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Error()
	}
	return "transient connect error"
}

// isTransientDialError reports whether err means Postgres could not be
// reached yet: a refused, unreachable, or timed-out dial, a temporary DNS
// failure, or a server that is still starting up. Credential, database,
// configuration, and schema errors are not transient.
func isTransientDialError(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// cannot_connect_now: the server is starting up or shutting down.
		return pgErr.Code == "57P03"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsTemporary || dnsErr.IsTimeout
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "dial" {
		return false
	}
	return opErr.Timeout() ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH)
}
