// Package submissionctx defines the lifetime policy for signed transaction
// broadcasts that must finish even if the initiating request disconnects.
package submissionctx

import (
	"context"
	"time"
)

// Timeout bounds the time allowed for a signed transaction broadcast.
const Timeout = 10 * time.Second

// New returns a context that preserves the request's values but ignores its
// cancellation, while imposing a finite deadline on the downstream client.
// This lets a completed signing flow finish after a client disconnect without
// allowing an unavailable node to hold a handler indefinitely.
func New(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), Timeout)
}
