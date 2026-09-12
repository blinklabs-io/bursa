package submissionctx

import (
	"context"
	"testing"
	"time"
)

func TestNewBoundsDisconnectedSubmission(t *testing.T) {
	key := struct{}{}
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), key, "preserved"))
	parentDeadline, parentCancel := context.WithDeadline(parent, time.Now().Add(time.Hour))
	defer parentCancel()
	ctx, submissionCancel := New(parentDeadline)
	defer submissionCancel()
	cancel()

	if err := ctx.Err(); err != nil {
		t.Fatalf("submission context canceled with request: %v", err)
	}
	if got := ctx.Value(key); got != "preserved" {
		t.Fatalf("context value = %v, want preserved", got)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("submission context has no deadline")
	}
	if remaining := time.Until(deadline); remaining <= 0 || remaining > Timeout {
		t.Fatalf("deadline remaining = %s, want >0 and <= %s", remaining, Timeout)
	}
}
