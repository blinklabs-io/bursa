package submissionerror

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestWrapPreservesSentinelsAndCause(t *testing.T) {
	unknown := errors.New("unknown")
	rejected := errors.New("rejected")
	cause := errors.New("backend failure")
	wrappedDeadline := fmt.Errorf("rpc: %w", context.DeadlineExceeded)
	wrappedCancellation := fmt.Errorf("rpc: %w", context.Canceled)

	for _, tc := range []struct {
		name    string
		cause   error
		want    error
		notWant error
	}{
		{name: "deadline", cause: wrappedDeadline, want: unknown, notWant: rejected},
		{name: "cancellation", cause: wrappedCancellation, want: unknown, notWant: rejected},
		{name: "rejection", cause: cause, want: rejected, notWant: unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Wrap(tc.cause, unknown, rejected)
			if !errors.Is(got, tc.want) || errors.Is(got, tc.notWant) {
				t.Fatalf("Wrap(%v) = %v, want %v only", tc.cause, got, tc.want)
			}
			if !errors.Is(got, tc.cause) {
				t.Fatalf("Wrap(%v) = %v, want original cause preserved", tc.cause, got)
			}
		})
	}
	if Wrap(nil, unknown, rejected) != nil {
		t.Fatal("Wrap(nil) must remain nil")
	}
}
