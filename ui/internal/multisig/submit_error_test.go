package multisig

import (
	"context"
	"errors"
	"testing"
)

func TestWrapSubmitErrorClassifiesOutcome(t *testing.T) {
	if err := wrapSubmitError(context.Canceled); !errors.Is(err, ErrSubmitUnknown) {
		t.Fatalf("cancellation error = %v, want ErrSubmitUnknown", err)
	}
	if err := wrapSubmitError(errors.New("ledger rejected")); !errors.Is(err, ErrSubmitRejected) {
		t.Fatalf("ordinary error = %v, want ErrSubmitRejected", err)
	}
}
