package multisig

import (
	"context"
	"errors"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/submissionerror"
)

func TestWrapSubmitErrorClassifiesOutcome(t *testing.T) {
	if err := submissionerror.Wrap(context.Canceled, ErrSubmitUnknown, ErrSubmitRejected); !errors.Is(err, ErrSubmitUnknown) {
		t.Fatalf("cancellation error = %v, want ErrSubmitUnknown", err)
	}
	if err := submissionerror.Wrap(errors.New("ledger rejected"), ErrSubmitUnknown, ErrSubmitRejected); !errors.Is(err, ErrSubmitRejected) {
		t.Fatalf("ordinary error = %v, want ErrSubmitRejected", err)
	}
}
