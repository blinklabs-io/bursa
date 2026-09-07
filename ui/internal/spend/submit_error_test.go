package spend

import (
	"context"
	"errors"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/submissionerror"
)

func TestWrapSubmitErrorClassifiesOutcome(t *testing.T) {
	if err := submissionerror.Wrap(context.DeadlineExceeded, ErrSubmitUnknown, ErrSubmitRejected); !errors.Is(err, ErrSubmitUnknown) {
		t.Fatalf("deadline error = %v, want ErrSubmitUnknown", err)
	}
	if err := submissionerror.Wrap(errors.New("ledger rejected"), ErrSubmitUnknown, ErrSubmitRejected); !errors.Is(err, ErrSubmitRejected) {
		t.Fatalf("ordinary error = %v, want ErrSubmitRejected", err)
	}
}
