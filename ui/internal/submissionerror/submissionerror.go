// Package submissionerror classifies transaction broadcast failures while
// preserving the package-specific sentinel used by the caller.
package submissionerror

import (
	"context"
	"errors"
	"fmt"
)

// Wrap classifies cancellation and deadline errors as unknown outcomes and all
// other errors as definitive rejection, preserving both sentinel and cause.
func Wrap(err, unknown, rejected error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", unknown, err)
	}
	return fmt.Errorf("%w: %w", rejected, err)
}
