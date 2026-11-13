package survey

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
)

// listUntilRead lists until the label history is fully read or refused.
func listUntilRead(t *testing.T, s *Service) error {
	t.Helper()
	for range 100 {
		if _, err := s.List(context.Background()); !errors.Is(err, ErrIndexing) {
			return err
		}
	}
	t.Fatal("label history never finished reading")
	return nil
}

// Anyone can publish label-17 metadata, so the history the service keeps must
// be bounded; past the bound it refuses explicitly rather than growing.
func TestLabelHistoryRefusesMoreRowsThanItKeeps(t *testing.T) {
	t.Parallel()
	f := newFakeChain()
	f.addJunk(maxLabelRows + chain.LabelPageSize)
	s := NewService(f, "preview")

	if err := listUntilRead(t, s); !errors.Is(err, ErrHistoryTooLarge) {
		t.Fatalf("List err = %v, want ErrHistoryTooLarge", err)
	}
	if len(s.labelRows) > maxLabelRows {
		t.Fatalf("kept %d rows, bound is %d", len(s.labelRows), maxLabelRows)
	}
}

func TestLabelHistoryRefusesMorePayloadBytesThanItKeeps(t *testing.T) {
	t.Parallel()
	d := simple(1, 60)
	d.Description = strings.Repeat("x", 15_000)
	raw, err := Marshal(defPayload(d))
	noErr(t, err)
	if _, err := Decode(raw); err != nil {
		t.Fatalf("fixture payload does not decode: %v", err)
	}
	f := newFakeChain()
	for i := range maxLabelPayloadBytes/len(raw) + chain.LabelPageSize {
		h := fmt.Sprintf("%064x", 1<<30+i)
		f.labels = append(f.labels, chain.LabelMetadata{TxHash: h, CBOR: raw})
		f.txs[h] = chain.TxInfo{Hash: h, BlockHeight: uint64(i + 1), BlockTime: timeIn(40)}
		f.signers[h] = []string{credHex(1)}
	}
	s := NewService(f, "preview")

	if err := listUntilRead(t, s); !errors.Is(err, ErrHistoryTooLarge) {
		t.Fatalf("List err = %v, want ErrHistoryTooLarge", err)
	}
}
