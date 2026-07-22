package multisig

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/blinklabs-io/bursa"
)

func TestPolicyFromScript_RoundTrip(t *testing.T) {
	kh := func(b byte) string { return hex.EncodeToString(bytesRepeat(b, 28)) }
	in := Policy{
		Threshold: 2,
		Participants: []Participant{
			{KeyHashHex: kh(1)}, {KeyHashHex: kh(2)}, {KeyHashHex: kh(3)},
		},
	}
	script, err := composeScript(in)
	if err != nil {
		t.Fatalf("composeScript: %v", err)
	}
	got, err := PolicyFromScript(script)
	if err != nil {
		t.Fatalf("PolicyFromScript: %v", err)
	}
	if got.Threshold != 2 || len(got.Participants) != 3 {
		t.Fatalf("got %d-of-%d, want 2-of-3", got.Threshold, len(got.Participants))
	}
	for i, part := range got.Participants {
		if part.KeyHashHex != in.Participants[i].KeyHashHex {
			t.Errorf("participant %d key hash = %s, want %s", i, part.KeyHashHex, in.Participants[i].KeyHashHex)
		}
	}
}

func TestPolicyFromScript_TimeLocked(t *testing.T) {
	before, after := uint64(100), uint64(200)
	kh := func(b byte) string { return hex.EncodeToString(bytesRepeat(b, 28)) }
	in := Policy{
		Threshold: 1, Participants: []Participant{{KeyHashHex: kh(1)}},
		InvalidBefore: &before, InvalidAfter: &after,
	}
	script, err := composeScript(in)
	if err != nil {
		t.Fatalf("composeScript: %v", err)
	}
	got, err := PolicyFromScript(script)
	if err != nil {
		t.Fatalf("PolicyFromScript: %v", err)
	}
	if got.InvalidBefore == nil || *got.InvalidBefore != before {
		t.Errorf("invalid_before = %v, want %d", got.InvalidBefore, before)
	}
	if got.InvalidAfter == nil || *got.InvalidAfter != after {
		t.Errorf("invalid_after = %v, want %d", got.InvalidAfter, after)
	}
	if got.Threshold != 1 || len(got.Participants) != 1 {
		t.Fatalf("got %d-of-%d, want 1-of-1", got.Threshold, len(got.Participants))
	}
}

// TestPolicyFromScript_UnsupportedShape covers a script shape composeScript
// never emits (a bare pubkey script, with no threshold clause at all): it
// must be rejected as ErrInvalidTx, not silently accepted or panicked on.
func TestPolicyFromScript_UnsupportedShape(t *testing.T) {
	kh := bytesRepeat(1, 28)
	script, err := bursa.NewScriptSig(kh)
	if err != nil {
		t.Fatalf("NewScriptSig: %v", err)
	}
	_, err = PolicyFromScript(script)
	if !errors.Is(err, ErrInvalidTx) {
		t.Fatalf("PolicyFromScript() error = %v, want ErrInvalidTx", err)
	}
}

func bytesRepeat(b byte, n int) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = b
	}
	return s
}
