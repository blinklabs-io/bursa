package txbuilder

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunTxSubmitWithRejectingFake(t *testing.T) {
	chain := NewFakeChain()
	txBytes := []byte{0x84, 0x00}
	chain.SubmitErr = errors.New("rejected: era mismatch")
	ctx := context.Background()
	err := chain.SubmitTx(ctx, txBytes)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rejected")
	require.Empty(t, chain.Submitted)

	chain.SubmitErr = nil
	require.NoError(t, chain.SubmitTx(ctx, txBytes))
	require.Len(t, chain.Submitted, 1)
	require.Equal(t, txBytes, chain.Submitted[0])
}
