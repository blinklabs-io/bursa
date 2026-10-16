package boot

import (
	"context"
	"time"

	"github.com/Salvionied/apollo/v2/backend"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// chainCallTimeout bounds each UTxO-RPC call, request and response body
// together. Callers pass HTTP request contexts, which carry no deadline: the
// server's WriteTimeout does not cancel them, so without this a node that
// accepts a query and never answers would hold the handler indefinitely.
// Submission keeps its own shorter deadline, which the derived context honors.
const chainCallTimeout = 30 * time.Second

// boundedChainContext applies a per-call deadline to every blocking method of
// the wrapped chain context, including the historic methods without a context
// parameter.
type boundedChainContext struct {
	inner   backend.ChainContext
	timeout time.Duration
}

var (
	_ backend.ChainContext        = boundedChainContext{}
	_ backend.ContextChainContext = boundedChainContext{}
	_ backend.CapabilityReporter  = boundedChainContext{}
)

func newBoundedChainContext(inner backend.ChainContext, timeout time.Duration) boundedChainContext {
	return boundedChainContext{inner: inner, timeout: timeout}
}

func (b boundedChainContext) Capabilities() backend.CapabilitySet {
	return backend.CapabilitiesOf(b.inner)
}

func (b boundedChainContext) NetworkId() uint8 { return b.inner.NetworkId() }

func (b boundedChainContext) ProtocolParamsContext(ctx context.Context) (backend.ProtocolParameters, error) {
	ctx, cancel := b.bound(ctx)
	defer cancel()
	return backend.ProtocolParamsContext(ctx, b.inner)
}

func (b boundedChainContext) GenesisParamsContext(ctx context.Context) (backend.GenesisParameters, error) {
	ctx, cancel := b.bound(ctx)
	defer cancel()
	return backend.GenesisParamsContext(ctx, b.inner)
}

func (b boundedChainContext) CurrentEpochContext(ctx context.Context) (uint64, error) {
	ctx, cancel := b.bound(ctx)
	defer cancel()
	return backend.CurrentEpochContext(ctx, b.inner)
}

func (b boundedChainContext) MaxTxFeeContext(ctx context.Context) (uint64, error) {
	ctx, cancel := b.bound(ctx)
	defer cancel()
	return backend.MaxTxFeeContext(ctx, b.inner)
}

func (b boundedChainContext) TipContext(ctx context.Context) (uint64, error) {
	ctx, cancel := b.bound(ctx)
	defer cancel()
	return backend.TipContext(ctx, b.inner)
}

func (b boundedChainContext) UtxosContext(ctx context.Context, address lcommon.Address) ([]lcommon.Utxo, error) {
	ctx, cancel := b.bound(ctx)
	defer cancel()
	return backend.UtxosContext(ctx, b.inner, address)
}

func (b boundedChainContext) SubmitTxContext(ctx context.Context, txCbor []byte) (lcommon.Blake2b256, error) {
	ctx, cancel := b.bound(ctx)
	defer cancel()
	return backend.SubmitTxContext(ctx, b.inner, txCbor)
}

func (b boundedChainContext) EvaluateTxContext(
	ctx context.Context,
	txCbor []byte,
	additionalUtxos []lcommon.Utxo,
) (map[lcommon.RedeemerKey]lcommon.ExUnits, error) {
	ctx, cancel := b.bound(ctx)
	defer cancel()
	return backend.EvaluateTxContext(ctx, b.inner, txCbor, additionalUtxos)
}

func (b boundedChainContext) UtxoByRefContext(
	ctx context.Context,
	txHash lcommon.Blake2b256,
	index uint32,
) (*lcommon.Utxo, error) {
	ctx, cancel := b.bound(ctx)
	defer cancel()
	return backend.UtxoByRefContext(ctx, b.inner, txHash, index)
}

func (b boundedChainContext) ScriptCborContext(ctx context.Context, scriptHash lcommon.Blake2b224) ([]byte, error) {
	ctx, cancel := b.bound(ctx)
	defer cancel()
	return backend.ScriptCborContext(ctx, b.inner, scriptHash)
}

func (b boundedChainContext) ProtocolParams() (backend.ProtocolParameters, error) {
	return b.ProtocolParamsContext(context.Background())
}

func (b boundedChainContext) GenesisParams() (backend.GenesisParameters, error) {
	return b.GenesisParamsContext(context.Background())
}

func (b boundedChainContext) CurrentEpoch() (uint64, error) {
	return b.CurrentEpochContext(context.Background())
}

func (b boundedChainContext) MaxTxFee() (uint64, error) {
	return b.MaxTxFeeContext(context.Background())
}

func (b boundedChainContext) Tip() (uint64, error) {
	return b.TipContext(context.Background())
}

func (b boundedChainContext) Utxos(address lcommon.Address) ([]lcommon.Utxo, error) {
	return b.UtxosContext(context.Background(), address)
}

func (b boundedChainContext) SubmitTx(txCbor []byte) (lcommon.Blake2b256, error) {
	return b.SubmitTxContext(context.Background(), txCbor)
}

func (b boundedChainContext) EvaluateTx(
	txCbor []byte,
	additionalUtxos []lcommon.Utxo,
) (map[lcommon.RedeemerKey]lcommon.ExUnits, error) {
	return b.EvaluateTxContext(context.Background(), txCbor, additionalUtxos)
}

func (b boundedChainContext) UtxoByRef(txHash lcommon.Blake2b256, index uint32) (*lcommon.Utxo, error) {
	return b.UtxoByRefContext(context.Background(), txHash, index)
}

func (b boundedChainContext) ScriptCbor(scriptHash lcommon.Blake2b224) ([]byte, error) {
	return b.ScriptCborContext(context.Background(), scriptHash)
}

func (b boundedChainContext) bound(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, b.timeout)
}
