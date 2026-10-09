package boot

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Salvionied/apollo/v2/backend"
	"github.com/Salvionied/apollo/v2/backend/utxorpc"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// TestBoundedChainContextStalledNode covers a node that accepts UTxO-RPC
// queries and never answers: callers with no deadline of their own, through
// either the context-aware or the historic method set, must still return.
func TestBoundedChainContextStalledNode(t *testing.T) {
	t.Parallel()
	accepted := make(chan struct{}, 8)
	release := make(chan struct{})
	node := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accepted <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	node.Config.Protocols = new(http.Protocols)
	node.Config.Protocols.SetUnencryptedHTTP2(true)
	node.Start()
	defer node.Close()
	defer close(release)

	const bound = 200 * time.Millisecond
	cc := newBoundedChainContext(utxorpc.NewUtxoRpcChainContext(node.URL, 0, nil), bound)

	calls := map[string]func() error{
		"ProtocolParamsContext": func() error {
			_, err := backend.ProtocolParamsContext(context.Background(), cc)
			return err
		},
		"UtxoByRef": func() error {
			_, err := cc.UtxoByRef(lcommon.Blake2b256{}, 0)
			return err
		},
	}
	for name, call := range calls {
		done := make(chan error, 1)
		go func() { done <- call() }()
		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("%s error = %v, want context.DeadlineExceeded", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s still blocked on a stalled node after 5s", name)
		}
		select {
		case <-accepted:
		default:
			t.Fatalf("%s never reached the node; the stall was not exercised", name)
		}
	}
}

func TestBoundedChainContextForwardsCapabilities(t *testing.T) {
	t.Parallel()
	inner := utxorpc.NewUtxoRpcChainContext("http://127.0.0.1:1", 0, nil)
	cc := newBoundedChainContext(inner, time.Second)
	if got, want := backend.CapabilitiesOf(cc), backend.CapabilitiesOf(inner); got != want {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}
	if got, want := cc.NetworkId(), inner.NetworkId(); got != want {
		t.Fatalf("network id = %d, want %d", got, want)
	}
}
