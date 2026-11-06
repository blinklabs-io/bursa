package boot

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
)

// TestPoolRegistryAdapterBypassesStaleCache covers a pool registered after the
// chain client cached a complete pool list: the cached lookup still reports it
// absent, and the adapter that decides whether a registration locks the pool
// deposit must read the node instead.
func TestPoolRegistryAdapterBypassesStaleCache(t *testing.T) {
	t.Parallel()
	var registered atomic.Bool
	node := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v0/pools/extended" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if registered.Load() {
				_, _ = w.Write(
					[]byte(`[{"pool_id":"pool1other"},{"pool_id":"pool1new"}]`),
				)
				return
			}
			_, _ = w.Write([]byte(`[{"pool_id":"pool1other"}]`))
		}),
	)
	defer node.Close()

	c := chain.NewClientURL(node.URL)
	ctx := context.Background()
	if _, err := c.Pool(ctx, "pool1new"); !errors.Is(err, chain.ErrNotFound) {
		t.Fatalf("Pool before registration: err = %v, want ErrNotFound", err)
	}
	registered.Store(true)
	if _, err := c.Pool(ctx, "pool1new"); !errors.Is(err, chain.ErrNotFound) {
		t.Fatalf(
			"cached Pool after registration: err = %v, want ErrNotFound from the cached complete list",
			err,
		)
	}

	got, err := poolRegistryAdapter{c: c}.PoolRegistered(ctx, "pool1new")
	if err != nil {
		t.Fatalf("PoolRegistered: %v", err)
	}
	if !got {
		t.Fatal(
			"PoolRegistered = false for a pool the node now lists; the stale cached list decided the deposit",
		)
	}
}
