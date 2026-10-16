package spend

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Salvionied/apollo/v2/backend/utxorpc"
	"github.com/blinklabs-io/bursa/ui/internal/submissionctx"
)

// stalledUTxORPCServer accepts SubmitTx requests over cleartext HTTP/2 and
// never answers them. accepted receives one value per request that reached the
// handler.
func stalledUTxORPCServer(t *testing.T) (url string, accepted <-chan struct{}) {
	t.Helper()
	seen := make(chan struct{}, 8)
	release := make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	return srv.URL, seen
}

func submitWithin(t *testing.T, baseURL string, limit time.Duration) error {
	t.Helper()
	svc := NewService(utxorpc.NewUtxoRpcChainContext(baseURL, 0, nil), nil, nil)
	done := make(chan error, 1)
	go func() {
		_, err := svc.Submit(context.Background(), []byte("signed-tx"))
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatalf("Submit still blocked after %s", limit)
		return nil
	}
}

func TestSubmitUnavailableEndpointFailsPromptly(t *testing.T) {
	t.Parallel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	if err := submitWithin(t, "http://"+addr, 5*time.Second); err == nil {
		t.Fatal("Submit to an unavailable endpoint returned nil error")
	}
}

func TestSubmitStalledEndpointIsBounded(t *testing.T) {
	t.Parallel()
	url, accepted := stalledUTxORPCServer(t)

	err := submitWithin(t, url, submissionctx.Timeout+5*time.Second)
	select {
	case <-accepted:
	default:
		t.Fatal("server never received the submission; the stall was not exercised")
	}
	if !errors.Is(err, ErrSubmitUnknown) {
		t.Fatalf("Submit error = %v, want an unknown-outcome error after the deadline", err)
	}
}
