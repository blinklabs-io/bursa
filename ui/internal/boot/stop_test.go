package boot

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Salvionied/apollo/v2/backend/utxorpc"
	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
)

// TestStopWaitsForStalledSubmission covers a detached submission whose node
// accepts the request and never answers: Stop must wait out the submission's
// own deadline rather than abandon the handler mid-broadcast.
func TestStopWaitsForStalledSubmission(t *testing.T) {
	t.Parallel()

	accepted := make(chan struct{}, 1)
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

	spendSvc := spend.NewService(utxorpc.NewUtxoRpcChainContext(node.URL, 0, nil), nil, nil)
	handlerDone := make(chan error, 1)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := spendSvc.Submit(r.Context(), []byte("signed-tx"))
		handlerDone <- err
	})}
	go func() { _ = srv.Serve(listener) }()

	app := &App{
		srv:      srv,
		listener: listener,
		sup:      supervisor.New(supervisor.Config{}),
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		ctx:      context.Background(),
		stop:     func() {},
		srvErr:   make(chan error, 1),
	}

	respDone := make(chan struct{})
	go func() {
		defer close(respDone)
		resp, err := http.Get("http://" + listener.Addr().String())
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("submission never reached the node")
	}

	if err := app.Stop(); err != nil {
		t.Fatalf("Stop abandoned an in-flight submission: %v", err)
	}
	select {
	case err := <-handlerDone:
		if !errors.Is(err, spend.ErrSubmitUnknown) {
			t.Fatalf("submission error = %v, want unknown outcome", err)
		}
	default:
		t.Fatal("Stop returned before the submission finished")
	}
	<-respDone
}
