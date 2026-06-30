package connector

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestQueueSubmitApprove(t *testing.T) {
	q := NewQueue(time.Now, func() string { return "req1" }, time.Second)
	req := q.Submit("https://a.io", "signTx", json.RawMessage(`{"tx":"00"}`))
	if req.ID != "req1" || len(q.Pending()) != 1 {
		t.Fatalf("submit: %+v pending=%d", req, len(q.Pending()))
	}
	go func() { _ = q.Decide("req1", Decision{Approved: true, Password: "pw"}) }()
	d, err := q.Await(context.Background(), "req1")
	if err != nil || !d.Approved || d.Password != "pw" {
		t.Fatalf("await: %+v %v", d, err)
	}
	if len(q.Pending()) != 0 {
		t.Fatal("decided request should leave the pending set")
	}
}

func TestQueueTimeout(t *testing.T) {
	q := NewQueue(time.Now, func() string { return "r" }, 10*time.Millisecond)
	q.Submit("https://a.io", "enable", nil)
	if _, err := q.Await(context.Background(), "r"); err != ErrTimeout {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
}

func TestQueueRejectsDuplicateAfterDecisionConsumed(t *testing.T) {
	q := NewQueue(time.Now, func() string { return "req1" }, time.Second)
	req := q.Submit("https://a.io", "signTx", nil)
	if err := q.Decide(req.ID, Decision{Approved: true}); err != nil {
		t.Fatalf("first Decide: %v", err)
	}

	q.mu.Lock()
	w := q.waiters[req.ID]
	q.mu.Unlock()
	if got := <-w.done; !got.Approved {
		t.Fatalf("first decision = %+v, want approved", got)
	}

	if err := q.Decide(req.ID, Decision{Approved: false}); err != ErrAlreadyDecided {
		t.Fatalf("duplicate Decide after consumed decision = %v, want ErrAlreadyDecided", err)
	}
}
