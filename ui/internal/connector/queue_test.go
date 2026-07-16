package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestQueueSubmitApprove(t *testing.T) {
	q := NewQueue(time.Now, func() (string, error) { return "req1", nil }, time.Second)
	req, err := q.Submit("https://a.io", "signTx", json.RawMessage(`{"tx":"00"}`))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
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
	q := NewQueue(time.Now, func() (string, error) { return "r", nil }, 10*time.Millisecond)
	if _, err := q.Submit("https://a.io", "enable", nil); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if _, err := q.Await(context.Background(), "r"); err != ErrTimeout {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
}

func TestQueueRejectsDuplicateAfterDecisionConsumed(t *testing.T) {
	q := NewQueue(time.Now, func() (string, error) { return "req1", nil }, time.Second)
	req, err := q.Submit("https://a.io", "signTx", nil)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
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

func TestQueueNotificationsCoalesceToAuthoritativeSnapshot(t *testing.T) {
	nextID := 0
	q := NewQueue(time.Now, func() (string, error) {
		nextID++
		return fmt.Sprintf("req%d", nextID), nil
	}, time.Second)
	ch, unsubscribe := q.Subscribe()
	defer unsubscribe()

	// Submit more requests than the old eight-event subscriber buffer without
	// consuming notifications. A single coalesced notification must still lead
	// the consumer to the complete current state.
	for i := 0; i < 12; i++ {
		origin := fmt.Sprintf("https://%d.example", i)
		if _, err := q.Submit(origin, "enable", nil); err != nil {
			t.Fatalf("Submit %d: %v", i, err)
		}
	}
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("missing queue state-change notification")
	}
	if got := len(q.Pending()); got != 12 {
		t.Fatalf("Pending length = %d, want 12", got)
	}
	select {
	case <-ch:
		t.Fatal("burst notifications should be coalesced")
	default:
	}
}

func TestQueueNotifiesWhenRequestExpires(t *testing.T) {
	q := NewQueue(time.Now, func() (string, error) { return "req1", nil }, 10*time.Millisecond)
	ch, unsubscribe := q.Subscribe()
	defer unsubscribe()
	if _, err := q.Submit("https://a.io", "enable", nil); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	<-ch // added snapshot

	if _, err := q.Await(context.Background(), "req1"); !errors.Is(err, ErrTimeout) {
		t.Fatalf("Await error = %v, want ErrTimeout", err)
	}
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("missing removal notification after timeout")
	}
	if got := q.Pending(); len(got) != 0 {
		t.Fatalf("Pending after timeout = %+v, want empty", got)
	}
}

func TestQueueBoundsPendingRequests(t *testing.T) {
	t.Run("per origin", func(t *testing.T) {
		nextID := 0
		q := NewQueue(time.Now, func() (string, error) {
			nextID++
			return fmt.Sprintf("req%d", nextID), nil
		}, time.Second)
		for i := 0; i < maxPendingRequestsPerOrigin; i++ {
			if _, err := q.Submit("https://a.io", "enable", nil); err != nil {
				t.Fatalf("Submit %d: %v", i, err)
			}
		}
		if _, err := q.Submit("https://a.io", "enable", nil); !errors.Is(err, ErrQueueFull) {
			t.Fatalf("excess per-origin Submit error = %v, want ErrQueueFull", err)
		}
	})

	t.Run("global", func(t *testing.T) {
		nextID := 0
		q := NewQueue(time.Now, func() (string, error) {
			nextID++
			return fmt.Sprintf("req%d", nextID), nil
		}, time.Second)
		for i := 0; i < maxPendingRequests; i++ {
			origin := fmt.Sprintf("https://%d.example", i)
			if _, err := q.Submit(origin, "enable", nil); err != nil {
				t.Fatalf("Submit %d: %v", i, err)
			}
		}
		if _, err := q.Submit("https://overflow.example", "enable", nil); !errors.Is(err, ErrQueueFull) {
			t.Fatalf("excess global Submit error = %v, want ErrQueueFull", err)
		}
	})
}
