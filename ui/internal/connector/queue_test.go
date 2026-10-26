package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/spend"
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

// TestDrainDecision covers the timeout/cancel tie-break: a decision buffered on
// the done channel at the instant the timer fires must be returned rather than
// dropped in favour of a spurious ErrTimeout.
func TestDrainDecision(t *testing.T) {
	done := make(chan Decision, 1)
	if _, err := drainDecision(done); err != ErrTimeout {
		t.Fatalf("empty channel: want ErrTimeout, got %v", err)
	}

	done <- Decision{Approved: true, Password: "pw"}
	d, err := drainDecision(done)
	if err != nil {
		t.Fatalf("buffered decision: unexpected error %v", err)
	}
	if !d.Approved || d.Password != "pw" {
		t.Fatalf("buffered decision: got %+v", d)
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
	w, ok := q.waiters[req.ID]
	q.mu.Unlock()
	if !ok {
		t.Fatalf("no waiter registered for %s", req.ID)
	}
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

func TestQueueReservationIsHiddenUntilPublished(t *testing.T) {
	q := NewQueue(time.Now, func() (string, error) { return "req1", nil }, time.Second)
	notifications, unsubscribe := q.Subscribe()
	defer unsubscribe()

	req, err := q.reserve("https://a.io", "signTx", json.RawMessage(`{"tx":"00"}`))
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if got := q.Pending(); len(got) != 0 {
		t.Fatalf("Pending before publish = %+v, want empty", got)
	}
	select {
	case <-notifications:
		t.Fatal("reservation notified approval clients")
	default:
	}
	if err := q.Decide(req.ID, Decision{Approved: true}); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("Decide reserved request = %v, want ErrUnknownRequest", err)
	}

	effects := spend.TxSummary{Fee: "170000"}
	published, err := q.publish(req.ID, &effects)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if published.Effects == nil || published.Effects.Fee != effects.Fee {
		t.Fatalf("published effects = %+v, want %+v", published.Effects, effects)
	}
	select {
	case <-notifications:
	case <-time.After(time.Second):
		t.Fatal("publish did not notify approval clients")
	}
	if got := q.Pending(); len(got) != 1 || got[0].Effects == nil {
		t.Fatalf("Pending after publish = %+v, want request with effects", got)
	}
}

func TestQueueReservationsCountTowardExistingLimits(t *testing.T) {
	t.Run("per origin", func(t *testing.T) {
		nextID := 0
		q := NewQueue(time.Now, func() (string, error) {
			nextID++
			return fmt.Sprintf("req%d", nextID), nil
		}, time.Second)
		for i := 0; i < maxPendingRequestsPerOrigin; i++ {
			if _, err := q.reserve("https://a.io", "signTx", nil); err != nil {
				t.Fatalf("reserve %d: %v", i, err)
			}
		}
		if _, err := q.reserve("https://a.io", "signTx", nil); !errors.Is(err, ErrQueueFull) {
			t.Fatalf("excess reservation = %v, want ErrQueueFull", err)
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
			if _, err := q.reserve(origin, "signTx", nil); err != nil {
				t.Fatalf("reserve %d: %v", i, err)
			}
		}
		if _, err := q.reserve("https://overflow.example", "signTx", nil); !errors.Is(err, ErrQueueFull) {
			t.Fatalf("excess reservation = %v, want ErrQueueFull", err)
		}
	})
}

// TestQueueGlobalBoundIgnoresDecidedWaiters verifies that a decided waiter that
// has not yet been cleaned up by its Await goroutine does not count against the
// global maxPendingRequests bound. A decided-but-unremoved waiter is not
// "pending" (Pending omits it), so it must not cause a fresh Submit to be
// rejected with ErrQueueFull.
func TestQueueGlobalBoundIgnoresDecidedWaiters(t *testing.T) {
	nextID := 0
	q := NewQueue(time.Now, func() (string, error) {
		nextID++
		return fmt.Sprintf("req%d", nextID), nil
	}, time.Second)

	// Fill the queue to the global bound, one request per origin so the
	// per-origin bound is never the limiting factor.
	ids := make([]string, 0, maxPendingRequests)
	for i := 0; i < maxPendingRequests; i++ {
		r, err := q.Submit(fmt.Sprintf("https://%d.example", i), "enable", nil)
		if err != nil {
			t.Fatalf("Submit %d: %v", i, err)
		}
		ids = append(ids, r.ID)
	}

	// Decide one request but do NOT drain it via Await, so it stays in the map
	// with decided=true. It is no longer pending.
	if err := q.Decide(ids[0], Decision{Approved: true}); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got := len(q.Pending()); got != maxPendingRequests-1 {
		t.Fatalf("pending after one decision = %d, want %d", got, maxPendingRequests-1)
	}

	// A fresh Submit must now be accepted: only maxPendingRequests-1 requests
	// are actually pending.
	if _, err := q.Submit("https://fresh.example", "enable", nil); err != nil {
		t.Fatalf("Submit after decision = %v, want success (decided waiter must not count)", err)
	}
}
