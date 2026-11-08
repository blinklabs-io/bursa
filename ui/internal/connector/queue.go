package connector

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/spend"
)

var (
	ErrTimeout        = errors.New("connector: request timed out")
	ErrUnknownRequest = errors.New("connector: unknown request id")
	ErrAlreadyDecided = errors.New("connector: request already decided")
	ErrQueueFull      = errors.New("connector: too many pending requests")
)

const (
	maxPendingRequests          = 64
	maxPendingRequestsPerOrigin = 8
)

type Request struct {
	ID      string           `json:"id"`
	Origin  string           `json:"origin"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Effects *spend.TxSummary `json:"effects,omitempty"`
	Created time.Time        `json:"created"`
}

type Decision struct {
	Approved bool
	Password string
}

type waiter struct {
	req       Request
	done      chan queueResult
	authority *pairingAuthority
	ready     bool
	decided   bool
}

type queueResult struct {
	decision Decision
	err      error
}

type Queue struct {
	now     func() time.Time
	mkID    func() (string, error)
	timeout time.Duration

	mu      sync.Mutex
	waiters map[string]*waiter
	subs    map[int]chan struct{}
	nextSub int
}

func NewQueue(
	now func() time.Time,
	mkID func() (string, error),
	timeout time.Duration,
) *Queue {
	return &Queue{
		now: now, mkID: mkID, timeout: timeout,
		waiters: map[string]*waiter{}, subs: map[int]chan struct{}{},
	}
}

func (q *Queue) Submit(
	origin, method string,
	params json.RawMessage,
) (*Request, error) {
	req, err := q.reserve(origin, method, params)
	if err != nil {
		return nil, err
	}
	return q.publish(req.ID, nil)
}

func (q *Queue) submitAuthorized(
	origin, method string,
	params json.RawMessage,
	authority pairingAuthority,
) (*Request, error) {
	req, err := q.reserveAuthorized(origin, method, params, authority)
	if err != nil {
		return nil, err
	}
	return q.publish(req.ID, nil)
}

// reserve claims queue capacity without exposing a request to approval clients.
// Callers must publish the complete request or cancel the reservation.
func (q *Queue) reserve(
	origin, method string,
	params json.RawMessage,
) (*Request, error) {
	return q.reserveWithAuthority(origin, method, params, nil)
}

func (q *Queue) reserveAuthorized(
	origin, method string,
	params json.RawMessage,
	authority pairingAuthority,
) (*Request, error) {
	return q.reserveWithAuthority(origin, method, params, &authority)
}

func (q *Queue) reserveWithAuthority(
	origin, method string,
	params json.RawMessage,
	authority *pairingAuthority,
) (*Request, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.pendingCountLocked() >= maxPendingRequests ||
		q.pendingForOriginLocked(origin) >= maxPendingRequestsPerOrigin {
		return nil, ErrQueueFull
	}
	id, err := q.mkID()
	if err != nil {
		return nil, err
	}
	params = append(json.RawMessage(nil), params...)
	r := Request{
		ID:      id,
		Origin:  origin,
		Method:  method,
		Params:  params,
		Created: q.now(),
	}
	q.waiters[r.ID] = &waiter{
		req:       r,
		done:      make(chan queueResult, 1),
		authority: authority,
	}
	return &r, nil
}

func (q *Queue) publish(id string, effects *spend.TxSummary) (*Request, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	w, ok := q.waiters[id]
	if !ok || w.decided || w.ready {
		return nil, ErrUnknownRequest
	}
	w.req.Effects = effects
	w.ready = true
	q.notifyLocked()
	r := w.req
	return &r, nil
}

func (q *Queue) cancelReservation(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	w, ok := q.waiters[id]
	if ok && !w.ready {
		delete(q.waiters, id)
	}
}

func (q *Queue) Await(ctx context.Context, id string) (Decision, error) {
	q.mu.Lock()
	w, ok := q.waiters[id]
	q.mu.Unlock()
	if !ok || !w.ready {
		return Decision{}, ErrUnknownRequest
	}
	defer q.remove(id)
	// Use NewTimer + defer Stop to avoid a goroutine/channel leak when the
	// request is resolved before the timeout fires (time.After leaks the
	// timer until it fires at the full 120s production timeout).
	t := time.NewTimer(q.timeout)
	defer t.Stop()
	select {
	case result := <-w.done:
		return result.decision, result.err
	case <-t.C:
		// A Decide may have fired at the very instant the timer expired: it sets
		// decided=true and sends on the buffered done channel while this select
		// simultaneously chose the timeout branch. Prefer a delivered decision so
		// the SPA/dApp (which saw Decide succeed) and the signing path agree on
		// the outcome instead of the caller reporting a spurious timeout.
		return drainQueueResult(w.done)
	case <-ctx.Done():
		// Same tie-break as the timeout branch: honour a decision that landed
		// concurrently with cancellation.
		select {
		case result := <-w.done:
			return result.decision, result.err
		default:
			return Decision{}, ctx.Err()
		}
	}
}

// drainQueueResult returns a result already buffered on done, or ErrTimeout if
// none is present. It never blocks.
func drainQueueResult(done <-chan queueResult) (Decision, error) {
	select {
	case result := <-done:
		return result.decision, result.err
	default:
		return Decision{}, ErrTimeout
	}
}

func (q *Queue) Decide(id string, d Decision) error {
	q.mu.Lock()
	w, ok := q.waiters[id]
	if !ok || !w.ready {
		q.mu.Unlock()
		return ErrUnknownRequest
	}
	if w.decided {
		q.mu.Unlock()
		return ErrAlreadyDecided
	}
	w.decided = true
	q.notifyLocked()
	q.mu.Unlock()

	w.done <- queueResult{decision: d}
	return nil
}

func (q *Queue) cancelAuthority(authority pairingAuthority) {
	q.mu.Lock()
	defer q.mu.Unlock()
	cancelled := false
	for _, w := range q.waiters {
		if w.decided || w.authority == nil || *w.authority != authority {
			continue
		}
		w.decided = true
		w.done <- queueResult{err: ErrRefused}
		cancelled = true
	}
	if cancelled {
		q.notifyLocked()
	}
}

func (q *Queue) Pending() []Request {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]Request, 0, len(q.waiters))
	for _, w := range q.waiters {
		if w.decided || !w.ready {
			continue
		}
		out = append(out, w.req)
	}
	return out
}

// Subscribe returns a coalesced state-change notification channel. Consumers
// must call Pending after each notification and replace their local state with
// that authoritative snapshot. The one-slot channel intentionally coalesces
// bursts: if a consumer is slow, a queued notification still causes it to read
// the latest complete state, so requests and removals cannot be lost.
func (q *Queue) Subscribe() (<-chan struct{}, func()) {
	q.mu.Lock()
	defer q.mu.Unlock()
	id := q.nextSub
	q.nextSub++
	ch := make(chan struct{}, 1)
	q.subs[id] = ch
	return ch, func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		if c, ok := q.subs[id]; ok {
			close(c)
			delete(q.subs, id)
		}
	}
}

func (q *Queue) remove(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.waiters[id]; ok {
		delete(q.waiters, id)
		q.notifyLocked()
	}
}

// pendingCountLocked returns the number of undecided waiters, including hidden
// reservations. Decided waiters linger until Await runs cleanup, but no longer
// consume admission capacity.
func (q *Queue) pendingCountLocked() int {
	n := 0
	for _, w := range q.waiters {
		if !w.decided {
			n++
		}
	}
	return n
}

func (q *Queue) pendingForOriginLocked(origin string) int {
	n := 0
	for _, w := range q.waiters {
		if !w.decided && w.req.Origin == origin {
			n++
		}
	}
	return n
}

func (q *Queue) notifyLocked() {
	for _, ch := range q.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
