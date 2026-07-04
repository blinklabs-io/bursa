package connector

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

var (
	ErrTimeout        = errors.New("connector: request timed out")
	ErrUnknownRequest = errors.New("connector: unknown request id")
	ErrAlreadyDecided = errors.New("connector: request already decided")
)

type Request struct {
	ID      string          `json:"id"`
	Origin  string          `json:"origin"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	Created time.Time       `json:"created"`
}

type Decision struct {
	Approved bool
	Password string
}

type waiter struct {
	req     Request
	done    chan Decision
	decided bool
}

type Queue struct {
	now     func() time.Time
	mkID    func() (string, error)
	timeout time.Duration

	mu      sync.Mutex
	waiters map[string]*waiter
	subs    map[int]chan Request
	nextSub int
}

func NewQueue(now func() time.Time, mkID func() (string, error), timeout time.Duration) *Queue {
	return &Queue{
		now: now, mkID: mkID, timeout: timeout,
		waiters: map[string]*waiter{}, subs: map[int]chan Request{},
	}
}

func (q *Queue) Submit(origin, method string, params json.RawMessage) (*Request, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	id, err := q.mkID()
	if err != nil {
		return nil, err
	}
	r := Request{ID: id, Origin: origin, Method: method, Params: params, Created: q.now()}
	q.waiters[r.ID] = &waiter{req: r, done: make(chan Decision, 1)}
	for _, ch := range q.subs {
		select {
		case ch <- r:
		default:
		}
	}
	return &r, nil
}

func (q *Queue) Await(ctx context.Context, id string) (Decision, error) {
	q.mu.Lock()
	w, ok := q.waiters[id]
	q.mu.Unlock()
	if !ok {
		return Decision{}, ErrUnknownRequest
	}
	defer q.remove(id)
	// Use NewTimer + defer Stop to avoid a goroutine/channel leak when the
	// request is resolved before the timeout fires (time.After leaks the
	// timer until it fires at the full 120s production timeout).
	t := time.NewTimer(q.timeout)
	defer t.Stop()
	select {
	case d := <-w.done:
		return d, nil
	case <-t.C:
		return Decision{}, ErrTimeout
	case <-ctx.Done():
		return Decision{}, ctx.Err()
	}
}

func (q *Queue) Decide(id string, d Decision) error {
	q.mu.Lock()
	w, ok := q.waiters[id]
	if !ok {
		q.mu.Unlock()
		return ErrUnknownRequest
	}
	if w.decided {
		q.mu.Unlock()
		return ErrAlreadyDecided
	}
	w.decided = true
	q.mu.Unlock()

	w.done <- d
	return nil
}

func (q *Queue) Pending() []Request {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]Request, 0, len(q.waiters))
	for _, w := range q.waiters {
		if w.decided {
			continue
		}
		out = append(out, w.req)
	}
	return out
}

func (q *Queue) Subscribe() (<-chan Request, func()) {
	q.mu.Lock()
	defer q.mu.Unlock()
	id := q.nextSub
	q.nextSub++
	ch := make(chan Request, 8)
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
	delete(q.waiters, id)
}
