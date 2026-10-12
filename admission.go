package password

import (
	"context"
	"sync"
	"time"
)

// Admission bounds active and queued expensive operations without worker
// goroutines. It is safe for concurrent use, but does not guarantee FIFO fairness
// or bound primitive duration. Use NewAdmission; its zero value is not usable.
// Contexts must be non-nil, and owners coordinate shutdown of shared controllers.
type Admission struct {
	mu         sync.Mutex
	capacity   int
	active     int
	queueLimit int
	queued     int
	closed     chan struct{}
	notify     chan struct{}
	closing    bool
}

// NewAdmission constructs an open controller with hard active and queue limits.
// concurrent must be positive and queue nonnegative; queue zero rejects waiters.
func NewAdmission(concurrent, queue int) (*Admission, error) {
	if concurrent < 1 || queue < 0 {
		return nil, newError(ErrInvalidPolicy, "configure admission", nil)
	}
	return newAdmission(concurrent, queue), nil
}

func newAdmission(concurrent, queue int) *Admission {
	return &Admission{capacity: concurrent, queueLimit: queue, closed: make(chan struct{}), notify: make(chan struct{}, 1)}
}

// Acquire waits for capacity within ctx and returns an idempotent release
// function. The caller must release every admitted operation. Queue overflow
// returns ErrAdmission; shutdown returns ErrClosed. Direct cancellation returns
// ctx.Err, whereas Service classifies it as ErrCanceled. A capacity notification
// racing cancellation can still admit the waiter; acquired work is not canceled.
func (a *Admission) Acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	if a.closing {
		a.mu.Unlock()
		return nil, newError(ErrClosed, "acquire", nil)
	}
	switch a.capacity - a.active {
	case 0:
	default:
		a.active++
		a.mu.Unlock()
		return a.release(), nil
	}
	if a.queued >= a.queueLimit {
		a.mu.Unlock()
		return nil, newError(ErrAdmission, "acquire", nil)
	}
	a.queued++
	a.mu.Unlock()
	for {
		select {
		case <-a.closed:
			a.removeWaiter()
			return nil, newError(ErrClosed, "acquire", nil)
		case <-ctx.Done():
			a.removeWaiter()
			return nil, ctx.Err()
		case <-a.notify:
			release, decided, err := a.admitNotifiedWaiter()
			if decided {
				return release, err
			}
		}
	}
}

func (a *Admission) admitNotifiedWaiter() (func(), bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closing {
		a.queued--
		return nil, true, newError(ErrClosed, "acquire", nil)
	}
	if a.active >= a.capacity {
		return nil, false, nil
	}
	a.queued--
	a.active++
	a.signalWaiterLocked()
	return a.release(), true, nil
}

func (a *Admission) removeWaiter() { a.mu.Lock(); a.queued--; a.mu.Unlock() }

// One buffered notification is enough: admission and release chain wakeups while
// capacity remains. A notification does not reserve capacity for a given waiter.
func (a *Admission) signalWaiterLocked() {
	if a.queued == 0 || a.active >= a.capacity {
		return
	}
	select {
	case a.notify <- struct{}{}:
	default:
	}
}

func (a *Admission) release() func() {
	var once sync.Once
	return func() { once.Do(func() { a.mu.Lock(); a.active--; a.signalWaiterLocked(); a.mu.Unlock() }) }
}

// Queued returns a concurrency-safe instantaneous waiter count.
func (a *Admission) Queued() int { a.mu.Lock(); defer a.mu.Unlock(); return a.queued }

// Active returns a concurrency-safe instantaneous active-operation count.
func (a *Admission) Active() int { a.mu.Lock(); defer a.mu.Unlock(); return a.active }

// Closed reports whether Shutdown has begun.
func (a *Admission) Closed() bool { a.mu.Lock(); defer a.mu.Unlock(); return a.closing }

// Shutdown rejects new work, wakes queued callers, and waits for admitted work
// to release capacity. Closure is permanent, even if ctx expires before drain.
// It never interrupts active work; a forgotten release can prevent draining.
// Repeating Shutdown observes the same drain. An already drained controller
// returns nil even if ctx is canceled; expiration during drain returns ctx.Err.
func (a *Admission) Shutdown(ctx context.Context) error {
	a.mu.Lock()
	if !a.closing {
		a.closing = true
		close(a.closed)
	}
	a.mu.Unlock()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for a.Active() != 0 || a.Queued() != 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	return nil
}
