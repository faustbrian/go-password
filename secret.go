package password

import (
	"errors"
	"sync"
)

// ErrInvalidSecret reports invalid construction, a zero/destroyed owner, a nil
// callback, simultaneous or reentrant use, or a failed/panicking callback.
var ErrInvalidSecret = errors.New("password: invalid secret")

// Secret owns an ephemeral password of 1..1,048,576 bytes. NewSecret copies the
// input. Value copies share ownership and terminal destruction, not byte copies.
// The zero value is invalid; Len returns zero and Use returns ErrInvalidSecret.
// Secret has no string, serialization or formatting methods; its private
// indirection keeps standard diagnostics from traversing the owned bytes.
// Explicit Destroy is required. Go cannot guarantee runtime-wide memory erasure.
type Secret struct{ state func() *secretState }

// secretState.mu owns bytes and busy. Callbacks never execute under this lock.
type secretState struct {
	mu    sync.Mutex
	bytes []byte
	busy  bool
}

// The cause must also be opaque: an arbitrary callback error may be a string
// or byte value that fmt traverses through Error's private cause field.
type secretCallbackCause func() error

// Error provides only a stable redacted callback classification.
func (secretCallbackCause) Error() string { return "password: secret callback failed" }

// Unwrap preserves callback classifications without traversable cause storage.
func (cause secretCallbackCause) Unwrap() error { return cause() }

// NewSecret copies valid input into a new independent owner. Empty input returns
// ErrInvalidSecret; input over 1,048,576 bytes returns ErrResourceRejected. Both
// errors are typed and omit input. Input is neither changed nor retained.
func NewSecret(input []byte) (Secret, error) {
	if len(input) == 0 {
		return Secret{}, newError(ErrInvalidSecret, "construct secret", nil)
	}
	if len(input) > 1<<20 {
		return Secret{}, newError(ErrResourceRejected, "construct secret", nil)
	}
	owned := make([]byte, len(input))
	copy(owned, input)
	owner := &secretState{bytes: owned}
	// A pointer field is insufficient: fmt's unsupported-verb diagnostics can
	// dereference it. A closure preserves shared ownership without traversable
	// byte fields, even for those diagnostics, without disclosure interfaces.
	return Secret{state: func() *secretState { return owner }}, nil
}

// Destroy clears the original owned bytes and terminally invalidates all copies.
// It is idempotent and safe from a callback. An already-admitted callback keeps
// its private borrow until return; that borrow is then cleared. Destroy neither
// waits for callbacks nor clears a concurrently accessed borrow.
func (s Secret) Destroy() {
	if s.state == nil {
		return
	}
	owner := s.state()
	owner.mu.Lock()
	clear(owner.bytes)
	owner.bytes = nil
	owner.mu.Unlock()
}

// Len reports the current owned byte length, or zero for a zero/destroyed owner.
// It is race-safe and may be called from a Use callback.
func (s Secret) Len() int {
	if s.state == nil {
		return 0
	}
	owner := s.state()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return len(owner.bytes)
}

// Use admits at most one synchronous callback across all value copies. Concurrent
// or reentrant Use fails immediately with ErrInvalidSecret; callbacks are never
// run under locks. The callback receives a private, mutable byte copy whose
// mutation does not affect subsequent uses. It must not retain the slice, start
// asynchronous access or copy secret material into diagnostics. All aliases are
// cleared on callback exit, including errors and panics. A panic is suppressed
// and returns a typed ErrInvalidSecret without its value. Callback errors are
// wrapped with ErrInvalidSecret and preserved for errors.Is/As, never formatted.
// Use does not accept cancellation; callers compose bounded contexts inside the
// callback. Destroy during Use prevents future admission without waiting.
func (s Secret) Use(callback func([]byte) error) (err error) {
	if s.state == nil || callback == nil {
		return newError(ErrInvalidSecret, "use secret", nil)
	}
	owner := s.state()
	owner.mu.Lock()
	if len(owner.bytes) == 0 || owner.busy {
		owner.mu.Unlock()
		return newError(ErrInvalidSecret, "use secret", nil)
	}
	owner.busy = true
	// Do not expose allocator-rounded spare capacity: legal callback reslicing
	// must never reach package-owned bytes beyond the cleanup slice's length.
	borrow := make([]byte, len(owner.bytes))
	copy(borrow, owner.bytes)
	owner.mu.Unlock()
	completed := false
	defer func() {
		clear(borrow)
		owner.mu.Lock()
		owner.busy = false
		owner.mu.Unlock()
		if !completed {
			_ = recover()
			err = newError(ErrInvalidSecret, "use secret", nil)
		}
	}()
	cause := callback(borrow)
	completed = true
	if cause != nil {
		return newError(ErrInvalidSecret, "use secret", secretCallbackCause(func() error { return cause }))
	}
	return nil
}
