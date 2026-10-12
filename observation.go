package password

import (
	"context"
	"errors"
	"time"
)

// Operation names an observation operation. Service emits only the constants
// below; arbitrary application conversions to this string type are not validated.
type Operation string

const (
	// OperationHash identifies one public Hash call.
	OperationHash Operation = "hash"
	// OperationVerify identifies one public Verify call.
	OperationVerify Operation = "verify"
	// OperationVerifyAndUpgrade identifies one public VerifyAndUpgrade call.
	OperationVerifyAndUpgrade Operation = "verify_and_upgrade"
)

// Outcome names an observation result. Service emits the constants below,
// without copying primitive errors or attacker-controlled input into labels.
type Outcome string

const (
	// OutcomeSuccess reports successful work without an upgrade.
	OutcomeSuccess Outcome = "success"
	// OutcomeUpgraded reports a successfully created replacement hash.
	OutcomeUpgraded Outcome = "upgraded"
	// OutcomeMismatch reports a valid hash that did not match.
	OutcomeMismatch Outcome = "mismatch"
	// OutcomeMalformed reports invalid encoded-hash syntax.
	OutcomeMalformed Outcome = "malformed"
	// OutcomeUnsupported reports an unsupported algorithm or version.
	OutcomeUnsupported Outcome = "unsupported"
	// OutcomeResourceRejected reports limits, admission, or lifecycle rejection.
	OutcomeResourceRejected Outcome = "resource_rejected"
	// OutcomeCanceled reports caller cancellation or deadline expiration.
	OutcomeCanceled Outcome = "canceled"
	// OutcomeFailed reports entropy or another operational failure.
	OutcomeFailed Outcome = "failed"
)

// Observation is a service event without password, hash, subject, or error data.
// Service supplies bounded labels; application-constructed values are not checked.
type Observation struct {
	// Operation identifies the public API call.
	Operation Operation
	// Algorithm is the configured target in Service events, not the stored hash
	// algorithm or attacker-controlled parsed parameters.
	Algorithm Algorithm
	// Outcome is the classified bounded result.
	Outcome Outcome
	// NeedsRehash reports the verified hash's upgrade decision.
	NeedsRehash bool
	// Duration covers the operation through result computation, including waits
	// and both upgrade phases, but excludes the observer callback itself.
	Duration time.Duration
}

// Observer consumes one synchronous event per public Hash, Verify, or
// VerifyAndUpgrade call. Calls may overlap or reenter; implementations must be
// concurrency-safe and bound their own latency. Panics are isolated, but blocking
// delays return. The borrowed context may contain application secrets: event
// redaction does not make context values safe to log.
type Observer interface {
	// Observe records a service event using the caller context. An upgrade emits
	// one combined event, not separate nested hash and verify callbacks.
	Observe(context.Context, Observation)
}

// WithObserver configures one borrowed caller-owned Observer; nil and typed-nil
// values are rejected. The service does not queue events or close the observer.
func WithObserver(observer Observer) Option {
	return func(service *Service) error {
		if isNilInterface(observer) {
			return newError(ErrInvalidPolicy, "configure observer", nil)
		}
		service.observer = observer
		return nil
	}
}

func (s *Service) observe(ctx context.Context, operation Operation, started time.Time, needsRehash, upgraded bool, err error) {
	if s.observer == nil {
		return
	}
	event := Observation{Operation: operation, Algorithm: s.policy.config.Algorithm, Outcome: observationOutcome(upgraded, err), NeedsRehash: needsRehash, Duration: time.Since(started)}
	defer func() { _ = recover() }()
	s.observer.Observe(ctx, event)
}

func observationOutcome(upgraded bool, err error) Outcome {
	if err == nil {
		if upgraded {
			return OutcomeUpgraded
		}
		return OutcomeSuccess
	}
	switch {
	case errors.Is(err, ErrCanceled):
		return OutcomeCanceled
	case errors.Is(err, ErrMismatch):
		return OutcomeMismatch
	case errors.Is(err, ErrMalformedHash):
		return OutcomeMalformed
	case errors.Is(err, ErrUnsupportedAlgorithm), errors.Is(err, ErrUnsupportedVersion):
		return OutcomeUnsupported
	case errors.Is(err, ErrResourceRejected), errors.Is(err, ErrAdmission), errors.Is(err, ErrClosed):
		return OutcomeResourceRejected
	default:
		return OutcomeFailed
	}
}
