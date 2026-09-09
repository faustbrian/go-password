package passwordauth

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	password "github.com/faustbrian/go-password"
	passwordauthentication "github.com/faustbrian/go-password/adapters/authentication"
)

var (
	// ErrInvalidConfig reports a missing service, lookup, or valid dummy hash.
	ErrInvalidConfig = errors.New("passwordauth: invalid configuration")
	// ErrRejected reports a missing identity or password mismatch.
	ErrRejected = errors.New("passwordauth: authentication rejected")
	// ErrUnavailable reports lookup, stored-data, resource, or entropy failure.
	ErrUnavailable = errors.New("passwordauth: authentication unavailable")
	// ErrCanceled reports caller cancellation or deadline expiration.
	ErrCanceled = errors.New("passwordauth: authentication canceled")
)

// Error is a classified authentication adapter error that omits Cause text.
type Error struct {
	kind  error
	cause error
}

func newError(kind, cause error) *Error { return &Error{kind: kind, cause: cause} }

// Kind returns the stable passwordauth sentinel.
func (e *Error) Kind() error { return e.kind }

// Cause returns the underlying operational error without formatting it.
func (e *Error) Cause() error { return e.cause }

// Error returns only the released stable classification.
func (e *Error) Error() string {
	return e.kind.Error()
}

// Unwrap exposes classification and cause to errors.Is/errors.As.
func (e *Error) Unwrap() []error {
	if e.cause == nil {
		return []error{e.kind}
	}
	return []error{e.kind, e.cause}
}

// Record is an application-owned subject and encoded password hash. Diagnostic
// formatting is redacted; EncodedHash is accessed explicitly for verification.
type Record struct {
	// Subject is the stable application identity.
	Subject string
	// EncodedHash is the current database value.
	EncodedHash string
}

// String returns a redacted diagnostic representation.
func (Record) String() string { return "password record [redacted]" }

// GoString returns a redacted Go-syntax representation.
func (Record) GoString() string { return "passwordauth.Record{redacted}" }

// Format redacts every fmt formatting verb.
func (Record) Format(state fmt.State, _ rune) {
	_, _ = fmt.Fprint(state, "password record [redacted]")
}

// Lookup retrieves an application-owned record without repository ownership.
type Lookup interface {
	// LookupPassword returns a record, its presence, and an operational error.
	LookupPassword(context.Context, string) (Record, bool, error)
}

// Config contains all mandatory authentication adapter collaborators.
type Config struct {
	// Passwords performs bounded verification and upgrades.
	Passwords *password.Service
	// Lookup retrieves application-owned records.
	Lookup Lookup
	// DummyHash is valid synthetic work used when the username is absent.
	DummyHash string
}

// Authenticator preserves the released adapter type while delegating behavior
// to the target-oriented successor.
type Authenticator struct {
	adapter *passwordauthentication.Authenticator
}

type lookupAdapter struct{ lookup Lookup }

// LookupPassword converts the released record type for successor delegation.
func (adapter lookupAdapter) LookupPassword(ctx context.Context, username string) (passwordauthentication.Record, bool, error) {
	record, found, err := adapter.lookup.LookupPassword(ctx, username)
	return passwordauthentication.Record{Subject: record.Subject, EncodedHash: record.EncodedHash}, found, err
}

// New validates all collaborators and parses DummyHash before accepting work.
func New(config Config) (*Authenticator, error) {
	var lookup passwordauthentication.Lookup
	if !nilLookup(config.Lookup) {
		lookup = lookupAdapter{lookup: config.Lookup}
	}
	adapter, err := passwordauthentication.New(passwordauthentication.Config{
		Passwords: config.Passwords,
		Lookup:    lookup,
		DummyHash: config.DummyHash,
	})
	if err != nil {
		return nil, translateError(err)
	}
	return &Authenticator{adapter: adapter}, nil
}

func nilLookup(lookup Lookup) bool {
	if lookup == nil {
		return true
	}
	reflected := reflect.ValueOf(lookup)
	switch reflected.Kind() { //nolint:exhaustive // Only nilable concrete kinds require handling.
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func translateError(err error) error {
	var classified *passwordauthentication.Error
	if !errors.As(err, &classified) {
		return err
	}
	var kind error
	switch {
	case errors.Is(classified.Kind(), passwordauthentication.ErrInvalidConfig):
		kind = ErrInvalidConfig
	case errors.Is(classified.Kind(), passwordauthentication.ErrRejected):
		kind = ErrRejected
	case errors.Is(classified.Kind(), passwordauthentication.ErrUnavailable):
		kind = ErrUnavailable
	case errors.Is(classified.Kind(), passwordauthentication.ErrCanceled):
		kind = ErrCanceled
	}
	return newError(kind, classified.Cause())
}

// Upgrade is an immutable optimistic compare-and-swap pair.
type Upgrade struct {
	expected    password.EncodedHash
	replacement password.EncodedHash
}

// Required reports whether a durable conditional update is needed.
func (u Upgrade) Required() bool { return u.replacement.String() != "" }

// Expected returns the hash that must still be stored for CAS to succeed.
func (u Upgrade) Expected() password.EncodedHash { return u.expected }

// Replacement returns the newly computed hash for the conditional update.
func (u Upgrade) Replacement() password.EncodedHash { return u.replacement }

// String returns a redacted diagnostic representation.
func (Upgrade) String() string { return "password upgrade [redacted]" }

// GoString returns a redacted Go-syntax representation.
func (Upgrade) GoString() string { return "passwordauth.Upgrade{redacted}" }

// Result is a successful stable subject plus optional CAS upgrade.
type Result struct {
	subject string
	upgrade Upgrade
}

// Subject returns the stable application identity.
func (r Result) Subject() string { return r.subject }

// Upgrade returns the optional immutable CAS pair.
func (r Result) Upgrade() Upgrade { return r.upgrade }

// String returns a secret-safe diagnostic representation.
func (Result) String() string { return "password authentication result" }

// GoString returns a redacted Go-syntax representation.
func (Result) GoString() string { return "passwordauth.Result{redacted}" }

// Authenticate delegates to the target-oriented successor while preserving
// the released result and error types.
func (a *Authenticator) Authenticate(ctx context.Context, username string, secret []byte) (Result, error) {
	result, err := a.adapter.Authenticate(ctx, username, secret)
	if err != nil {
		return Result{}, translateError(err)
	}
	upgrade := result.Upgrade()
	return Result{
		subject: result.Subject(),
		upgrade: Upgrade{expected: upgrade.Expected(), replacement: upgrade.Replacement()},
	}, nil
}
