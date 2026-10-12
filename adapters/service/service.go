package passwordservice

import (
	"context"
	"errors"

	password "github.com/faustbrian/go-password/v2"
)

// ErrInvalidConfig reports a missing admission controller.
var ErrInvalidConfig = errors.New("passwordservice: invalid configuration")

// Lifecycle exposes service-compatible start and stop hooks for Admission.
type Lifecycle struct{ admission *password.Admission }

// New wraps a caller-owned admission controller without replacing or reopening
// it. Shared owners must coordinate shutdown; use password.NewAdmission, not a
// zero controller. A nil controller is ErrInvalidConfig.
func New(admission *password.Admission) (*Lifecycle, error) {
	if admission == nil {
		return nil, ErrInvalidConfig
	}
	return &Lifecycle{admission: admission}, nil
}

// Start validates the non-nil context and rejects restart after shutdown.
// It starts no worker and does not reserve capacity.
func (l *Lifecycle) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if l.admission.Closed() {
		return password.ErrClosed
	}
	return nil
}

// Stop permanently closes admission and observes drain within the non-nil ctx.
// It cannot cancel active primitives; expiration leaves the controller closed.
func (l *Lifecycle) Stop(ctx context.Context) error { return l.admission.Shutdown(ctx) }
