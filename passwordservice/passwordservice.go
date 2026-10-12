package passwordservice

import (
	"context"
	"errors"

	password "github.com/faustbrian/go-password/v2"
	serviceadapter "github.com/faustbrian/go-password/v2/adapters/service"
)

// ErrInvalidConfig reports a missing admission controller.
var ErrInvalidConfig = errors.New("passwordservice: invalid configuration")

// Lifecycle preserves the released service lifecycle adapter type.
type Lifecycle struct{ adapter *serviceadapter.Lifecycle }

// New wraps a caller-owned admission controller without replacing or reopening
// it. Shared owners must coordinate shutdown; use password.NewAdmission, not a
// zero controller. A nil controller is ErrInvalidConfig.
func New(admission *password.Admission) (*Lifecycle, error) {
	adapter, err := serviceadapter.New(admission)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return &Lifecycle{adapter: adapter}, nil
}

// Start validates the non-nil context and rejects restart after shutdown.
// It starts no worker and does not reserve capacity.
func (l *Lifecycle) Start(ctx context.Context) error { return l.adapter.Start(ctx) }

// Stop permanently closes admission and observes drain within the non-nil ctx.
// It cannot cancel active primitives; expiration leaves the controller closed.
func (l *Lifecycle) Stop(ctx context.Context) error { return l.adapter.Stop(ctx) }
