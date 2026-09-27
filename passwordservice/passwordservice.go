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

// New wraps a caller-owned admission controller.
func New(admission *password.Admission) (*Lifecycle, error) {
	adapter, err := serviceadapter.New(admission)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return &Lifecycle{adapter: adapter}, nil
}

// Start validates the context and rejects restart after shutdown.
func (l *Lifecycle) Start(ctx context.Context) error { return l.adapter.Start(ctx) }

// Stop closes admission and drains active work within ctx.
func (l *Lifecycle) Stop(ctx context.Context) error { return l.adapter.Stop(ctx) }
