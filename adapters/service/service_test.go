package passwordservice_test

import (
	"context"
	"errors"
	"testing"

	password "github.com/faustbrian/go-password"
	passwordservice "github.com/faustbrian/go-password/adapters/service"
)

func TestLifecycleProvidesServiceCompatibleHooks(t *testing.T) {
	if _, err := passwordservice.New(nil); !errors.Is(err, passwordservice.ErrInvalidConfig) {
		t.Fatalf("nil admission error = %v", err)
	}
	admission, err := password.NewAdmission(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := passwordservice.New(admission)
	if err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Start(context.Background()); !errors.Is(err, password.ErrClosed) {
		t.Fatalf("restart = %v", err)
	}
	admission, err = password.NewAdmission(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err = passwordservice.New(admission)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := lifecycle.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled start = %v", err)
	}
}
