package password

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
)

type failingEntropy struct{ err error }

func (r failingEntropy) Read([]byte) (int, error) { return 0, r.err }

type diagnosticCause struct{ Marker string }

func (cause diagnosticCause) Error() string { return cause.Marker }

func TestDeterministicEntropySupportRemainsInternal(t *testing.T) {
	policy := DefaultPolicy()
	if _, err := newService(policy, nil); !errors.Is(err, ErrEntropy) {
		t.Fatalf("nil entropy error = %v", err)
	}
	if _, err := newService(Policy{}, strings.NewReader("entropy")); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("invalid policy error = %v", err)
	}

	service, err := newService(policy, failingEntropy{err: io.ErrUnexpectedEOF})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Hash(context.Background(), []byte("synthetic")); !errors.Is(err, ErrEntropy) {
		t.Fatalf("entropy error = %v", err)
	}
}

func TestClassifiedErrorDoesNotExposeCause(t *testing.T) {
	const sensitiveCause = "sensitive entropy detail"
	observer := &internalRecordingObserver{}
	service, err := newService(
		DefaultPolicy(),
		failingEntropy{err: diagnosticCause{Marker: sensitiveCause}},
		WithObserver(observer),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Hash(context.Background(), []byte("synthetic"))
	if !errors.Is(err, ErrEntropy) {
		t.Fatalf("entropy classification = %v", err)
	}
	var classified *Error
	if !errors.As(err, &classified) || !errors.Is(classified.Kind(), ErrEntropy) || classified.Cause() == nil || classified.Operation() != "read salt" {
		t.Fatalf("classified error = %#v", classified)
	}
	for _, format := range []string{"%s", "%q", "%v", "%+v", "%#v"} {
		if rendered := fmt.Sprintf(format, err); strings.Contains(rendered, sensitiveCause) {
			t.Fatalf("format %s leaked cause: %s", format, rendered)
		}
	}
	for _, handler := range []func(*bytes.Buffer) slog.Handler{
		func(output *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(output, nil) },
		func(output *bytes.Buffer) slog.Handler { return slog.NewTextHandler(output, nil) },
	} {
		var output bytes.Buffer
		slog.New(handler(&output)).Info("password operation", "error", err)
		if strings.Contains(output.String(), sensitiveCause) {
			t.Fatalf("structured log leaked entropy cause: %s", output.String())
		}
	}
	if len(observer.events) != 1 || observer.events[0].Outcome != OutcomeFailed {
		t.Fatalf("observations = %#v", observer.events)
	}
}

func TestVerifyAndUpgradePreservesMatchWhenEntropyFails(t *testing.T) {
	legacyConfig := DefaultPolicy().config
	legacyConfig.Algorithm = Bcrypt
	legacyConfig.BcryptCost = 4
	legacyPolicy, err := NewPolicy(legacyConfig)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := New(legacyPolicy)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := legacy.Hash(context.Background(), []byte("synthetic"))
	if err != nil {
		t.Fatal(err)
	}

	service, err := newService(DefaultPolicy(), failingEntropy{err: io.ErrUnexpectedEOF})
	if err != nil {
		t.Fatal(err)
	}
	result, upgraded, err := service.VerifyAndUpgrade(context.Background(), []byte("synthetic"), encoded.String())
	if !result.Match() || !result.NeedsRehash() || upgraded.String() != "" || !errors.Is(err, ErrEntropy) {
		t.Fatalf("result = %#v, upgraded = %q, error = %v", result, upgraded.String(), err)
	}
}

type internalRecordingObserver struct{ events []Observation }

func (o *internalRecordingObserver) Observe(_ context.Context, event Observation) {
	o.events = append(o.events, event)
}
