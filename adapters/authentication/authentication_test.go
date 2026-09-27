package passwordauthentication_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"

	password "github.com/faustbrian/go-password/v2"
	passwordauthentication "github.com/faustbrian/go-password/v2/adapters/authentication"
)

type lookupFunc func(context.Context, string) (passwordauthentication.Record, bool, error)

func (f lookupFunc) LookupPassword(ctx context.Context, username string) (passwordauthentication.Record, bool, error) {
	return f(ctx, username)
}

type diagnosticCause struct{ Marker string }

func (cause diagnosticCause) Error() string { return cause.Marker }

func TestAuthenticateReturnsExplicitCASUpgrade(t *testing.T) {
	limits := password.DefaultPolicy().Limits()
	limits.MemoryKiB = 64
	limits.Argon2Time = 2
	policy, err := password.NewPolicy(password.PolicyConfig{
		Algorithm: password.Argon2id,
		Argon2id:  password.Argon2idParameters{Version: 19, Time: 1, MemoryKiB: 8, Parallelism: 1, SaltLength: 8, OutputLength: 16},
		Limits:    limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	passwords, err := password.New(policy)
	if err != nil {
		t.Fatal(err)
	}
	bcryptPolicy, err := password.NewPolicy(password.PolicyConfig{Algorithm: password.Bcrypt, BcryptCost: 4, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	bcryptPasswords, err := password.New(bcryptPolicy)
	if err != nil {
		t.Fatal(err)
	}
	current, err := bcryptPasswords.Hash(context.Background(), []byte("synthetic user password"))
	if err != nil {
		t.Fatal(err)
	}
	dummy, err := passwords.Hash(context.Background(), []byte("synthetic dummy password"))
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := passwordauthentication.New(passwordauthentication.Config{
		Passwords: passwords,
		Lookup: lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
			return passwordauthentication.Record{Subject: "user-123", EncodedHash: current.String()}, true, nil
		}),
		DummyHash: dummy.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := authenticator.Authenticate(context.Background(), "synthetic-user", []byte("synthetic user password"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Subject() != "user-123" || !result.Upgrade().Required() || result.Upgrade().Expected().String() != current.String() || result.Upgrade().Replacement().Algorithm() != password.Argon2id {
		t.Fatalf("result = %#v", result)
	}
	if errors.Is(err, passwordauthentication.ErrRejected) {
		t.Fatal("successful authentication was rejected")
	}
}

type nilLookup struct{}

func (*nilLookup) LookupPassword(context.Context, string) (passwordauthentication.Record, bool, error) {
	panic("typed-nil lookup invoked")
}

type missingLookup struct{}

func (missingLookup) LookupPassword(context.Context, string) (passwordauthentication.Record, bool, error) {
	return passwordauthentication.Record{}, false, nil
}

func testServices(t *testing.T) (*password.Service, string, string) {
	t.Helper()
	limits := password.DefaultPolicy().Limits()
	limits.MemoryKiB = 64
	limits.Argon2Time = 2
	policy, err := password.NewPolicy(password.PolicyConfig{
		Algorithm: password.Argon2id,
		Argon2id:  password.Argon2idParameters{Version: 19, Time: 1, MemoryKiB: 8, Parallelism: 1, SaltLength: 8, OutputLength: 16},
		Limits:    limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	passwords, err := password.New(policy)
	if err != nil {
		t.Fatal(err)
	}
	bcryptPolicy, err := password.NewPolicy(password.PolicyConfig{Algorithm: password.Bcrypt, BcryptCost: 4, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	bcryptPasswords, err := password.New(bcryptPolicy)
	if err != nil {
		t.Fatal(err)
	}
	current, err := bcryptPasswords.Hash(context.Background(), []byte("synthetic user password"))
	if err != nil {
		t.Fatal(err)
	}
	dummy, err := passwords.Hash(context.Background(), []byte("synthetic dummy password"))
	if err != nil {
		t.Fatal(err)
	}
	return passwords, current.String(), dummy.String()
}

func TestConfigurationAndClassifiedErrors(t *testing.T) {
	service, _, dummy := testServices(t)
	validLookup := lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
		return passwordauthentication.Record{}, false, nil
	})
	for _, config := range []passwordauthentication.Config{
		{},
		{Passwords: service},
		{Passwords: service, Lookup: validLookup},
		{Passwords: service, Lookup: validLookup, DummyHash: "broken"},
	} {
		_, err := passwordauthentication.New(config)
		if !errors.Is(err, passwordauthentication.ErrInvalidConfig) {
			t.Fatalf("config=%#v error=%v", config, err)
		}
		var classified *passwordauthentication.Error
		if !errors.As(err, &classified) || !errors.Is(classified.Kind(), passwordauthentication.ErrInvalidConfig) {
			t.Fatalf("classified error = %v", err)
		}
		if classified.Error() != passwordauthentication.ErrInvalidConfig.Error() {
			t.Fatalf("error text = %q", classified.Error())
		}
		if config.DummyHash == "broken" {
			if classified.Cause() == nil || len(classified.Unwrap()) != 2 {
				t.Fatalf("malformed dummy cause = %v", classified.Cause())
			}
		} else if classified.Cause() != nil || len(classified.Unwrap()) != 1 {
			t.Fatalf("unexpected cause = %v", classified.Cause())
		}
	}
	var typedNil *nilLookup
	if _, err := passwordauthentication.New(passwordauthentication.Config{Passwords: service, Lookup: typedNil, DummyHash: dummy}); !errors.Is(err, passwordauthentication.ErrInvalidConfig) {
		t.Fatalf("typed-nil lookup error = %v", err)
	}
	if _, err := passwordauthentication.New(passwordauthentication.Config{Passwords: service, Lookup: missingLookup{}, DummyHash: dummy}); err != nil {
		t.Fatalf("value lookup error = %v", err)
	}
}

func TestNewRejectsDummyHashThatDoesNotMatchTargetWork(t *testing.T) {
	validLookup := lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
		return passwordauthentication.Record{}, false, nil
	})
	limits := password.DefaultPolicy().Limits()
	limits.MemoryKiB = 64
	limits.Argon2Time = 2
	targetParameters := password.Argon2idParameters{Version: 19, Time: 1, MemoryKiB: 16, Parallelism: 1, SaltLength: 8, OutputLength: 16}
	targetPolicy, err := password.NewPolicy(password.PolicyConfig{Algorithm: password.Argon2id, Argon2id: targetParameters, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	service, err := password.New(targetPolicy)
	if err != nil {
		t.Fatal(err)
	}
	matchingDummy, err := service.Hash(context.Background(), []byte("synthetic dummy password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := passwordauthentication.New(passwordauthentication.Config{Passwords: service, Lookup: validLookup, DummyHash: matchingDummy.String()}); err != nil {
		t.Fatalf("matching dummy rejected: %v", err)
	}

	bcryptPolicy, err := password.NewPolicy(password.PolicyConfig{
		Algorithm:  password.Bcrypt,
		BcryptCost: 4,
		Limits:     limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	bcryptService, err := password.New(bcryptPolicy)
	if err != nil {
		t.Fatal(err)
	}
	bcryptDummy, err := bcryptService.Hash(context.Background(), []byte("synthetic dummy password"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		parameters password.Argon2idParameters
	}{
		{"time", password.Argon2idParameters{Version: 19, Time: 2, MemoryKiB: 16, Parallelism: 1, SaltLength: 8, OutputLength: 16}},
		{"memory", password.Argon2idParameters{Version: 19, Time: 1, MemoryKiB: 32, Parallelism: 1, SaltLength: 8, OutputLength: 16}},
		{"parallelism", password.Argon2idParameters{Version: 19, Time: 1, MemoryKiB: 16, Parallelism: 2, SaltLength: 8, OutputLength: 16}},
		{"salt length", password.Argon2idParameters{Version: 19, Time: 1, MemoryKiB: 16, Parallelism: 1, SaltLength: 9, OutputLength: 16}},
		{"output length", password.Argon2idParameters{Version: 19, Time: 1, MemoryKiB: 16, Parallelism: 1, SaltLength: 8, OutputLength: 17}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			differentPolicy, err := password.NewPolicy(password.PolicyConfig{Algorithm: password.Argon2id, Argon2id: tt.parameters, Limits: limits})
			if err != nil {
				t.Fatal(err)
			}
			differentService, err := password.New(differentPolicy)
			if err != nil {
				t.Fatal(err)
			}
			differentDummy, err := differentService.Hash(context.Background(), []byte("synthetic dummy password"))
			if err != nil {
				t.Fatal(err)
			}
			assertMismatchedDummy(t, service, validLookup, differentDummy.String())
		})
	}
	assertMismatchedDummy(t, service, validLookup, bcryptDummy.String())
}

func assertMismatchedDummy(t *testing.T, service *password.Service, lookup passwordauthentication.Lookup, dummy string) {
	t.Helper()
	_, err := passwordauthentication.New(passwordauthentication.Config{Passwords: service, Lookup: lookup, DummyHash: dummy})
	if !errors.Is(err, passwordauthentication.ErrInvalidConfig) {
		t.Fatalf("mismatched dummy error = %v", err)
	}
}

func TestNewRejectsDummyHashWithDifferentBcryptCost(t *testing.T) {
	limits := password.DefaultPolicy().Limits()
	lookup := lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
		return passwordauthentication.Record{}, false, nil
	})
	serviceForCost := func(cost int) *password.Service {
		t.Helper()
		policy, err := password.NewPolicy(password.PolicyConfig{Algorithm: password.Bcrypt, BcryptCost: cost, Limits: limits})
		if err != nil {
			t.Fatal(err)
		}
		service, err := password.New(policy)
		if err != nil {
			t.Fatal(err)
		}
		return service
	}
	target := serviceForCost(4)
	matchingDummy, err := target.Hash(context.Background(), []byte("synthetic dummy password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := passwordauthentication.New(passwordauthentication.Config{Passwords: target, Lookup: lookup, DummyHash: matchingDummy.String()}); err != nil {
		t.Fatalf("matching bcrypt dummy rejected: %v", err)
	}
	differentDummy, err := serviceForCost(5).Hash(context.Background(), []byte("synthetic dummy password"))
	if err != nil {
		t.Fatal(err)
	}
	assertMismatchedDummy(t, target, lookup, differentDummy.String())
}

func TestMissingAndTargetMismatchTimingSmoke(t *testing.T) {
	previousGCPercent := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previousGCPercent)

	limits := password.DefaultPolicy().Limits()
	limits.MemoryKiB = 2 * 1024
	limits.Argon2Time = 2
	policy, err := password.NewPolicy(password.PolicyConfig{
		Algorithm: password.Argon2id,
		Argon2id: password.Argon2idParameters{
			Version: 19, Time: 2, MemoryKiB: 2 * 1024, Parallelism: 1,
			SaltLength: 8, OutputLength: 16,
		},
		Limits: limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := password.New(policy)
	if err != nil {
		t.Fatal(err)
	}
	current, err := service.Hash(context.Background(), []byte("current password"))
	if err != nil {
		t.Fatal(err)
	}
	dummy, err := service.Hash(context.Background(), []byte("dummy password"))
	if err != nil {
		t.Fatal(err)
	}
	lookup := lookupFunc(func(_ context.Context, username string) (passwordauthentication.Record, bool, error) {
		if username == "missing" {
			return passwordauthentication.Record{}, false, nil
		}
		return passwordauthentication.Record{Subject: "present", EncodedHash: current.String()}, true, nil
	})
	authenticator, err := passwordauthentication.New(passwordauthentication.Config{
		Passwords: service,
		Lookup:    lookup,
		DummyHash: dummy.String(),
	})
	if err != nil {
		t.Fatal(err)
	}

	measure := func(username string) time.Duration {
		started := time.Now()
		_, err := authenticator.Authenticate(context.Background(), username, []byte("wrong password"))
		if !errors.Is(err, passwordauthentication.ErrRejected) {
			t.Fatalf("Authenticate(%q) error = %v", username, err)
		}
		return time.Since(started)
	}
	const samples = 31
	missing := make([]time.Duration, samples)
	present := make([]time.Duration, samples)
	for index := range samples {
		if index%2 == 0 {
			missing[index] = measure("missing")
			present[index] = measure("present")
		} else {
			present[index] = measure("present")
			missing[index] = measure("missing")
		}
	}
	slices.Sort(missing)
	slices.Sort(present)
	index := (samples - 1) / 2
	missingMedian := missing[index]
	presentMedian := present[index]
	if missingMedian > presentMedian*5 || presentMedian > missingMedian*5 {
		t.Fatalf(
			"obvious missing-user median timing regression: missing=%s present=%s",
			missingMedian,
			presentMedian,
		)
	}
}

func TestAuthenticationFailureClassification(t *testing.T) {
	service, current, dummy := testServices(t)
	tests := []struct {
		name   string
		lookup passwordauthentication.Lookup
		secret []byte
		want   error
		cause  error
	}{
		{"missing", lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
			return passwordauthentication.Record{}, false, nil
		}), []byte("candidate"), passwordauthentication.ErrRejected, nil},
		{"missing dummy collision", lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
			return passwordauthentication.Record{}, false, nil
		}), []byte("synthetic dummy password"), passwordauthentication.ErrRejected, nil},
		{"mismatch", lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
			return passwordauthentication.Record{Subject: "user", EncodedHash: current}, true, nil
		}), []byte("wrong"), passwordauthentication.ErrRejected, password.ErrMismatch},
		{"empty subject", lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
			return passwordauthentication.Record{EncodedHash: current}, true, nil
		}), []byte("candidate"), passwordauthentication.ErrUnavailable, nil},
		{"empty hash", lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
			return passwordauthentication.Record{Subject: "user"}, true, nil
		}), []byte("candidate"), passwordauthentication.ErrUnavailable, nil},
		{"malformed hash", lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
			return passwordauthentication.Record{Subject: "user", EncodedHash: "broken"}, true, nil
		}), []byte("candidate"), passwordauthentication.ErrUnavailable, password.ErrMalformedHash},
		{"lookup failure", lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
			return passwordauthentication.Record{}, false, errors.New("database detail")
		}), []byte("candidate"), passwordauthentication.ErrUnavailable, nil},
		{"lookup canceled", lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
			return passwordauthentication.Record{}, false, context.Canceled
		}), []byte("candidate"), passwordauthentication.ErrCanceled, context.Canceled},
		{"lookup deadline", lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
			return passwordauthentication.Record{}, false, context.DeadlineExceeded
		}), []byte("candidate"), passwordauthentication.ErrCanceled, context.DeadlineExceeded},
		{"resource rejection", lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
			return passwordauthentication.Record{Subject: "user", EncodedHash: current}, true, nil
		}), make([]byte, 1025), passwordauthentication.ErrUnavailable, password.ErrResourceRejected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authenticator, err := passwordauthentication.New(passwordauthentication.Config{Passwords: service, Lookup: tt.lookup, DummyHash: dummy})
			if err != nil {
				t.Fatal(err)
			}
			_, err = authenticator.Authenticate(context.Background(), "user", tt.secret)
			if !errors.Is(err, tt.want) || (tt.cause != nil && !errors.Is(err, tt.cause)) {
				t.Fatalf("error = %v", err)
			}
			if strings.Contains(err.Error(), "database") {
				t.Fatalf("error leaked cause: %v", err)
			}
		})
	}
}

func TestAuthenticationErrorFormattingDoesNotExposeCause(t *testing.T) {
	service, _, dummy := testServices(t)
	lookup := lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
		return passwordauthentication.Record{}, false, diagnosticCause{Marker: "sensitive database detail"}
	})
	authenticator, err := passwordauthentication.New(passwordauthentication.Config{Passwords: service, Lookup: lookup, DummyHash: dummy})
	if err != nil {
		t.Fatal(err)
	}
	_, err = authenticator.Authenticate(context.Background(), "synthetic-user", []byte("synthetic"))
	for _, format := range []string{"%s", "%q", "%v", "%+v", "%#v"} {
		if rendered := fmt.Sprintf(format, err); strings.Contains(rendered, "sensitive") || strings.Contains(rendered, "database") {
			t.Fatalf("format %s leaked cause: %s", format, rendered)
		}
	}
}

func TestCancellationNoUpgradeAndFormatting(t *testing.T) {
	service, _, dummy := testServices(t)
	current, err := service.Hash(context.Background(), []byte("current secret"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	authenticator, err := passwordauthentication.New(passwordauthentication.Config{
		Passwords: service,
		Lookup: lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
			called = true
			return passwordauthentication.Record{}, false, nil
		}),
		DummyHash: dummy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.Authenticate(ctx, "user", []byte("secret")); !errors.Is(err, passwordauthentication.ErrCanceled) || !errors.Is(err, context.Canceled) || called {
		t.Fatalf("pre-canceled error = %v, called = %v", err, called)
	}

	ctx, cancel = context.WithCancel(context.Background())
	authenticator, err = passwordauthentication.New(passwordauthentication.Config{
		Passwords: service,
		Lookup: lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
			cancel()
			return passwordauthentication.Record{Subject: "user", EncodedHash: current.String()}, true, nil
		}),
		DummyHash: dummy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.Authenticate(ctx, "user", []byte("current secret")); !errors.Is(err, passwordauthentication.ErrCanceled) {
		t.Fatalf("verification cancellation = %v", err)
	}

	authenticator, err = passwordauthentication.New(passwordauthentication.Config{
		Passwords: service,
		Lookup: lookupFunc(func(context.Context, string) (passwordauthentication.Record, bool, error) {
			return passwordauthentication.Record{Subject: "user", EncodedHash: current.String()}, true, nil
		}),
		DummyHash: dummy,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := authenticator.Authenticate(context.Background(), "user", []byte("current secret"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Upgrade().Required() || result.Upgrade().Expected().String() != "" || result.Upgrade().Replacement().String() != "" {
		t.Fatalf("unexpected upgrade: %#v", result.Upgrade())
	}
	if result.String() != "password authentication result" || result.GoString() != "passwordauthentication.Result{redacted}" || result.Upgrade().String() != "password upgrade [redacted]" || result.Upgrade().GoString() != "passwordauthentication.Upgrade{redacted}" {
		t.Fatal("unsafe result formatting")
	}
	record := passwordauthentication.Record{Subject: "user", EncodedHash: current.String()}
	if record.String() != "password record [redacted]" || record.GoString() != "passwordauthentication.Record{redacted}" || fmt.Sprintf("%v", record) != "password record [redacted]" {
		t.Fatal("unsafe record formatting")
	}
}

func TestRecordAndConfigStructuredLoggingAreRedacted(t *testing.T) {
	const (
		subjectMarker = "structured-log-subject-marker"
		hashMarker    = "structured-log-hash-marker"
	)
	values := []any{
		passwordauthentication.Record{Subject: subjectMarker, EncodedHash: hashMarker},
		passwordauthentication.Config{DummyHash: hashMarker},
	}
	config := passwordauthentication.Config{DummyHash: hashMarker}
	if config.String() != "password authentication config [redacted]" || config.GoString() != "passwordauthentication.Config{redacted}" {
		t.Fatal("unsafe config formatting")
	}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			rendered := fmt.Sprintf(format, value)
			if strings.Contains(rendered, subjectMarker) || strings.Contains(rendered, hashMarker) {
				t.Fatalf("format %s leaked sensitive field: %s", format, rendered)
			}
		}
	}
	for _, handler := range []func(*bytes.Buffer) slog.Handler{
		func(output *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(output, nil) },
		func(output *bytes.Buffer) slog.Handler { return slog.NewTextHandler(output, nil) },
	} {
		for _, value := range values {
			var output bytes.Buffer
			slog.New(handler(&output)).Info("diagnostic", "value", value)
			if strings.Contains(output.String(), subjectMarker) || strings.Contains(output.String(), hashMarker) {
				t.Fatalf("structured log leaked sensitive field: %s", output.String())
			}
		}
	}
}
