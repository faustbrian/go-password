package password_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	password "github.com/faustbrian/go-password/v2"
)

func TestSecretOwnership(t *testing.T) {
	input := []byte{0, 255, 42}
	s, err := password.NewSecret(input)
	if err != nil {
		t.Fatal("construction failed")
	}
	copyOwner := s
	input[1] = 0
	var borrowed []byte
	if err := s.Use(func(b []byte) error {
		if !bytes.Equal(b, []byte{0, 255, 42}) {
			t.Error("input copy or binary fidelity failed")
		}
		borrowed = b
		b[2] = 0
		return nil
	}); err != nil {
		t.Fatal("use failed")
	}
	if !bytes.Equal(borrowed, make([]byte, 3)) {
		t.Error("borrow not cleared")
	}
	if err := copyOwner.Use(func(b []byte) error {
		if b[2] != 42 {
			t.Error("callback changed owner")
		}
		return nil
	}); err != nil {
		t.Fatal("sequential use failed")
	}
	s.Destroy()
	copyOwner.Destroy()
	if s.Len() != 0 || copyOwner.Len() != 0 {
		t.Error("copies did not share destruction")
	}
	if !errors.Is(s.Use(func([]byte) error { t.Error("destroyed use invoked callback"); return nil }), password.ErrInvalidSecret) {
		t.Error("destroyed state not classified")
	}
}

func TestSecretBorrowClearsFullCapacityOnEveryExit(t *testing.T) {
	for _, outcome := range []string{"success", "error", "panic"} {
		t.Run(outcome, func(t *testing.T) {
			s, err := password.NewSecret([]byte{1, 255, 42})
			if err != nil {
				t.Fatal("construction failed")
			}
			defer s.Destroy()
			var fullAlias []byte
			err = s.Use(func(borrow []byte) error {
				fullAlias = borrow[:cap(borrow)]
				// Reslicing a borrow within its capacity is legal Go. Any spare
				// capacity remains package-owned and must not preserve copies.
				for i := len(borrow); i < len(fullAlias); i++ {
					fullAlias[i] = borrow[(i-len(borrow))%len(borrow)]
				}
				switch outcome {
				case "error":
					return errors.New("synthetic tail callback failure")
				case "panic":
					panic("synthetic tail callback panic")
				default:
					return nil
				}
			})
			if outcome == "success" && err != nil {
				t.Error("successful callback rejected")
			}
			if outcome != "success" && !errors.Is(err, password.ErrInvalidSecret) {
				t.Error("callback failure not classified")
			}
			if !bytes.Equal(fullAlias, make([]byte, len(fullAlias))) {
				t.Error("callback capacity retained material after exit")
			}
			s.Destroy()
			if !bytes.Equal(fullAlias, make([]byte, len(fullAlias))) {
				t.Error("callback capacity retained material after destruction")
			}
		})
	}
}

func TestSecretBounds(t *testing.T) {
	for _, size := range []int{0, 1, (1 << 20) - 1, 1 << 20, (1 << 20) + 1} {
		s, err := password.NewSecret(make([]byte, size))
		switch {
		case size == 0:
			if !errors.Is(err, password.ErrInvalidSecret) {
				t.Error("empty secret accepted")
			}
		case size > 1<<20:
			if !errors.Is(err, password.ErrResourceRejected) {
				t.Error("oversize secret accepted")
			}
		default:
			if err != nil || s.Len() != size {
				t.Error("valid length rejected")
			}
		}
		s.Destroy()
	}
	var zero password.Secret
	zero.Destroy()
	if zero.Len() != 0 || !errors.Is(zero.Use(func([]byte) error { t.Error("zero callback invoked"); return nil }), password.ErrInvalidSecret) {
		t.Error("zero state invalid")
	}
}

type diagnosticCallbackError string

func (e diagnosticCallbackError) Error() string { return string(e) }

func TestSecretCallbackOutcomesAndReentrancy(t *testing.T) {
	s, _ := password.NewSecret([]byte("synthetic callback material"))
	defer s.Destroy()
	if !errors.Is(s.Use(nil), password.ErrInvalidSecret) {
		t.Error("nil callback accepted")
	}
	var alias []byte
	cause := diagnosticCallbackError("synthetic classified cause")
	err := s.Use(func(b []byte) error { alias = b; return cause })
	var typed *password.Error
	var classified diagnosticCallbackError
	if err == nil {
		t.Fatal("callback error missing")
	}
	if !errors.As(err, &typed) || typed == nil {
		t.Fatal("callback error type missing")
	}
	if !errors.Is(err, cause) || !errors.Is(err, password.ErrInvalidSecret) || strings.Contains(err.Error(), cause.Error()) {
		t.Error("callback error classification/redaction failed")
	}
	if typed.Cause() == nil {
		t.Fatal("callback error cause missing")
	}
	if !errors.As(err, &classified) || classified != cause || strings.Contains(typed.Cause().Error(), cause.Error()) {
		t.Error("opaque cause lost classification or disclosed")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		if strings.Contains(fmt.Sprintf(verb, err), cause.Error()) {
			t.Errorf("callback cause leaked for %s", verb)
		}
	}
	if !bytes.Equal(alias, make([]byte, len(alias))) {
		t.Error("error borrow not cleared")
	}
	err = s.Use(func(b []byte) error { alias = b; panic("synthetic panic material") })
	if err == nil {
		t.Fatal("panic error missing")
	}
	if !errors.Is(err, password.ErrInvalidSecret) || strings.Contains(err.Error(), "synthetic panic") || !bytes.Equal(alias, make([]byte, len(alias))) {
		t.Error("panic cleanup/redaction failed")
	}
	if err = s.Use(func(b []byte) error {
		if s.Len() != len(b) {
			t.Error("reentrant length failed")
		}
		if !errors.Is(s.Use(func([]byte) error { t.Error("reentrant borrower admitted"); return nil }), password.ErrInvalidSecret) {
			t.Error("reentrant use not rejected")
		}
		s.Destroy()
		if s.Len() != 0 {
			t.Error("reentrant destruction failed")
		}
		if len(b) == 0 || b[0] != 's' {
			t.Error("active borrow changed during destruction")
		}
		alias = b
		return nil
	}); err != nil {
		t.Error("callback deadlock or failure")
	}
	if !bytes.Equal(alias, make([]byte, len(alias))) {
		t.Error("destroyed active borrow not cleared")
	}
}

func TestSecretConcurrentCopiesStressAndJoinedLifetime(t *testing.T) {
	for range 40 {
		s, _ := password.NewSecret([]byte("synthetic concurrent material"))
		copied := s
		entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var active atomic.Int32
		go func() {
			defer close(done)
			if err := copied.Use(func(b []byte) error {
				if active.Add(1) != 1 {
					t.Error("multiple borrowers")
				}
				close(entered)
				<-release
				b[0] = 0
				active.Add(-1)
				return nil
			}); err != nil {
				t.Error("first borrower rejected")
			}
		}()
		<-entered
		var group sync.WaitGroup
		for range 8 {
			group.Go(func() {
				_ = s.Len()
				if !errors.Is(s.Use(func([]byte) error { t.Error("busy/destroyed callback admitted"); return nil }), password.ErrInvalidSecret) {
					t.Error("busy use not rejected")
				}
				copied.Destroy()
			})
		}
		group.Wait()
		close(release)
		<-done
		if active.Load() != 0 || s.Len() != 0 {
			t.Error("borrower lifetime or destruction failed")
		}
		if !errors.Is(copied.Use(func([]byte) error { t.Error("resurrected callback"); return nil }), password.ErrInvalidSecret) {
			t.Error("resurrection")
		}
	}
}

func TestSecretNilPanicAndGoexitReleaseBorrow(t *testing.T) {
	s, _ := password.NewSecret([]byte("synthetic abnormal callback"))
	defer s.Destroy()
	var alias []byte
	for _, panicValue := range []any{nil, "synthetic panic"} {
		if !errors.Is(s.Use(func(b []byte) error { alias = b; panic(panicValue) }), password.ErrInvalidSecret) {
			t.Error("panic not classified")
		}
		if !bytes.Equal(alias, make([]byte, len(alias))) {
			t.Error("panic borrow retained")
		}
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Use(func(b []byte) error { alias = b; runtime.Goexit(); return nil }) }()
	<-done
	if !bytes.Equal(alias, make([]byte, len(alias))) {
		t.Error("Goexit borrow retained")
	}
	if err := s.Use(func([]byte) error { return nil }); err != nil {
		t.Error("abnormal exit held admission")
	}
}

func TestSecretDiagnosticsNeverDisclose(t *testing.T) {
	material := []byte("synthetic-diagnostic-467829")
	s, _ := password.NewSecret(material)
	defer s.Destroy()
	copyOwner := s
	for valueIndex, value := range []any{s, &s, copyOwner, []password.Secret{s}, map[string]password.Secret{"secret": s}, struct{ Secret password.Secret }{s}} {
		var output strings.Builder
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
			formatted := fmt.Sprintf(verb, value)
			for _, forbidden := range []string{string(material), hex.EncodeToString(material), strings.ToUpper(hex.EncodeToString(material)), base64.StdEncoding.EncodeToString(material), decimalBytes(material)} {
				if strings.Contains(formatted, forbidden) {
					t.Errorf("format disclosure at value %d verb %s", valueIndex, verb)
				}
			}
			output.WriteString(formatted)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Error("JSON diagnostics failed")
		}
		output.Write(encoded)
		slog.New(slog.NewJSONHandler(&output, nil)).Info("diagnostic", "secret", value)
		slog.New(slog.NewTextHandler(&output, nil)).Info("diagnostic", "secret", value)
		for _, forbidden := range []string{string(material), hex.EncodeToString(material), strings.ToUpper(hex.EncodeToString(material)), base64.StdEncoding.EncodeToString(material), decimalBytes(material)} {
			if strings.Contains(output.String(), forbidden) {
				t.Errorf("secret diagnostics disclosed material at value %d", valueIndex)
			}
		}
	}
}

func decimalBytes(input []byte) string {
	output := []byte{'['}
	for index, value := range input {
		if index > 0 {
			output = append(output, ' ')
		}
		output = strconv.AppendUint(output, uint64(value), 10)
	}
	return string(append(output, ']'))
}

func parametersValid(p password.Parameters) bool {
	switch p.Algorithm {
	case password.Bcrypt:
		return p.Argon2id == (password.Argon2idParameters{}) && p.BcryptCost >= 4 && p.BcryptCost <= 31
	case password.Argon2id:
		a := p.Argon2id
		return p.BcryptCost == 0 && a.Version == 19 && a.Time >= 1 && a.Parallelism >= 1 && uint64(a.MemoryKiB) >= uint64(a.Parallelism)*8 && a.SaltLength >= 8 && a.OutputLength >= 16
	default:
		return false
	}
}

func TestParametersIntrinsicBoundariesAndPolicyComposition(t *testing.T) {
	a := password.Argon2idParameters{Version: 19, Time: 1, MemoryKiB: 8, Parallelism: 1, SaltLength: 8, OutputLength: 16}
	boundaries := []uint32{0, 1, 7, 8, 15, 16, 19, 20, 254, 255, 2039, 2040, 2041, ^uint32(0)}
	cases := make([]password.Parameters, 0, 8+6*len(boundaries)+4)
	cases = append(cases, password.Parameters{}, password.Parameters{Algorithm: "unrecognized"}, password.Parameters{Algorithm: password.Bcrypt, BcryptCost: 3}, password.Parameters{Algorithm: password.Bcrypt, BcryptCost: 4}, password.Parameters{Algorithm: password.Bcrypt, BcryptCost: 31}, password.Parameters{Algorithm: password.Bcrypt, BcryptCost: 32}, password.Parameters{Algorithm: password.Bcrypt, BcryptCost: 4, Argon2id: a}, password.Parameters{Algorithm: password.Argon2id, Argon2id: a, BcryptCost: 4})
	for field := range 6 {
		for _, value := range boundaries {
			b := a
			switch field {
			case 0:
				b.Version = value
			case 1:
				b.Time = value
			case 2:
				b.MemoryKiB = value
			case 3:
				if value > 255 {
					continue
				}
				b.Parallelism = uint8(value)
			case 4:
				b.SaltLength = value
			case 5:
				b.OutputLength = value
			}
			cases = append(cases, password.Parameters{Algorithm: password.Argon2id, Argon2id: b})
		}
	}
	for _, memory := range []uint32{2039, 2040, 2041} {
		b := a
		b.Parallelism = 255
		b.MemoryKiB = memory
		cases = append(cases, password.Parameters{Algorithm: password.Argon2id, Argon2id: b})
	}
	cases = append(cases, password.Parameters{Algorithm: password.Argon2id, Argon2id: password.Argon2idParameters{Version: 19, Time: ^uint32(0), MemoryKiB: ^uint32(0), Parallelism: 255, SaltLength: ^uint32(0), OutputLength: ^uint32(0)}})
	for _, p := range cases {
		got, err := password.NewParameters(p)
		if parametersValid(p) {
			if err != nil || got != p {
				t.Error("intrinsically valid input rejected")
			}
		} else if !errors.Is(err, password.ErrInvalidPolicy) || got != (password.Parameters{}) {
			t.Error("invalid input not rejected atomically")
		}
	}
	for _, algorithm := range []password.Algorithm{password.Argon2id, password.Bcrypt} {
		p := password.Parameters{Algorithm: algorithm}
		if algorithm == password.Argon2id {
			p.Argon2id = a
		} else {
			p.BcryptCost = 4
		}
		p, err := password.NewParameters(p)
		if err != nil {
			t.Fatal("parameter construction failed")
		}
		limits := password.DefaultPolicy().Limits()
		policy, err := password.NewPolicy(password.PolicyConfig{Algorithm: p.Algorithm, Argon2id: p.Argon2id, BcryptCost: p.BcryptCost, Limits: limits})
		if err != nil {
			t.Fatal("policy composition failed")
		}
		svc, err := password.New(policy)
		if err != nil {
			t.Fatal("service construction failed")
		}
		s, _ := password.NewSecret([]byte{1, 255, 0, 42})
		if err = s.Use(func(b []byte) error {
			hash, err := svc.Hash(context.Background(), b)
			if err != nil {
				return err
			}
			result, err := svc.Verify(context.Background(), b, hash.String())
			if err == nil && !result.Match() {
				t.Error("composed proof did not match")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, errCanceled := svc.Hash(ctx, b)
			if !errors.Is(errCanceled, password.ErrCanceled) {
				t.Error("cancellation lost")
			}
			return err
		}); err != nil {
			t.Error("real composed hash/verify failed")
		}
		s.Destroy()
	}
	above := a
	above.Time = password.DefaultPolicy().Limits().Argon2Time + 1
	p, err := password.NewParameters(password.Parameters{Algorithm: password.Argon2id, Argon2id: above})
	if err != nil {
		t.Fatal("default imposed universal ceiling")
	}
	limits := password.DefaultPolicy().Limits()
	c := password.PolicyConfig{Algorithm: p.Algorithm, Argon2id: p.Argon2id, Limits: limits}
	if _, err = password.NewPolicy(c); !errors.Is(err, password.ErrInvalidPolicy) {
		t.Error("caller work ceiling ignored")
	}
	c.Limits.Argon2Time = above.Time
	if _, err = password.NewPolicy(c); err != nil {
		t.Error("above-default valid caller budget rejected")
	}
	c.Limits.EncodedHashBytes = 60
	c.Argon2id.SaltLength = 64
	if _, err = password.NewPolicy(c); !errors.Is(err, password.ErrInvalidPolicy) {
		t.Error("encoded length ceiling ignored")
	}
	legacy := password.PolicyConfig{Algorithm: password.Bcrypt, BcryptCost: 4, Argon2id: a, Limits: limits}
	if _, err = password.NewPolicy(legacy); err != nil {
		t.Error("legacy policy arm shape tightened")
	}
}

func TestParametersClosedArms(t *testing.T) {
	valid := password.Parameters{Algorithm: password.Argon2id, Argon2id: password.Argon2idParameters{Version: 19, Time: 1, MemoryKiB: 8, Parallelism: 1, SaltLength: 8, OutputLength: 16}}
	if got, err := password.NewParameters(valid); err != nil || got != valid {
		t.Error("valid parameters rejected or changed")
	}
	valid.BcryptCost = 4
	if _, err := password.NewParameters(valid); !errors.Is(err, password.ErrInvalidPolicy) {
		t.Error("mismatched arm accepted")
	}
	if _, err := password.NewParameters(password.Parameters{}); !errors.Is(err, password.ErrInvalidPolicy) {
		t.Error("unspecified algorithm accepted")
	}
}
