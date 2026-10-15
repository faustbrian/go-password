package password_test

import (
	"bytes"
	"errors"
	"testing"

	password "github.com/faustbrian/go-password/v2"
)

func FuzzSecretConstructor(f *testing.F) {
	for _, seed := range [][]byte{nil, {0}, {0, 255, 1}, []byte("synthetic constructor seed")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		s, err := password.NewSecret(input)
		if len(input) == 0 {
			if !errors.Is(err, password.ErrInvalidSecret) {
				t.Error("empty accepted")
			}
			return
		}
		if len(input) > 1<<20 {
			if !errors.Is(err, password.ErrResourceRejected) {
				t.Error("oversize accepted")
			}
			return
		}
		if err != nil {
			t.Fatal("valid input rejected")
		}
		defer s.Destroy()
		var alias []byte
		if err = s.Use(func(b []byte) error {
			if !bytes.Equal(b, input) {
				t.Error("bytes changed")
			}
			alias = b
			return nil
		}); err != nil {
			t.Error("use failed")
		}
		if !bytes.Equal(alias, make([]byte, len(alias))) {
			t.Error("borrow retained")
		}
	})
}

func FuzzParametersConstructor(f *testing.F) {
	f.Add(uint8(0), uint32(19), uint32(1), uint32(8), uint8(1), uint32(8), uint32(16), int32(0))
	f.Add(uint8(0), uint32(19), ^uint32(0), uint32(2040), uint8(255), uint32(8), uint32(16), int32(0))
	f.Add(uint8(1), uint32(0), uint32(0), uint32(0), uint8(0), uint32(0), uint32(0), int32(31))
	f.Fuzz(func(t *testing.T, arm uint8, version, time, memory uint32, lanes uint8, salt, output uint32, cost int32) {
		algorithms := []password.Algorithm{password.Argon2id, password.Bcrypt, ""}
		p := password.Parameters{Algorithm: algorithms[int(arm)%len(algorithms)], Argon2id: password.Argon2idParameters{Version: version, Time: time, MemoryKiB: memory, Parallelism: lanes, SaltLength: salt, OutputLength: output}, BcryptCost: int(cost)}
		got, err := password.NewParameters(p)
		if parametersValid(p) {
			if err != nil || got != p {
				t.Error("valid parameters rejected")
			}
		} else if !errors.Is(err, password.ErrInvalidPolicy) || got != (password.Parameters{}) {
			t.Error("invalid parameters accepted")
		}
	})
}
