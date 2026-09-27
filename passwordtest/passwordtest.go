package passwordtest

import (
	"errors"
	"sync"
)

const (
	// SyntheticPassword is the non-secret password for compatibility fixtures.
	SyntheticPassword = "synthetic password"
	// LaravelBcrypt is a synthetic PHP 8.5 bcrypt fixture at cost 10.
	LaravelBcrypt = "$2y$10$ABk0ypUBDSb78zn66THffuHDCkhvUWaMk2g..sQiEEfh1RemSi6vm"
	// LaravelArgon2id is a synthetic PHP 8.5 Argon2id fixture.
	LaravelArgon2id = "$argon2id$v=19$m=65536,t=2,p=1$SBj4Q9N+Krb5qUX9O00GHg$r0xVBSfxyYkNbAcWCI8kZHSz5Z3U/vV9bx8o7aYjxbc"
)

// Entropy is a concurrency-safe repeating deterministic reader for tests.
type Entropy struct {
	mu     sync.Mutex
	seed   []byte
	offset int
}

// NewEntropy copies a non-empty deterministic seed.
func NewEntropy(seed []byte) (*Entropy, error) {
	if len(seed) == 0 {
		return nil, errors.New("passwordtest: entropy seed is empty")
	}
	return &Entropy{seed: append([]byte(nil), seed...)}, nil
}

// Read fills destination by repeating the seed.
func (e *Entropy) Read(destination []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for index := range destination {
		destination[index] = e.seed[e.offset%len(e.seed)]
		e.offset++
	}
	return len(destination), nil
}
