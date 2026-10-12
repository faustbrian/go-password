package password

import "context"

// Hasher creates encoded hashes using caller-cancelable admission. Underlying
// primitives cannot be interrupted once invoked.
type Hasher interface {
	// Hash hashes a caller-owned password without retaining or mutating it.
	// The caller keeps the bytes stable until return, including admission waits.
	Hash(context.Context, []byte) (EncodedHash, error)
}

// Verifier verifies encoded hashes and evaluates the configured upgrade policy.
type Verifier interface {
	// Verify returns a typed match/rehash result or classified failure.
	// Password bytes must remain stable until return; a mismatch is ErrMismatch.
	Verify(context.Context, []byte, string) (Result, error)
	// NeedsRehash evaluates an already parsed hash without invoking a primitive
	// or proving that any password matches.
	NeedsRehash(EncodedHash) bool
}

// HasherVerifier combines hashing, verification, and explicit upgrade work.
type HasherVerifier interface {
	Hasher
	Verifier
	// VerifyAndUpgrade returns the parsed original after a match needing no
	// upgrade, or a newly generated hash after a successful upgrade. An upgrade
	// failure preserves the matched Result but returns an empty hash and error.
	// Password bytes stay caller-owned and stable until return; no write occurs.
	VerifyAndUpgrade(context.Context, []byte, string) (Result, EncodedHash, error)
}
