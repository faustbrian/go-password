package password

// Parameters specifies exactly one algorithm's intrinsic work parameters.
// Validate the enclosing caller resource budget with NewPolicy before hashing.
// DefaultPolicy limits are deployment defaults, not universal maxima.
type Parameters struct {
	// Algorithm selects the populated arm; all other arms must be zero.
	Algorithm Algorithm
	// Argon2id specifies version 19 work when Algorithm is Argon2id.
	Argon2id Argon2idParameters
	// BcryptCost specifies cost 4..31 when Algorithm is Bcrypt.
	BcryptCost int
}

// NewParameters copies and validates intrinsic algorithm bounds and arm closure.
// Invalid input returns a zero value and a typed ErrInvalidPolicy error without
// hashing or allocating work buffers. Caller limits remain NewPolicy's concern.
func NewParameters(p Parameters) (Parameters, error) {
	switch p.Algorithm {
	case Argon2id:
		a := p.Argon2id
		if p.BcryptCost != 0 || a.Version != 19 || a.Time == 0 || a.Parallelism == 0 || a.MemoryKiB < 8*uint32(a.Parallelism) || a.SaltLength < 8 || a.OutputLength < 16 {
			return Parameters{}, newError(ErrInvalidPolicy, "configure parameters", nil)
		}
	case Bcrypt:
		if p.Argon2id != (Argon2idParameters{}) || p.BcryptCost < 4 || p.BcryptCost > 31 {
			return Parameters{}, newError(ErrInvalidPolicy, "configure parameters", nil)
		}
	default:
		return Parameters{}, newError(ErrInvalidPolicy, "configure parameters", nil)
	}
	return p, nil
}
