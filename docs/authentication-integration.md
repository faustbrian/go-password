# Authentication integration

`adapters/authentication` bridges application lookup to password verification
without a reverse dependency from `authentication` or ownership of users.

1. Implement `passwordauthentication.Lookup` over the application repository.
2. Hash a synthetic dummy password with the active target `password.Service`,
   configure that encoding, and rotate it whenever the target policy changes.
3. Call `Authenticate` with the Basic credential username/password.
4. Convert the returned stable subject into a `authentication.Principal`
   with method `password` in the application adapter.
5. Apply `Result.Upgrade()` with a conditional database update.

The adapter returns `ErrRejected` for absence/mismatch, `ErrCanceled` for caller
cancellation, and `ErrUnavailable` for lookup, stored-data, resource, entropy,
or primitive failures. Public endpoint responses should normally collapse these
to a safe authentication response while operational telemetry keeps bounded
classification.

Construction rejects a dummy whose algorithm, Argon2id parameters, or bcrypt
cost differ from the service target. This keeps the normal missing-user
primitive work aligned with current target verification; it does not equalize
database, malformed-record, legacy-hash, cancellation, or response timing.

The adapter intentionally does not import `authentication`: its narrow lookup
boundary keeps password verification independent of a principal or session
model. An application-level adapter can implement
`authentication.Authenticator` without changing either core package.

The released `passwordauth` import path remains as a deprecated delegating
facade. New code should import
`github.com/faustbrian/go-password/v2/adapters/authentication` after v2 is
published.
