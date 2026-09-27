# Security review packet

## Internal audit status

The repository contains executable coverage for the following boundaries.
This list is not a claim that historical results apply to the current release
candidate or its newer dependencies:

- maintained Argon2id and bcrypt vectors;
- independent PHP 8.5.8 bcrypt and Argon2id fixtures;
- strict canonical parsing and pre-primitive resource rejection;
- match/mismatch, rehash, downgrade, entropy, cancellation, and admission paths;
- concurrent policy/admission use and shutdown race states;
- optimistic upgrade data and crash-safe persistence guidance;
- diagnostic and observation redaction;
- exact production statement coverage, fuzz, race, mutation, vulnerability,
  lint, API, documentation, and release gates.

## Independent specialist review

The independent complete-final-diff review is a release blocker for security
hardening and cannot be self-certified by implementation tests. It must include
the concrete cryptographic scope below; this does not require a separate
procedural review stage. The reviewer must assess:

1. Parameter selection against intended deployment hardware and threat model.
2. PHC/bcrypt grammar and Laravel interoperability.
3. Monotonic rehash and downgrade prevention.
4. Admission/resource ceilings under malicious valid hashes.
5. Error, formatting, observation, and timing surfaces.
6. CAS migration and crash/concurrent-login behavior.
7. Whether maintained primitive usage introduces any unsafe assumptions.

The coordinator records reviewer identity, scope, date, exact candidate tree or
source commit, findings, remediations, and final disposition in the compact
ecosystem ledger or the repository's GitHub review record. This packet defines
the audit scope; a tracked post-review attestation commit is not required. Do
not replace the actual review with coverage, automated scanning, or an internal
assertion of expertise.

## 2026-09-13 remediation audit

The implementation audit began from commit
`cdc30d0593fdb4f3a41cd2c6d17f0a437eab9089` and covered all seven domains
above. It found and remediated these repository-owned gaps:

1. Authentication accepted an arbitrary valid dummy hash, permitting a cheaper
   algorithm or parameter set than the target policy. Construction now requires
   exact target algorithm and work-factor parity.
2. `Record` and `Config` redacted `fmt` output but standard structured logging
   could serialize their exported sensitive fields. Both the target adapter and
   deprecated facade now implement redacted `log/slog` values.
3. The root production API exposed caller-controlled entropy through
   `NewTestService`. Entropy injection is now package-internal, while
   deterministic readers and compatibility vectors remain in the explicitly
   non-production `passwordtest` package.
4. Parallelism documentation described every Argon2id dimension as monotonic
   even though implementation treats lane mismatch as target resource shape.
   The decision register, algorithm guidance, README, and threat model now state
   the implemented ordered-dimension contract.
5. The `%#v` diagnostic form could expose the internal cause fields of
   classified root and authentication errors. Every classified error now owns
   `fmt.Formatter` and renders only its stable public classification.

The implementation audit directly checked the repository against these
authoritative or pinned sources on 2026-09-13:

- RFC 9106 Sections 3.1, 4, and 7.4:
  https://www.rfc-editor.org/rfc/rfc9106.html
- `golang.org/x/crypto` v0.54.0 Argon2id and bcrypt implementations:
  https://github.com/golang/crypto/blob/v0.54.0/argon2/argon2.go and
  https://github.com/golang/crypto/blob/v0.54.0/bcrypt/bcrypt.go
- PHP `password_hash` and `password_verify` manuals:
  https://www.php.net/manual/en/function.password-hash.php and
  https://www.php.net/manual/en/function.password-verify.php
- Go `log/slog` `LogValuer` contract:
  https://pkg.go.dev/log/slog#LogValuer

That historical implementation audit is not the independent disposition for
the current release candidate or its newer dependencies. The coordinator must
obtain and record the independent final-diff review before publication; this
document does not self-certify that review.

## 2026-09-27 delivery preparation

The release candidate preserves remote main's `x/crypto` v0.57.0 and
`x/sys` v0.48.0 rather than reverting to the remediation audit's older pins.
Its production paths still call maintained Argon2id and bcrypt primitives,
compare Argon2id outputs with `crypto/subtle.ConstantTimeCompare`, obtain salts
from `crypto/rand.Reader`, and validate work before primitive entry. No custom
primitive or endpoint-wide constant-time guarantee is introduced. Deployment
hardware must be benchmarked with the actual dependencies; earlier latency
measurements are not current performance evidence.

The OpenBSD errata review is recorded in `specification/README.md`. The
independent final review must assess the seven concrete security domains above
against this candidate and the newer dependencies. This preparation entry is
not that reviewer's disposition and does not authorize publication.

## Review invariants

- No custom primitive, unsafe, cgo, assembly, or reversible storage.
- No secret-bearing diagnostics or high-cardinality observations.
- No attacker-selected primitive work above limits.
- No upgrade before match or unconditional stale overwrite.
- No claim of guaranteed erasure, cancellation, or side-channel immunity.
