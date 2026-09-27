# Compatibility matrix

Observable standards and profile choices are recorded in the
[specification decision register](specification-decisions.md).

| Producer/encoding | Verify | Hash target | Upgrade behavior |
| --- | --- | --- | --- |
| Go Argon2id PHC v19 | Yes | Yes | Monotonic parameter upgrade |
| PHP/Laravel Argon2id v19 | Yes | Shared PHC encoding | Monotonic upgrade |
| Go bcrypt `$2a$` | Yes | Yes when bcrypt policy | Upgrade to Argon2id |
| Standard bcrypt `$2b$` | Yes | Parser/verify | Upgrade to Argon2id |
| PHP/Laravel bcrypt `$2y$` | Yes | PHP produces it | Upgrade to Argon2id |
| Argon2i/Argon2d | No | No | Unsupported algorithm |
| Argon2 version other than 19 | No | No | Unsupported version |
| Scrypt/PBKDF2/custom formats | No | No | Adapter not present |

Minimum and tested Go version is 1.27.0. The pinned cryptographic dependency is
`golang.org/x/crypto` v0.57.0. The immutable v1.1.0 release specifies Go 1.26.6
and pins `x/crypto` v0.54.0. The PHP corpus was generated with PHP 8.5.8 and
contains only the literal synthetic password documented in the migration guide.
Producer commands and source provenance are recorded in
[vector and fixture provenance](vector-provenance.md).

No format extension is inferred. New algorithms require an explicit adapter,
grammar, bounds, vectors, fuzzing, migration policy, and compatibility entry.

## Module v2 transition

The `github.com/faustbrian/go-password/v2` module at v2.0.0 removes
`password.NewTestService` and
`passwordtest.NewService` so production-importable code cannot construct a
password service with deterministic entropy. This is an intentional public API
break isolated behind the v2 module path. Adopt it once the public tag and
module artifacts are available. Before publication, retain released v1.1.0;
then replace ordinary test construction with
`password.New` and deterministic hash assertions with the `passwordtest`
fixture constants. Encoded-hash formats and primitive verification remain
unchanged. Authentication construction now rejects dummy hashes whose
algorithm or complete work-factor parameters differ from the target policy.

## Adapter import paths

New v2 code should use `adapters/authentication` and `adapters/service`. The
`passwordauth` and `passwordservice` packages under `/v2` remain deprecated
delegating facades with distinct facade types and stable error strings.
Their v2 reflected identities are distinct from immutable v1 types. Moving
between the v2 facade and its successor does not change
password formats, persistence ownership, lifecycle ordering, or error
classification.
