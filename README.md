# password

[![CI](https://github.com/faustbrian/go-password/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/faustbrian/go-password/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/badge/CodeQL-required-blue)](https://github.com/faustbrian/go-password/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25_required-blue)](CONTRIBUTING.md#verification)
[![Mutation](https://img.shields.io/badge/mutation-100%25_required-blue)](CONTRIBUTING.md#verification)
[![Documentation](https://img.shields.io/badge/docs-checked_in_CI-blue)](docs/)
[![Go Reference](https://pkg.go.dev/badge/github.com/faustbrian/go-password/v2.svg)](https://pkg.go.dev/github.com/faustbrian/go-password/v2)
[![Release](https://img.shields.io/github/v/release/faustbrian/go-password?sort=semver)](https://github.com/faustbrian/go-password/releases)
[![Go](https://img.shields.io/badge/go-1.27.0-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`password` is a narrowly scoped password hashing, verification, parsing,
and login-time upgrade library. It uses maintained Go implementations of
Argon2id and bcrypt. It does not own users, repositories, registration, login
endpoints, sessions, password reset, MFA, authorization, or reversible secrets.

This source tree defines `github.com/faustbrian/go-password/v2` at v2.0.1
and requires Go 1.27.0. Eligibility and a changelog date do not establish
publication; adoption requires the public tag and module artifacts. The
immutable legacy v1.1.0 module specifies Go 1.26.6.

## Requirements

- Go 1.27.0 or newer.
- `golang.org/x/crypto` v0.57.0.

## Install

After the public v2.0.1 tag and module artifacts are available:

```sh
go get github.com/faustbrian/go-password/v2@v2.0.1
```

Use the `/v2` imports shown below. Existing v2 applications can retain
released v2.0.0 until the patch is published; legacy applications can retain
v1.1.0 without local replacements or pseudo-versions.

## Five-minute Argon2id quickstart

```go
package main

import (
	"context"
	"errors"
	"fmt"

	password "github.com/faustbrian/go-password/v2"
)

func main() {
	passwords, err := password.New(password.DefaultPolicy())
	if err != nil {
		panic(err)
	}

	encoded, err := passwords.Hash(
		context.Background(),
		[]byte("caller-owned password"),
	)
	if err != nil {
		panic(err)
	}

	result, err := passwords.Verify(
		context.Background(),
		[]byte("caller-owned password"),
		encoded.String(), // explicit persistence access
	)
	if errors.Is(err, password.ErrMismatch) {
		fmt.Println("rejected")
		return
	}
	if err != nil {
		panic(err)
	}
	fmt.Println(result.Match(), result.NeedsRehash())
}
```

`DefaultPolicy` uses Argon2id version 19, time 2, 64 MiB memory, one lane, a
16-byte salt, and a 32-byte output. Historical measurements do not establish
performance for the current dependency or deployment hardware. Benchmark the
deployed toolchain and dependencies before setting concurrency or pod limits.

## Laravel migration

Use `VerifyAndUpgrade` or
`passwordauthentication.Authenticator` from `adapters/authentication` during
successful login.
Laravel `$2y$` bcrypt and PHC Argon2id strings are accepted. Never replace the
database value until verification succeeds and the new hash is durably written
with an optimistic comparison against the old value.

```sql
UPDATE users
SET password_hash = $1
WHERE id = $2
  AND password_hash = $3;
```

Treat one affected row as success and zero as a benign concurrent update. See
the [Laravel migration guide](docs/laravel-migration.md) for complete Go and
PostgreSQL examples.

## Security defaults

- Parser and primitive resources are bounded before expensive work.
- Active and queued work have explicit hard limits and drainable lifecycle.
- Argon2id verification uses constant-time derived-key comparison.
- Bcrypt verification delegates to the maintained bcrypt primitive.
- Rehash decisions never downgrade ordered cost/entropy dimensions or
  Argon2id to bcrypt; parallelism follows the target deployment's resource
  shape only when the ordered dimensions are not lowered.
- Production constructors use `crypto/rand.Reader`; deterministic entropy is
  confined to internal tests and the non-production `passwordtest` package.
- Password slices are copied and not retained. Best-effort clearing of the copy
  is not a guarantee of runtime memory erasure.
- `EncodedHash.String()` is explicit persistence access; `fmt` and `log/slog`
  formatting of secret-bearing authentication values is redacted.
- Observations contain bounded enums, upgrade state, and duration only.

## Packages

| Package | Purpose |
| --- | --- |
| root | Policy, limits, parsing, admission, service, errors, observations |
| `argon2id` | Argon2id service constructors |
| `bcrypt` | Bcrypt compatibility constructors |
| `adapters/authentication` | Application lookup and explicit CAS upgrade adapter |
| `adapters/service` | Admission lifecycle hooks |
| `passwordauth` | Deprecated compatibility path for `adapters/authentication` |
| `passwordservice` | Deprecated compatibility path for `adapters/service` |
| `passwordtest` | Synthetic fixtures and deterministic test entropy |

## Documentation

- [API and error semantics](docs/api.md)
- [Encoded-hash grammar](docs/parser-grammar.md)
- [Laravel migration](docs/laravel-migration.md)
- [Database upgrades and concurrency](docs/database-upgrades.md)
- [Kubernetes sizing and performance](docs/kubernetes-sizing.md)
- [Threat model](docs/threat-model.md)
- [Security and secret handling](docs/secret-handling.md)
- [Testing and release gates](docs/testing.md)
- [Compatibility matrix](docs/compatibility.md)
- [Specification decisions](docs/specification-decisions.md)
- [Vector and fixture provenance](docs/vector-provenance.md)
- [FAQ](docs/faq.md) and [troubleshooting](docs/troubleshooting.md)
- [Support](SUPPORT.md) and [security policy](SECURITY.md)

For ecosystem-wide package selection, construction, ownership, and lifecycle
guidance, see the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.6.1/docs/ecosystem/README.md)
and its [Service edge family](https://github.com/faustbrian/go-library-tools/blob/v1.6.1/docs/ecosystem/design-language.md#package-families-and-selection).

## License

MIT
