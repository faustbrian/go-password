# Testing and release gates

The root and optional packages maintain meaningful 100% production statement
coverage. Coverage is a floor; vectors, boundary assertions, fuzzing, race
tests, mutation checks, and integration fixtures prove behavior.

## Ordinary local commands

Use the declared Go 1.27.2 producer with the unchanged Go 1.27.0 module minimum.
No services or test/build tags are declared in the manifest. Test the standalone
module without sibling checkouts:

```sh
GOWORK=off go test ./...
make check
make ci
make boundaries
make conformance-local
```

Ordinary tests run deterministic fuzz seeds and saved corpus regressions, not
active exploration. Both Make routes retain source dependency/unsafe/cgo/
assembly/entropy-API refusals and the manifest/header/seven-decision guard.
They use the public verifier without building it from source. Hosted CI selects
the same guards in a five-minute private-cache job; Required requires it and the
shared workflow. The ordinary race selection is exactly
`^Test(SharedPolicyAndAdmissionAreRaceSafe|AdmissionShutdownWakesQueueAndDrainsWithinContext)$`,
count one with a two-minute timeout. It asserts 32 successful shared-policy
hash/verify workers plus queued rejection, closed intake and eventual drain.

Short active exploration selects one target; optional local mutation selects
one package:

```sh
GOMAXPROCS=2 GOWORK=off go test -run '^$' -fuzz '^FuzzParseEncodedHash$' -fuzztime=2s -parallel=1 -timeout=2m .
golib mutation --module . --package .
```

Base-free checks run seeds/corpora; changed-source CI selects bounded active
smoke for causally affected targets. The explicit full route retains both
native ten-second fuzz campaigns, each with a two-minute timeout. Seed corpora
include valid PHP hashes, truncation, duplicate
fields, overflow, invalid base64, unsupported versions, and parameter bombs.

Race tests share immutable policies, production entropy, admission, hashing,
verification, queue wakeup, and shutdown across goroutines.

## Explicit full, interoperability and release commands

```sh
make check-full
make specification-check-online
make -f verification/package.mk conformance
make -f verification/package.mk interoperability
make -f verification/package.mk api-docs
make -f verification/package.mk portability
make -f verification/package.mk resource
make -f verification/package.mk kubernetes-bench
golib release dry-run --module .
```

`make check-full` retains original full Go/PHP conformance and interoperability,
API documentation, source boundaries, Linux/386 compilation, resource-tagged
stress, one-iteration approved benchmarks and full coverage, race, mutation,
API, security and documentation qualification. It also checks upstream
specification authority online; ordinary `make ci` selects offline authority.
Live bidirectional interoperability requires PHP and does not become an ordinary
contribution prerequisite. Local checks are not public-release evidence.

`make -f verification/package.mk kubernetes-bench` requires Docker and verifies
its 2-CPU/512 MiB cgroup before measuring all approved policies in pinned Go
Linux. The build-tagged `make -f verification/package.mk resource` gate
runs approved 64 MiB Argon2id work under the race detector and asserts the
configured active-memory ceiling. Go runtime
out-of-memory termination cannot be injected or recovered as an ordinary
allocation error; policy/encoding boundary tests and pre-primitive rejection
are the executable allocation-failure boundary.

Mutation scope targets match/mismatch, canonical parser boundaries, parameter
ceilings, admission decisions, and rehash downgrade prevention. Timeouts are
bounded and reported; survivors require review, not automatic acceptance.
Full scheduled/release mutation retains its configured acceptance contract;
optional one-package local mutation is not a universal submission gate.

`passwordtest` credentials are synthetic. Never add real hashes, usernames,
tokens, database dumps, or incident artifacts to fixtures.
See [vector and fixture provenance](vector-provenance.md) for exact independent
producers and maintenance requirements.
