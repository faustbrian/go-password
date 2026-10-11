# Contributing

## Before Editing

1. Read [`AGENTS.md`](AGENTS.md) and the affected module's docs.
2. Run the standalone Go baseline below.
3. Identify owned dependencies and reverse dependants in `modules.json`.
4. Preserve unrelated work and generated/corpus provenance.

## Changes

Keep commits focused and conventional. Update every affected changelog with
the behavior and migration impact. Public API changes require compatibility
evidence and documentation. Specification behavior requires a decision record,
fixture coverage, and interoperability evidence.

New direct dependencies and dependency updates must follow the
[dependency governance policy](AGENTS.md#dependencies-and-supply-chain). Package-local
update bots are forbidden; the root policy owns every module and action update.

Specification-backed changes must follow the
[specification governance contract](AGENTS.md#design), update
the affected stable entries in the
[specification decision register](docs/specification-decisions.md), and
complete the Specification Decisions section of the pull request template. An
unresolved interpretation or stale source pin is release-blocking; peer
behavior cannot silently select policy.

Explicit full and release mutation gates must finish with zero surviving viable
mutants. Local mutation is optional, not a universal contribution prerequisite.

Do not fork shared verification workflows, add permanent replacements, machine-specific
paths, bypass flags, broad mutation exclusions, or aggregate quality metrics
that hide a failing package.

## Verification

Use the declared Go 1.27.2 producer; the module minimum remains Go 1.27.0.
Test independently of sibling checkouts:

```bash
GOWORK=off go test ./...
```

The module declares no services or test/build tags. This ordinary command runs
deterministic fuzz seeds and saved corpus regressions, not active exploration;
it excludes the explicit `resource`-tagged campaign.

With the checksum-pinned public verifier selected by `.golib.yaml`, use:

```bash
make inventory
make check
make ci
```

Both Make routes retain the source dependency/unsafe/cgo/assembly/entropy-API
refusal guard and the manifest/header/seven-decision conformance guard, then
run bounded local checks. One root race command selects shared-policy hash/verify
outcomes and admission queue wakeup/shutdown drain, count one with a two-minute
bound. `make ci` checks specification authority offline. Hosted CI runs the same
owned guards in a five-minute task-cache boundary job; Required needs it and the
shared workflow to succeed. Ordinary CI consumes the public verifier without
building it from source.

Base-free checks run seeds/corpora; changed-source CI selects bounded active
smoke for causally affected targets. Short active exploration selects one
target; optional local mutation selects one package:

```bash
GOMAXPROCS=2 GOWORK=off go test -run '^$' -fuzz '^FuzzParseEncodedHash$' -fuzztime=2s -parallel=1 -timeout=2m .
golib mutation --module . --package .
```

`make specification-check-online` retains explicit upstream authority checks.
`make check-full` includes them and preserves both native ten-second fuzz
campaigns, full Go/PHP conformance and interoperability, API documentation,
source boundaries, Linux/386 compilation, resource-tagged admission stress,
one-iteration approved benchmarks and full coverage, race, mutation, API and
security qualification. PHP is required for the explicit interoperability lane;
Docker/cgroup prerequisites apply to the separately selected Kubernetes
benchmark. See [testing guidance](docs/testing.md) for the actual package Make
targets. Parser, primitive, lifecycle and upgrade changes still need their
affected refusal, cancellation, admission, CAS and compatibility assertions.
Release rehearsal remains `golib release dry-run --module .`. Report skipped,
unavailable and failed boundaries; local checks are not hosted-CI or release proof.

## Selected Weekly Assurance

The owner-level [selected-assurance caller](.github/workflows/assurance.yml) is
configured for main only, on Fridays at 03:41 UTC. It selects one of the
2 current declared root-module fuzz targets using the shared UTC-week
rotation, with 30 seconds of active exploration. The selected risks are:
encoded-hash round trips and algorithm identity, plus verification under
small explicit resource limits with classified refusal outcomes.
These in-process parser/verification targets do not certify cryptographic
primitives, zeroization, admission concurrency or resource-tagged stress.
Existing source/conformance guards, named races, Go/PHP interoperability,
portability and separately selected container benchmarks remain unchanged.

Base-free ordinary checks execute deterministic seeds, not active exploration;
committed-range CI selects affected active smoke. Manual assurance requires an
exact anchored selector from the root fuzz operation in `.golib.yaml`, for
example `^FuzzParseEncodedHash$`.
Empty, unknown and malformed selections refuse. The shared job bounds setup
and execution to ten minutes, active workers and CPU to two, owned memory to
2 GiB, native output to 1 MiB and private-cache lifetime. Failure, cancellation,
exhausted budgets and cleanup refusal remain attributable failures. This lane
does not run mutation or replace Required, original full fuzz budgets,
explicit `make check-full`, or relevant release qualification.

## Adding A Module

Follow [repository structure policy](AGENTS.md#repository-structure). New modules
require an explicit purpose, ownership boundary, dependency review, package
catalog entry, full quality gates, documentation, changelog, license, security
policy, compatibility plan, and release dry-run.
