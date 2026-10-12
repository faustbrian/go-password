# Source documentation audit

## Scope and reproduction

Documentation-only audit of base `b0066c725edad1456c9279d259fc9305003d027f`.
Reproduce the source inventory with `git ls-files '*.go'`, module boundaries
with `git ls-files '*go.mod'`, and assurance entry points with
`rg '^func (Test|Fuzz|Benchmark|Example)' --glob '*_test.go'`.
The table covers all 57 tracked Go files: 25 implementation/command sources
and 32 assurance files. Every exported declaration, named public field,
interface method, and method was reviewed alongside its implementation;
private coordination and caller-owned collaborators were included. The native
AST inventory identifies 207 public declarations/fields/methods and one exported
method on a private receiver; all 57 files parse with comments.

One module, `github.com/faustbrian/go-password/v2`, owns eight public packages:
root, `argon2id`, `bcrypt`, `adapters/authentication`, `adapters/service`,
`passwordauth`, `passwordservice`, and `passwordtest`. There are no nested
modules. The three `verification` files are separate build-ignored command
variants, not a normal importable package. `resource_test.go` requires the
`resource` tag. There are no generated Go files or generation directives.
The interoperability generator is a hand-maintained producer of temporary
synthetic encodings, not a producer of tracked Go source.

## Initial gaps and investigated rationale

The initial source checker reported one missing package comment on
`verification/check-api-docs.go`; public APIs already had syntactic comments.
The substantive audit concerns were contracts not implied by signatures:

- Password bytes remain borrowed until copied **after** admission; callers
  must keep them stable for the whole operation, including queued work.
  Clearing an owned temporary is not guaranteed runtime memory erasure.
- Contexts govern entry and waiting, not an already started KDF or salt read.
  Cancellation racing a notification can still admit work; completion is not
  followed by a cancellation recheck. Nil contexts are not supported.
- Limits are caller-selected ceilings, not universal machine-safe budgets.
  `NewPolicy` validates every algorithm ceiling without filling defaults;
  direct parsing applies supplied limits without validating a complete policy.
  Bcrypt service policies cap cost at 31; a direct parser call with a larger
  supplied ceiling is not proof that the primitive accepts that cost.
- Parsing proves canonical syntax/budgets, not password possession. Encodings
  and password bytes are not normalized. Decoded arrays are privately owned;
  copied hash values expose no mutable buffers, but raw String access and raw
  error causes are deliberate sensitive boundaries.
- `NeedsRehash` compares metadata only. Ordered time, memory, salt, and output
  dimensions cannot decrease; parallelism can move in either direction to
  the target when that guard holds. It is not ordered security strength.
- `VerifyAndUpgrade` returns the parsed original on a match needing no change.
  Verification and replacement generation acquire admission separately;
  replacement failure preserves a matched Result but returns no hash and an
  error. No persistence is performed. Authentication adapters reject this
  failure rather than exposing a partially successful authentication result.
- Admission bounds active and queued counts, not FIFO fairness or latency.
  Shutdown permanently closes it and observes caller releases; it cannot
  interrupt a primitive or recover a forgotten release. Shared admission
  ownership and shutdown must be coordinated by the application.
- Observer callbacks run synchronously, may overlap/reenter, and exclude their
  own callback latency from event Duration. Events use library-owned labels;
  caller contexts can still contain secrets. Public string enum types alone
  do not validate arbitrary application-constructed observations.
- Exact-target dummy verification narrows the ordinary missing-user branch,
  not all endpoint timing. Lookup, malformed records, legacy work, upgrades,
  cancellation, and responses remain distinguishable application boundaries.
  Public Record/Config fields and generic serialization are not protected by
  their redacted fmt/slog methods.
- Deprecated wrappers deliberately retain distinct released types and error
  identities via delegation/translation; they are not type aliases.
  Algorithm constructors choose generation targets, not verifier allowlists.
- Test entropy copies a nonempty public seed and serializes reads. It is not
  cryptographic entropy, has no useful zero value, and scheduling controls
  which concurrent reader gets each part of the stream.

These statements were grounded in the source and existing policy/parser,
rehash matrix, admission, lifecycle, entropy, error/redaction, observer,
authentication/CAS, deprecated-identity and vector tests. Timing smoke tests
are not side-channel proofs. Benchmarks are workload descriptions, not current
performance evidence. The two fuzz targets bound parsing and low-cost verifier
inputs; no new active fuzz campaign is appropriate for comment changes.

## Standards, fixtures, and native surfaces

The seven existing decisions distinguish RFC 9106 computation, RFC 4648
encoding, OpenBSD bcrypt compatibility, and repository-owned migration/error
policy. Their manifest, resolved decisions, historical decision digests,
committed vectors, dependency graph, API baselines, and dated security review
remain unchanged. PHP fixtures are documented as synthetic PHP 8.5.8 output;
the reference Argon2 CLI and maintained bcrypt test vector retain the existing
producer attribution. This audit does not regenerate fixtures, refresh online
standards, or certify current PHP interoperability or release status.

`.golib.yaml` uses `apidiff` with `api/v2.txt`; it is not a full-prose snapshot.
The native `api-docs` target runs `verification/check-api-docs.go`, an AST
comment check, not a snapshot generator. `api/root.txt` is retained historical
API evidence. Rendered docs for all eight public packages are selected to check
contract presentation. The source-boundary script checks dependencies,
unsafe/cgo/assembly, and absence of a production entropy constructor.
`check-conformance.sh --local` only checks the manifest header and seven-decision
register; the unrestricted version also runs runtime and PHP campaigns and is
not selected here. Existing three executable examples are unchanged; examples
are checked only if their maintained usage contract is directly affected.

## Open questions and limitations

No runtime repair or new security policy is included. Direct-parser limits
larger than service-valid bcrypt costs remain the caller's responsibility;
no new primitive acceptance guarantee is inferred. Historical benchmark,
timing, interoperability, and release evidence is not newly executed evidence.
Online source monitoring, resource-tagged stress, race/leak/fuzz campaigns,
PHP bidirectional verification, release qualification and public consumers are
outside this prose-only batch. No unresolved source interpretation is hidden
by a synthetic guarantee.

A full-current-file secret snapshot flags nine unchanged published
`PASSWORD-DEC-*` SHA-256 decision digests in historical changelog entries.
Their exact lines match the audit base, and all nine digests occur in the native
decision register/history; they are public integrity metadata, not credentials.
The historical bytes and scanner policy are preserved; added content and staged
changed lines remain the applicable secret-check boundaries.

## Complete file review

| Tracked Go file | Contract or assurance purpose reviewed |
| --- | --- |
| `adapters/authentication/authentication.go` | package/API contracts; ownership and compatibility |
| `adapters/authentication/authentication_test.go` | lookup, exact dummy work, CAS, classification, timing and redaction |
| `adapters/authentication/delivery_security_test.go` | composite-cause redaction or cross-algorithm dummy rejection |
| `adapters/authentication/doc.go` | package/API contracts; ownership and compatibility |
| `adapters/authentication/example_test.go` | executable construction, verification or explicit CAS usage |
| `adapters/service/doc.go` | package/API contracts; ownership and compatibility |
| `adapters/service/service.go` | package/API contracts; ownership and compatibility |
| `adapters/service/service_test.go` | hash/verify, original buffer ownership, replacement or lifecycle |
| `adapters_test.go` | algorithm constructors, interface composition and PHP fixtures |
| `admission.go` | capacity, wait notification, idempotent release, permanent drain |
| `admission_internal_test.go` | notifications, queue accounting and closed/full transitions |
| `admission_test.go` | active/queued ceilings and invalid controller bounds |
| `argon2id/argon2id.go` | package/API contracts; ownership and compatibility |
| `argon2id/argon2id_test.go` | Argon2id constructors and invalid parameters |
| `argon2id/doc.go` | package/API contracts; ownership and compatibility |
| `bcrypt/bcrypt.go` | package/API contracts; ownership and compatibility |
| `bcrypt/bcrypt_test.go` | bcrypt constructor cost validation |
| `bcrypt/doc.go` | package/API contracts; ownership and compatibility |
| `benchmark_test.go` | default Argon2id and cost-10 bcrypt hash/verify workloads |
| `boundaries_internal_test.go` | exact policy/parser ceilings and widened base64 length arithmetic |
| `concurrency_test.go` | shared immutable policy and admission hash/verify workers |
| `contracts.go` | public interfaces and partial upgrade result |
| `contracts_matrix_test.go` | configuration, canonical parser, operation and admission partitions |
| `delivery_security_test.go` | composite-cause redaction or cross-algorithm dummy rejection |
| `doc.go` | package/API contracts; ownership and compatibility |
| `encoding.go` | canonical syntax, allocation ceilings, persistence/redaction |
| `entropy_internal_test.go` | internal entropy failures, raw-cause redaction and partial upgrade results |
| `errors.go` | classified errors and trusted raw causes |
| `example_test.go` | executable construction, verification or explicit CAS usage |
| `fuzz_test.go` | parser round-trip and bounded low-cost verifier classification |
| `lifecycle_test.go` | close intake, wake waiters and observe drain |
| `mutation_boundaries_internal_test.go` | typed-nil, decoder, version/algorithm and lane-memory partitions |
| `observation.go` | synchronous borrowed observer and bounded event |
| `observation_test.go` | bounded events, outcome mapping, typed nil and panic isolation |
| `password_test.go` | policy, persistence escape hatch and redaction |
| `passwordauth/doc.go` | package/API contracts; ownership and compatibility |
| `passwordauth/example_test.go` | executable construction, verification or explicit CAS usage |
| `passwordauth/passwordauth.go` | package/API contracts; ownership and compatibility |
| `passwordauth/passwordauth_test.go` | delegating lookup/CAS, failure and released identity contracts |
| `passwordauth/translation_test.go` | unclassified error pass-through in deprecated facade |
| `passwordservice/doc.go` | package/API contracts; ownership and compatibility |
| `passwordservice/passwordservice.go` | package/API contracts; ownership and compatibility |
| `passwordservice/passwordservice_test.go` | released lifecycle identity, delegation and restart refusal |
| `passwordtest/doc.go` | package/API contracts; ownership and compatibility |
| `passwordtest/passwordtest.go` | package/API contracts; ownership and compatibility |
| `passwordtest/passwordtest_test.go` | seed copy, repeat stream and empty-seed rejection |
| `policy.go` | complete validated values, cross-algorithm ceilings |
| `rehash_test.go` | ordered-dimension and parallelism upgrade matrix, canonical decimal |
| `resource_test.go` | opt-in race/resource stress of two active default-memory slots |
| `security_test.go` | redaction and hostile input rejection before primitive/admission |
| `service.go` | copy timing, primitive admission, upgrade and observation |
| `service_test.go` | hash/verify, original buffer ownership, replacement or lifecycle |
| `timing_test.go` | match/mismatch and malformed-path timing smoke, not a security proof |
| `vectors_test.go` | maintained bcrypt and independent reference Argon2id output |
| `verification/check-api-docs.go` | hand-maintained standalone ignored command; producer/checker boundary |
| `verification/generate-interoperability.go` | hand-maintained standalone ignored command; producer/checker boundary |
| `verification/verify-interoperability.go` | hand-maintained standalone ignored command; producer/checker boundary |
