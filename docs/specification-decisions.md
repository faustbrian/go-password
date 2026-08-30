# Password specification decisions

This register is the human-readable view of
[`specification/decisions.json`](../specification/decisions.json). RFC 9106 is
authoritative for Argon2, RFC 4648 is authoritative for base64 mechanics, and
OpenBSD 7.8 documents bcrypt. The PHC-style framing, compatibility set, limits,
errors, and upgrade rules are explicitly package-owned decisions.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they
appear in all capitals, as shown here.

Statuses are `resolved`, `unresolved`, or `superseded`. Changes preserve old
digests in `specification/decision-history.json` and require compatibility,
changelog, conformance, and peer-evidence review.

## PASSWORD-DEC-001: Argon2id version and primitive profile

| Field | Decision |
| --- | --- |
| Status | resolved |
| Owner | password maintainers |
| Classification | optional behavior |
| Decision scope | normative |
| Specification | RFC 9106 Argon2 |
| Exact version | RFC 9106 (September 2021) |
| Source authority | rfc9106-source |
| Authoritative URL | https://www.rfc-editor.org/rfc/rfc9106.txt |
| Section | Sections 1, 3, and 5.3 |
| Requirement strength | MUST |
| Issue | RFC 9106 requires Argon2id support but permits additional variants and parameters that this password-specific API could expose or reject. |
| Credible interpretations | Expose Argon2d, Argon2i, and several versions<br>Support only Argon2id version 1.3 encoded as decimal version 19 |
| Known peer behavior | The pinned golang.org/x/crypto/argon2 implementation computes Argon2id version 1.3, and the Argon2 reference CLI vector agrees with the package output. |
| Selected behavior | Hash and verify only Argon2id version 1.3, represented as version 19; classify other Argon2 variants as unsupported algorithms and other encoded versions as unsupported versions. |
| Normative rationale | One mandatory RFC variant and version avoids algorithm negotiation while preserving the deployed Argon2id contract. |
| Security consequences | Callers cannot select data-dependent Argon2d or silently verify an unknown version. |
| Resource consequences | The primitive receives only validated and bounded memory, time, lane, salt, and output parameters. |
| Compatibility consequences | Argon2i, Argon2d, and non-version-19 hashes require a separately reviewed adapter or version policy. |
| Wire consequences | Accepted Argon2 encodings begin exactly with $argon2id$v=19$. |
| Executable evidence | TestMaintainedImplementationVectors<br>TestEncodedHashParserMatrix<br>TestArgon2idHashVerifyAndUpgrade |
| Official or pinned fixtures | vectors_test.go |
| Fuzz evidence | FuzzParseEncodedHash<br>FuzzBoundedVerify |
| Interoperability evidence | None. |
| Differential evidence | scripts/check-interoperability.sh |
| Affected public APIs | Algorithm<br>Argon2idParameters<br>ParseEncodedHash<br>Service.Hash<br>Service.Verify |
| Affected documentation | docs/specification-decisions.md<br>docs/parser-grammar.md<br>docs/algorithm-selection.md |
| Upstream status | RFC 9106 and its errata are monitored; no current erratum changes the selected Argon2id version. |
| Reconsider when | RFC 9106 is superseded, an applicable erratum changes Argon2id, or another variant or version is proposed. |

## PASSWORD-DEC-002: Argon2id password parameter policy

| Field | Decision |
| --- | --- |
| Status | resolved |
| Owner | password maintainers |
| Classification | optional behavior |
| Decision scope | recommended |
| Specification | RFC 9106 Argon2 |
| Exact version | RFC 9106 (September 2021) |
| Source authority | rfc9106-source |
| Authoritative URL | https://www.rfc-editor.org/rfc/rfc9106.txt |
| Section | Sections 3.1, 4, and 7.4 |
| Requirement strength | RECOMMENDED |
| Issue | RFC 9106 provides two general recommended profiles and application tuning guidance, while this package needs bounded defaults suitable for its service admission model. |
| Credible interpretations | Use the 2 GiB first recommended profile<br>Use the 64 MiB second profile exactly<br>Publish a measured package profile with explicit limits and caller tuning |
| Known peer behavior | PHP and Laravel expose configurable Argon2id memory, time, and thread costs; the live PHP peer accepts the package profile and package output. |
| Selected behavior | Default to Argon2id with 64 MiB memory, time cost 2, one lane, a 16-byte unique random salt, and a 32-byte output; require memory of at least 8 KiB per lane and expose immutable bounded policy configuration. |
| Normative rationale | The default keeps the RFC-recommended salt and tag sizes while choosing a measured service profile whose concurrency is explicitly admitted and whose deviation from RFC 9106's generic profiles is visible. |
| Security consequences | Deployments must benchmark and may raise costs; random salts remain unique in ordinary operation and weak or unbounded parameter sets are rejected. |
| Resource consequences | Default work consumes approximately 64 MiB per active operation, and configured maxima bound hostile persisted parameters before primitive invocation. |
| Compatibility consequences | Changing defaults marks weaker successfully verified hashes for upgrade without invalidating them. |
| Wire consequences | New default hashes encode m=65536,t=2,p=1 with 16-byte salts and 32-byte outputs. |
| Executable evidence | TestPolicyExactBoundaries<br>TestArgonParallelismMemoryBoundary<br>TestArgon2idHashVerifyAndUpgrade<br>TestHostileHashesAreRejectedBeforePrimitive |
| Official or pinned fixtures | passwordtest/passwordtest.go |
| Fuzz evidence | FuzzBoundedVerify |
| Interoperability evidence | None. |
| Differential evidence | scripts/check-interoperability.sh |
| Affected public APIs | DefaultPolicy<br>NewPolicy<br>Argon2idParameters<br>Limits<br>Service.Hash<br>Service.Verify |
| Affected documentation | docs/specification-decisions.md<br>README.md<br>docs/kubernetes-sizing.md |
| Upstream status | RFC 9106 parameter recommendations are unchanged; this package profile is an explicit deployment policy, not a claim to use either generic profile verbatim. |
| Reconsider when | Benchmarks, deployment memory, cryptanalytic guidance, RFC errata, or service admission requirements change. |

## PASSWORD-DEC-003: Canonical unpadded Argon2id base64

| Field | Decision |
| --- | --- |
| Status | resolved |
| Owner | password maintainers |
| Classification | optional behavior |
| Decision scope | application-policy |
| Specification | RFC 4648 Base-N Encodings |
| Exact version | RFC 4648 |
| Source authority | rfc4648-source |
| Authoritative URL | https://www.rfc-editor.org/rfc/rfc4648.txt |
| Section | Sections 3.2, 3.3, 3.5, and 4 |
| Requirement strength | not specified |
| Issue | RFC 4648 normally requires padding unless a referring specification states otherwise, while deployed PHC Argon2 strings conventionally omit padding and require one canonical textual identity. |
| Credible interpretations | Require padded RFC 4648 base64<br>Accept padded and unpadded encodings<br>Define an explicit unpadded canonical profile and reject alternate spellings |
| Known peer behavior | The Argon2 reference CLI, golang.org/x/crypto ecosystem, and PHP password_hash emit unpadded standard-alphabet base64 in Argon2id strings. |
| Selected behavior | Encode and accept only unpadded canonical RFC 4648 standard-alphabet base64 for Argon2id salt and output fields, reject non-alphabet characters and non-zero trailing pad bits, and round-trip accepted bytes exactly. |
| Normative rationale | An explicit no-padding profile preserves PHC and PHP interoperability without claiming that RFC 4648 itself selected omission for password hashes. |
| Security consequences | Strict canonical decoding prevents multiple textual identities for one salt or output and rejects hidden trailing data. |
| Resource consequences | Encoded lengths are bounded before decoding and decoded salt and output lengths are bounded afterward. |
| Compatibility consequences | Padded or non-canonical base64 hashes are rejected rather than normalized. |
| Wire consequences | Salt and output fields use the RFC 4648 base64 alphabet without = padding. |
| Executable evidence | TestRawBase64EncodedLengthMatchesStandardLibrary<br>TestEncodedHashParserMatrix<br>TestArgonAndBcryptDecoderFailuresRemainIndependent |
| Official or pinned fixtures | vectors_test.go<br>passwordtest/passwordtest.go |
| Fuzz evidence | FuzzParseEncodedHash |
| Interoperability evidence | None. |
| Differential evidence | scripts/check-interoperability.sh |
| Affected public APIs | EncodedHash.String<br>ParseEncodedHash<br>Service.Hash<br>Service.Verify |
| Affected documentation | docs/specification-decisions.md<br>docs/parser-grammar.md<br>docs/laravel-migration.md |
| Upstream status | RFC 4648 errata are monitored; unpadded PHC usage remains a package profile decision. |
| Reconsider when | A standardized Argon2 string format defines different padding or canonicalization requirements, or an RFC 4648 erratum applies. |

## PASSWORD-DEC-004: Canonical Argon2id encoded-hash grammar

| Field | Decision |
| --- | --- |
| Status | resolved |
| Owner | password maintainers |
| Classification | omission |
| Decision scope | application-policy |
| Specification | RFC 9106 Argon2 |
| Exact version | RFC 9106 (September 2021) |
| Source authority | rfc9106-source |
| Authoritative URL | https://www.rfc-editor.org/rfc/rfc9106.txt |
| Section | Repository-owned persistence grammar; RFC 9106 defines primitive inputs and output but not this PHC field grammar |
| Requirement strength | not specified |
| Issue | RFC 9106 does not define parameter field order, decimal spelling, separators, minimum persistence lengths, or parser error precedence for an encoded password hash. |
| Credible interpretations | Accept flexible field ordering and normalize<br>Delegate parsing to a primitive<br>Require one fixed-order bounded grammar before primitive invocation |
| Known peer behavior | PHP emits the same $argon2id$v=19$m=...,t=...,p=...$salt$output shape, but parsers differ in acceptance of reordered or non-canonical fields. |
| Selected behavior | Require exactly six dollar-separated fields, fixed m,t,p order, unsigned decimal without signs or leading zeroes, version 19, salt of at least 8 bytes, output of at least 16 bytes, and no whitespace or trailing data. |
| Normative rationale | One persistence grammar makes classification, resource admission, rehash decisions, and round trips deterministic for hostile stored values. |
| Security consequences | Duplicate, reordered, overflowing, malformed, and parameter-bomb fields fail before expensive work. |
| Resource consequences | Complete encoding, numeric fields, encoded fields, decoded values, and primitive parameters are bounded before allocation or hashing. |
| Compatibility consequences | Non-canonical but potentially decodable PHC strings must be migrated through an explicit adapter rather than silently normalized. |
| Wire consequences | Accepted Argon2id persistence strings have one fixed textual grammar and exact round-trip identity. |
| Executable evidence | TestEncodedHashParserMatrix<br>TestParserExactBoundaries<br>TestParserRejectsNonCanonicalDecimal<br>TestHostileHashesAreRejectedBeforePrimitive |
| Official or pinned fixtures | passwordtest/passwordtest.go |
| Fuzz evidence | FuzzParseEncodedHash<br>FuzzBoundedVerify |
| Interoperability evidence | None. |
| Differential evidence | scripts/check-interoperability.sh |
| Affected public APIs | ParseEncodedHash<br>EncodedHash<br>Limits<br>Service.Verify |
| Affected documentation | docs/specification-decisions.md<br>docs/parser-grammar.md<br>docs/api.md |
| Upstream status | No RFC 9106 erratum currently defines the missing persistence grammar; the deployed profile remains package-owned. |
| Reconsider when | A normative Argon2 encoded-string specification is adopted or an existing producer requires an explicit compatibility mode. |

## PASSWORD-DEC-005: Bcrypt format and variant compatibility profile

| Field | Decision |
| --- | --- |
| Status | resolved |
| Owner | password maintainers |
| Classification | interoperability policy |
| Decision scope | application-policy |
| Specification | OpenBSD 7.8 bcrypt password hashing |
| Exact version | OpenBSD 7.8 bcrypt(3) |
| Source authority | openbsd-bcrypt-source |
| Authoritative URL | https://man.openbsd.org/OpenBSD-7.8/bcrypt.3 |
| Section | Blowfish crypt |
| Requirement strength | not specified |
| Issue | OpenBSD documents $2b$ and a 72-byte maximum password, while deployed Go and PHP hashes also use $2a$ and $2y$ variants with a specialized base64 alphabet. |
| Credible interpretations | Accept only current OpenBSD $2b$<br>Accept every $2 prefix<br>Accept the reviewed $2a$, $2b$, and $2y$ compatibility set with strict canonical bodies |
| Known peer behavior | golang.org/x/crypto/bcrypt emits and verifies $2a$ and accepts compatible $2b$ and $2y$ inputs; PHP emits $2y$ and bidirectionally verifies package bcrypt hashes. |
| Selected behavior | Accept exactly 60-byte $2a$, $2b$, and $2y$ hashes with two-digit costs from 04 through the configured maximum and canonical bcrypt ./A-Za-z0-9 salt and digest encodings; generate through pinned golang.org/x/crypto and reject passwords above 72 bytes. |
| Normative rationale | The narrow compatibility set covers Go, OpenBSD, and Laravel migrations without treating every historical or unknown bcrypt prefix as equivalent. |
| Security consequences | Unknown variants, malformed encodings, excessive costs, and truncation-prone passwords fail before bcrypt verification. |
| Resource consequences | Cost and password length are bounded before the maintained primitive performs exponential work. |
| Compatibility consequences | $2a$, $2b$, and $2y$ remain verifiable; other bcrypt variants require explicit review. |
| Wire consequences | Generated hashes retain the maintained Go implementation prefix, while accepted stored hashes preserve their exact reviewed prefix and body. |
| Executable evidence | TestMaintainedImplementationVectors<br>TestBcryptParserRejectsNonCanonicalBase64<br>TestServiceFailureAndBoundaryMatrix<br>TestLaravelBcryptUpgrade |
| Official or pinned fixtures | vectors_test.go<br>passwordtest/passwordtest.go |
| Fuzz evidence | FuzzParseEncodedHash<br>FuzzBoundedVerify |
| Interoperability evidence | None. |
| Differential evidence | scripts/check-interoperability.sh |
| Affected public APIs | Bcrypt<br>ParseEncodedHash<br>EncodedHash.BcryptCost<br>Service.Hash<br>Service.Verify |
| Affected documentation | docs/specification-decisions.md<br>docs/parser-grammar.md<br>docs/compatibility.md |
| Upstream status | OpenBSD 7.8 errata and maintained Go and PHP behavior are monitored separately; no RFC is claimed for bcrypt. |
| Reconsider when | OpenBSD changes bcrypt format guidance, golang.org/x/crypto changes variant handling, or another producer variant is proposed. |

## PASSWORD-DEC-006: Verification and mismatch semantics

| Field | Decision |
| --- | --- |
| Status | resolved |
| Owner | password maintainers |
| Classification | omission |
| Decision scope | defensive |
| Specification | RFC 9106 Argon2 |
| Exact version | RFC 9106 (September 2021) |
| Source authority | rfc9106-source |
| Authoritative URL | https://www.rfc-editor.org/rfc/rfc9106.txt |
| Section | Repository-owned verification API around Sections 3 and 4 |
| Requirement strength | not specified |
| Issue | Primitive specifications define computed outputs but not API error classification, admission ordering, diagnostic redaction, or how Argon2id and bcrypt mismatches share one verifier. |
| Credible interpretations | Return primitive errors directly<br>Treat every failure as mismatch<br>Parse and admit explicitly, compare through the maintained primitive, and preserve classified failures |
| Known peer behavior | PHP password_verify returns a boolean for supported hashes, while this package exposes additional classified resource, syntax, version, algorithm, cancellation, and lifecycle failures. |
| Selected behavior | Parse and resource-check before admission and primitive work, compare Argon2id outputs in constant time, delegate bcrypt comparison to golang.org/x/crypto, return ErrMismatch only for a valid supported hash with a wrong password, and redact hashes and primitive causes from diagnostics. |
| Normative rationale | Separating mismatch from invalid or rejected input gives callers safe authentication behavior without losing operational classification. |
| Security consequences | Hostile encodings cannot trigger unbounded primitive work, and secret hashes, passwords, and primitive causes do not enter ordinary diagnostics. |
| Resource consequences | Parsing precedes bounded admission; accepted cryptographic work consumes configured active capacity and respects cancellation at owned boundaries. |
| Compatibility consequences | Callers may distinguish mismatch from malformed, unsupported, resource, cancellation, and lifecycle errors and must not collapse them unintentionally. |
| Wire consequences | No normalization occurs during verification; accepted encoded hashes retain exact persistence bytes. |
| Executable evidence | TestServiceFailureAndBoundaryMatrix<br>TestHostileHashesAreRejectedBeforeAdmission<br>TestClassifiedErrorDoesNotExposeCause<br>TestStandardLoggingDoesNotExposeHashOrErrorCause |
| Official or pinned fixtures | passwordtest/passwordtest.go |
| Fuzz evidence | FuzzBoundedVerify |
| Interoperability evidence | None. |
| Differential evidence | None. |
| Affected public APIs | Service.Verify<br>Verification<br>Error<br>ErrMismatch<br>ErrMalformedHash<br>ErrResourceRejected |
| Affected documentation | docs/specification-decisions.md<br>docs/api.md<br>docs/secret-handling.md |
| Upstream status | The verification API and error model are package policy; RFC 9106 remains authoritative only for Argon2 computation. |
| Reconsider when | A public error contract, primitive boundary, admission model, or supported algorithm changes. |

## PASSWORD-DEC-007: Monotonic login-time upgrade policy

| Field | Decision |
| --- | --- |
| Status | resolved |
| Owner | password maintainers |
| Classification | omission |
| Decision scope | application-policy |
| Specification | RFC 9106 Argon2 |
| Exact version | RFC 9106 (September 2021) |
| Source authority | rfc9106-source |
| Authoritative URL | https://www.rfc-editor.org/rfc/rfc9106.txt |
| Section | Repository-owned migration policy adjacent to Section 7.4 recommendations |
| Requirement strength | not specified |
| Issue | RFC 9106 recommends Argon2id parameters but does not define migration from bcrypt or mixed stronger and weaker persisted Argon2id dimensions. |
| Credible interpretations | Rehash whenever any parameter differs<br>Compare only a single cost<br>Upgrade bcrypt to Argon2id and require every Argon2id dimension to move monotonically |
| Known peer behavior | PHP password_needs_rehash compares against requested algorithm options, but application policy still owns cross-algorithm migration and durable replacement. |
| Selected behavior | Mark verified bcrypt for upgrade when the target is Argon2id, never mark Argon2id for downgrade to bcrypt, preserve higher bcrypt cost, and recommend an Argon2id rehash only when at least one target dimension is higher and no target dimension is lower. |
| Normative rationale | A partial stronger profile must not be replaced by a mixed profile that lowers another security or entropy dimension. |
| Security consequences | Login-time migration cannot silently lower memory, time, lanes, salt length, output length, algorithm, or higher bcrypt cost. |
| Resource consequences | Upgrade hashing occurs only after successful verification and remains subject to the target policy and admission limits. |
| Compatibility consequences | Existing valid hashes continue to verify; callers receive an explicit upgrade recommendation and control durable compare-and-swap replacement. |
| Wire consequences | Successful upgrades produce a new canonical target hash while failed or concurrent replacement leaves the old hash usable. |
| Executable evidence | TestNeedsRehashNeverRecommendsDowngrade<br>TestNeedsRehashArgon2idTransitionMatrix<br>TestAuthenticateReturnsExplicitCASUpgrade<br>TestConcurrentUpgradeCrashAndCASStatesPreserveUsableHash |
| Official or pinned fixtures | passwordtest/passwordtest.go |
| Fuzz evidence | None. |
| Interoperability evidence | None. |
| Differential evidence | None. |
| Affected public APIs | Service.NeedsRehash<br>Service.VerifyAndUpgrade<br>Verification.NeedsRehash<br>passwordauth.Authenticator |
| Affected documentation | docs/specification-decisions.md<br>docs/database-upgrades.md<br>docs/algorithm-selection.md |
| Upstream status | No external specification owns this migration policy; RFC 9106 recommendations are inputs rather than upgrade semantics. |
| Reconsider when | A new algorithm, parameter dimension, downgrade rule, or durable upgrade protocol is introduced. |

## Unresolved decisions

None. New ambiguity, erratum, source drift, parser policy, algorithm behavior,
or migration rule must be registered before it changes observable behavior.
