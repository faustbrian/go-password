# Changelog

All notable changes are documented here. The project follows semantic
versioning after v1.

## Unreleased

The [specification decision register](docs/specification-decisions.md) records
the current standards and compatibility policy.

### Changed

- Publish schema-v2 cohesion metadata for the password module, algorithm
  packages, authentication and service integrations, and test support.
- Adopt the checksum-verified `go-library-tools` v1.3.0 CLI, expose the local
  `make cohesion` gate, and pin reusable-workflow cohesion enforcement to its
  final immutable revision.

- Adopt the checksum-pinned `go-library-tools` v1.2.0 contract and immutable
  `1f9629e5f27418600460b55a50a5b2fc81697fab` workflow while retaining
  package-owned policy and verification evidence.

### Documentation

- Link consumers to the immutable v1.3.0 Golib ecosystem index and Service edge
  package-family guidance.

- Make RFC 9106 Argon2id, RFC 4648 base64, OpenBSD bcrypt, parser,
  verification, interoperability, and monotonic-upgrade decisions explicit
  and release-gated:
  PASSWORD-DEC-001 sha256:81d693f05f84c603efdb629d9249e13e134def4e645afffd12e50b1e7233823c;
  PASSWORD-DEC-002 sha256:d0aff45bb407811912bc21be738605732adbd604decc339b449bd25fdf125ddf;
  PASSWORD-DEC-003 sha256:abb7d2b09fe08461078fbebe88637d317ef52b5ffc035fa3072950717978f24f;
  PASSWORD-DEC-004 sha256:35d8b75df3f64f7a8d45e38c763ebc7e110953b0542d3c03cd230c2d1194e83e;
  PASSWORD-DEC-005 sha256:ed3cb3293b84a79a7cd06892599874eaf56b4f91071e8537df71fc93794a7104;
  PASSWORD-DEC-006 sha256:d020717a693732de00655a0a0c4359626feacc6f71d130acbd21800e3979a748;
  PASSWORD-DEC-007 sha256:e3dcdee13b077e6effd51a4b6dd9d00c0b3a373826aaa0ee305495e4088a5def.

- Replace archived monorepo links and completed execution artifacts with a
  standalone, human-oriented documentation structure.

## 1.0.0 - 2026-08-25

### Changed

- Exclude intentional nested modules from root local-proxy archives so local,
  bootstrap, CI, and public module checksums describe the same source
  boundary.

- Track the pinned documentation-tool lockfile so clean CI checkouts install
  the exact validated cspell dependency.

- Reconcile standalone dependency checksums against deterministic current
  module archives so CI, local verification, and release consumers resolve
  identical content.

- Harden standalone documentation validation with deterministic spelling and
  link checks, package-specific documentation gates, and repository-local
  contributor guidance.

### Documentation

- Correct stale package, standalone, and authoritative-source links in public
  documentation.

### Documentation

- Link the package README to package-owned documentation.

### Security

- Parse Argon2id parallelism at its exact eight-bit representation before
  conversion, while retaining stricter configured resource limits.

### Changed

- Publish the module from its standalone `github.com/faustbrian/go-password` identity while preserving its documented API and behavior.
- Delegate local mutation checks to the canonical exact-100 repository runner
  and remove the superseded package-local Gremlins configuration.
- Remove an obsolete conversion suppression now that Argon2id parallelism is
  parsed at eight-bit width.
- Execute API compatibility tooling against the isolated module graph so owned
  dependency source changes cannot conflict with release checksums.
- Updated the pinned `apidiff` revision used by API compatibility checks.

### Fixed

- Prevented mixed Argon2id policy transitions from lowering any stronger
  memory, salt, or output dimension.
- Rejected bcrypt passwords above 72 bytes before verification work instead of
  misclassifying the primitive failure as a mismatch.
- Rejected oversized Argon2id salt and output fields before base64 decoding.

### Security

- Extended the interoperability gate to generate fresh PHP hashes for Go
  verification in addition to generating fresh Go hashes for PHP.
- Added bcrypt and malformed-path timing regression evidence plus a
  cgroup-constrained Kubernetes benchmark gate.

### Added

- Immutable Argon2id and bcrypt policy with strict resource limits.
- Canonical PHC Argon2id and Laravel-compatible bcrypt parsing.
- Hash, verify, rehash, and explicit verify-and-upgrade operations.
- Bounded admission with cancellation and drainable lifecycle.
- Secret-safe classified errors, encoded-hash formatting, and observations.
- Immutable classified errors with read-only kind, operation, and cause access.
- Synthetic PHP 8.5 Laravel compatibility fixtures and maintained vectors.
- Application lookup/CAS, service lifecycle, and deterministic test adapters.
- Exact production coverage, race, fuzz, timing, and benchmark evidence.

### Security

- Hostile encoded hashes are rejected before primitive execution.
- Rehash decisions are monotonic and cannot downgrade Argon2id to bcrypt.
- Password inputs are copied, never retained, and omitted from diagnostics.
