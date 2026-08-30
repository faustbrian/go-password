# Changelog

All notable changes are documented here. The project follows semantic
versioning after v1.

## Unreleased

### Changed

- Replace copied repository tooling with the checksum-pinned
  `go-library-tools` v1.0.13 contract while retaining package-owned policy and
  verification evidence.

### Documentation

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
