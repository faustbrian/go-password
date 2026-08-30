# Changelog

All notable changes are documented here. The project follows semantic
versioning after v1.

## Unreleased

The [specification decision register](docs/specification-decisions.md) records
the current standards and compatibility policy.

### Changed

- Replace copied repository tooling with the checksum-pinned
  `go-library-tools` v1.0.13 contract while retaining package-owned policy and
  verification evidence.

### Documentation

- Make RFC 9106 Argon2id, RFC 4648 base64, OpenBSD bcrypt, parser,
  verification, interoperability, and monotonic-upgrade decisions explicit
  and release-gated:
  PASSWORD-DEC-001 sha256:ba44cc58be46506940728e9d6edfcfc165f84c201ac01efe709b4949a211cd92;
  PASSWORD-DEC-002 sha256:9d92027d805ca587dcce9875bb0af09d2d9913ad883bee56e173407d7a6b6362;
  PASSWORD-DEC-003 sha256:ea20f1c77cbbb8f8b5ca43a23c217ae77e142eed42ee4db1f636be1fc949ab45;
  PASSWORD-DEC-004 sha256:3526e9549c855d048fec5c31220d1c3085331eef128437c1d3bc1a1e682daf9d;
  PASSWORD-DEC-005 sha256:695d1894768e03f3a3d5994e432d9eac0248b981bc3493c0931ce9ba19996d84;
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
