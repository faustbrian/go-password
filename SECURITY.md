# Security policy

## Supported versions

Security reports are accepted for the latest published stable major. A fix may
require migration to a new major; security fixes are not guaranteed to be
backported to the unsuffixed module. The `/v2` source becomes a supported public
release only when its tag and module artifacts are published; prepared source
alone is not publication. Legacy reports remain welcome but remediation may
require migration. The `main` branch is not a supported deployment target.

| Version | Supported |
| --- | --- |
| v2.0.0 | Supported after public tag and module publication |
| Legacy v1 releases | Reports accepted; fixes may require migration |
| `main` | No |

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue. Open a
[detail-free support issue](https://github.com/faustbrian/go-password/issues/new)
asking a maintainer for a private contact channel.

Include the affected version, a synthetic reproduction, realistic impact,
suspected password/hash exposure, and embargo constraints. Do not send real
credentials or production hashes.

## Security boundary

The package protects parsing, resource admission, primitive invocation,
classified outcomes, safe diagnostic formatting, and explicit upgrade data. It
does not protect a compromised process, malicious collaborators, application
logging of raw inputs, user enumeration at the endpoint, insecure transport,
weak application password policy, database compromise, or authorization after
authentication.

Only maintained `golang.org/x/crypto/argon2` and
`golang.org/x/crypto/bcrypt` primitives are used. There is no unsafe, cgo,
assembly, reversible storage, custom password primitive, or default pre-hash.

See the [threat model](docs/threat-model.md),
[secret-handling guide](docs/secret-handling.md), and
[security review packet](docs/security-review.md).
