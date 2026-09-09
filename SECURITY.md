# Security policy

## Supported versions

The latest stable v1 release receives security fixes. Older releases and the
`main` branch are unsupported; upgrade before reporting unless the issue is a
regression under active development.

| Version | Supported |
| --- | --- |
| Latest stable v1 release | Yes |
| Older releases | No |
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
