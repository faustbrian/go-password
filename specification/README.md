# Specification conformance matrix

The [specification decision register](../docs/specification-decisions.md)
records which behavior comes from RFC 9106, RFC 4648, OpenBSD bcrypt, or
package policy. Source and change authorities are pinned separately in
`monitoring.json`.

| Decision | Observable boundary | Peer boundary |
| --- | --- | --- |
| PASSWORD-DEC-001 | Argon2id version 1.3 primitive profile | Argon2 reference vector and live PHP agreement |
| PASSWORD-DEC-002 | Default and bounded Argon2id parameters | Live PHP agreement for the package profile |
| PASSWORD-DEC-003 | Strict unpadded RFC 4648 base64 | Argon2 reference and live PHP agreement |
| PASSWORD-DEC-004 | Fixed canonical Argon2id persistence grammar | Live PHP agreement for accepted output; stricter rejection is package policy |
| PASSWORD-DEC-005 | Reviewed bcrypt variants, body, cost, and password bounds | Maintained Go vector and live PHP agreement |
| PASSWORD-DEC-006 | Verification ordering, comparison, errors, and redaction | No independent differential claim for package error policy |
| PASSWORD-DEC-007 | Monotonic login-time rehash and durable upgrade policy | No independent differential claim for package migration policy |

The bidirectional PHP lane is maintained-peer differential evidence. It does
not make PHP normative and does not replace the pinned sources or the focused
executable evidence in `conformance.json`.
