# Threat model

## Assets

- Caller password bytes during synchronous execution.
- Encoded hashes, salts, and derived outputs.
- Hashing policy and resource budgets.
- Correct match/mismatch and upgrade decisions.
- Availability under attacker-controlled password/hash input.

## Trust boundaries

Password input, encoded database values, contexts, lookups, entropy failures,
observers, queue pressure, and shutdown timing may be malformed, unavailable,
or adversarial. The maintained Go cryptographic implementations and Go runtime
are trusted within their documented behavior.

## Controls

| Threat | Control |
| --- | --- |
| Custom/weak cryptography | Maintained `x/crypto` Argon2id and bcrypt only |
| Parameter bomb | Parse and bound time, memory, lanes, cost, salt, output first |
| Parser ambiguity | Canonical fixed-order grammar and strict base64 |
| CPU/memory exhaustion | Input bounds, admission concurrency, bounded queue |
| Queue retention | Context cancellation, queue ceiling, drainable shutdown |
| Hash downgrade | Monotonic rehash rules; never Argon2id to bcrypt |
| Stale concurrent upgrade | Expected/replacement database CAS |
| Entropy failure | Complete `crypto/rand` salt or classified failure |
| Diagnostic leakage | Redacted `fmt`/`log/slog` values and cause-free error strings |
| Metric cardinality/leakage | Bounded observation enums only |
| Observer failure | Panic isolation; observation cannot change result |
| Caller-buffer retention | Internal copy, no retained password field |

## Explicit non-protections

- Compromised process memory, debugger, kernel, runtime, or host.
- Guaranteed memory wiping or side-channel immunity.
- Application logs/traces of raw inputs before this package.
- Username enumeration, endpoint rate limiting, breach lookup, or strength UI.
- TLS, user lifecycle, sessions, MFA, recovery, or authorization.
- Database confidentiality after hash exfiltration and offline guessing.
- A malicious lookup or observer supplied by the application, or an entropy
  implementation supplied only inside package-owned tests.

## Abuse cases

Hostile encodings cannot request work above policy ceilings. A flood of valid
maximum-cost hashes can occupy only `Concurrent` operations and `Queue` waiters;
additional calls fail explicitly. Applications still need network-level rate
limits, endpoint timeouts, and capacity planning.

Go does not expose a recoverable general-purpose allocation failure. A process
may terminate if its trusted policy and container limit are incompatible. The
package therefore validates generated lengths, rejects attacker-selected work
before primitive allocation, and bounds simultaneous default-policy work; it
does not claim to catch runtime out-of-memory termination. `make resource`
exercises that boundary with two 64 MiB slots and eight concurrent callers.

The authentication adapter requires its missing-user dummy to match the active
target algorithm and every encoded work-factor parameter. This prevents a
stale or cheap dummy from making the ordinary missing-user primitive path
materially cheaper than target-hash verification. Stored legacy hashes,
malformed records, lookup latency, cancellation, admission, and endpoint
responses remain distinguishable, so complete timing equalization remains an
application/system concern. Rotate the dummy whenever the target policy
changes and use uniform public responses and endpoint rate limits.

## Accepted risks

| ID | Severity | Owner | Rationale | Mitigation | Review condition |
| --- | --- | --- | --- | --- | --- |
| PASSWORD-RISK-001 | Medium | go-password maintainers | The maintained Argon2id and bcrypt APIs are synchronous and cannot be interrupted after primitive work starts. Detached replacement work would retain passwords and escape admission ownership. | Parse and bound work before admission, cap active and queued operations, propagate cancellation before primitive entry, and document the synchronous boundary. | Revisit when `x/crypto` offers cancellable primitives or any work, concurrency, queue, or timeout limit changes. |
| PASSWORD-RISK-002 | Medium | integrating application owner | Hash cost parity cannot equalize lookup, malformed-record, legacy-hash, cancellation, network, or response timing without ownership of the application authentication flow. | Require exact target dummy work, use uniform public failures and endpoint rate limits, and migrate legacy hashes through CAS upgrades. | Revisit when the adapter owns another authentication boundary, a timing regression is observed, or supported legacy algorithms change. |
| PASSWORD-RISK-003 | Medium | go-password maintainers and deployment operator | A single portable default cannot prove an appropriate password cost for every deployment. The 64 MiB, time-2, one-lane package profile differs from the RFC 9106 recommended profiles; historical measurements do not establish current latency or deployment suitability. | Keep limits explicit and require benchmarks and capacity planning for the deployed toolchain and dependencies before adopting the profile. | Revisit after material Go, `x/crypto`, hardware, container-budget, or RFC guidance changes. |
