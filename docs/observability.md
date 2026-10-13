# Logging and telemetry

[Documentation index](README.md)

Use `password.WithObserver` to adapt events into standard `log/slog`,
`log`, or `telemetry`. The package intentionally depends on none of them.

Only record the supplied fields:

- `Operation`: `hash`, `verify`, or `verify_and_upgrade`;
- configured `Algorithm`;
- bounded `Outcome`;
- `NeedsRehash` boolean;
- `Duration` histogram value.

Do not attach password bytes, encoded hashes, salt/output data, usernames,
subjects, database IDs, raw errors, parser fields, or context-derived secrets.
Use operation/algorithm/outcome as bounded metric dimensions. Keep duration in
a histogram, and count resource rejection/cancellation separately.

Event Duration includes admission and computation but excludes the observer
callback; it is not the total end-to-end call latency. Context values are not
redacted or validated by the package.

Observers run synchronously and must bound latency. A panic is isolated, but a
blocking observer delays the password call. If an application needs asynchronous
delivery, it owns a bounded queue, drop policy, shutdown, and secret review.

Continue with [API and error semantics](api.md).
