# Concurrency and lifecycle

[Documentation index](README.md)

Policies are immutable values. `Service` and `Admission` are safe for concurrent
use. Test entropy is mutex-protected; custom observers must be concurrency-safe.

`Limits.Concurrent` bounds primitive executions. `Limits.Queue` bounds waiting
callers. A full queue returns `ErrAdmission` immediately. Waiting honors context
cancellation, though a racing capacity notification can still admit work. FIFO
fairness is not promised. Admission creates no workers or background rehash
jobs; the maintained Argon2id primitive can use joined internal lane workers.

`Admission.Shutdown` atomically rejects new work, wakes waiters with `ErrClosed`,
and waits for active operations to release capacity. A deadline may expire while
a maintained primitive finishes; call Shutdown again to continue observing the
same drain. Shutdown is idempotent.

Use `password.WithAdmission` to share a controller across services and
`passwordservice.Lifecycle` from `adapters/service` to expose `Start`/`Stop`
hooks to a caller-owned service runtime. Start cannot reopen a closed
controller.

Concurrent login upgrades must use database compare-and-swap. Admission protects
process resources; it does not serialize database writers or replace a CAS.

Continue with [API and error semantics](api.md).
