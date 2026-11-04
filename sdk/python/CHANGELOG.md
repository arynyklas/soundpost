# Changelog

## Unreleased — 03.04 authored, qualification pending

- Add client-owned token-restored trace context, strict traceparent-only propagation, sync/async C09 span scopes and closed native C04 span DTO admission.
- Add independent strict signed traces/jobs permissions (absent false), deployment intersections, trace-sampling loss and error trace/span links; retain policy-first durable delivery.
- Add explicit ASGI/WSGI streaming lifecycle, requests/httpx target-origin-safe calls, psycopg real execution, template-only logging and detached-by-default asyncio task/thread adapters with owned leases.
- Add real concurrent HTTP/PostgreSQL/cancellation/privacy fixtures plus context/protocol/policy/adapter behavior tests; worker did not execute them. Framework security blocks and runtime matrix remain explicit.
- Add optional strict signed loss permission and policy-gated native span/policy loss hook; require actual admitted loss count/source/producer/epoch in the real critical-path smoke instead of treating local sampling counters as native evidence.
- Use the configured wall-clock source consistently in span/event stamps; represent uncalibrated uncertainty as canonical uint64 maximum, with an explicit trusted calibrated-bound option and preserved local monotonic durations.
- Document bounded native-loss aggregation acceptance versus durable ACK, exact observed/acknowledged/pending/unexported counters and explicit recovery/expiry/close loss without potentially committed-count replay.
- Author actual Starlette/FastAPI/Flask route/stream/error/cancel-or-close adapter cases for parent-approved patched targets; preserve historical vulnerable rows as BLOCKED_SECURITY without claiming runtime qualification.
- Document03.05 manual job-attempt public scopes and finite alias→JobID registry: durable started/terminal observations, independent sanitized failed-body errors, explicit unscheduled semantics and no current-health/availability qualification claim.
- Add `test_transport_retry.py`: behavior tests against a real local TLS server (throwaway CA, verification on) proving 429/503 stay pending and are retried with the same frozen batch bytes/hash, Retry-After seconds/HTTP-date honored and clamped to 0.25–30 s, a later 200 receipt ACKs without re-freezing, and 401/403 are denied (no retry, export stops).
- Correct README: jobs (`client.job_attempt`) are implemented; replay, profiling and any Celery adapter are not. Document that error `code` is authorized by the signed source policy's independent error-code registry (`Codes`), not by span operations.

## 0.1.0 — 2026-11-03

- Add installation-trusted signed policy admission and bounded immutable safe error/log capture.
- Keep unimplemented instrumentation/replay APIs unavailable; no support claims before qualification.
- Reject boolean envelope versions, preserve explicitly registered log severity, and enforce strict UTF-8 byte boundaries.
- Pin cryptography 50.0.0 following primary advisory review; retain Apache-2.0 OR BSD-3-Clause dependency licensing and exact artifact evidence.
- Add intrinsic bounded cause/context/group graphs and project-relative traceback identities; explicit no-raw-identity episodes and conditional sys/threading/asyncio hook leases.
- Bind episode arms to weak Thread/source/loop/Task identities; require explicit same-source context opt-in for nonweak exceptions, and skip message-only asyncio occurrences.
- Freeze shared C04 mechanisms/edges and document observation-based fatality; preserve prior handlers and no-raw-error retention.
- Enforce canonical nonzero opaque IDs, uint64 revisions and signed int64 UnixNano at SDK admission; reject bad injected clocks with safe counters instead of application exceptions.
- Add real typed resources, all fixed64 owner keys/native-JSON goldens, bounded ordered HTTPS delivery and exact durable/historical receipt-aware flush/close.
- Add opt-in authenticated AES-GCM backend spool with policy-transition historical recovery, exclusive OS leases, capped atomic writes and explicit corruption/full-disk failures.
- Preserve exact optional metric start timestamps and approved closed native-profile metadata; retain frozen payload bytes once and expire/recover whole batches without identity mutation.
