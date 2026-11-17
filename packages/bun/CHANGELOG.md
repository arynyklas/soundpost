# Changelog

## Unreleased

- `test/inspect-canary.test.ts` pins the `Bun.inspect` Response summary the D31 probe reads (first line `Response (N bytes | N.NN KB|MB|GB)` for a held body, `Response (0 KB)` for a null/empty/stream/touched/used body and `Response.error()`), one body kind at a time, and a second test proves the canary notices seven kinds of drift. A Bun release that changes the text now fails this file by name instead of silently changing which bodies installServe wraps. `bufferedSummary` is exported from `serve.ts` for it.

- One `AsyncLocalStorage` store per client for trace, job and exporter scopes (it was three), and `installServe` reads `request.headers` once and passes `Bun.inspect` one shared options object. The two native wrappers per request (`request.headers`, `request.signal`) and the `Bun.inspect` summary remain: reading either property is what D31 and the propagation header need, and no cheaper exact probe exists in Bun 1.3.14.

- `installServe`: a span that ends when the handler returns (a buffered `Response`, `undefined`, a thrown error) no longer registers an abort listener, three closures and an in-flight entry per request; only a span that outlives the return (an async handler, a streaming body) is held, ended `cancelled` on abort and `incomplete` when the lease closes, with its listener removed when it ends. D31 behaviour is unchanged and pinned over a body kind x state x init corpus (`test/serve-probe.test.ts`, `test/serve-lifecycle.test.ts`); the `Bun.inspect` summary stays the probe because no cheaper probe is exact in Bun 1.3.14.

- `startProfile({client})` now delivers the finished report through the client's queue (`captureRuntimeProfile`): a `capability` record (method `runtime_engine_samples`) and, only for a supported run, linked `profile_chunk` records (chunk method `runtime_cpu`, units `samples`; line/column are not sent). `report.ack` is `obtained` (flush cursors), `failed` or `not_available` (`profile_not_admitted` / `no_profile_admission_path`). Needs `deploymentProfiles: true` and a source policy that lists `profile_chunk` and `capability`.

## 0.1.0 — 2026-11-03

- Expose policy-first native error graph capture and explicit bounded leases.
- Report absent qualified Bun fatal monitoring without installing consuming handlers or changing default exit/rejection behavior.
- Install the non-consuming `uncaughtExceptionMonitor` on Bun 1.3.14 (probed: it fires for synchronous uncaught throws and never for unhandled promise rejections, and exit codes are unchanged); capabilities report `fatalMonitor: true`, `unhandledRejectionMonitor: false`, `reason: "bun_unhandled_rejection_monitor_unavailable"`, and `useEpisode` arms a handled episode like Node. Supersedes the line above.
- Align the explicit episode method signature and shared exception vocabulary; unsupported fatal association still rejects without changing runtime behavior.
- Add native HTTPS delivery/receipt-aware flush/close, own exporter context and explicit encrypted backend spool; keep independent Bun qualification and fatal-monitor limits.
- Add independent Bun AsyncLocalStorage/clock, Bun.serve streaming/cancel, HTTP/fetch/pg8 and explicit closed worker-context adapters.
- Add real Bun1.3.14 critical-path/worker/PostgreSQL fixtures and a real-dependency gateway without canned replies; retain independent qualification gates.
- Add manual job attempts through Bun's own async-local run context and a separately executable real C03/C05 journey, without inheriting Node qualification or inventing cron health.
- Correct HTTP client lifetime tracking for Bun's headers-time request close and error-without-close behavior; preserve body completion, native discard and non-consuming application error ownership.
- Remove the nonexistent ambient HeadersInit reference and add an independently executable Bun1.3.14 HTTP lifecycle regression gate.
- Correct the real Worker fixture's unsupported browser-close assumption using documented worker-local process.exit only after reply/client cleanup; require actual close code0 and avoid redundant termination. Four-cell diagnostic evidence is separate from full changed-fixture qualification.

## Unreleased — runtime supplement

- Add explicit `startProfile` / `ProfileHandle.stop` (C09) for Bun on its own: JavaScriptCore sampler through one in-process inspector session, `runtime_engine_samples` with engine time deltas (no CPU unit), unobserved idle/native gaps reported separately from samples, per-process profiler state handled (worker isolates refused `profiler_state_shared`, stolen state reported `profiler_state_lost`), bounded cleanup, code-identity-only frames, no ACK path yet. Real Bun 1.3.14 fixture `fixtures/sdk/profiles/bun.ts`.
