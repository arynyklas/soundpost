# @soundpost/bun

Copyright 2026 Aryn Yklas. Apache-2.0.

Policy-first local capture with native error branding through Bun's own `node:util.types` compatibility implementation. Explicit `installHooks(client)` returns a bounded owned lease whose capability reports `fatalMonitor: false`, `reason: "bun_fatal_monitor_unavailable"`. It installs no fatal/rejection listeners: Node monitor registration alone is not Bun qualification, and a consuming listener would change application behavior. `useEpisode` rejects with that limitation rather than pretending to arm fatal monitoring. Close is idempotent; client close releases its own leases.

Safe manual cause/group extraction is implemented; original JS frames report `safe_original_stack_unavailable`. See ../core/README.md for graph/episode/privacy boundaries. Bun1.3.14 actual child-process on/off qualification remains parent-owned and independent from Node. Native HTTPS flush/durable-receipt validation and historical-lookup-first recovery are implemented; this is not kill-proof fatal delivery, replay, profiling or full original/source-mapped stack support.

Config requires real registered typed resources and a bound fixed64 descriptor (or constructs that public descriptor from its verified policy/Config). `flush(timeoutMs=2000)` uses HTTPS with private bearer authentication, no cookies/redirects and TLS verification on. AsyncLocalStorage isolates exporter suppression; close releases its context, transport and hook leases without changing Bun's default fatal behavior.

No disk queue is enabled by default. Explicit `openEncryptedSpool(path, protected32ByteKey, descriptor, policyRevision, maxBytes?)` uses the same capped AES-GCM/atomic backend and conservative exclusive process lease as Node, but Bun must execute its own qualification. Close retains encrypted pending state and releases leases. Filesystem/power-loss qualifications are not inferred from process restart tests.

## Independent Bun critical-path adapters

`installServe(client,{operation:"request"}).handler(handler)` wraps an actual Bun.serve fetch handler. It preserves application exceptions/status/headers and observes streaming pull, close and cancellation without collecting body bytes. It forwards cancellation to the original reader; unsupported upgrade/opaque/locked-body lifetimes remain explicitly incomplete. `installHttp` is separately implemented for Bun's Node HTTP compatibility boundary, not evidence inherited from Node.

`installFetch(client,{operation:"http.call",origins:[{origin:"https://dependency.example",dependency:"dependency"}]})` returns an explicit fetch wrapper, never a global patch. It observes through response headers and returns the original Response, with application streaming/cancel/rejection outcomes preserved. Propagation goes only to exact registered origins; SQL, URLs, queries, headers and bodies never become telemetry fields. Opaque/accessor request options are not inspected or attributed. `installPg(client,{operation:"db.execute",dependency:"postgres"}).query(poolOrClient,sql,values?,callback?)` supports real pg8 promise/callback calls; unsupported cursor lifetimes are incomplete.

This package's own per-client AsyncLocalStorage and hrtime.bigint trace-clock adapter is distinct from both Node's adapter and exporter-recursion suppression. Workers receive only `serializeWorkerContext(context)` causal envelopes and use `withWorkerContext(theirOwnClient,envelope,callback)`; worker credentials/configuration are independent. Closing the client owns idempotent integration teardown and unfinished spans. Signed trace permission/default100% tracing and errors remain independent; explicit budgets declare probability/loss.

Parent-run gates: `bun test packages/bun/test/integrations.test.ts` and a real `bun fixtures/sdk/bun/critical-path.ts` process, both exactly Bun1.3.14 with PostgreSQL16 and the independently authorized real HTTPS source/dependency/verifier. `bun fixtures/sdk/bun/gateway.ts --dependency-env SOUNDPOST_FIXTURE_DEPENDENCY_URL` is a real outbound gateway: its selected authorized dependency must actually respond, and no canned model result qualifies. Gateway logs identify only the safe dependency alias and explicit internal dependency unobserved. Node passes never qualify Bun.

## Manual job attempts

`Config.jobRegistry` copies a finite safe alias→canonical nonzero JobID registry. `withJobAttempt(alias, runId, positiveSafeIntegerOrdinal, async () => result)` preserves application outcomes while emitting policy-gated native `started` and terminal events through the existing durable-receipt-aware queue. This runtime owns its separate AsyncLocalStorage job scope; concurrent run links are never borrowed from another client or from Node qualification. Failed-body sanitized errors remain independent of trace sampling. Intrinsic DOMException AbortError is cancellation, not success.

`manual.<runID>` is explicitly unscheduled, with no SDK cron/current-health calculation or invented external-observer health. Parent-run gates are `bun test packages/bun/test/jobs.test.ts` and the real `bun fixtures/sdk/bun/job-attempts.ts` C03/C05 journey on the exact approved Bun build. No runtime pass is inferred from authored tests.

## Bun HTTP client lifecycle boundary

Bun1.3.14 can emit `ClientRequest.close` at response headers, before its `IncomingMessage` body ends, and its transport rejection need not emit a request close. The owned HTTP adapter therefore observes actual response end/abort/close and non-consuming request/response errorMonitor events; it does not manufacture close events or consume application errors. Its prepended observer preserves native auto-discard when no application response consumer exists and never buffers response bytes.

Run `bun fixtures/sdk/bun/http-lifecycle.ts` in the actual pinned process, independently of compiled Node22/24 lifecycle fixtures. The real HTTP gate covers streaming completion, callback behavior, native no-consumer discard, socket-reset ownership and cancellation; no timeout increase or inferred Node support substitutes for that evidence.

## Worker-local fixture termination

Do not assert the browser-only `globalThis.close()` API exists in Bun. Parent's actual Bun1.3.14 win32/x64 four-cell no-SDK probe found it undefined: scope-close crashed with HTTPS both off/on, while the documented worker-local `process.exit(0)` completed with worker exit0 in both controls. These diagnostic controls are not full SDK qualification.

The real critical-path worker now sends its actual safe record/receipt reply, awaits its real client.close, and then exits its own worker with `process.exit(0)`—never the main process. The parent retains independent C05 readback and requires actual worker close code0; it does not repeatedly terminate a worker that already exited. No Worker, source-authority, causality or receipt assertion is skipped. Full `bun fixtures/sdk/bun/critical-path.ts` qualification requires the parent's changed-code real run; a diagnostic control or newer Bun version cannot replace that gate.

Parent subsequently executed the corrected full Bun1.3.14 fixture successfully on its exact Windows/x64 build: actual parent exit0, worker close0,9 admitted records/3 batches, verified TLS, independent worker/main C05 readback and completed cleanup. Retained evidence is `03.05-bun-critical-supported-worker-exit.txt` in the approved-product report workspace. This is evidence for that exact runtime/OS/build only—not another OS, Bun version or browser; the separate four-cell diagnostic is not its substitute.
