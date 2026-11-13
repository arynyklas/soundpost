# @soundpost/browser

Copyright 2026 Aryn Yklas. Apache-2.0.

Policy-first local capture plus explicit `installHooks(client, targetWindow?)`. Owned addEventListener callbacks observe actual global errors and unhandled rejections, reading only native ErrorEvent/PromiseRejectionEvent descriptors, never messages or event-provided getters. They do not assign `onerror`/`onunhandledrejection`, preventDefault, stop propagation, or change default reporting. Close removes only owned listeners and is idempotent; client close releases its own leases (maximum eight).

Native Error branding uses intrinsic Error.isError where available, else UnknownError/native_brand_unavailable. Original frames remain safe_original_stack_unavailable and unsafe aggregate containers retain their explicit limitation. `lease.useEpisode(episode, error, "uncaught_exception" | "unhandled_rejection")` binds weak object identity plus exact event source on this Window lease; an unrelated rejection cannot consume an error-event arm, nor can another thrown object. `clearEpisode(episode)` cancels pending association. Primitive rethrows reject arming rather than inventing identity. Browser fatal=False denotes reporting without process-termination evidence. The actual browser fixture tests real cross-source interleaving; exact approved browser matrix rows, source-mapped frames and replay remain separate unmet gates.

Native delivery implements `flush(timeoutMs=2000)` with bounded fixed64-partitioned batches, exact matching durable receipts and historical-lookup-first ambiguous recovery. Config requires the source's real registered resource IDs/instance and its signed policy. This entrypoint always selects `X-Soundpost-Source`, `credentials:omit`, no referrer and forbidden redirects; it never sends private bearer auth or ingestion cookies. The server must configure the exact permitted Origin and trusted HTTPS certificate; the SDK does not create wildcard CORS or bypass TLS.

Browser disk spools are prohibited, including injected backend spools. Keepalive/beacon acceptance without reading a matching receipt is unacknowledged, never durable/indexed/rule-processed. Browser fatal callbacks still do not wait for delivery or prevent default handling. Close flushes within its deadline, releases only owned hooks/requests, then counts remaining nondisk work as loss. Exact browser transport/runtime qualification remains parent-run, not inferred from Bun/Node fixtures.

## Explicit browser causality

`withSpan` implements native C04 elapsed spans with registered operation/dependency aliases. A browser has no qualified implicit async-local scope: `traceContext()` is valid only during synchronous callback invocation. Save the closed context before await and pass it explicitly to the next adapter; otherwise the new operation is a root, not guessed causality.

`installNavigation(client,{operations:["navigation"]}).navigate("navigation", async context => { ... })` measures the caller's actual router/navigation commit promise. Its callback receives an explicit context to pass across async boundaries. It reads neither location/history values nor DOM content. This is elapsed navigation timing, not Long Task CPU profiling or inferred page-load internals.

`installFetch(client,{operation:"http.call",origins:[{origin:"https://api.example",dependency:"dependency"}]}).fetch(input,init?,parent?)` accepts that explicit parent as its third argument. Without one it starts a root. It adds W3C/closed companion propagation only for exact registered origins, removes baggage/foreign trace headers for ordinary data-only options, and returns the original Response without reading its body. It never patches global fetch. Opaque/accessor init values are delegated without inspection or invented attribution. Failed/CORS-denied foreign requests are honest missing external internals.

Workers receive only closed `serializeWorkerContext(context)` envelopes, never a serialized application message or source/project/credential. Initialize the worker independently, then use `withWorkerContext(workerClient,envelope,callback)`. Parent causality never authorizes another tenant or relabels local clock stamps. Closing integrations is idempotent, single-install is enforced per client, and unfinished navigation/streams remain incomplete.

Actual browser→Express→HTTP dependency→PostgreSQL fixtures live under `fixtures/sdk/browser/`. Parent builds app/worker separately and serves an independently configured public browser source; no private/read credential enters a bundle or worker message. The driver asserts actual browser build IDs and verifies admitted native records with an independent server-side read credential. Target rows are Chrome142.0.7444.59, Edge142.0.3595.53, Firefox144.0.2 and real Safari26.0.1. Playwright WebKit is not Safari evidence; absent macOS/Safari remains unqualified, not a skipped success. No browser support row is claimed by the authored fixtures alone.

## Manual job attempts and honest async boundaries

`Config.jobRegistry` registers at most1024 safe aliases→canonical nonzero JobIDs. `withJobAttempt(alias, runId, positiveSafeIntegerOrdinal, async () => result)` emits native manual attempt observations and preserves return/rejection/cancellation identity. Signed jobs permission and deployment narrowing are independent of error/trace admission; argument/result/message values are never serialized.

Browser job context is real synchronous dynamic extent only. Direct `captureException` before the first await can link its run; arbitrary post-await application captures have no guessed ambient run. The wrapper explicitly rebinds its own failure/terminal scope after await, preserving correct run links for overlapping jobs without a process-global current job or invented browser async-local support. Intrinsic DOMException AbortError is cancelled. `manual.<runID>` is unscheduled/unknown-observer evidence, not current cron health, and optional links never prove target availability.

Parent-run boundary tests: `bun test packages/browser/test/jobs.test.ts`. Actual browser/C03/C05 qualification uses separately built `fixtures/sdk/browser/job-attempts.ts`, its HTML entry and `job-attempts.spec.ts` with a write-only browser source and independent server-side reader. Exact browser builds remain separately qualified; Playwright WebKit is not real Safari evidence.

## Replay recorder

`createRecorder(config, emit)` records only an owned, masked structure: ids, the server's closed tag enum and the constant `"[masked]"` text mask. Text content, input values, attributes, ids, classes, CSS, layout, pseudo-content, canvas/media pixels, clipboard, console and key events are never read. Frames, editable regions, textarea/select and media are one opaque node. `ReplayStream` is the bounded `AsyncIterable<ReplayChunk>` shared with the renderer. Closed shadow roots are not observable by page script: their content is simply unreachable, and the recorder cannot mark the host opaque (an optional `dom.closedShadow` hook exists for platforms that can detect it).

`client.startReplay(config, tap?)` plus `client.setReplayConsent(enabled)` is the delivery path: every chunk the recorder emits is enqueued by the client itself on its ordinary queue (closed wire validation, batching, retry, receipts; `deploymentReplay: true` and a source policy with replay on are both required), so a chunk the queue refuses is the recorder's counted loss, healed by a gap-marked checkpoint. `tap` is an optional local consumer (for example a `ReplayStream` feeding a viewer) that sees every chunk; its failure never affects delivery. Revoking consent stops capture at once and destroys this client's replay chunks that are queued but not yet part of a batch; acknowledged chunks are not recalled and a resumed recording starts with a gap-marked checkpoint.

Parent-run checks: `bun test packages/browser packages/replay-viewer packages/core`; real browser: `playwright test -c fixtures/sdk/replay/playwright.config.ts --project=chromium --grep "pre-buffer canaries|consent revocation"` (`SOUNDPOST_BUN` = bun binary used to bundle the recorder, `SOUNDPOST_CHROME` = optional Chrome executable).

### Replay chain hash, one chunk per emission (cross-language contract)

Each chunk's `previous_hash`/`checkpoint_hash` is SHA-256 over `canonicalJSON(chunk)` (`src/replay/policy.ts`): sorted keys, no whitespace, integers only, exactly what Go's `replays.ChunkHash` computes, so the server verifies the chain whatever order the wire object serializes in. `fixtures/sdk/replay/chain-vectors.json` (generated by the real Go validator) is asserted by both this recorder and `packages/replay-viewer`.

One emission is exactly one chunk (at most 4096 nodes and 120,000 own-accounted bytes, under the 128 KiB protocol cap). When a snapshot or mutation subtree does not fit, `fitSubtrees` replaces whole low-priority subtrees (later in document order and deeper first, smallest first) with opaque placeholders (same id and parent, tag and class `masked`, empty text) until it fits, counts the loss, adds a `gap` event (a truncated checkpoint is also gap-marked) and suppresses deltas under the replaced ids until the next complete checkpoint. There is no fragmented-checkpoint format. A flat run of thousands of siblings can only shrink by collapsing their parent.

### Wire schema (decision D2: the server's closed schema is the contract)

The recorder emits exactly `model.ReplayChunk` of the server and nothing else; the server allowlist (`internal/replays` `ValidateChunk` after `model.StrictJSON`, and the ingest replay gate) stays closed and was not widened for it. A node is exactly `id parent tag class text`: `tag` is one of `div span p button input section canvas masked` (every other element, SVG and custom elements included, is the generic structural tag `masked`), `class` is empty or `masked` (opaque subtree), `text` is empty or exactly `[masked]`. There is no geometry, presentation, style or attribute field; the recorder does not read layout or computed style at all. An event is `at_ns kind node x y`; `at_ns` is the monotonic reading of the chunk's clock (the server's `MonoNano`), and pointer/scroll/resize coordinates are quantized to 8 CSS px and clamped to ±32768. Node ids are per chunk and restart at every checkpoint (the server admits at most 2^31). `replayId`, `sessionId` and the clock domain are 32 lowercase hex digits (not zero) and `capturePolicyRevision` is a decimal revision; `createRecorder` throws on anything else.

A replay has a server-side budget of 65536 chunks and 1024 checkpoints. The recorder ends capture for good when the next chunk would exceed either, rather than emit a chunk the server would refuse (a refused chunk would fail its whole ingest batch).

Cross-language contract tests: `packages/browser/test/replay-wire.test.ts` drives the real recorder over a scripted page and asserts the closed schema, masking (no canary text, value, class or id in any chunk) and that the committed golden chunks `fixtures/replays/recorder/{session,recovery}` are byte-identical to what the recorder emits now (regenerate after an intentional change with `SOUNDPOST_UPDATE_RECORDER_FIXTURES=1 bun test packages/browser/test/replay-wire.test.ts`). `fixtures/replays/recorder/recorder_test.go` decodes those same chunks with the Go strict decoder, validates them with `replays.ValidateChunk`, checks that Go's `ChunkHash` equals the hash chain computed in the browser, and shows the schema stayed closed against the former recorder shapes; `internal/replays/recorder_chain_test.go` admits them through the production path and reads the stored chain (continuous, a lost chunk as a gap, a refused chunk healed by a gap-marked checkpoint). The evidence smoke row `replay_real_recorder_chunks` and the journeys row `replay_masked_interaction_real_recorder` run the same chunks and a real Chrome recording against a real `soundpost serve`.

## Browser JS Self-Profiling (optional, off by default)

```ts
import {startProfile} from "@soundpost/browser";
const handle = await startProfile({durationMs: 5000, intervalUs: 10_000, scope: "main", longTasks: true});
// ...application work...
const report = await handle.stop(); // idempotent, bounded, never rejects
```

`startProfile` wraps the W3C JS Self-Profiling `Profiler` (method `browser_js_self_profile`, signal `profile_chunk`) and never throws into the application: every expected failure is a report with a capability `status` + `reason`, empty `frames/stacks/samples`, `sample_count: 0` and `stopped_by: "not_started"`. Detection is by actually constructing the API, never by browser version:

| Situation | status | reason |
| --- | --- | --- |
| `Profiler` is not a constructor (Firefox, Safari, old Chromium, Chrome workers) | `unsupported` | `js_self_profiling_unavailable` |
| constructor throws `NotAllowedError` (what Chrome 156 throws, "JS profiling is disabled by Document Policy") or `NotSupportedError` | `denied` | `document_policy_missing` |
| any other `DOMException` (`SecurityError`, ...) | `denied` | `permission_denied` |
| any other constructor failure | `error` | `sampler_failed` |
| a second start while one is running (one lease per global, held under `Symbol.for("soundpost.profile.lease.browser_js_self_profile")`, so duplicate module copies conflict) | `denied` | `profiler_owned` |
| declared `scope` differs from the real global (Window vs WorkerGlobalScope) | `denied` | `isolate_scope_mismatch` |
| invalid options (`durationMs` integer 1..60000, `intervalUs` 1000..1,000,000, `maxSamples` 1..8192, `origin` an http(s) origin) | `denied` | `invalid_options` |
| `Profiler.stop()` does not settle within 5 s | `error` | `stop_timeout` (no samples, `timeout_cleanup` loss) |

The page must be served with `Document-Policy: js-profiling` (an HTTP response header on the document; the browser fixture proves Chrome refuses without it). A profile only covers the calling global: `coverage` is `{frames: partial, threads: partial, workers: none, tasks: none}` (JS frames only; native frames and cross-origin scripts without CORS are anonymized by the browser), and a worker needs its own start (Chrome 156 does not expose `Profiler` in dedicated workers at all, which is reported as `unsupported` with `scope.isolate: "worker"`).

Privacy: frames are `{module_id, function, artifact_id, line, column, offset: "0", reason}` code identities only. A script becomes its origin-relative path (`assets/app.js`) only when it is on `origin` (default: the global's own origin) with no query, fragment, user info or unsafe path characters; everything else (other origins, query/fragment URLs, the document itself, native frames) collapses to one `external` placeholder frame (consecutive duplicates removed). Function names must match a conservative identifier regex, otherwise the function is empty with `reason: "not_captured"`. Stacks are leaf-first (`stack_order: "leaf_first"`, at most 128 frames, root-most frames cut, counted in `scope.stack_depth_truncated_samples` and `truncated`), at most 4096 frames/stacks and `maxSamples` (<= 8192) samples; the passed `origin` is never copied into the report. Samples without a stack are engine idle: they are counted in `scope.idle_samples`, never invented as frames. Script-path secrets that are part of the path itself (e.g. `/u/12345/app.js`) cannot be detected and are kept.

Honest timing: `interval.requested_us` is what you asked for; `interval.achieved_us` is the median gap of the returned sample timestamps and `scope.granted_interval_us` is the `sampleInterval` the browser says it granted (Chrome 156 granted 10 ms for a 5 ms request in the fixture). Timestamps are `DOMHighResTimeStamp` milliseconds since the time origin; `samples[].at_us` are decimal-string offsets from the first sample and nothing is converted to wall time (`clock.uncertainty_ns` is the uncalibrated maximum). A `sample_gap` loss is reported for gaps over twice the effective interval (count = estimated missing samples) and whenever the document was hidden or its visibility changed during the run (background throttling; `scope.visibility`). A full browser buffer (`samplebufferfull`) or samples dropped at the caps is `truncated` with a lower-bound `truncated` loss count. Units are `samples`; no CPU unit exists anywhere in the report. `longTasks: true` adds `long_task` entries (`duration_ms`, `start_ms` relative to the profile start, nothing else, at most 256, overflow in `scope.long_tasks_dropped`) as separate `non_profile` metric entries, never inside the samples.

`createProfiler(env)` in `src/profile.ts` is the test seam (fake `Profiler`/`PerformanceObserver`/clock/timers); `startProfile` reads the real globals when it is called. Importing the module has no side effects and imports no replay code, so core capture/replay is unaffected where profiling is unsupported.

Checks: `bun test packages/browser/test/profile.test.ts` (fakes only); real Chrome: `playwright test -c fixtures/sdk/profiles/playwright.config.ts --project=chromium` (`SOUNDPOST_BUN` bundles `src/profile.ts`, `SOUNDPOST_CHROME` optional executable); the spec prints one `SOUNDPOST_PROFILE_EVIDENCE {...}` JSON line. Not qualified: Firefox, Safari, Edge, Chrome 142, Windows/macOS Chrome, headed runs.

### Delivering a profile (`client.startProfile`)

The module-level `startProfile` above returns a local report and sends nothing. To deliver, start the run on a client:

```ts
const client = init({...config, deploymentProfiles: true});
const handle = await client.startProfile({durationMs: 5000, scope: "main"});
// ...
await handle.stop();   // the finished report is already queued; client.flush() sends it
```

The finished report (a refusal at start, a caller `stop()`, the duration timer or the stop timeout; exactly once per run) goes through the client's ordinary queue and transport: same batching, retry, durable-receipt ACK and loss counters as errors and spans. There is no second transport. `client.submitProfile(report)` does the same for a report you already hold (`createProfiler(env, report => client.submitProfile(report))` is the test seam).

What is sent, by `src/profile_wire.ts`:

| Report | Wire |
| --- | --- |
| any run (supported, `denied`, `unsupported`, `error`) | one `capability` record: `runtime/version/build/os/arch`, `signal: profile_chunk`, `method: browser_js_self_profile`, `status`, `reason`, `coverage`, `clock_domain`, `expires_ns`. Its record id is the capability id the chunks name. |
| `status: supported` only | one or more `profile_chunk` records: `profile_id`, a per-client `process_id`, `capability_id`, `method: runtime_cpu` (the server's closed method vocabulary has no browser value), `units: samples`, the same clock domain, frames `{module_id, function, artifact_id, offset, reason}` (no line/column: the closed server frame has none), stacks, samples `{at_ns, stack, count: "1", thread}` and `loss`/`truncated` from the report's losses. |

A refused or failed run is therefore the capability truth record alone: no chunk, no samples, never a fabricated profile. Sample times are offsets from the first sample (`at_ns = at_us * 1000`, `clock.mono_ns = "0"`, `clock.wall_ns = wall_start_ns`) with the report's maximal `uncertainty_ns`: no wall alignment is claimed. Threads map `main -> "1"`, `worker -> "2"`. A profile too large for one record (the queue refuses records over 262,144 bytes) is split into several chunks with the same `profile_id`, each with its own frame/stack tables; the loss count and `truncated` ride on the first chunk only. Long-task entries are not sent (they are metrics, not samples).

Privacy is the report's: origin-relative script paths without query/fragment, conservative-regex function names or `external`, nothing else. `test/profile-delivery.test.ts` proves with canaries that a query string, a fragment, a foreign origin, an argument-bearing function name and extra trace fields (`arguments`, `locals`, `source`) never reach the serialized batch.

**Policy.** Delivery is off unless `deploymentProfiles: true` (`client.policyDecision.profiles`). There is no signed-policy flag for profiles: the server enforces the source policy's `kinds`, and a record whose kind is not listed makes the whole batch fail with 403, which stops the client's delivery. Enable `deploymentProfiles` only for a source whose policy lists both `profile_chunk` and `capability`. With the flag off nothing is enqueued and the drop is counted (`diagnostics().policy_disabled`, `profile_chunk_dropped`). Failures are counted, never thrown: `invalid_profile_record`, `profile_wire_failed`, `queue_full`, `record_too_large`, `closed`. A run still active when the client closes is delivered into a closed client and counted as `closed`.

Checks: `bun test packages/browser/test/profile-delivery.test.ts`; the real-process proof is the `journeys` smoke row `profile_linkage_with_capability_truth`.
