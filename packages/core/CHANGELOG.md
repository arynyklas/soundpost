# Changelog

## Unreleased

- Server capture cost (lane 4 wave 27): a root span draws its trace and span IDs with one entropy draw and one hex encoding, the queue reads the three IDs of a queued span back with one hex call (was two or three), and a batch draws its ID when its first record is selected (a slot's last batch no longer draws one it never uses): hex encodings per exported span 5 -> 3 plus one per batch instead of two (`test/hex-batching.test.ts`). Wire bytes, routing, privacy and limits unchanged; no effect measurable in process (hot cost per span 1.5 + 5.7 us on Node, 1.5 + 7.3 us on Bun, before and after).

- Server capture cost (lane 4 wave 25): acknowledging a batch skips the scan of the queue's entries when no loss bucket exists, and removing a batch splices the batch list instead of filtering it a second time; a lean span's payload is composed from per-vocabulary fragments and its start-wall text is built once (JavaScriptCore string cells per queued span 33 -> 24 for the payload). Wire bytes unchanged.

- Server capture cost (lane 4 wave 23): a captured error is serialized once (the client's canonical text is the stored form and the batch form is that text with the resource spliced in: `DeliveryQueue.enqueueNative`; a record whose parse removed an empty optional field takes the old path). Wire bytes, routing, privacy and limits unchanged.

- Server capture cost (lane 4 wave 22, collector pressure): a queued span is a slot in a compact typed-array store (`lean_slab.ts`) instead of nine heap objects (about 500 bytes -> one queue entry), trace contexts are recognised by a private brand instead of a WeakSet entry per span, the in-flight lean spans are a linked list instead of a Set, the route slot is read from a hex digest (no ArrayBuffer per span), the batch form of a span is built without its safe text, and the parsed frames of a stack seen again are found by the SHA-256 of the stack (the text is not kept). Wire bytes, routing, privacy and limits unchanged.

- Breaking (internal entries): `captureRuntimeProfile` moved off `Client` to the new `@soundpost/core/runtime` entry (`RuntimeClient`, `initRuntime`), and the encrypted-spool persistence/recovery moved off `DeliveryQueue` to `SpoolingDeliveryQueue` (`queue_spool.ts`, installed by `RuntimeClient` through the protected `Client.createDelivery`). The base `Client`/`DeliveryQueue` (what the browser uses, which prohibits a spool) refuse a spool instead of ignoring it. The Node and Bun clients extend `RuntimeClient`. Browser core bundle: 42,603 B -> 40,123 B gzip.

- `Client.captureRuntimeProfile(report)` admits a Node/Bun `runtime_engine_samples` report as a capability record plus linked, size-split `runtime_cpu` chunks (`runtimeProfileWire` in `profile_wire.ts`), with truncated samples recorded as a loss.

- Original JS exception frames (D7): descriptor-only, formatter-safe stack read with a bounded V8/JavaScriptCore/SpiderMonkey parser, `Config.artifactRoot`/`Config.artifactIds`, and the graph reasons `stack_formatter_hooked`, `stack_not_plain`, `stack_unparsed`.

## 0.1.0 — 2026-11-03

- Add installation-trusted signed policy admission and bounded immutable safe error/log capture.
- Keep unimplemented job/replay/profiling APIs unavailable; no support claims before qualification.
- Preserve explicitly registered log severity, enforce strict UTF-8 byte boundaries, and expose runtime types through an owned package export.
- Add bounded privacy-safe exception graphs, explicit handling episodes and per-client hook lease ownership; keep original JS frame limitations explicit.
- Omit nullish phantom causes; retain value-free non-Error cause nodes and visible aggregate overflow topology.
- Add bounded source/weak-object episode matching, cancellation and ambiguity rejection; unify C04 mechanism/edge enums.
- Enforce canonical nonzero opaque IDs, uint64 revisions and signed int64 UnixNano at SDK admission; reject bad injected clocks with safe counters instead of application exceptions.
- Add native resource/descriptor construction, fixed64 owner/native-JSON goldens, bounded ordered delivery, exact durable/historical receipt validation and real HTTPS flush/close.
- Add opt-in authenticated policy-bound backend spooling with frozen-identity restart recovery, capacity/corruption/lease failures and no browser/default disk queue.
- Preserve exact optional metric start timestamps and closed native-profile task/capability/loss metadata without raw addresses, false corrections or implicit capability success.
- Mirror separately signed traces/jobs permissions (absent false) with deployment narrowing.
- Implement native C04 withSpan and internal start/run/end lifecycle, independent error causal links, explicit sampling, bounded contexts and runtime-injected local exact clocks.
- Add independently signed loss permission and content-free span sampling/active-limit loss handoff; native queue export remains receipt-aware.
- Add real C09 `withJobAttempt`, finite immutable JobID registries, native closed C04 validation, exact epoch/sequence/ordinal/time, independent sanitized failed-job errors and honest manual/unknown-observer semantics.
- Distinguish actual Bun timer cancellation through a bounded runtime-issued direct brand, rejecting generic/non-abort/proxy/getter controls without reading inherited values; preserve Node's independent own-data path.
- Add `deploymentProfiles` / `PolicyDecision.profiles` (deployment-only, default off; no signed-policy flag) and `Client.captureProfile(capability, chunks)`: admits browser-built `capability`/`profile_chunk` records on the ordinary queue with counted drops (`policy_disabled`, `profile_chunk_dropped`, `invalid_profile_record`, `profile_wire_failed`).
- Add `Client.captureReplay(chunk)` and `Client.discardUnsentReplay()` for browser-recorded `replay_chunk` records: gated by the source policy's replay flag AND `deploymentReplay`, validated by the existing closed `replay_chunk` wire, never throwing (refusals are counted in `diagnostics()`); `DeliveryQueue.discardUnsent(kind)` destroys queued, not yet batched records of one kind.
- Cut per-span capture cost (11.17): a full queue now drops spans as `queue_full` in O(1) before any encoding, hashing or routing (same counters, policy and clock checks still first); queue expiry and the evictable-priority check no longer scan every queued record per admission; each record is canonicalized once into its stored and wire forms and batches reuse the wire form instead of re-parsing; canonical JSON, UTF-8 key order, uint64/UnixNano checks, ID generation (pooled CSPRNG bytes) and clock reads avoid per-call encoders, BigInt and array allocations; batch bodies hash with the runtime's native SHA-256 on Node/Bun; ed25519 base-point table window reduced from 8 to 4 bits (about 4 MB less heap and ~40 ms less first-use work; signature verification unchanged). No admission, privacy, policy or delivery rule changed.
