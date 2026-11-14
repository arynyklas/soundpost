<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Soundpost replay evidence v1

Copyright 2026 Aryn Yklas. Apache-2.0.

This document is the server side of the owned masked replay protocol: what the backend accepts, stores and reconstructs. The recorder (packages/browser) and the inert renderer own capture and display. **This validator cannot certify the SDK pre-buffer masking by itself.** Masking happens before any buffering in the recorder; the server only re-checks, as defense in depth, that what reaches it is inside a closed format with no channel for raw page content. A recorder that masks wrongly but stays inside the format is not detectable here, and the server never "repairs" or scrubs a raw node later: retaining a raw node until a server scrub is not permitted. Anything outside the format is refused before it is stored.

## Chunk format

A chunk is one `replay_chunk` record (model.ReplayChunk), at most 128 KiB of canonical JSON, with a closed field set. Unknown or duplicate fields are rejected (`invalid`); there is no field for HTML, text content, attributes, CSS, URLs, canvas pixels, or request or response bodies, so none can be stored.

| field | rule |
| --- | --- |
| `replay_id`, `session_id` | non-zero IDs; the replay root is `(project, replay_id)` bound to one session |
| `recorder_version` | exactly a supported version (`"1"`); anything else is `unsupported` at admission |
| `sequence` | decimal string, 1 to 65536 |
| `previous_hash` | zero for sequence 1, otherwise the hash of the previous chunk |
| `checkpoint_sequence`, `checkpoint_hash` | a checkpoint has `checkpoint_sequence == sequence` and `checkpoint_hash == previous_hash`; a delta names an earlier checkpoint and its non-zero hash; sequence 1 is a checkpoint |
| `clock` | non-zero wall time and a non-zero host/boot/runtime domain |
| `nodes` | at most 4096; `id` 1 to 2^31 and unique in the chunk, `parent` not itself, `tag` one of `div span p button input section canvas masked`, `class` empty or `masked`, `text` empty or exactly `[masked]` |
| `events` | at most 4096; `kind` one of `pointer scroll resize mutation checkpoint gap`; coordinates within 2^24 |
| `loss`, `gap` | cumulative drop counter; `gap` marks a recorder-declared hole before or in this chunk |
| `capture_policy_revision` | non-zero and equal to the source policy revision (enforced by admission) |

The chunk hash is SHA-256 over the canonical JSON of the whole chunk (sorted keys, no insignificant whitespace, decimal-string integers). The recorder and the server must agree on this serialization: a recorder that hashes a different byte form produces a chain the server reports as `hash_mismatch` gaps, never as continuity.

### The browser recorder emits this schema

The closed format above is the contract and the only one: the browser recorder (`packages/browser/src/replay`) is built to emit exactly these fields and vocabularies, and the server never widens to fit it. A recorder node is `id parent tag class text` with no geometry, presentation or style; an element outside the tag list is the generic tag `masked`; an event's `at_ns` is the chunk clock's monotonic reading; node ids restart at every checkpoint; and the recorder stops at the sequence and checkpoint ceilings below instead of sending a chunk the server would refuse. Masking therefore holds on both sides: no raw text, input value, attribute or class is ever read in the browser, and nothing outside the allowlist can be admitted by the server.

The two sides are held together by golden chunks emitted by the real recorder (`fixtures/replays/recorder`). The recorder's test regenerates them and fails if they drift; the Go tests decode them strictly, validate them with `ValidateChunk`, check that `ChunkHash` equals the chain the recorder computed in the browser, and admit them through the production path to read the stored chain. See `packages/browser/README.md` for the commands.

## Admission order

1. `Validate(grant, chunk)` (or `ValidateJSON(grant, raw)` for a wire chunk) before anything is durable, and before any quota is charged. The grant must be fresh. Failures are fixed `model.Fault` codes and never echo content. In a served process ingest installs `ValidateChunk` as its replay gate, so a chunk outside the closed format is refused `invalid`/`unsupported` and leaves no reservation and no record.
2. `CheckIndex(scope, project, chunk)` before the append. It reads the immutable index under the credential's own organization and project (nothing is widened, and a scope whose authority cannot be confirmed is told nothing) and refuses, as typed `conflict` (or `too_large` for a full index), a chunk that RecordScope would refuse: a different chunk at a recorded checkpoint sequence, or a foreign session for the replay root. Such a chunk is not stored at all. A batch that contradicts itself (two sessions for one replay, two different checkpoints at one sequence) is refused the same way before any chunk of it is stored. Only the first chunk of each replay in a batch (its root session) and every checkpoint are asked of the index.
3. Durable append through the normal admission path.
4. `RecordScope(scope, project, chunk, retainUntil)` (`Record(grant, …)` for a caller that holds a source grant) adds a checkpoint to the immutable index and extends the group retention deadline. `retainUntil` is the replay deadline of the batch receipt, whether the receipt is fresh or the original receipt of a retried batch.

`appcore.NewReplayIndexingAppender` is steps 2 to 4 as a decorator of the durable appender, so ingest consumes the index step through the `Appender` it already has and the agent and conformance binaries that link ingest still do not link the replay reader. A batch with no replay record passes straight through and the index is never read for it. The decorator logs nothing and every error it returns is a bare typed fault.

### What the sender sees

- **No acknowledgement before the index step.** A failed `CheckIndex` or `RecordScope` returns its typed fault and drops the receipt. Unavailable, corrupt, timeout, stale and cancelled map to the retryable 503. The batch may already be durable (a failure after step 3), exactly as for a failed finalize: its reservation stays charged and the sender retries the SAME batch (same id, same bytes). The retry meets the original receipt at step 3 (the append is idempotent: same cursor, nothing appended twice), runs step 4 again (idempotent: the index is written once), and only then is acknowledged. A process that dies between steps 3 and 4 is repaired the same way.
- **A conflict that raced past step 2.** Two chunks at one checkpoint sequence that both passed step 2 are both stored; the index pins whichever `RecordScope` sees first. The other sender gets the typed, terminal 409 `conflict`, never a receipt. Its row is stored but unpinned: the reader settles competing chunks only by the pinned hash, so the stored row neither replaces the pinned checkpoint nor makes the replay look discontinuous, and a retry of that batch is refused by step 2 before anything more is stored. No acknowledged row is lost, because none was acknowledged. The pin goes to the first chunk RECORDED, not the first stored.
- **A retried batch whose replay deadline has passed** gets its original receipt without an index step: its chunks are due for erasure and there is nothing to protect.
- **Receipt lookup pins the checkpoint it answers for.** `POST /ingest/v1/receipts` returns the stored receipt of a batch. Before it answers for a batch that carries replay records and whose replay deadline has not passed, the lookup reads the batch's chunks back from the stored command the receipt's cursor names and runs step 4 (`RecordScope`, the same idempotent write with the receipt's replay deadline) for them. A sender that lost the acknowledgement between steps 3 and 4 and asks for the receipt instead of resending therefore leaves its checkpoint pinned, never merely stored. The step fails like admission does: an unavailable index is the retryable 503 and a checkpoint that lost the race to a competing chunk is the terminal 409 `conflict`, in both cases instead of the receipt. A batch whose bytes were erased or redacted yields no chunks and the lookup answers as before; a repeated lookup writes nothing.
- **A refusal at step 2 or 4 comes after the quota reservation** (the gate of step 1 does not). The reservation stays charged like any other refusal after reservation; a retry of the same batch id reuses it and does not charge twice.

## Index and retention groups

For each replay the control state holds an append-only checkpoint index (at most 1024 checkpoints) sealed by a digest and pinned per project by `(seq, head)`. An index that was edited, rolled back or partly removed is `corrupt` on read. A second, different chunk at a recorded checkpoint sequence, or a chunk of another session claiming the root, is a `conflict` and changes nothing. Removing both the index and its pin removes the tamper evidence but not chain verification.

A replay lives and dies with its root: `LatestReference` (the retention References interface) answers the latest chunk deadline of the whole group for every chunk, so the expiry pass never erases a checkpoint or chunk while any later chunk is retained. The group deadline may trail the newest chunk's by up to one minute (control writes are coalesced); no chunk is erased before its own deadline. An entity, range or retire deletion takes precedence: a covered chunk answers zero. An index is forgotten 24 hours after its group deadline.

Every control write is a replicated entry that rewrites the whole control state and spends a control revision, the compare-and-set token of admin commands. `RecordScope` therefore reads the index first and writes only when the index or the pin would change: re-recording a checkpoint, a delta inside the one-minute slack or an older deadline writes nothing, which is what keeps a retried batch and a stream of deltas from churning the control revision.

## Reading

`Read(ctx, scope, replay_id, window)` returns a stream of `checkpoint`, `delta`, `gap`, `unsupported`, `revoke` and `error` events with sequence, hash, previous hash, checkpoint reference, policy revision, clock and loss. Only a `Read` scope reads; a caller that is not authorized, whose projects do not contain the replay, or for whom it does not exist or was deleted gets the identical `not_found`. A replay ID present in more than one of the caller's projects is `not_found`.

Continuity is proven, never assumed. The reader walks sequences in order and releases a delta only when the chain since a verified checkpoint is unbroken: the previous hash equals the previous released chunk's hash and the named checkpoint is the current one. Otherwise the sequence becomes part of a `gap` event (`missing_chunk`, `hash_mismatch`, `dependency_mismatch`, `recorder_gap`, `conflicting_chunk`, `invalid_chunk`, `index_mismatch`, `no_checkpoint`) that lasts until the next accepted checkpoint. A chunk staged ahead of a missing one is kept (and becomes part of the gap), so the replay can heal if the missing chunk arrives, but it can never make the replay look continuous. A checkpoint that contradicts a present predecessor is not a recovery point. A stored chunk of an unsupported recorder version, or one that no longer passes the closed format, is never rendered.

A window starting on a delta snaps back to its checkpoint and releases every verified step since.

## Release fencing

Before every released event (and again after its body was fetched) the stream revalidates the scope (current grants, visibility fingerprint, epoch), the org delete generation and any covering deletion. A denial ends the stream with a typed `revoke` (`authority_revoked` or `deleted`) before any further byte, drops buffered bodies and stops reading storage. An unreachable authority is an `error` event, not a revocation. A chunk whose stored bytes no longer hash to the verified plan is an `error` (`corrupt`), not a release. At most 8 chunk bodies are buffered.

## What this does not cover

- SDK pre-buffer masking, consent and opt-out (packages/browser).
- Rendering and the investigation UI (the console has `web/src/replays/`, which reads the route below; this package defines none of it). The read route is `POST /api/v1/replays/stream` (`internal/httpapi/replay_view.go`, mounted in `appcore`); it streams NDJSON of this package's events. No running recorder feeds it: the SDK does not enqueue replay chunks (`docs/acceptance/reference-journeys.md`).
- Covert channels inside the closed numeric fields (coordinates, node IDs).
- Cross-language hash agreement is a contract between the recorder and `ChunkHash`; this package only defines the server side.
