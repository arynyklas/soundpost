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

## Admission order

1. `Validate(grant, chunk)` (or `ValidateJSON(grant, raw)` for a wire chunk) before anything is durable. The grant must be fresh. Failures are fixed `model.Fault` codes and never echo content.
2. Durable append through the normal admission path.
3. `Record(grant, project, chunk, retainUntil)` adds a checkpoint to the immutable index and extends the group retention deadline.

Wiring steps 1 and 3 into ingest admission is the integration owner's: the ingest package must consume `Validate` and `Record` through a narrow interface. Today admission applies only the model's own replay checks (closed node/event vocabulary), not the chain rules above.

## Index and retention groups

For each replay the control state holds an append-only checkpoint index (at most 1024 checkpoints) sealed by a digest and pinned per project by `(seq, head)`. An index that was edited, rolled back or partly removed is `corrupt` on read. A second, different chunk at a recorded checkpoint sequence, or a chunk of another session claiming the root, is a `conflict` and changes nothing. Removing both the index and its pin removes the tamper evidence but not chain verification.

A replay lives and dies with its root: `LatestReference` (the retention References interface) answers the latest chunk deadline of the whole group for every chunk, so the expiry pass never erases a checkpoint or chunk while any later chunk is retained. The group deadline may trail the newest chunk's by up to one minute (control writes are coalesced); no chunk is erased before its own deadline. An entity, range or retire deletion takes precedence: a covered chunk answers zero. An index is forgotten 24 hours after its group deadline.

## Reading

`Read(ctx, scope, replay_id, window)` returns a stream of `checkpoint`, `delta`, `gap`, `unsupported`, `revoke` and `error` events with sequence, hash, previous hash, checkpoint reference, policy revision, clock and loss. Only a `Read` scope reads; a caller that is not authorized, whose projects do not contain the replay, or for whom it does not exist or was deleted gets the identical `not_found`. A replay ID present in more than one of the caller's projects is `not_found`.

Continuity is proven, never assumed. The reader walks sequences in order and releases a delta only when the chain since a verified checkpoint is unbroken: the previous hash equals the previous released chunk's hash and the named checkpoint is the current one. Otherwise the sequence becomes part of a `gap` event (`missing_chunk`, `hash_mismatch`, `dependency_mismatch`, `recorder_gap`, `conflicting_chunk`, `invalid_chunk`, `index_mismatch`, `no_checkpoint`) that lasts until the next accepted checkpoint. A chunk staged ahead of a missing one is kept (and becomes part of the gap), so the replay can heal if the missing chunk arrives, but it can never make the replay look continuous. A checkpoint that contradicts a present predecessor is not a recovery point. A stored chunk of an unsupported recorder version, or one that no longer passes the closed format, is never rendered.

A window starting on a delta snaps back to its checkpoint and releases every verified step since.

## Release fencing

Before every released event (and again after its body was fetched) the stream revalidates the scope (current grants, visibility fingerprint, epoch), the org delete generation and any covering deletion. A denial ends the stream with a typed `revoke` (`authority_revoked` or `deleted`) before any further byte, drops buffered bodies and stops reading storage. An unreachable authority is an `error` event, not a revocation. A chunk whose stored bytes no longer hash to the verified plan is an `error` (`corrupt`), not a release. At most 8 chunk bodies are buffered.

## What this does not cover

- SDK pre-buffer masking, consent and opt-out (packages/browser).
- Rendering and the investigation UI. No HTTP route reads replays yet.
- Covert channels inside the closed numeric fields (coordinates, node IDs).
- Cross-language hash agreement is a contract between the recorder and `ChunkHash`; this package only defines the server side.
