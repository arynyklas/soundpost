<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Artifact, Symbolication and Replay Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** APPROVED for implementation by Aryn Yklas on 2026-11-03 with m1 implementers and m2 reviewers. Code/test paths are Create until implemented; planned commands are requirements, not executed results.

**Goal:** Deliver the real server-side artifact/source-map and replay evidence modules consumed by custom SDKs and native investigation, rather than leave SDK integration dependent on an unowned backend.

**Architecture:** Scoped content-addressed artifacts and sandboxed owned source-map symbolication sit above plan01 durable storage/control. A replay module validates the owned masked protocol, sequence/checkpoint dependencies and authorized reads. Plan03 owns capture/build uploader/recorder/viewer; plan05 owns HTTP/UI integration; this plan owns the actual server evidence implementations.

**Tech Stack:** Go 1.27.3; owned source-map v3 parsing/mapping, checksummed durable blob/metadata primitives from plan01, bounded subprocess symbolicator; no current Sentry server or AGPL code copied.

**Spec:** [design sections5,9–10,12](../specs/2026-11-03-soundpost-design.md), [contracts C02/C04/C07/C11–C12](../specs/2026-11-03-soundpost-contracts.md).

## Global Constraints

- Soundpost-owned artifacts/build identities/protocol and custom SDKs; no Sentry envelope/upload API compatibility requirement.
- First-party Apache-2.0; dependencies require exact provenance and notices. No external telemetry engine or arbitrary URL source-map/symbol fetch.
- Exact org/project/build/debug/generated/map hashes determine artifacts. Content hashes alone are not authorization/cache identity.
- Source content excluded by default; source maps/symbol identities need explicit policy and artifacts.read, private sources additional grant.
- Max bundle32 MiB expanded,1024 files,map nesting8; symbolicator100 ms/frame,5 seconds/subprocess,256 MiB.
- Replay opt-in and strict pre-buffer masking are mandatory upstream; server revalidation is defense-in-depth, not a substitute. Chunk128 KiB/checkpoint30 seconds; dependency gaps are explicit.

## Review Focus

1. Same artifact hash in two organizations crosses a warmed cache/download path: exact scope/visibility binding (Tasks1,4).
2. Malicious indexed/source map causes path traversal/decompression/CPU/memory exhaustion: sandbox/limit rejection with original frame retained (Tasks2,3).
3. Release rename/build collision silently selects wrong map: exact immutable debug/generated identity (Tasks1,3).
4. Missing replay middle chunk or deleted checkpoint displays invented continuity: chain/dependency-aware read/retention (Task5).
5. Source/replay deletion during stream or old snapshot restore leaks cached bytes: response fencing and deletion authority integration (Task6).

---

### Task1: Durable protected artifact upload and content identity

**Files:** Create `internal/artifacts/{types,service,store,manifest,policy}.go`, `internal/artifacts/service_test.go`, `internal/app/artifacts.go`, `docs/protocol/artifacts-v1.md`.

Also Create `internal/model/blob.go`, `internal/storage/blob.go`, `internal/storage/blob_test.go`: C07 `(*storage.Engine).WriteBlob(ctx,scope,manifest model.BlobManifest,input io.Reader)(model.BlobReceipt,error)` supplies BlobStore through internal/app, using private fixed-root-owner ArtifactFragment entries capped256 KiB, same quotas/fences/Raft/fsync/snapshot/retention as telemetry. These are protected build artifacts, not a newly enabled arbitrary attachment/heap channel.

**Interfaces:** C07 `(*Service).Put(ctx context.Context, scope auth.Scope, manifest Manifest, input io.Reader)(Artifact,error)` and `(*Service).Get(ctx,scope,artifactID ArtifactID)(io.ReadCloser,error)` with injected `BlobStore`, `MetadataStore`, `ScopeAuthorizer`; common types live in artifacts/types.go. `Manifest` exact fields from C07. BlobStore commits checksummed replicated bytes using plan01 owned storage and returns a durable cursor; metadata publication is a C12 fenced reference intent with content hash/cursor, not a fake cross-group transaction.

- [ ] Write `TestArtifactExactIdentityAndPrivateGrant`: generated hash/debug/build mismatch rejects; same permitted hash under orgA and orgB cannot share unscoped lookup/read; sourcesContent absent by default and private source read requires specific grant. Stream cap/hash failure yields no published artifact reference and cannot ACK a failed upload.
- [ ] Write `TestArtifactFragmentDurabilityAndWholePublication`: kill leader after some/all fragments but before reference publication; Put cannot report complete/readable artifact until all fragment cursors and reference intent commit. Snapshot/replacement retains every referenced byte; incomplete orphans are unreadable and explicit GC is idempotent. Run `go test ./internal/storage -run TestArtifactFragmentDurabilityAndWholePublication -count=1` red/green and include it in actual artifact-upload smoke.
- [ ] Run `go test ./internal/artifacts -run TestArtifact -count=1`; verify red.
- [ ] Implement streaming verified temporary upload, policy transform before durable blob admission, source-content separation, content-addressed safe storage and durable reference publication after bytes commit. Staged orphan blobs are invisible and later GC'd only with explicit unreferenced proof; a missing blob produces unavailable, not empty successful symbolication.
- [ ] Run tests and `go run ./tools/smoke artifact-upload --artifact-dir <temp>` using actual private uploader credentials/server/storage: restart between byte commit and reference publish, resume intent, compare exact hashes/cursors and denied reads. Commit `feat(artifacts): Store scoped durable build artifacts`.

### Task2: Owned bounded source-map decoding and mapping semantics

**Files:** Create `internal/sourcemap/{types,vlq,decode,index,lookup}.go`, `internal/sourcemap/{decode,lookup}_test.go`, `fixtures/artifacts/{simple.ts,indexed.ts,generate.mjs}`, `docs/artifacts/source-maps.md`.

**Interfaces:** `sourcemap.Decode(input io.Reader, limits Limits)(*Map,error)` and `(*Map).Lookup(generatedLine,generatedColumn uint32)(Position,bool,error)`; Position is project-relative source ID/function-name/line/column, not runtime source contents. Limits exact C07 plus checked integer/offset/section bounds. No remote section/source URL resolution.

- [ ] Write `TestRealGeneratedMapPosition`, `TestIndexedOffsetsAndVLQBounds`, `TestRecursiveRemoteTraversalMapRejected`: build actual Vite/webpack fixture, map known generated location to exact original function/line/column; test section offsets, missing name, malformed VLQ, overflow, nonmonotonic segments, unsupported recursion/depth, absolute/traversal paths and remote map sections.
- [ ] Run `go test ./internal/sourcemap -count=1`; verify red behavior before parser implementation.
- [ ] Implement independently authored v3 VLQ/state/section mapping, explicit source-root normalization, no file/network access, checked arithmetic and size bounds. Preserve original sanitized frame when unmapped/invalid. Source contents are optional protected artifacts, not silently copied into Position/diagnostics.
- [ ] Run tests against generated fixture and `node fixtures/artifacts/generate.mjs` plus `go run ./tools/smoke source-map --artifact-dir <temp>`; require actual thrown/generated position resolves known source and malformed cases reject without canary content. Commit `feat(symbols): Decode owned source maps accurately`.

### Task3: Sandboxed symbolication with exact build selection

**Files:** Create `internal/symbolicate/{types,service,worker,limits}.go`, `cmd/soundpost-symbolicate/main.go`, `internal/symbolicate/service_test.go`, `fixtures/artifacts/symbolicate/main.go`, `docs/operations/symbolication.md`.

**Interfaces:** C07 `(*Service).Resolve(ctx,scope,BuildID,[]model.Frame)([]SymbolicatedFrame,error)` consumes injected authorized artifact reader. `SymbolicatedFrame` includes original sanitized frame, optional resolved code identity, map/build hash and safe resolution reason. Worker input is closed bounded manifest/frame DTO, no arbitrary path/command; output same typed result.

- [ ] Write `TestSymbolicationBuildNotReleaseLabel`, `TestWorkerLimitsPreserveOriginalFrames`, `TestSourceContextGrantSeparate`: renaming release cannot change selected artifact, wrong hash never fetches fallback, deadline/memory/invalid map produces safe unresolved original frame, default result has no source contents.
- [ ] Run `go test ./internal/symbolicate -count=1`; verify red.
- [ ] Implement bounded no-network/no-arbitrary-file worker, per-frame100 ms and process5 s/256 MiB limits with OS-enforced memory/CPU where supported, cancellation/kill/reap, exact artifact selection and org/project visibility-bound cache. Sandbox launch rejects unsupported required restriction rather than silently run unconstrained in production.
- [ ] Run actual built source fixture through `go run ./fixtures/artifacts/symbolicate --endpoint-env SOUNDPOST_FIXTURE_API --restart-worker --inject-timeout`; inspect exact readable stack and unresolved reason on deadline, no raw path/source canaries. Commit `feat(symbolicate): Resolve build-scoped frames in a bounded worker`.

### Task4: Artifact policy, reference retention and read revocation

**Files:** Create `internal/artifacts/{references,retention,reader}.go`, `internal/artifacts/retention_test.go`, `tools/smoke/artifact_policy.go`.

**Interfaces:** `Reference(ctx,scope,ArtifactID,OriginCursor,RetainUntil)error`, `ReadAuthorized(ctx,scope,ArtifactID,Window)(ArtifactReader,error)` and fenced unreference/GC commands; typed references derive from retained error/profile/build usage, not user URL strings. Common Get delegates the same current scope/generation checks.

- [ ] Write `TestLastRetainedOccurrencePinsMap`, `TestPrivateArtifactCacheAndReadRevocation`, `TestRestoreCannotReviveDeletedArtifact`: defaults retain maps90 days or until last referencing occurrence/profile expires, whichever later; deletion takes precedence through C12; same permissions/disjoint private-source grants cannot reuse cached source bytes; midstream revoked read stops.
- [ ] Run `go test ./internal/artifacts -run 'TestLast|TestPrivate|TestRestore' -count=1`; verify red.
- [ ] Implement durable reference/outbox reconciliation, visibility-fingerprint cache and streaming response fences. Physical GC requires complete reference/tombstone state and snapshot pins. Do not release local authoritative replicas based only on optional backup upload.
- [ ] Run tests and `go run ./tools/smoke artifact-policy --artifact-dir <temp>` with real error/profile references, expiry/delete, restart and current-ledger restore. Commit `feat(artifacts): Respect references privacy and deletion fences`.

### Task5: Real replay chain validation, storage and authorized reconstruction

**Files:** Create `internal/replays/{types,service,validate,chain,read,retention}.go`, `internal/replays/{chain,privacy,read}_test.go`, `internal/app/replays.go`, `fixtures/replays/server-smoke/main.go`, `docs/protocol/replay-v1.md`.

**Interfaces:** `replays.New(scanner ReplayScanner, authorizer ScopeAuthorizer, control ReferenceStore)(*Service,error)`; `(*Service).Validate(grant policy.SourceGrant, chunk model.ReplayChunk)error`, `(*Service).Read(ctx,scope,replayID model.ID,window ReplayWindow)(ReplayStream,error)`. ReplayStream.Next returns typed checkpoint/delta/gap/unsupported/revoke/error with sequence/hash/policy/clock metadata and Close. Plan01 admission injects the validator; UI plan05 injects Read into its C11 view, SDK plan03 owns renderer/recorder format.

- [ ] Write `TestReplayCheckpointAndMissingChunk`, `TestReplayRejectsRawChannelsBeforeStorage`, `TestReplayGrantRevokedBetweenChunks`: duplicate/out-of-order sequence and altered previous hash cannot apply invalid deltas; missing middle chunk produces gap until next verified checkpoint; raw text/HTML/attributes/CSS/URL/canvas/bodies fields reject before durable admission; denied reader cannot distinguish foreign recording existence.
- [ ] Run `go test ./internal/replays -count=1`; verify red.
- [ ] Implement closed format validation, immutable root/sequence indexes, checkpoint dependency graph, gap-aware reads, permission/fingerprint/delete revalidation and retention groups. Retaining a raw node until server scrub is not permitted upstream; this validator cannot certify that SDK pre-buffer behavior alone. Staged future chunk may be retained as incomplete but cannot make a replay appear continuous.
- [ ] Run real recorder fixture into actual server and `go run ./fixtures/replays/server-smoke --endpoint-env SOUNDPOST_FIXTURE_API --drop-middle --revoke-reader --delete-root`; view via actual plan03 inert renderer and plan05 UI. Require masked interaction order, explicit gap/checkpoint recovery and no post-revocation/deletion bytes. Commit `feat(replay): Store and read authorized checkpointed evidence`.

### Task6: Cross-module evidence and actual browser acceptance

**Files:** Create `tests/acceptance/evidence_test.go`, `tools/smoke/evidence.go`, `docs/acceptance/evidence.md`; modify implemented app wiring only to integrate real artifact/symbolication/replay services. UI owns HTTP artifact/investigation handlers, SDK owns build/capture, native plan04 owns ProfileView.

**Interfaces:** `go run ./tools/smoke evidence --artifact-dir <temp>` launches actual service/SDK/UI fixture and verifies real frame/replay/profile references through scoped C11 views, not canned mappings. New receipts and historical receipt lookup use C03; no raw data resurrected by receipts.

- [ ] Write `TestEvidenceRealFrameReplayAndScopeLifecycle`: build/capture error + optional replay + actual profile; exact build/frame resolves, authorized links navigate, same IDs/hash in another org deny; delete/revoke while UI open clears/halts forbidden subsequent content; current deletion authority survives old backup restore and old users/tokens stay inactive.
- [ ] Run `go test ./tests/acceptance -run TestEvidence -count=1`; verify red until real path exists.
- [ ] Complete `internal/app` wiring with consumer-owned narrow interfaces and dependency-cycle checks; no feature imports from control. Add precise source-map/replay unsupported/degraded user reasons, no placeholder success data.
- [ ] Run the test and actual `evidence` smoke plus plan05 browser evidence fixture; inspect known mapped line, safe masked replay, real native/runtime method/loss and authorization/deletion/canary results. Commit `test(evidence): Verify real protected application investigation`.

## Completion evidence

All server evidence paths above must work before SDK Task6/8 and UI Task4/8 final integration can pass. Unit decoders alone are not source-map/replay delivery; actual thrown frame/recorder/server/browser plus policy/deletion/restore acceptance is mandatory. This plan closes backend ownership, adds no optional scope and does not make research/runtime support claims.
