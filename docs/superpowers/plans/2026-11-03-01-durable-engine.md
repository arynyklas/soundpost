<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Durable Isolated Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** APPROVED for implementation by Aryn Yklas on 2026-11-03 with m1 implementers and m2 reviewers. Planned commands are acceptance instructions, not executed results. Source paths are Create operations until implemented.

**Goal:** Deliver an actual authenticated, privacy-checked, durable single-host/distributed telemetry engine with scope-enforced scans and retention/deletion.

**Architecture:** Go modules implement owned typed records, admission, WAL/segments/indexes and state machines. etcd Raft is a consensus primitive; bbolt is an embedded metadata primitive, not a telemetry query engine. Same interfaces run with one or three voters.

**Tech Stack:** Go 1.27.3, stdlib HTTPS/crypto, permissively licensed OIDC/Argon2 primitives, etcd Raft, bbolt, optional zstd with locked dependency licenses/hashes.

**Spec:** [design](../specs/2026-11-03-soundpost-design.md), [contracts C01–C05/C11–C12](../specs/2026-11-03-soundpost-contracts.md).

## Global Constraints

- All first-party material is Apache-2.0; primitives retain approved notices. Own ingestion/index/layout/query/evaluation; no upstream engine fallback.
- Single-host is non-HA. Three voters on distinct disks/nodes commit only on two durable copies; no acknowledged loss from one node failure.
- Scope precedes index/cache lookup. Metadata, live streams, artifacts, deletion/export and instance elevation obey the same project/org authorization.
- Default structured templates only; bodies/prompts/credentials/full SQL/locals/heap/object values excluded. Public source keys grant write only.
- C03 limits: 1 MiB compressed, 4 MiB expanded, 256 KiB/record, 512 records; atomic per batch, 7-day dedup horizon and stable original receipt.
- Public product contracts are Soundpost's own. PromQL/LogQL language semantics, not upstream backend routes, are retained.

## Review Focus

1. ACK lost before HTTP response then retry after restart: same receipt/records, no duplicate issue effects (Tasks 3, 7).
2. Foreign project/negative cache/metadata/elevation requests: denied before lookup, with no target existence leak (Tasks 1, 5).
3. Torn WAL/full disk/failed sync: no false ACK; corrupt non-tail bytes cause explicit unavailable state (Tasks 3, 7).
4. Deletion followed by old replica or backup restore: deny data before serving any response and preserve tombstones (Tasks 8, 9).
5. Snapshot and compaction concurrent with ingest: every receipt still resolves to exact typed data with no stale-marker/duplicate corruption (Tasks 4, 7, 9).

---

### Task 1: Actual first-boot identity and protected control actions

**Files:** Create `go.mod`, `go.sum`, `cmd/soundpost/main.go`, `internal/model/{identity,errors,value}.go`, `internal/auth/{service,scope,session,elevation,oidc,local,secrets}.go`, `internal/httpapi/{server,auth,session,control}.go`, `internal/control/{store,types,bootstrap}.go`, `internal/auth/security_integration_test.go`, `tools/smoke/main.go`, `docs/operations/bootstrap.md`.

**Interfaces:** Produce C01 types, C02 opaque `Scope`, `Authorize`, `Revalidate`, `Elevate`, C05 `Transact`; HTTPS `serve --mode=single --data-dir <path> --listen <address>`, one-time bootstrap and own control actions. Start with a real local durable control adapter needed by this behavior; Task 6 replaces its write path with Raft, not a fake in-memory fallback. Source code remains one implementation with one-voter consensus at completion.

`auth.Service` is the injected owner of session/login/local/OIDC/elevation operations; `httpapi.RegisterSessionRoutes(mux,*auth.Service)` owns real C11 routes. UI plan05 consumes it rather than creates a second auth backend. The later Raft cutover removes the obsolete local-only write path, with no compatibility adapter retained.

Keep the C02/C05 seam opaque and acyclic: plain control state/command/result DTOs belong in the shared model leaf; auth consumes a narrow store interface over those DTOs, while control accepts the exact `auth.Scope` at `Transact`. Do not replace it with a caller-implementable authorization interface. Task1 declares the closed C05 command kinds and generates the complete authorization VisibilityFingerprint, including named restricted-source grants. Add a behavioral same-org/disjoint-source-grants isolation case. Later command owners explicitly extend the shared control DTO/apply files:01.02 quotas,01.08 fences/deletion/evidence gaps,02.11 rule evaluation,06.01–05 evidence/releases/jobs/conditions/incidents and06.07–09 delivery/cutover. Those edits remain coordinated by the integration owner; control never imports feature implementations.

Task1 also creates `internal/httpapi/admin.go`, `internal/httpapi/admin_test.go`, C11 `AdminCommandRequest`/`AdminReadRequest` and real closed `/api/v1/admin/commands`/`admin/read` routes. `TestAdminCannotGrantOutsideOrgOrReadSecrets` proves instance-only org creation, scoped org/team/project/membership/source-policy/SSO management, write-only secrets, reauthentication/audit and ordinary-member denial through actual HTTP. UI consumes these routes; no CLI-only hidden onboarding requirement.

- [ ] Write `TestBootstrapTokenConsumedOnce`, `TestProjectGrantNotOrgMembership`, `TestOIDCIssuerStateNonceAndPKCE`, `TestElevationAuditsBeforeRead`, `TestRevocationStopsLiveResult` with real temp storage/server and local signed OIDC fixture. Assert bootstrap second use is unauthorized; an org member without a project grant receives not-found for its object; forged issuer/nonce and reused state reject; failed audit commit yields no elevated result.
- [ ] Run `go test ./internal/auth ./internal/httpapi -run 'TestBootstrap|TestProjectGrant|TestOIDC|TestElevation|TestRevocation' -count=1`; expect specific missing implementation failures before code.
- [ ] Implement exact C01/C02/C05 surfaces, Argon2id/TOTP/recovery, OIDC code flow, CSRF/session rotation, explicit grant mappings, encrypted destination/source secret store and one-time admin bootstrap. Generate randomness outside deterministic control apply. Lock exact audited dependencies and Go toolchain/hash in module/build metadata; retain notices. No scaffold-only authentication endpoint.
- [ ] Run the same tests plus `go run ./tools/smoke bootstrap-scope --artifact-dir <temp>`; harness starts actual server, completes login, creates two orgs/projects, grants/revokes access and records authorized/denied responses without credentials in artifacts. Expected real 2xx only in granted scope, replayed bootstrap rejected, audit order verified. Add user-facing bootstrap/config docs.
- [ ] Commit only Task 1 files with `feat(auth): Establish isolated first-boot identity`.

### Task 2: Typed admission and privacy contract

**Files:** Create `internal/model/telemetry.go`, `internal/ingest/{types,codec,canonical,service,routing,receipts}.go`, `internal/policy/{source,templates,quota}.go`, `internal/control/quota.go`, `internal/httpapi/ingest.go`, `internal/ingest/admission_test.go`, `docs/protocol/ingestion-v1.md`; extend shared leaf control command DTOs/apply under the integration owner.

**Interfaces:** Consume auth/control and C01; produce C03 `Batch`, `Record`, `Receipt`, `ResolveSource`, `Normalize`, `Admit`, C04 closed typed payloads in `internal/model/telemetry.go`. `Payload` uses typed concrete variants, not an arbitrary object bag. `SourceGrant` is opaque and credential-bound.

- [ ] Write `TestAdmissionAtomicPolicyAndLimits`: a 513-record batch, gzip expansion over 4 MiB, duplicate JSON key, mismatched project, unknown template and mixed payload tag each produce a terminal safe error and zero accepted records. Approved template fields survive; unknown optional keys disappear before canonical bytes. Assert float stale bits/native integer histogram counts survive exactly.
- [ ] Write `TestBrowserSourceKeyCannotReadOrElevate` and `TestQuotaReservationIsAtomic`: a public source key can only append its project, and concurrent reservations cannot exceed a hard cap then acknowledge rejected excess.
- [ ] Write `TestOwnerRoutingAndConcurrentMetricConflict` and `TestReservationNotRefundedOnAmbiguousAppend`: fixed64 owner routing maps same metric across producers to one slot; mixed-slot batch admits zero; equal same-series/time/type/value collapses and different value conflicts at ordered apply, not only preflight. A timeout/router death leaves quota charged until a committed cancellation fence plus owner-group no-commit proof.
- [ ] Exercise browser-source HTTP admission with `X-Soundpost-Source`, exact configured CORS origins, exposed retry/receipt headers and no ingestion cookies. Reject foreign origins and wildcard-with-cookie behavior. Assert the C12 `CancelReservation` DTO and its committed cancellation fence, not a TTL-only refund.
- [ ] Run `go test ./internal/ingest ./internal/policy -run 'TestAdmission|TestBrowserSource|TestQuota' -count=1`; expect missing behavior failures.
- [ ] Implement C03/C04 codec, canonical hashing, fixed64 owner routing and C12 durable global quota reservations. Source descriptors expose routing identity only, not read grants. Preserve integer histogram counts above2^53, immutable native template-revision log line, stream-label/structured-metadata separation and per-signal retention deadlines. Policy changes use the C12 barrier, not ReadIndex-only cross-group assumptions. Bounded decompression/errors never log rejected payloads.
- [ ] Rerun tests and `go run ./tools/smoke privacy-admission --artifact-dir <temp>` with canary strings across forbidden fields and failed batches; expected no canary in admitted records, diagnostic output or persisted files. Document policy/retry semantics; commit `feat(ingest): Enforce typed atomic source admission`.

### Task 3: Fsync-backed records and original receipts

**Files:** Create `internal/storage/{group,wal,receipt,apply,recovery}.go`, `internal/storage/wal_test.go`, `internal/storage/crash_test.go`, `tools/smoke/durable.go`, `docs/operations/durability.md`.

**Interfaces:** Produce C03 `Append(ctx,scope,NormalizedBatch)(Receipt,error)` and exact durable receipt; WAL header version/length/CRC32C/term/index. Stable dedup key/hash/retention decisions persist with applied cursor. Store infrastructure exposes injectable syscall faults only in internal tests; no consumer-visible bypass.

- [ ] Write `TestRetryReturnsOriginalReceiptAcrossRestart`: append batch B, lose response, restart, retry B and assert original hash/cursor/retention/dedup times and exactly one logical event. Same ID/different content must return conflict without changing B.
- [ ] Write `TestHistoricalReceiptLookupAfterPolicyDeleteAndRevocation`: C03 LookupReceipt with current valid source returns unchanged receipt/hash/deadlines and `historical:true` after restrictive policy/historical deletion without normalization/reservation/append; invalid/revoked credentials or retired scope deny. Receipt lookup is not post-fence new admission and cannot resurrect data.
- [ ] Write `TestSyncFailureNeverAcknowledges`, `TestTornTailRecovery`, `TestInteriorCorruptionRefusesRead`; inject failure at write/sync/receipt/apply points and assert never return a durable receipt before its required writes, tail truncation only, interior corruption explicit fault.
- [ ] Run `go test ./internal/storage -run 'TestRetry|TestSync|TestTorn|TestInterior' -count=1`; verify red behavior.
- [ ] Implement owned WAL and crash-consistent receipt/applied-cursor bbolt transactions with explicit write/sync/directory-fsync/rename ordering. Use the one-voter group interface that Task 6 wires to the same state machine. No blanket success after enqueue and no unacknowledged post-ACK drop.
- [ ] Rerun tests and `go run ./tools/smoke durable-restart --artifact-dir <temp>`; kill actual process after an observed ACK and verify receipt plus exact retained data after restart. Document assumptions and observed drill; commit `feat(storage): Persist durable batches and retry receipts`.

### Task 4: Owned typed segments, indexes and complete scans

**Files:** Create `internal/storage/{segment,page,encoding,index,scan_types,read,live,manifest,flush,compact}.go`, `internal/storage/roundtrip_test.go`, `internal/storage/compaction_test.go`, `internal/storage/live_test.go`, `docs/storage/format-v1.md`.

**Interfaces:** Produce C05 `Engine.Scan`, `ScanRequest`, `ReadFence`, `RowIterator`, `Matcher`, `Field`, `Page`, `Publish`; exact header/column encodings/version checks. Iterator pages borrow until next Next/Close; no unnecessary per-row allocation. Signal-specific typed indexes consume C04, not an external telemetry database.

Also produce C05 `(*Engine).Subscribe(ctx,scope,SubscribeRequest)(ChangeIterator,error)` with exact ChangePage/Watermarks/Close contract. It reads a bounded committed-apply feed, emits explicit gap/revoke records and uses scans only for catch-up, never polling disguised as live.

- [ ] Write `TestHotColdCompactedTypedEquality`: same metric floats/NaNs/stale/native histogram integer counts, duplicate-timestamp distinct log IDs, span/error/job/replay/profile records produce equal logical output before flush, after flush, after compaction and restart. Duplicate batch retry does not duplicate; legitimate same-line distinct IDs do.
- [ ] Write `TestUnknownSegmentVersionIsNotEOF`, `TestCancelledScanReleasesPages`, `TestForeignProjectNeverTouchesIndex`. Assert explicit errors, resource release and scope check before index lookup rather than filtered results after lookup.
- [ ] Write `TestCommittedSubscriptionGapAndRevocation`: an applied row becomes visible only after commit, slow subscriber overrun yields explicit cursor gap rather than silent loss, and revocation stops the next chunk. Run `go test ./internal/storage -run TestCommittedSubscriptionGapAndRevocation -count=1` red then green and exercise live feed in storage-roundtrip smoke.
- [ ] Run `go test ./internal/storage -run 'TestHotCold|TestUnknownSegment|TestCancelledScan|TestForeignProject' -count=1`; verify red.
- [ ] Implement segment headers/checksums, column pages, delta/dictionary/float/histogram encodings, typed postings/ID/time indexes, memtable merge, immutable manifests and fenced compaction. Do not drop stale bits/reset metadata, replay checkpoints or equal-time multiplicity. Retained files remain authoritative on local replicas.
- [ ] Rerun tests and `go run ./tools/smoke storage-roundtrip --artifact-dir <temp>` against actual server with ingest/flush/compact/restart/read. Report page/byte counts and exact values, not just non-empty output; commit `feat(storage): Query owned typed segments and indexes`.

### Task 5: Secondary-surface isolation and cross-org audit

**Files:** Create `internal/link/resolve.go`, `internal/httpapi/{capabilities,exports}.go`, `internal/auth/cache.go`, `internal/exports/service.go`, `internal/httpapi/isolation_test.go`, `tools/smoke/isolation.go`. C11 `investigate.go`/`workflow_types.go` and real projections are owned by UI plan05; consume them in final integration denial checks, not duplicate handlers here.

**Interfaces:** Produce C04 Resolve, C11 capabilities/export, visibility-fingerprint/epoch/delete-bound cache keys/tickets. Artifact/replay/profile/investigation handlers integrate later through the same scope contract; never return stub data for not-yet-implemented readers.

- [ ] Write `TestCrossOrgGuessedIDNegativeCacheAndLink`: seed equal content hashes/names in two orgs; unauthorized query/discovery/link/capability/export cannot reveal target existence or counts, including warmed positive/negative caches. Assert project team restrictions inside one org as well as org separation.
- [ ] Write `TestExportRevokedBeforeDownload` and `TestElevationReadAuditMustCommit`: pending export completes after revocation/deletion but download fails; failed audit cannot release elevated bytes.
- [ ] Write `TestNamedSourceVisibilityCannotShareWarmCacheOrCursor`: same org/projects/actions but disjoint restricted-source reader grants produce distinct authorization fingerprints; warm query/discovery/pagination/live replay/export never leaks the other source. Run red/green with `go test ./internal/httpapi -run TestNamedSourceVisibilityCannotShareWarmCacheOrCursor -count=1`.
- [ ] Run `go test ./internal/httpapi ./internal/exports -run 'TestCrossOrg|TestExportRevoked|TestElevationReadAudit' -count=1`; verify red.
- [ ] Implement visibility-fingerprint/epoch-bound lookup/caches, real capability/export/link operations, short-lived grants and audit-before-elevated-response. Revalidate before result/chunk release. Typed investigation rendering/handler belongs to plan05; integrate its actual projections into the final denial matrix after that plan, never a fake intermediate response.
- [ ] Rerun and run `go run ./tools/smoke isolation --artifact-dir <temp>` with real identities and HTTP denial matrix. Commit `feat(auth): Fence secondary reads and exports by scope`.

### Task 6: Three-voter replicated durable data and control groups

**Files:** Create `internal/replica/{node,ready,transport,membership,routing,fence}.go`, `internal/control/replicated.go`, `internal/storage/replicated.go`, `internal/replica/quorum_test.go`, `tools/smoke/cluster.go`, `docs/operations/distributed.md`.

**Interfaces:** `replica.Propose(ctx, GroupID, Entry)(CommittedEntry,error)`, `ReadIndex(ctx,GroupID)(Cursor,error)`, `ChangeMembers(ctx,GroupID,ExpectedRevision,Members)error`, `FenceToken{Group,Term,Revision}`. `CommittedEntry` carries term/index/payload; `Entry` closed data/control command union. Exact writes use C03/C05; no duplicate single/distributed data implementation.

- [ ] Write `TestMajorityMeansDurableNotReceived`: follower receipt without sync cannot count; leader cannot ACK on minority; durable majority survives losing either acknowledged copy's node with committed state recoverable by the remaining quorum.
- [ ] Write `TestPartitionedLeaderCannotPublishOrSend`, `TestReadYourReceiptWaitsForApply`, `TestReassignmentKeepsDedupAndScope`; assert term-fenced stale workers, lagging read returns freshness fault rather than absence, relocation preserves original receipt.
- [ ] Run `go test ./internal/replica ./internal/control ./internal/storage -run 'TestMajority|TestPartitioned|TestReadYourReceipt|TestReassignment' -count=1`; verify red under deterministic transport/fault schedule.
- [ ] Implement etcd Raft Ready persistence/advance ordering, mTLS node transport, control and data voters, stable routing/membership, leader fences, ReadIndex and joint membership changes. Bootstrap supports one-voter single and three-voter distributed. Separate physical failure-domain placement is mandatory. Publish/live/data responses use applied fences; metadata and data remain separate committed groups, not fake cross-group atomic transactions.
- [ ] Run tests and `go run ./tools/smoke quorum-node-loss --nodes=3 --artifact-dir <temp>` with three actual server processes/disks: collect ACK IDs, remove current ingest/storage leader including its disk directory from availability, keep writing, restore replacement, and reconcile every ACKed batch and value. Repeat each node role and majority/minority partition scenario. Commit `feat(replica): Survive one server loss without losing receipts`.

### Task 7: Snapshot, repair and crash-point coverage

**Files:** Create `internal/replica/{snapshot,install,repair}.go`, `internal/storage/snapshot.go`, `internal/replica/snapshot_test.go`, `tools/smoke/snapshot.go`, `docs/operations/recovery.md`.

**Interfaces:** `CreateSnapshot(ctx,GroupID,at Cursor)(Snapshot,error)`, `InstallSnapshot(ctx,SnapshotManifest,io.Reader)error`; snapshot includes stable metadata, receipts, segments, indexes/rebuild state, applied/commit cursor and tombstones. Reader/writer references pin manifest files during copy; installation switches only after file/dir sync.

- [ ] Write `TestSnapshotConcurrentAppendCompactionAndRetry`: create snapshot while flushing/compacting, restart from it plus committed suffix, compare every ACKed receipt/data and unchanged idempotency result.
- [ ] Write `TestSnapshotChecksumAndGenerationFence`: corrupt/missing files or a snapshot with missing deletion ledger never become ready. Interrupted installation retains the old valid directory; replay suffix begins at the correct committed index.
- [ ] Write `TestBackupCutPinsPostCheckpointEvidence` and `TestRestoreRebuildsPostControlCutQuota`: event after control H is processed/expired live before D but backup pin preserves replay; a reservation created after C and consumed in D reconstructs one exact charge before intake. Use C12 replay-or-gap interval and quota-reconciliation certificates; missing proof blocks readiness.
- [ ] Run `go test ./internal/replica ./internal/storage -run 'TestSnapshot' -count=1`; verify red.
- [ ] Implement full-byte snapshots/install/repair/truncation and crash hooks. For installation backup, capture C/H and atomically pin required post-H journal, then seal D>=H with replay/gap and reservation/consumption/release certificates; privacy deletion aborts/restarts or updates deny certificate. Rebuild/reconcile quotas from D before restored intake, including post-C charges and pending cancellation fences. Missing group/data/proof is a failed backup, not partial success.
- [ ] Rerun and `go run ./tools/smoke snapshot-repair --artifact-dir <temp>` with actual node replacement/restart/receipt retry during compaction. Commit `feat(recovery): Restore complete snapshots and committed suffixes`.

### Task 8: Retention, deletion, holds and disk-pressure admission

**Files:** Create `internal/retention/{types,policy,delete,worker,holds}.go`, `internal/control/fence.go`, `internal/storage/pressure.go`, `internal/retention/delete_test.go`, `tools/smoke/deletion.go`, `docs/privacy/retention.md`.

**Interfaces:** C11 Delete/PollDelete and exact retire_org/retire_project/historical_range/entity modes; C12 BeginFence/RecordBarrier/CompleteFence saga. Receipt phase fencing/complete/held/failed separates immediate read suppression from completed all-group admission/effect fencing. Historical predicates reject matching late writes while allowing new epoch data outside the range. Authority checkpoint is injected and required when off-host backup is enabled.

- [ ] Write `TestDeleteBeforeResponseReleaseAndRestore`: race an authorized query/cache/export/live response with delete; no bytes after fence. Restore an old snapshot plus current ledger and confirm suppressed data before readiness. Hold rejects physical-erasure success.
- [ ] Write `TestDiskPressureNeverSilentlyShortensRetention`: at 80/90/95% transitions produce defined warnings/admission rejection; no ACKed record disappears before retention or explicit deletion. Replay checkpoint groups and last artifact references remain consistent.
- [ ] Write `TestDeleteBarrierRacesOldGrantAndDerivedEffects` and `TestEvidenceExpiryRecordsGapNotRecovery`: old proposal ordered before barrier may complete before operation completion; one ordered after it cannot ACK. Unavailable slot leaves202/fencing, not complete. Deleted-origin rule/issue/notification effects are suppressed; unprocessed journal cannot disappear before durable gap and unknown state. Run these tests red/green plus actual delete barrier/pipeline outage smoke.
- [ ] Run `go test ./internal/retention ./internal/storage -run 'TestDelete|TestDiskPressure' -count=1`; verify red with deterministic clocks/disk accounting.
- [ ] Implement design section 12 exact retention defaults, tombstone/response fences, file rewrite, holds, reference-aware artifact/replay expiry, backup tombstone preservation and consensus/audit reserved space. Policy changes are versioned/audited, not rewritten receipt times.
- [ ] Rerun and `go run ./tools/smoke delete-restore-pressure --artifact-dir <temp>`; observe HTTP denial plus local physical cleanup and backup suppression manifest. Document lag/hold limits; commit `feat(retention): Enforce deletion and honest capacity limits`.

### Task 9: Encrypted backup/export and isolated restore

**Files:** Create `internal/backup/{manifest,encrypt,object,authority,restore,reconcile}.go`, `internal/auth/restore.go`, `cmd/soundpost/backup.go`, `internal/backup/restore_test.go`, `tools/smoke/backup.go`, `docs/operations/backup-restore.md`.

**Interfaces:** `Backup(ctx,Scope,SnapshotSet,Destination)(BackupManifest,error)`, `Restore(ctx,BackupManifest,DestinationRoot,DeletionLedger)(RestoreReport,error)`; manifests include hash/size/cursors/retention/delete generation and encryption key IDs. Optional S3-compatible destination is a backup/export primitive; local retained replicas remain authoritative.

Implement the exact C12 authority seam `CheckpointDeletion(ctx,LedgerGeneration)(AuthorityReceipt,error)` and `CurrentDeletionLedger(ctx)(Ledger,error)`; consumers use those names rather than a second backup/deletion authority protocol.

- [ ] Write `TestRestoreRequiresCurrentDeletionLedger`, `TestRestoreDisablesSourcesAndSenders`, `TestMissingObjectAndWrongKeyFailClosed`: restore must not reemit notifications or revive source secrets, omit ACKed data silently, or serve old deleted content.
- [ ] Write `TestAuthorityFailurePreventsCompletedDeletion` and `TestRestoreNeverReactivatesRevokedIdentity`: backup precedes deletion/token revoke/account demotion; current independently durable authority suppresses deleted data, missing authority fails closed, all old sessions/API/source/MFA/OIDC-derived privileges remain inactive under fresh auth generation. Fresh login cannot restore former grants before audited reauthorization.
- [ ] Run `go test ./internal/backup -run 'TestRestore|TestMissingObject' -count=1`; verify red.
- [ ] Implement verified encrypted bundles and complete C/H/D replay/quota certificates, C12 independently durable versioned deletion authority with conditional monotonic HEAD, and current-ledger verification before any restored read. Restore is bootstrap-only with fresh authentication generation/keys, inactive old users/grants/OIDC/tokens/sources/senders until explicit audited reconciliation. Old decryption keys do not confer authority. Never evict local retained replicas on upload success.
- [ ] Rerun and `go run ./tools/smoke backup-restore --artifact-dir <temp>` to a clean process/storage root; reconcile receipts/typed queries/tombstones and disabled delivery state. Document measured backup RPO and no backup-based single-node RPO claim. Commit `feat(backup): Verify isolated encrypted restore`.

## Completion evidence

Run the task tests cumulatively once integration is complete, then actual bootstrap/privacy/restart/isolation/three-node/snapshot/delete/backup smoke scenarios. Record exact Go/dependency versions, node/disks/failure schedule, ACK ledger hashes, result comparisons and safe artifact paths. No completion claim from tests alone; no product-wide completion until every other plan and final acceptance passes.
