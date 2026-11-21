# Single-host durability boundary

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

This implementation owns a single-host, non-HA telemetry WAL and ordered apply state. It is not a claim of implemented Raft, snapshots, segments, physical retention/deletion, backup, restore reconciliation or a qualified power-loss guarantee. Those later gates remain mandatory. Do not enable a distributed deployment by treating the current local lock or fsync as a quorum.

## Explicit control activation at the 01.06 cutover

Opening a control database does not activate a feature write path. Store.Update is unavailable until the actual Raft authority is enabled; no generic local feature-ACK fallback is allowed. Before activation, auth.NewService may only prepare and seal random bearer material and invoke the narrow InitializeBearerHashKey transition on pristine bootstrap state. Existing initialized/versioned authority is never overwritten or regenerated; a missing installed root is corrupt even when the token set is empty.

Auth-only HTTPS/CLI/test compositions explicitly call Store.EnableSingle(ctx, persistentRaftDirectory) after NewService and before Bootstrap, login mutations, administrative writes or other feature traffic. This enables a real one-voter group, not an in-memory fixture. Store.Close owns its group/loopback lifecycle. Restart must reuse the same Raft directory. Full application composition uses its actual control-plus-data activation, then publishes data-initialized state; neither constructor order nor a fixture may acknowledge features before that activation. These setup requirements are distinct from HA/power-loss qualification.

## What an intake acknowledgement waits for

1. Current source credential, scope, registered privacy policy, every record owner and the whole batch are validated.
2. One durable control transaction reserves organization/project/source canonical bytes and canonical-series charge, bound to batch identity/hash, owner slot and policy epoch. Ambiguity does not refund it.
3. The installed one-voter group serializes validation and proposal. It rejects equal-time metric conflicts and terminal job rewrites as a whole batch.
4. The group writes an owned WAL entry and fsyncs that file. A newly created WAL namespace is directory-fsynced before it can acknowledge.
5. A bbolt apply transaction persists admitted records, metric/job ordered state, the original complete receipt, the consumed reservation ID/cursor and the applied cursor. The transaction uses real synchronous bbolt commit, not NoSync or an in-memory substitute.
6. Control verifies the owning group's durable consumption proof and finalizes the existing charge. Credential/policy release checks still precede the returned success.

A failure at write, sync, apply, receipt or applied-cursor publication cannot return a new durable receipt. An uncertain append faults that engine instance rather than continuing behind a possibly committed entry. Restart replays the WAL. A failed post-data control finalize leaves a charged reservation; receipt lookup and an unchanged admission retry can recover the original result. A source policy restriction may require the separate historical lookup rather than a new-admission retry.

## Owned files and recovery

`control.db` remains the protected control authority. The first data adapter uses `data/apply.db` for transactional applied records/receipts/ordered indexes/consumption and `data/slot-NN.wal` for the fixed 64 logical groups. Group identity is installation-owned and persisted in the data authority; it is not derived from a caller's source descriptor or current replica placement.

Control publishes a data-initialized marker only after the data namespace, group identity and recovery are durable. Losing apply.db after that marker denies application startup rather than silently opening a fresh empty engine. An existing data authority missing its group identity or required buckets also denies. Group identity randomness is prepared outside deterministic state callbacks.

WAL v1 headers are 40 bytes, big-endian: magic `SPW1`, uint16 version, uint16 slot, uint32 payload length, uint32 entry CRC32C, uint64 term, uint64 ordered index, uint32 header CRC32C, and four reserved zero bytes. Entries contain the closed normalized input and its original receipt, or a cancellation/source barrier. The header checksum protects length/term/index before allocation or tail repair; the entry checksum covers the header (excluding its entry-CRC field) plus payload. Payload length is bounded at 8 MiB. The local term is 1; later Raft must feed this same apply state rather than introduce another telemetry implementation.

Recovery scans every installed WAL in order, validates magic/version/slot/term/index/length/checksums and replays committed but unapplied entries. It truncates only an incomplete final header or payload, syncs the truncation, and verifies the durable applied cursor is still covered. A checksum mismatch is corruption even in the final complete entry. Missing WAL coverage, interior corruption and unverifiable applied state deny opening the engine; they are not EOF, an empty query result, a newly generated group identity, or a successful repair. The implementation does not truncate acknowledged WAL for snapshots or reclamation.

Original receipt hash/cursor/per-kind deadlines/minimum deadline/dedup deadline persist in the same transaction as apply. Receipt lookup is source-owner authorized but independent of new capture admission. It cannot append, normalize, reserve, recreate rows or extend deadlines. Later data expiry and deletion must preserve this receipt contract and durable deny state.

## Authority side-file ordering (01.01 F5)

`internal/durablefs` is the shared ordering primitive; failures propagate, including unsupported directory flush/rename behavior.

- New data-directory ancestry is published by syncing each new directory and its parent.
- Initial `control.db` namespace publication is flushed before authority use.
- The private bootstrap token's bytes and containing directory entry become durable before the transaction commits its authority hash. Consumption commits first; token unlink is followed by directory sync. An old surviving token cannot restore consumed authority.
- A new envelope decrypt key's bytes and directory entry become durable before any acknowledged database envelope can reference its key ID. Existing key publication is re-established on use; an earlier failed sync is not silently accepted merely because a file exists.
- Rotation durably publishes the new decrypt key, fsyncs the active-pointer temporary file, atomically renames it, and fsyncs the pointer parent before activation acknowledges. Old decrypt keys remain. Missing/malformed key authority never silently acquires a replacement root.
- Generated TLS key and certificate files each receive file and namespace synchronization before HTTPS starts. Existing files are also flushed before use. Partial first-boot TLS identity remains explicit unavailable state; no silent key substitution occurs.

On POSIX, required directory `Sync` errors fail the operation. The Windows implementation calls real directory-handle `FlushFileBuffers` and write-through rename; it does not ignore ERROR_INVALID_HANDLE/access/unsupported errors. A Windows filesystem/privilege combination unable to establish the required namespace ordering is unavailable, including at control boot. This can prevent otherwise functional Windows authentication tests from opening their test store; it must not be worked around with a fake fsync or a production acknowledgement bypass. Linux server durability is the target of the first durability gate. Existing Windows functional results are not power-loss qualification.

Require an operator-owned private data directory, appropriately restricted host/volume access and backups of decrypt material. This change does not administer host ACLs or claim that Unix file mode alone establishes Windows ACL security. Network filesystems, WSL host-mounted filesystems and storage-controller/device write-cache behavior have no power-loss qualification from a process-kill drill.

## Source barriers and quotas

A source policy/revocation operation first commits closing state. The real installed owner drains prior ordered work and fsyncs a barrier to every one of the 64 slots. Only after all durable cursors are recorded does control mark complete. Startup resumes pending source barriers before opening intake. Unavailable groups block completion. Concurrent changes to an already closing source fail instead of overwriting an unfinished saga. Operation history is retained separately from the current source fence.

Cancellation is a distinct durable data entry: while holding the same order lock as append, the owner proves no receipt exists and commits a permanent reservation no-use fence. Control accepts only that installed owner's exact persisted proof, then commits the refund. An append or consumed reservation cannot be cancelled. TTLs and router death are not proofs. Retention/deletion live-charge release and backup/restore reconciliation certificates are later work, not an implied lazy refund.

The one-voter no-commit proof is safe only with the complete recovered ordered prefix plus the fault latch that prevents cancellation after uncertain append/apply errors. A Raft owner at 01.06 must replace that argument with commit-set-watermark evidence including committed-but-unapplied proposals; an absent applied receipt is not sufficient. Lock order is engine order mutex → control read. Owner verification must finish before a control write starts; no control Update/Transact/apply callback may call back into the engine.

Source authority failures use the same content-free forbidden/403 result for invalid, missing, expired or revoked credentials on admission and historical receipts. This does not change browser-session or server/API-token authentication. Historical denial never creates a new write, reservation or data resurrection.

## Parent-owned checks and qualification

From the worktree root on the pinned Linux toolchain:

```sh
GOTOOLCHAIN=local .tools/linux/go/bin/go test ./internal/model ./internal/control ./internal/auth ./internal/httpapi ./cmd/soundpost -count=1
GOTOOLCHAIN=local .tools/linux/go/bin/go test ./internal/ingest ./internal/policy ./internal/storage ./internal/appcore -count=1
GOTOOLCHAIN=local .tools/linux/go/bin/go run ./tools/smoke bootstrap-scope --artifact-dir .superpowers/sdd/approved-product/01.02-03-bootstrap-linux
GOTOOLCHAIN=local .tools/linux/go/bin/go run ./tools/smoke privacy-admission --artifact-dir .superpowers/sdd/approved-product/01.02-03-privacy-linux
GOTOOLCHAIN=local .tools/linux/go/bin/go run ./tools/smoke durable-restart --artifact-dir .superpowers/sdd/approved-product/01.02-03-durable-linux
```

Both new smoke commands launch an actual child HTTPS process with the real application/control/storage, bootstrap and onboard through protected HTTP, append through actual source credentials, observe an HTTP ACK, force-kill, restart, retrieve the identical receipt, deny changed-content retry, and inspect retained typed values including integer histogram count and timestamp `9007199254740993`. Privacy cases exercise unknown optional fields, prohibited payload fields, failed batches, duplicate JSON/invalid UTF-8/overflow, mixed slots, foreign project, record count and gzip expansion. Artifacts contain only observed status/boolean/count metadata; no credentials or request bodies. They scan the private fixture's persisted files for the canary and check rejected batches created neither records nor reservations.

The commands above are acceptance instructions, not an assertion they were run. The implementing worker executed no tests, builds, formatters, smoke or Git commands. Parent verification must record actual results. A passing process-kill/restart drill does not establish power-loss, filesystem, device-cache, HA, snapshot, deletion, backup or disaster-restore qualification.
