# Snapshots, repair and crash-point recovery

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

This describes task 01.07: full-byte snapshots, installation, repair, Raft journal truncation and the C12 backup/restore certificates. Nothing here is a power-loss, distinct-hardware or at-scale qualification. The `snapshot-repair` smoke (`tools/smoke/snapshot.go`) drives real local processes with separate private directories; after the follow-up described under "Local maintenance on every voter" and "Repairing a learner added after a truncation" it passed five consecutive local runs (three voters, three maintenance cycles per node with live receipt retries, destruction of one voter's disk, a fresh learner under a new member id repaired from a snapshot, promotion, restart from truncated journals, exact ACK/value reconciliation).

## What a snapshot is

Every owned group (control and the 64 data slots) cuts its own snapshot at its current applied index, under the group lock, so state, receipts and ledger agree. A snapshot is a directory under `<group directory>/snapshots/`:

| File | Content |
| --- | --- |
| `envelope.json` | Raft snapshot payload: the machine's complete serialized state (for a data slot the whole ordered command history: normalized batches, original receipts, cancellation/source fences, artifact fragments and GC fences), the completed-command table that makes proposals idempotent, membership and the C05 application cursor |
| `ledger.json` | The deletion ledger: every tombstone-class command (source fence, cancellation fence, artifact GC) with its application index and digest, plus the tombstone generation |
| `raft.conf` | Raft configuration at the cut |
| `files/<name>` | Machine-supplied immutable files pinned during the copy. Slot 0 carries the storage manifest and every cold segment (`storage-manifest.json`, `segment-NNNNNN.sps`) |
| `MANIFEST.json` | Checksummed manifest: group, physical index/term, application cursor, ledger generation/count/digest, every file with size and SHA-256, and a SHA-256 over the manifest itself |

Segments and indexes are derived from the command history, which is the authoritative byte set. They are copied as a verified transfer set, and an installed receiver rebuilds typed rows and indexes by replaying the history it received; installed segment files are not adopted as live state.

### When a snapshot is ready

A snapshot is selected only if all of these hold, checked when it is created, when it is installed, at startup repair and again before any truncation:

* the manifest checksum verifies and its file list is exactly the directory content (no missing, extra or resized file);
* every file hashes to its manifest value;
* the deletion ledger exists, parses, belongs to the group, has the manifest generation, strictly ascending indexes not beyond the cursor, and the manifest's count and digest. A ledger of `null` or a missing file is not an empty ledger; an empty ledger is `"entries": []`;
* the envelope's application cursor equals the manifest cursor;
* its ledger generation is not older than the store's generation fence (`RequireGeneration`, called by the restore authority before any data read) or than the snapshot already selected.

Violations return `ErrCorrupt`, `ErrNoLedger` or `ErrStale`/`ErrConflict`. A snapshot that fails any check never becomes `CURRENT`, so a node opened on it refuses to start rather than serving data it cannot prove.

## Creating and installing

`Group.CreateSnapshot(ctx, at)` waits for `at`, cuts under the group lock, pins the machine's files (`FileMachine.PinFiles`) for the duration of the copy and releases them exactly once, even on failure. A storage compaction that retires a pinned segment while it is being copied defers the removal until release. Snapshot directories are written to `tmp-*`, every file and directory is fsynced, the directory is renamed into place and only then is the `CURRENT` pointer replaced by temp-file + fsync + atomic rename + parent fsync. The previous valid directory is kept.

`SnapshotStore.InstallSnapshot(ctx, manifest, reader)` consumes exactly the stream `Snapshot.WriteTo` produces into a fresh `install-*` directory, verifying each file's hash as it is written, refuses a short or over-long stream, validates content and the generation fence, and switches `CURRENT` only after file and directory sync. Installing the snapshot that is already selected is a no-op; a different snapshot at the same index is a conflict. A group opened on an empty journal whose store has a selected snapshot starts from it (deep-verified first), so replay of the committed suffix begins at `index + 1`.

Replacing a node that lost its disk must use a new member identity through the existing learner/joint membership change; a node must not come back under the same Raft identity with less history than its peers recorded. The leader repairs a fresh learner from its snapshot when its journal no longer holds the history.

## Journal truncation

`Group.CompactJournal` is the only code that shortens `ready.wal`. It requires a deep-verified selected snapshot, the machine's durable applied index at or beyond the cut, and an in-memory Raft snapshot at exactly the cut. It then writes `ready.wal.compact` (snapshot record, the retained tail, current HardState), fsyncs it, renames it over `ready.wal`, fsyncs the directory, reopens the append handle and compacts the in-memory log. Startup removes a leftover temp file. Because the journal now begins at the snapshot, restart restores from the snapshot and replays only the suffix; it is no longer O(history). The completed-command table travels in the snapshot, so a retry after truncation still returns the original receipt and a changed payload under an old ID is still a conflict.

Storage exposes `Engine.CreateSnapshots` (all 64 groups) and `Engine.CompactJournals`. The storage manifest records the verified cuts in `SnapshotCoverage`.

## Local maintenance on every voter

A voter's physical layout (storage manifest, segment files, page locations) is node-local: every voter rebuilds it independently from the replicated command history, and clients and peers see only logical contents, through that node's own fenced reads. Publishing a manifest (`Engine.Flush`, `Engine.Compact`, `Engine.Publish`) therefore needs **no Raft leadership, no quorum round trip and no group lock**. A leader, a follower, a node that leads only some groups and a node that has just lost leadership all flush hot pages, rewrite segments, record snapshot coverage and truncate their own journals. An earlier version took a quorum fence and then the lock of every one of the 65 groups, and required the caller to be leader of all of them at once; a follower could never publish and, once leadership was spread across nodes, nobody could.

Which interleavings still need serialization, and what serializes them:

| Interleaving | Serialized by |
| --- | --- |
| publication vs apply of any slot | the engine mutex `e.mu`. `Apply` (called with its group lock held) takes it for the whole bolt transaction; a publication holds it from choosing the pages to relocate until the durable compare-and-swap, so a hot page cannot grow or move while it is flushed and the recorded `Applied` watermarks and `SnapshotCoverage` come from the state that was verified. Lock order is group lock, then `e.mu`; a publication never takes a group lock |
| publication vs snapshot installation (`Restore`) | `e.mu` |
| publication vs snapshot cut (`Snapshot`, `DeletionLedger`, `PinFiles`) | `e.mu` per call. A cut needs its own slot's history, ledger and cursor to agree (the slot's group lock) and one consistent pinned file set (`PinFiles` under `e.mu`); the layout is not part of a slot's state, and a segment retired by a publication is removed only after the last pin is released |
| publication vs journal truncation (`CompactJournal`) | independent: truncation touches only the group's journal and in-memory log under the group lock and requires a verified snapshot, not a manifest revision |
| two publications | `e.mu` plus the compare-and-swap on the manifest revision |

The only fences that remain are those protecting an externally visible effect: `Group.Fence`/`ValidateFence` for workers and external destinations, and the quorum read fence of reads and appends. A publication cannot change `TombstoneGeneration` and cannot drop a retained page, so it can neither delete nor hide data; deletion, retention decisions and anything sent outside the node must be replicated commands, never this local path. The manifest `Term` is an on-disk format constant (always 1), not a Raft term, and has no leader meaning.

Publication cost follows the data published, not the whole store: segments that the previous publication (or the engine's open) already verified are immutable and are carried forward after an existence, size and header check; a new or altered segment is hashed and every page is read back before the manifest can point at it, and only then are retired files removed.

## Repairing a learner added after a truncation

etcd raft refuses to restore a snapshot whose configuration does not contain the recipient. The stored snapshot anchors the truncated journal and predates any member added later, so a fresh learner (a replacement voter under a new id) added after a truncation would ignore every snapshot forever. The leader therefore offers such a recipient a snapshot cut at its applied index with the current configuration (`internal/replica/joinsnapshot.go`). That snapshot is sent only: it is never stored in the in-memory log or the journal, so truncation keeps anchoring on the verified snapshot directory, and it is released once delivered. Startup (`appcore.OpenDistributed`) waits for each group's readiness round until its 60-second startup budget is spent (each round has its own 5-second freshness window, which previously ended startup at the first slow group); intake still opens only after every group answered.

## Crash hooks

`Config.Fault` (the engine's fault function) is called immediately before each step below; an error simulates process death at that step, and nothing is cleaned up in process. `OpenSnapshotStore` removes `tmp-*`, `install-*` and `*.tmp` leftovers and prunes unselected orphans on the next open, and re-selects the newest fully verified directory only when `CURRENT` itself is unusable.

| Phase | Hooks |
| --- | --- |
| Create | `snapshot_cut`, `snapshot_pin`, `snapshot_file_write`, `snapshot_file_sync`, `snapshot_manifest_write`, `snapshot_dir_sync`, `snapshot_switch`, `snapshot_renamed`, `snapshot_current_write`, `snapshot_current_switch`, `snapshot_published` |
| Install | `install_begin`, `install_file_write`, `install_file_sync`, `install_manifest_write`, `install_dir_sync`, `install_switch`, `install_renamed`, `install_current_write`, `install_current_switch`, `install_published` |
| Truncate | `compact_begin`, `compact_archive`, `compact_write`, `compact_sync`, `compact_switch`, `compact_renamed`, `compact_memory` |
| Restore | `quota_certificate_persisted` |

At every hook the tests prove: an ACKed entry is never lost, a retry returns the original receipt, an unacknowledged write is retried rather than duplicated, the selected snapshot (if any) verifies, and a snapshot without a deletion ledger is never selected. Only `*_published` hooks leave the new snapshot selected; all earlier ones keep the old valid directory.

## C12 installation backup and restore

The typed C12 certificate interface lives in `internal/storage/snapshot.go` because no other module defines it yet: `ControlCut` (control checkpoint C: processed highwater H per data group and the reservations control held), `DeclaredGap` (a committed `RecordEvidenceGap`), `ReplayInterval`/`ReplayCertificate`, `QuotaEvidence`, `BackupBundle` and `QuotaReconciliation`.

1. `Engine.BeginBackup(ctx, cut)` requires exactly the 64 owned groups with H not beyond the applied data, and pins every group's committed journal beyond H (`Group.PinJournal`). Truncation archives pinned entries durably before discarding them; pins survive a restart and keep archiving. A privacy deletion touching pinned evidence calls `Backup.NoteDeletion`, which aborts the backup so it restarts after the deletion fence.
2. `Backup.Seal(ctx, gaps)` cuts D>=H and proves, for every group, that every command in `(H, D]` is either replayable from the pinned journal or inside an exactly matching declared gap. The certificate is re-derived from the command history inside the sealed snapshots. Missing groups, undeclared holes, inexact gaps and altered digests fail the backup; there is no partial success. Consumption and cancellation evidence is derived from the same sealed bytes.
3. `Engine.InstallBackup` installs all 64 snapshots and keeps intake closed (a durable `restore-quota.pending` marker, reloaded by `EnableReplication`) until reconciliation. It re-derives the quota evidence from the installed bytes and refuses a bundle whose evidence differs.
4. `ReconcileQuota` reconstructs exactly one charge per consumed reservation including reservations created after C, releases reservations that D proves cancelled by a committed fence, retains charged reservations that are neither consumed nor fenced (pending intents), and fails on consumed-in-C-without-proof, fenced-and-consumed and cancelled-without-fence. `Engine.CommitQuotaReconciliation` checks the certificate against the bundle and against the series recomputed from the restored project index, persists it, and only then removes the marker. Until then `Append`, receipt lookup and cancellation return unavailable. `QuotaReconciliation.Apply` yields the exact per-key charge for the control quota objects.

## Known limits and open items

* The control snapshot has no deletion ledger of its own beyond the machine hooks of the control group; the data-slot ledger is implemented. Retention/deletion (01.08) still has to feed `TombstoneGeneration` and the restore-authority journal; this task provides the fence (`RequireGeneration`) and generation checks only.
* Artifact quota reservations are not part of the admission-reservation reconciliation. Per-retention live-byte classes do not exist yet, so charges are per quota key only.
* A backup pin archives evidence on the node that took it; a snapshot of another voter is not a substitute.
* The completed-command table inside the envelope still grows with history; bounded dedup horizon pruning belongs to retention.
* Manifest publication (flush, compaction, snapshot coverage) takes no Raft leadership, quorum round trip or group lock (see "Local maintenance on every voter" above). Its remaining limits: the manifest `Term` stays pinned to 1; a publication holds the engine mutex for the whole flush or compaction, so a long segment write delays apply (and therefore heartbeats) of groups with committed entries on that node and maintenance rounds should stay short; it still walks the whole page index (metadata only) under that mutex; and bit rot inside an already published, unchanged segment is detected when the page is read or the node next opens, not at every publication. A failed publication leaves an orphaned new segment file behind (it is never referenced); reclaiming such files belongs to retention.
* Local process kills and loopback tests do not establish durability under power loss, lying fsync hardware or distinct failure domains.
