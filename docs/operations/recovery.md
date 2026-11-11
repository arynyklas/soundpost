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

`Group.CompactJournal` is the only code that shortens `ready.wal`. It requires a deep-verified selected snapshot, the machine's durable applied index at or beyond the cut, and an in-memory Raft snapshot at exactly the cut. It then writes `ready.wal.compact` (snapshot record, the retained tail, current HardState), fsyncs it, renames it over `ready.wal`, fsyncs the directory, reopens the append handle and compacts the in-memory log. Startup removes a leftover temp file. Because the journal now begins at the snapshot, only the Raft journal **replay** after a restart is bounded by the retained suffix: entries before the cut are never re-proposed or re-applied. That is not the whole cost of starting the engine, which is still O(history) in several places; see "Engine startup cost" below. The completed-command table travels in the snapshot, so a retry after truncation still returns the original receipt and a changed payload under an old ID is still a conflict.

Storage exposes `Engine.CreateSnapshots` (all 64 groups) and `Engine.CompactJournals`. The storage manifest records the verified cuts in `SnapshotCoverage`.

## Engine startup cost

Truncation bounds Raft journal replay. It does not make engine startup independent of history. Read from `internal/replica/{node,ready,install,repair}.go` and `internal/storage/{replicated,manifest,index_integrity}.go`:

**O(retained suffix)**

* Re-applying journal entries. `Group.applyCommitted` skips every entry at or below the machine's durable applied index, so only entries after it run through `slotMachine.Apply`, and entries before a truncation cut are never re-proposed or re-applied.
* `Group.rebuildKnown` indexes the retained in-memory log entries.

**O(history), paid at every start whether or not the journals were truncated**

* Reading the journal. `openReadyWAL` reads and CRC-checks every record. After truncation the first record is the snapshot, whose envelope carries the slot's whole command history (`slotSnapshot.Entries`) and the completed-command table. Truncation bounds the number of retained log entries, not the bytes read: the truncated journal is larger than the untruncated one in the table below.
* Verifying that snapshot record. `Group.restoreSnapshot` calls `slotMachine.VerifySnapshot`, which decodes the whole envelope and byte-compares every command of the slot with `replica_commands` in the apply database. `slotMachine.Restore`, a full `applyTx` replay of every command above the local applied index, runs only if the local database is behind the snapshot (a node rebuilt from a snapshot); that node pays the whole replay once.
* Structural checks over the apply database: `validateReplicaNamespaces` looks up every command key of every slot (`EnableReplication`), and `initStorage` (`Open`) walks every scan-index entry (`validateIndexIntegrity`) and, for every cold segment in the manifest, hashes the whole file and checks its header, so `Open` also costs the size of the cold segments.
* The completed-command (retry) table is serialized into every snapshot envelope and loaded whole into memory. It is pruned only by the dedup horizon owned by retention, so it and the envelope grow with the number of commands inside that horizon.
* Snapshot cuts, the C12 backup evidence (`QuotaEvidence`, the replay interval digests) and `CommitQuotaReconciliation` each re-walk the full history under the engine mutex, so the pause a snapshot cut causes and the memory a backup holds while it seals (a small multiple of the whole command history) grow with history inside the retention window. Bounding these needs per-window digests and an incremental snapshot format; neither exists yet.

**Not part of a plain restart.** The SHA-256 of every byte of the snapshot directory (`SnapshotStore.Verify`) runs when a journal is created from an installed snapshot (no `ready.wal`, `loadInstalledSeed`), when the `CURRENT` pointer is unusable (`repair`), and on every `CompactJournal`. A plain restart that finds `ready.wal` validates the selected snapshot only structurally (manifest, file presence and sizes, ledger parse).

### Measured

`BenchmarkEngineStartup` (`internal/storage/startup_bench_test.go`) builds a real single-voter replicated engine (loopback transport, 64 data groups) holding N committed batches, one metric record each, through `Engine.Append`, closes it, and times the reopen with the steps of `openTestEngine`: `Open`, `EnableReplication`, then registering and campaigning the 64 groups. The same data is measured in three states, each reopened 5 times (median shown): `full` (journals untouched), `trunc` (after `Engine.CreateSnapshots` and `Engine.CompactJournals`) and `flush` (additionally after `Engine.Flush`, so cold segment files exist). Reopen times are milliseconds, median of 5; where two figures are given they are two independent passes (pass 1 / pass 2; N=100 and 500 were measured in pass 1 only).

| N | state | reopen total | Open | EnableReplication | register + campaign | journal entries retained | journal file MB | snapshot MB |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | full | 3037 | 38.8 | 675 | 2343 | 484 | 0.76 | 0 |
| 100 | trunc | 3217 | 32.4 | 878 | 2292 | 320 | 1.08 | 0.68 |
| 100 | flush | 3333 | 35.5 | 879 | 2368 | 704 | 1.35 | 0.68 |
| 500 | full | 3603 | 39.0 | 914 | 2650 | 884 | 2.55 | 0 |
| 500 | trunc | 3386 | 29.6 | 889 | 2474 | 320 | 4.31 | 3.11 |
| 500 | flush | 3199 | 44.2 | 917 | 2283 | 704 | 4.58 | 3.11 |
| 1000 | full | 3171 / 4536 | 46.4 / 51.7 | 847 / 1568 | 2335 / 2994 | 1384 | 4.79 | 0 |
| 1000 | trunc | 3292 / 4840 | 33.0 / 59.1 | 947 / 1943 | 2339 / 2876 | 320 | 8.33 | 6.12 |
| 1000 | flush | 3050 / 4437 | 39.2 / 48.1 | 931 / 1645 | 2042 / 2675 | 704 | 8.60 | 6.12 |
| 2500 | full | 2104 / 4475 | 35.3 / 62.3 | 730 / 1651 | 1339 / 2704 | 2884 | 11.55 | 0 |
| 2500 | trunc | 2032 / 5208 | 37.1 / 70.1 | 676 / 2309 | 1345 / 2932 | 320 | 20.47 | 15.23 |
| 2500 | flush | 2133 / 5313 | 38.1 / 71.6 | 720 / 2349 | 1376 / 2896 | 704 | 20.74 | 15.23 |
| 5000 | full | 4702 / 3843 | 166 / 136 | 2146 / 1405 | 2491 / 2035 | 5384 | 22.79 | 0 |
| 5000 | trunc | 5130 / 3388 | 84.1 / 74.3 | 2232 / 1375 | 2567 / 2039 | 320 | 40.65 | 30.38 |
| 5000 | flush | 5105 / 3945 | 102 / 70.9 | 2289 / 1596 | 2714 / 2318 | 704 | 40.92 | 30.36 |

Retained journal entries are summed over the 64 groups at the last reopen. They include the election entries each start appends, one per group: 64 for the initial start and 64 for each reopen, so `full` holds N + 384 entries and `trunc` holds only the 5 x 64 = 320 appended after the cut. The "journal entries retained" and "journal file MB" columns are deterministic; the times are not.

What the numbers show, and what they do not:

* Truncation does what it promises for the log: retained entries fall from N plus the election entries to the election entries alone (5384 to 320 at N=5000). The journal file does not shrink: it grows by about 1.8x (22.8 to 40.7 MB at N=5000) because the snapshot record repeats the history.
* Reopen time is not visibly lower after truncation at any N. At N=5000 the median total is 4702 / 3843 ms (full) against 5130 / 3388 ms (trunc) in the two passes; the difference is inside the pass-to-pass spread.
* Most of the time is a fixed cost, not history: registering and campaigning 64 groups (an fsync each) took 1.3 to 3.0 s at every N, including N=100, and the 64 group opens in `EnableReplication` took 0.7 to 0.9 s at N=100. Both moved by up to a factor of 3 between passes on the same data because other work was using the same machine (load average 3 to 15 while measuring).
* The N-dependent part is small next to that noise at N up to 5000 and was not resolved by this data. `Open` alone is the least noisy step: it was about 30 to 70 ms up to N=2500 and 71 to 166 ms at N=5000, which agrees with the O(history) index walk above, but it is a small fraction of the total. Do not read the table as a scaling law for larger histories: the journal and snapshot reads (tens of MB at N=5000) and the per-slot byte comparison grow linearly with history, and nothing measured here bounds them.

Caveats: one machine (Intel i9-14900KF, 32 logical cores, 62 GB RAM, WSL2 kernel 6.6.87.2-microsoft-standard-WSL2 on a Windows host, `/tmp` on an ext4 virtual disk whose backing storage was not identified), `go1.27.3`, single voter on a loopback transport, shared with other processes, page cache warm after the build. It says nothing about fsync-bound power-loss latency on real disks, multi-voter catch-up, or histories much larger than N=5000. N=10000 and larger were not measured: building N batches through the real `Append` path takes about 20 minutes at N=5000 (the control-store fixture grows quadratically with N), and setup time is not part of any figure above. This is a local measurement, not a qualification.
The figures in the table above were measured by the implementing worker; the parent read the method and the benchmark source and has not re-run it.

Reproduce: `go test ./internal/storage -run '^$' -bench BenchmarkEngineStartup -benchtime 1x -timeout 5h` (set `SOUNDPOST_STARTUP_BENCH_N=1000,5000` to choose the sizes). Each N prints one line with `full-`, `trunc-` and `flush-` prefixed metrics.

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
| Redact (`Group.RedactCompleted`) | `redact_begin`, `redact_pins`, `redact_write`, `redact_sync`, `redact_switch`, `redact_renamed`, `redact_memory`; the engine adds `redact_replica` before it calls the group |
| Redact the pre-replication WAL (engine, `data/slot-NN.wal` of a node upgraded from the 01.03 layout) | `legacy_wal_begin`, `legacy_wal_write`, `legacy_wal_sync`, `legacy_wal_switch`, `legacy_wal_renamed` |
| Restore | `quota_certificate_persisted` |

An error from a redact hook up to and including `redact_switch` (or a read, temp-file or pin-archive error before the journal rename) is returned without failing the group and the next pass retries it; `redact_renamed`, `redact_memory` and any failure after the journal rename fail the group until restart. The legacy WAL rewrite is streamed into `slot-NN.wal.redact`, fsynced and renamed, so a crash leaves the complete old or the complete new file; a leftover `*.wal.redact` holds no erased byte and is removed by the next pass.

At every hook the tests prove: an ACKed entry is never lost, a retry returns the original receipt, an unacknowledged write is retried rather than duplicated, the selected snapshot (if any) verifies, and a snapshot without a deletion ledger is never selected. Only `*_published` hooks leave the new snapshot selected; all earlier ones keep the old valid directory.

## C12 installation backup and restore

The typed C12 certificate interface lives in `internal/storage/snapshot.go` because no other module defines it yet: `ControlCut` (control checkpoint C: processed highwater H per data group and the reservations control held), `DeclaredGap` (a committed `RecordEvidenceGap`), `ReplayInterval`/`ReplayCertificate`, `QuotaEvidence`, `BackupBundle` and `QuotaReconciliation`.

1. `Engine.BeginBackup(ctx, cut)` requires exactly the 64 owned groups with H not beyond the applied data, and pins every group's committed journal beyond H (`Group.PinJournal`). Truncation archives pinned entries durably before discarding them. A pin carries an owner (the group instance, i.e. the process lifetime that created it) and a lease (`Config.PinTTL`, default 24 h, judged by `Config.Now`) in its durable header, and `Open` re-validates every pin file: a header that never became durable was never a pin and is removed, a pin without a lease or whose lease lapsed is removed, a header that names another pin is refused (`ErrCorrupt`). A pin of a dead process whose lease has not lapsed survives the restart and keeps archiving until the lease lapses (truncation drops an expired pin instead of archiving into it and a backup that still holds it fails closed: `Entries` returns `ErrStale`) or until it is dropped. `Group.Pins()` lists them (`Orphaned` marks those no live backup in this process can hold) and `Group.DropPin(id)` drops one, idempotently; `Engine.JournalPins()` and `Engine.DropJournalPin(id)` are the engine-level adapter over the 64 groups for `internal/backup`'s `PinReaper` (the wiring is described on `JournalPins`). A privacy deletion touching pinned evidence calls `Backup.NoteDeletion`, which aborts the backup so it restarts after the deletion fence; `Group.RedactCompleted` also rewrites the pin archives, so a pin never keeps a redacted payload.
2. `Backup.Seal(ctx, gaps)` cuts D>=H and proves, for every group, that every command in `(H, D]` is either replayable from the pinned journal or inside an exactly matching declared gap. The certificate is re-derived from the command history inside the sealed snapshots. Missing groups, undeclared holes, inexact gaps and altered digests fail the backup; there is no partial success. Consumption and cancellation evidence is derived from the same sealed bytes.
3. `Engine.InstallBackup` installs all 64 snapshots and keeps intake closed (a durable `restore-quota.pending` marker, reloaded by `EnableReplication`) until reconciliation. It re-derives the quota evidence from the installed bytes and refuses a bundle whose evidence differs.
4. `ReconcileQuota` reconstructs exactly one charge per consumed reservation including reservations created after C, releases reservations that D proves cancelled by a committed fence, retains charged reservations that are neither consumed nor fenced (pending intents), and fails on consumed-in-C-without-proof, fenced-and-consumed and cancelled-without-fence. `Engine.CommitQuotaReconciliation` checks the certificate against the bundle and against the series recomputed from the restored project index, persists it, and only then removes the marker. Until then `Append`, receipt lookup and cancellation return unavailable. `QuotaReconciliation.Apply` yields the exact per-key charge for the control quota objects.

## Known limits and open items

* The control snapshot has no deletion ledger of its own beyond the machine hooks of the control group; the data-slot ledger is implemented. The deletion ledger and the restore-authority journal (`retention.BuildLedger`, `Service.Restore`, `CheckpointDeletion`) are implemented by 01.08/01.09: a restore re-imports the authority's tombstones into the restored control state and re-applies their control-state erasure (`control.Store.ImportDeletions`), so a restored backup does not bring back control payloads a completed deletion erased. A backup cut between a deletion's begin and its completion restores the operation as fencing: the import finds it and applies nothing, and the resumed operation erases the restored payloads when it completes. The control Raft journal, its snapshots and retry table of the restored installation hold earlier copies of the control state until the retention worker's pass has run on that node (`Store.RedactRetainedControlCommands`, see docs/privacy/retention.md, "The control Raft journal"): `control_raft_journal` is reported until then. That pass is per voter (each voter redacts its own copy; nothing observes the others) and does not reach a backup cut before it, a pin archive a live backup holds, or a snapshot already shipped off the node; the control group is also compacted by that pass, which keeps no previous snapshot to fall back on until the next cut.
* Artifact quota reservations are not part of the admission-reservation reconciliation. Per-retention live-byte classes do not exist yet, so charges are per quota key only.
* A backup pin archives evidence on the node that took it; a snapshot of another voter is not a substitute.
* The completed-command table inside the envelope still grows with history; bounded dedup horizon pruning belongs to retention.
* The retry table is rebuilt from the selected snapshot on open, so a redaction that reached only the table is repeated after a restart; the engine does so from the stored redacted commands (see docs/privacy/retention.md, "Replication-layer redaction"). A snapshot directory and the snapshot record a compacted journal begins with are sealed and cannot be redacted in place: they are replaced by a later cut (`CreateSnapshot` at an advanced index, `SnapshotStore.DropSuperseded`, `CompactJournal`), and `Group.Residue(floor)` / `Engine.ResidualStores` report them until then.
* A snapshot whose generation is lower than the store's is refused even when its index is higher, with or without a `FENCE` file (`TestSnapshotHigherIndexLowerGenerationIsStaleWithoutAFenceFile`, and at every install crash point). `CompactJournal` refuses a cut the machine has not durably applied (`TestCompactJournalRefusesACutTheMachineHasNotDurablyApplied`).
* Manifest publication (flush, compaction, snapshot coverage) takes no Raft leadership, quorum round trip or group lock (see "Local maintenance on every voter" above). Its remaining limits: the manifest `Term` stays pinned to 1; a publication holds the engine mutex for the whole flush or compaction, so a long segment write delays apply (and therefore heartbeats) of groups with committed entries on that node and maintenance rounds should stay short; it still walks the whole page index (metadata only) under that mutex; and bit rot inside an already published, unchanged segment is detected when the page is read or the node next opens, not at every publication. A failed publication leaves an orphaned new segment file behind (it is never referenced); reclaiming such files belongs to retention.
* Local process kills and loopback tests do not establish durability under power loss, lying fsync hardware or distinct failure domains.
