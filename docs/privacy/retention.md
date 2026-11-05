# Retention, deletion, holds and capacity

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

This describes task 01.08 as implemented. Nothing here is a power-loss, distinct-hardware or at-scale qualification.

## Retention defaults (design section 12)

| Signal | Days | Note |
| --- | --- | --- |
| metrics, logs, traces (spans) | 14 | |
| capability and loss reports | 14 | ambiguity: the design names neither; they describe the data they accompany |
| errors, lifecycle conditions, job attempts | 90 | the declared lifecycle evidence journal |
| replay chunks, profile chunks | 7 | a replay checkpoint outlives its own deadline while a retained chunk depends on it |
| restricted raw sources | 1 (24 h) | never longer than 7 days (model validation) |
| source maps / symbols | 90 | or until the last retained error/profile of the same build expires, whichever is later |
| audit | 365 | |

`retention.Defaults()` holds these values; `retention.Resolve` layers the audited, append-only versions in control state (`RetentionPolicies`, organization default then project) over them. A new version only affects batches admitted after its effective time. **Receipts keep the absolute deadlines they were issued with**; a policy change, a disk-pressure event or a restore never recomputes or rewrites a receipt time. Every version records actor, reason and time and appends an audit record (`retention.policy`).

## Capacity (storage/pressure.go)

80% used: warning. 90%: new low-priority batches (spans, replay, profile only) are rejected. 95%: every telemetry admission is rejected, before the consensus/audit reserve is exhausted. Rejections are retryable `unavailable`/`capacity` faults (503). Level changes are recorded in a bounded warning ring (`PressureStatus`), visible through the worker status. **Pressure never expires, trims or compacts away ACKed data and never alters a receipt deadline**: it has no such API. Retry of an already ACKed batch still returns the original receipt. Deletion barriers, control writes, cancellations and maintenance are not subject to telemetry admission pressure, so freeing space by deleting always works. A failing disk meter fails closed (rejects).

## Deletion (C11/C12)

Modes: `retire_org`, `retire_project` (permanent source/read denial), `historical_range` (persistent `[start,end)` predicate per signal; an empty signal list is rejected, never "all"), `entity` (replay/profile/artifact roots; records that merely link a deleted replay are retained and the link resolves as unavailable). There is no arbitrary field-text predicate.

1. **Begin** (`DeleteScope`, one control commit): the org delete generation advances, retirement removes the project/org from the authorizable set, bumps the org policy epoch (every earlier scope dies at revalidation) and retires its sources. Reads of covered data are denied from this instant by control state, before any slot has a barrier. Receipt phase `fencing` (HTTP 202) is not success.
2. **Barriers**: the worker commits a `delete_barrier` in each of the 64 data slots (a replicated `Barrier` entry validated against control). A write ordered before a slot's barrier may be ACKed under the old policy; a matching write ordered after it is rejected at apply and never ACKed; data outside the predicate keeps flowing in the new epoch. Control records every cursor (`RecordBarrier`). An unavailable slot, a failing authority checkpoint or a missing cursor leaves the operation `fencing`; a group is never skipped.
3. **Complete**: only with all 64 barriers and, when off-host backup is enabled, a verified authority checkpoint (`CheckpointDeletion`) whose generation covers the operation. The generation advances again.
4. **Physical cleanup** (separate from logical completion, target 24 h healthy). The worker advances the generation, then, per pass:
   1. erases covered records, artifact roots and their derived rows (one bbolt transaction per batch; the stored command becomes a `batch_redacted` that keeps the original hash and receipt) and rewrites the segments that held them;
   2. **scrubs the free pages of `apply.db`**: bbolt never zeroes a page it frees, so after step 1 the deleted bytes still sat in the raw file. In bounded chunks, each inside its own write transaction, every page the freelist reports free is overwritten with zeros (nothing can reach a free page when no read transaction is open; if one is, the chunk is deferred and the pass reports `ScrubPending`). The owed scrub is a durable counter set by the erasing transaction, so a crash after step 1, or a rerun that finds nothing left to erase, still completes it. Rejected alternative: `bbolt.Compact` into a new file plus an atomic swap needs every one of the engine's ~30 `e.db` users quiesced and a second full copy of the database on disk; the in-place scrub is crash-safe by construction (a failed chunk rolls back, zeroed free pages are harmless);
   3. re-commits the operation's barrier in every group (`CheckpointErasure`, a no-op duplicate: the tombstone row is kept) so the applied index moves, because a snapshot cut at an index the group already has is a no-op and journal compaction at an index it already holds keeps the old snapshot inside the journal; then cuts a verified snapshot, drops every older snapshot directory (`DropSupersededSnapshots`; the store would otherwise keep the pre-deletion snapshot as the "previous" one, with its pinned segment copies) and compacts the journals onto it;
   4. only then records `physical: done`. A veto (hold), an owed scrub or any failure in 1-3 leaves it `pending`/`held` and the next pass retries.

   **Not erased (declared, not hidden):** the replication layer keeps every committed command, original payload included, in an idempotence cache that it writes into every snapshot's `envelope.json` (`completed`) and into the journal's `ready.wal`. Erasure rewrites the machine state and the stored commands, but this cache has no redaction API (`internal/replica` is outside this task), so those copies of the deleted bytes remain after `physical: done`. The receipt says so: `residual_stores: ["raft_completed_entries"]`, reported only once `physical` is `done`. No lag bound is claimed for them; closing this needs a redaction operation in the replication layer. The deletion smoke holds the statement to account: the canary must be found exactly there and in no other store (`apply.db`, segments, snapshot files/state, `control.db` are clean). `control.db` never holds telemetry values (tombstone predicates carry none). Unlinked files and freed blocks may survive on the device below the filesystem; this is not secure deletion of media. Backups and replicas on other nodes erase when their own worker runs; backup expiry is at most 30 days and suppression (the ledger) survives restore. Expiry erasure (no deletion operation, hence no checkpoint) refreshes snapshots and journals only as the groups' applied indexes advance with later writes.

`held`: an active legal hold overlapping the request blocks Begin (receipt `held`, nothing denied or erased). Releasing a hold never starts the deletion on its own; `Resume` (BeginFence) does. A hold placed after logical completion keeps the bytes physically present (receipt `physical: held`) while reads stay suppressed; releasing it lets the next worker pass erase after advancing the generation.

`failed` is terminal for automation; the predicate stays active, nothing is ever un-deleted.

### Delete generation
`retention.Service` implements `auth.DeleteGenerations`: source-lifecycle base plus a durable per-org counter that advances at Begin, at completion, before physical erasure, on artifact GC cancellation, on expiry erasure and on erasure after a hold release. Caches, cursors, live positions and export tickets bound to an older generation die.

### Restore
`BuildLedger` derives the digest ledger plus exact tombstones from control state; the authority stores both on every completion. `Service.Restore(authority)` imports the missing tombstones into the restored control state, records the barrier in every slot and only then opens the engine's restore gate. A restore whose authority is unavailable or unverifiable stays closed. Task 01.09 implements `CheckpointDeletion`/`CurrentDeletionLedger` (and `CurrentDeletionTombstones`) in `internal/backup`.

### Derived effects
`control.EffectSuppressed(state, org, project, kind, at, entity)` must be called by every derived-effect consumer inside the control transaction that would commit the effect. Rules, issues and notifications (plans 06/02) do not exist yet; only this hook is delivered and tested with a fake consumer.

## Evidence journal and gaps
Error, condition and job evidence expires only through `EraseExpired` gated by the lifecycle processing checkpoint. Unprocessed evidence is erased only after a durable `RecordEvidenceGap` (interval, count, signals) commits; expiry never advances a processing checkpoint, and a gap that cannot commit keeps the evidence (`EvidenceHeld`). Journal truncation (`CreateSnapshots` + `CompactJournals`, default hourly) retains the whole history inside the verified snapshot, so it never loses evidence.

## Known limits
Expired-but-unerased data stays readable until the next expiry pass (default hourly). A gap interval is the contiguous index run of the expired candidates and may include non-expired entries between them. Quota charges of erased data are not refunded. While a hold or an open reader keeps `physical` from being recorded, the deleted bytes are still physically present everywhere (reads stay denied). During physical cleanup, until the next snapshot cut, a group has no "previous" snapshot to fall back on.
