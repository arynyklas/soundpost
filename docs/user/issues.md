<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Issue evidence, late history and regression

`internal/issues` holds Soundpost's owned recurring-error lifecycle: deduplicated evidence, late history, explainable regression and human issue actions. It is separate from alert conditions, human incidents and notification delivery. A resolved issue regressing is never an alert recovery or an incident state, and acknowledging an incident does not resolve an issue.

**Wiring status.** The reducer, regression decision, checkpoint, gap and action logic are implemented and tested against narrow consumer-owned interfaces (`Store`, `GraphSource`, `Fence`, `PolicyAuthorizer`, `Migrator`, `Clock`) using an in-memory fake store. They are **not yet bound to the C05 control store, the data journal worker or the C11 action dispatcher**: the control `ApplyIssueEvidence` handler currently implements only the 06.01 grouping migration, and `internal/app` composition does not yet construct the service. Until that binding exists no production data reaches this package.

## Deduplicated evidence

Evidence is keyed by its occurrence ID, which originates at a durable data cursor (group, index), never at a delivery attempt. `ApplyThrough(ctx, scope, cursor, evidence)` applies a batch and advances that data group's checkpoint in **one** store commit together with the issue changes, the occurrence index, effects and audits.

- Evidence at or below the group's checkpoint was already processed, suppressed or declared a gap, and is skipped, so a worker restart or lost acknowledgement cannot reapply it.
- Evidence above the checkpoint is deduplicated by occurrence ID. A retry with the same identity (record ID, origin cursor, grouping version, fingerprint, event time) changes nothing and keeps the first arrival time. The same occurrence ID with different identity is a conflict, never a silent merge.
- A crash before the commit leaves nothing; a crash after it replays as a no-op. A torn store that applied evidence but not the checkpoint still cannot double count, regress or emit a second effect: the effect ID derives from the occurrence.
- A concurrent commit makes the service reread and reduce again; a human action is never overwritten blindly.
- The batch must lie in the cursor's group at or below the cursor. A cursor behind the checkpoint never moves it back.

Evidence is routed to the issue with the same grouping version and fingerprint, or a new open issue with a deterministic ID. Evidence under an older grouping version reattaches to the original issue after a migration; migration itself is never run by the reducer.

Evidence keeps event time, arrival time (receipt, never rewritten), release/build, ancestry knowledge, producer epoch/ordinal, freshness and an optional named denominator (window, count, completeness, cursors). Denominators are stored verbatim; this package computes no rates.

## Late history and counts

While an issue is resolved, evidence whose event time is at or before the resolution boundary goes to the issue's late history. Counts, first seen and last seen are recomputed from the immutable ledger (`Summarize`) by event time; arrival times are reported as recorded.

## Regression

`Regresses(issue, evidence, graph)` is a pure function of the stored resolution facts, the evidence and the release graph (a partial order from 06.01, never version text or time):

- Only a **resolved** issue regresses. Ignored and open issues keep counting but are never "recovered" or reopened by evidence.
- Evidence at or before the resolution boundary is late history and never qualifies.
- With a recorded fixed-descendant frontier, evidence qualifies only in a frontier release or a descendant. Without one, evidence qualifies in a release that is the same as, or a descendant of, an observed resolution release. Older and concurrent releases do not qualify.
- Unknown ancestry (unversioned, source-declared unknown, or a release the graph cannot place against the frontier) is reported as `ancestry unknown`, not guessed. After the explicit event-time boundary it qualifies; at or before the boundary it is history.

The service reopens the issue when `RegressionPolicy.MinOccurrences` qualifying deduplicated occurrences (default one) fall within `Window` event-time nanoseconds (default unbounded). Each post-boundary evaluation is stored as an `Explanation` (occurrence, release, event time, decision with reason/frontier/ancestry-known, resolution boundary, threshold, window, qualifying count, reopened) readable with `Service.Explain`. A reopen also commits one `issue_regressed` effect whose ID derives from the occurrence. These effects are intents in the commit; no notification is sent by this package.

## Human actions

`Service.Act` takes an `IssueAction` (command ID, expected issue revision, issue ID, kind, reason, optional resolution boundary and fixed-descendant frontier). The actor and organization come from the scope, which must be a revalidated `issues.write` scope for the issue's project; a scope with only another permission is forbidden, and another organization's issue is indistinguishable from a missing one.

- `resolve` (open only): the boundary defaults to admission time, may not be in the future or precede recorded evidence; the observed release set at the boundary becomes the resolution frontier; frontier releases must exist in the project's graph. `ignore` (open or resolved), `unignore` (ignored to open) and `reopen` (resolved to open) clear resolution facts as applicable. Any other transition is a conflict.
- A reason is required. The command, actor, reason and frontier are audited in the same commit.
- A stale expected revision is a conflict. Evidence changes the issue revision, so a human acting on a revision that evidence has since changed must reread.
- A command ID retries to the stored result; reusing it for a different action is a conflict.
- `grouping_migration` additionally requires project `policy.write` (checked through `PolicyAuthorizer`) and the migration's source revision, and delegates to the 06.01 migration through `Migrator`.

## Evidence gaps and health

`RecordGap` commits a declared gap (interval of a data group that expired unprocessed) together with the checkpoint advance over it, and only if the gap starts exactly at the current checkpoint. A denied or failed commit advances nothing. After a gap, `Health` reports the project as incomplete; it is never reported as zero or recovered.

## Deletion and scope fences

Every operation revalidates the scope, checks permission and project, and consults the deletion `Fence` before any state or release graph is read or written.

## Not implemented here

Production binding to the control store, journal worker and C11 dispatch; rate computation and urgency policy; notification delivery; the 90-day journal expiry scheduler that decides when to record a gap; privacy-deletion suppression of already stored evidence (only the fence at the boundary exists here).
