<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Issue evidence, late history and regression

`internal/issues` holds Soundpost's owned recurring-error lifecycle: deduplicated evidence, late history, explainable regression and human issue actions. It is separate from alert conditions, human incidents and notification delivery. A resolved issue regressing is never an alert recovery or an incident state, and acknowledging an incident does not resolve an issue.

## What runs in a served node

A served node wires the whole lifecycle (`internal/appcore`):

| Stage | What it does |
| --- | --- |
| Issue producer | Reads the error occurrences the product ingested, groups them by fingerprint and commits them with the data group's checkpoint (`ApplyThrough`) under the system `issues.write` scope. |
| Journal-expiry producer | Declares a gap (`RecordGap`) for unprocessed error evidence about to expire from the 90-day journal; holds the journal if the gap cannot commit (see below). |
| Incident producer | Opens one incident per open issue episode (the first episode and every regression). |
| Effect producer | Acknowledges the lifecycle's effect intents once they have been acted on (see below). |
| Human actions | `POST /api/v1/actions` with `entity_kind: issue` dispatches `resolve`, `ignore`, `unignore`, `reopen` and `grouping_migration` to `issues.Service.Act`. |

All stages are leader-only and idempotent. The control store (`issues.NewControlStore`) holds issues, the occurrence index, checkpoints, effect intents, command records, gaps and audits; every commit is one control transaction.

## Who may act (decision D20)

Issue actions need `issues.write` on the project; the grouping migration needs `issues.write` **and** `policy.write`. An organization administrator keeps every right and acts as a person (the audit names the administrator). The in-process runner's `org.admin` scope is never an actor of human actions. A caller without the grant gets the same not-found a missing project gets. The lifecycle re-proves `policy.write` itself (`control.Store.AuthorizePolicyWrite`), so the C11 route is not the only gate.

The action answer is the issue as the lifecycle committed it (`issue`: id, workflow, revision, resolution time, fixed descendants, migration links). A stale expected revision is HTTP 409 with detail `issue_version_conflict` and the current version; a transition the workflow forbids at the revision the caller saw is 409 `issue_state_conflict`. While a deletion saga covering the project is fencing, issue actions are refused (retryable 503, detail `deletion_fencing`).

### What the console sends and shows

Every issue action carries a non-empty `reason` (it is the audit record's reason; an empty one is HTTP 400). Only `resolve` may carry `fixed_frontier` (registered release IDs that contain the fix) and `resolution_boundary`. The console sends the revision on screen as `expected_version`, shows nothing as changed until the server answers `state: committed`, then re-reads the stored issue; both 409 details are shown as different facts (a moved revision, or a transition the workflow does not allow).

## Reading an issue: `/api/v1/evidence/*`

All three reads are `POST`, scope-first (a wrong organization, a project the caller does not hold and a missing target are one indistinguishable 404) and need the session's CSRF binding.

| Route | Answer |
| --- | --- |
| `/api/v1/evidence/issue` | Grouping version and hash, workflow and revision, the newest evidence window with counts folded out (`compacted_*`), late history listed apart, and `regression`: the stored regression evaluations of the issue, oldest first. Needs an organization administrator; a project reader is told so (`issue_evidence_needs_org_admin`) and nothing is read. |
| `/api/v1/evidence/occurrence` | Body `{org, project, issue, occurrence}`. The stored error record behind one occurrence the issue lists: `exception_class`, `mechanism`, `handled`, `fatal`, `code`, `template_id`, `build_id`, `release_id`, `trace_id`, `span_id`, `frames` and the exception chain (`exception_graph`: nodes, edges `cause`/`context`/`group`, and the `reasons` a part was not captured). It holds no message text. Reading it needs an organization administrator **and** `telemetry.read` on the project: administration alone never reads telemetry (`occurrence_needs_telemetry_read`). An occurrence the issue does not list is a 404; a record that expired or was erased is `occurrence_not_stored`; a partial storage read is `incomplete` (`occurrence_read_partial`), never proof of absence. |
| `/api/v1/evidence/release` | Release identity, label history, parents and partial-order comparisons, and `regressions`: the stored evaluations whose occurrence ran in this release, each with its issue. |

Regression evaluations are exactly what the lifecycle stored when an occurrence arrived after a resolution (decision, the evaluator's reason, the fix frontier compared with, threshold/window/qualifying, whether it reopened the issue). The `regression` section is `not_available` when no reader is wired, `empty` (`no_regression_evaluated`) when nothing was evaluated, and never a verdict inferred from timestamps or release labels. The frames of a stored occurrence are mapped through the exact source map of the record's own build (`/api/v1/evidence/frames`), which needs the sandbox to be ready (`docs/operations/symbolication.md`).

## Deduplicated evidence

Evidence is keyed by its occurrence ID, which originates at a durable data cursor (group, index), never at a delivery attempt. `ApplyThrough(ctx, scope, cursor, evidence)` applies a batch and advances that data group's checkpoint in **one** store commit together with the issue changes, the occurrence index, effects and audits.

- Evidence at or below the group's checkpoint was already processed, suppressed or declared a gap, and is skipped, so a worker restart or lost acknowledgement cannot reapply it.
- Evidence above the checkpoint is deduplicated by occurrence ID. A retry with the same identity changes nothing and keeps the first arrival time. The same occurrence ID with different identity is a conflict, never a silent merge.
- A crash before the commit leaves nothing; a crash after it replays as a no-op.
- A concurrent commit makes the service reread and reduce again; a human action is never overwritten blindly.

Evidence is routed to the issue with the same grouping version and fingerprint, or a new open issue with a deterministic ID. Evidence under an older grouping version reattaches to the original issue after a migration; migration itself is never run by the reducer.

## Late history and counts

While an issue is resolved, evidence whose event time is at or before the resolution boundary goes to the issue's late history. Counts, first seen and last seen are recomputed from the ledger (`Summarize`) by event time; arrival times are reported as recorded.

## Evidence window

An issue's two ledgers hold at most 1024 evidence records together. When one more would not fit, the oldest records fold into an exact aggregate (count, event and arrival bounds, first event per release, the last 512 occurrence IDs for duplicate recognition) down to 512, and control verifies every fold. The fold does not depend on which side of a resolution boundary the evidence lies: a resolved issue whose post-boundary evidence keeps arriving (a hot fingerprint in a release without the fix) folds it like any other, so it never stalls the data group's checkpoint. The aggregate keeps the first event per release, so the releases observed at or before a later resolution boundary stay exact. A folded occurrence reads as `incomplete` (`evidence_window_compacted`) on the evidence route.

The stored regression evaluations of one issue are bounded by size (192 KiB, pruned down to 128 KiB, against control's 256 KiB): the oldest evaluations that nothing decides by are dropped first. An evaluation that reopened the issue is never dropped (the episode number of its incident counts them), and neither is, while the issue is resolved, an eligible evaluation of the current resolution (it counts toward the reopen threshold).

## Regression

`Regresses(issue, evidence, graph)` is a pure function of the stored resolution facts, the evidence and the release graph (a partial order from 06.01, never version text or time): only a **resolved** issue regresses; evidence at or before the resolution boundary is late history; with a recorded fixed-descendant frontier evidence qualifies only in a frontier release or a descendant; unknown ancestry is reported as `ancestry unknown`, not guessed.

The service reopens the issue when `RegressionPolicy.MinOccurrences` qualifying deduplicated occurrences fall within `Window`. Each post-boundary evaluation is stored as an `Explanation` readable with `Service.Explain`. A reopen also commits one `issue_regressed` effect intent whose ID derives from the occurrence.

## Effect intents

Intents stay in the project's book (at most 256) until a consumer acknowledges them through the control acknowledgement arm (`issues.ControlStore.AckEffects`); an intent that is never acknowledged would make the commit that mints the 257th fail as quota. The effect producer acknowledges an `issue_regressed` intent when the incident of that regression's episode exists, or when that episode can no longer receive one: a later regression superseded it, the issue is no longer open (the incident producer opens one incident per open issue, for its current episode), or the issue or evaluation was erased. An intent of an unknown kind is never acknowledged. Acknowledging touches no issue, ledger, checkpoint or revision.

## Evidence gaps, the 90-day journal and health

The error evidence journal is retained for its declared period. Before unprocessed evidence expires:

1. the journal-expiry producer lists the error occurrences expiring within twice the lead (default lead 24 hours; the listing is cached for 15 minutes);
2. when an unprocessed occurrence expires within the lead, `RecordGap` commits one gap over the contiguous unprocessed run that is expiring, starting exactly at the group's checkpoint, and advances the checkpoint over it in the same transaction; `Health` then reports the project incomplete, never zero or recovered;
3. if the gap cannot commit (control unavailable; a full book of 128 gaps is not a reason, it coalesces, see Bounds), the journal is **held** (`storage.HoldJournal`): the retention worker keeps what no gap covers, and admissions of error evidence for that project are accepted only while a reserve of 64 MiB lasts, then rejected with a retryable `journal_reserve` fault instead of discarding anything. A committed gap releases the hold. The hold is in memory on the leader and is set again on the next pass.

## Deletion and scope fences

Every operation revalidates the scope, checks permission and project, and consults the deletion `Fence` before any state or release graph is read or written. Privacy deletion erases matching stored evidence, explanations and effect intents (`internal/control/erase_issues.go`).

## Bounds

Per project: 256 issues, 4 MiB of issue JSON, 256 effect intents, 128 gaps, 128 data-group checkpoints, 1024 command records. Per issue: an evidence window of at most 1024 records and 256 KiB of explanations.

None of the lists below refuses the project for the rest of its life:

- **Gaps.** The 129th declared gap of a data group is coalesced with the oldest gap of that group (`merged` counts the declarations a gap absorbed): the lost count is the exact sum, the cursor span covers both (evidence processed between them lies inside the span, so a span may overstate where evidence was lost, never how much), and the newest declaration stays as it was. Only a book whose 128 gaps are all of different groups would refuse, and the group bound makes that unreachable.
- **Command records.** The 1025th explicit command (a human action or a gap) evicts the oldest record, by the book revision that committed it. A command ID re-sent after a thousand newer ones is no longer recognized as a retry; the issue's own revision check then refuses a stale action.
- **Explanations.** See "Evidence window" above.
