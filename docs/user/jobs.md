<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Jobs: attempt history, schedules and current health

Soundpost's job model is an owned Apache-2.0 implementation by Aryn Yklas (`internal/jobs`). It keeps four things apart:

| Concept | What it is | Who writes it |
|---|---|---|
| **Definition** | Configured schedule, time zone, grace, maximum runtime | the schedule observer (revisioned) |
| **Run / Attempt** | Immutable evidence of what executed and how it ended | the SDK, through the evidence journal |
| **Observer** | An external clock plus a statement of how complete the data path is | the schedule observer |
| **Current health** | A verdict *derived* from the three above, with the evidence it used | nobody: it is computed |

Job health is independent of alert conditions, error issues and incidents. Nothing here acknowledges, resolves, snoozes or notifies, and an incident acknowledgement never changes a job's health. A job can fail, miss a run, and be healthy again without any of those lifecycles moving.

## Attempts are immutable

An attempt is identified by `(job, run, attempt ID)`. Each SDK event carries a producer epoch and sequence; the exact `(epoch, sequence)` of one attempt is applied once. Consequences:

- Re-delivering any event (journal replay, retry after a crash, restore) is a no-op. Re-sending an identical terminal result from a restarted producer (new epoch) is also accepted without effect on the result.
- `started` and terminal events may arrive in either order and in any interleaving across attempts; the same set of events always yields the same state.
- A terminal result is never rewritten. A second terminal event for the same attempt with a different state or terminal time is rejected with `conflict` and changes nothing. A different start time, ordinal, run or occurrence for a known attempt is also a conflict. Cause trace/error references may be filled in once and are then immutable.
- A retry is a new attempt in the same run. Attempt 1 stays `failed` forever; if the final attempt (highest ordinal) succeeds the run's status becomes `recovered` and current health becomes `succeeded` with reason `run_recovered_after_retry`. Retries sent twice are not counted twice.
- `cancelled` is its own result. It is never success and a later `succeeded` for the same attempt is a conflict.
- Overlap policy is `allow`: a run that starts while another is running is recorded, never dropped or merged. Other policies are rejected as unsupported.

## Schedule occurrences

A scheduled run reports `schedule_occurrence` as the key made by `jobs.OccurrenceKey(timezone, utcInstant, fold)`:

```
s.<scheduled UTC instant, decimal nanoseconds>.f<0|1>.<8 hex digits of the configured zone>
```

The key stays within the SDK alphabet (`[A-Za-z0-9_.-]`, at most 256 bytes). Any other string (for example `manual.<run id>`, which today's Python SDK sends) identifies a manual or unscheduled execution. Such runs are ordered by their earliest attempt start. **Until an SDK or scheduler adapter supplies the scheduled instant in this form, runs are attributed to a schedule window by start time only**: a run that starts at or after an expected instant covers that occurrence (and, if it is the newest run, every earlier one).

Which run is "newer" is decided by the occurrence's scheduled instant (or, for manual runs, start time), never by arrival order. A late failure from an old schedule cannot overwrite the health of a newer successful occurrence; it is appended to history and shown as the older run.

## Schedule definitions

A definition is revisioned by the observer and has an `EffectiveFrom` instant. Revisions are totally ordered, a late older revision is inserted rather than dropped, and an older revision keeps governing the windows before the next revision took effect. A different definition under an existing revision is a conflict.

`Schedule` is a five-field cron expression (minute hour day-of-month month day-of-week) in an IANA time zone. Supported: `*`, numbers, ranges `a-b`, steps `*/n` and `a-b/n`, comma lists; day-of-week `0-7` (0 and 7 are Sunday). When both day-of-month and day-of-week are restricted either matching selects the day. Names (`MON`, `JAN`), macros (`@daily`), seconds and the zone `Local` are rejected. The zone database is embedded in the binary so every node resolves DST identically.

DST semantics (wall-clock time in the configured zone):

- A local time that does not exist (spring-forward gap) is skipped. No run is expected for it, and the health evidence lists it under `skipped_local_times` with reason `nonexistent_local_time_skipped`.
- A local time that occurs twice (fall-back) produces one expected occurrence per distinct UTC instant, with fold 0 for the first and fold 1 for the second. Both have distinct keys.
- The enumeration assumes at most one UTC-offset transition within a day of the wall time.

Grace defaults to 5 minutes (`DefaultGrace`). Maximum runtime is off unless configured. `ObserverStaleAfter` defaults to 10 minutes.

## The schedule observer

A missed run is the *absence* of evidence, so only something with its own clock and an attestation of data completeness can claim it. Each observation carries:

- `ObservedAt`: the observer's clock;
- `CompleteThrough`: the instant through which the data path (source producing, ingest ACKed, journal processed) is attested complete for the job; never later than `ObservedAt`;
- `Healthy`: false when the observer cannot attest anything;
- optionally a definition revision and declared incomplete intervals.

Observations are a join: the newest clock wins, an unhealthy observation beats a healthy one at the same clock, observations never regress, and delivery order does not matter. The service refuses an observation whose clock is more than 5 minutes ahead of the service clock, because a far-future observation would otherwise outrank every later one.

## Current health

`Evaluate(state, at, extraIntervals...)` is pure. Statuses:

| Status | Meaning |
|---|---|
| `succeeded` | The newest run's effective final attempt succeeded and nothing in the evidence undermines that |
| `failed` / `cancelled` | The newest run's final attempt ended that way |
| `running` | The newest attempt started and has no result |
| `running_too_long` | `running` past the configured maximum runtime, judged on the observer clock |
| `late` | An expected occurrence is past its grace with no run yet, its window is still open, and absence is attested complete through the grace deadline |
| `missed` | An expected occurrence's window closed (the next expected instant arrived) with no run, absence attested complete through the window end. Stays `missed` until a run happens |
| `unknown` | The evidence cannot support any other claim |

The rules that keep `unknown` honest:

- No attempts and no overdue schedule: `unknown / no_evidence` (no data yet), never healthy.
- A scheduled job with no observer, an unhealthy observer, or an observer older than `ObserverStaleAfter` cannot be called `succeeded` or `running`: the verdict is `unknown` with reason `no_schedule_observer`, `schedule_observer_unhealthy` or `schedule_observer_stale`. SDK silence is never inferred as success, and SDK/source loss is never inferred as missed.
- `late`/`missed` additionally need `CompleteThrough` to cover the span and no declared incomplete interval overlapping it. Otherwise: `unknown / evidence_of_absence_incomplete`.
- An incomplete interval (observer-declared, or a committed project `RecordEvidenceGap` covering job attempts or all signals) that overlaps the time after the newest attempt's result makes a positive verdict `unknown / evidence_gap_overlaps`. A gap before the attempt's result cannot hide that result and does not downgrade it.
- A negative verdict that was observed (`failed`, `cancelled`, `late`, `missed`, `running_too_long`) is never hidden by incomplete evidence; it is reported with `complete=false` and the reason.

Every verdict carries its `evidence`: occurrence key, run, attempt, attempt state and count, expected instant and window end, cause trace/error references, definition revision, observer state (including `stale`), gap IDs and skipped local times. Cause references are IDs only; reading the trace or error needs its own grant.

The stored `CurrentHealth` in a job state is as of the newest observer observation (no staleness). Reads (`Service.Health`) re-evaluate with the service clock and the project's committed gaps and also return every known interval so unknown stretches of history stay annotated.

## Corrections

`Service.Correct` records an audited later assertion about a terminal attempt: command ID, expected job-state version, attempt ID, an explicit newer correction version, the corrected state and a reason. It requires `policy.write`; the actor is the scope's principal, never a request field. The original terminal event stays untouched; the attempt's *effective* result becomes the newest correction's, and run status and health derive from the effective result. The same version with the same content is an idempotent retry; the same version with other content, or an older version, is a conflict. A correction of a non-terminal attempt is a conflict. Reasons are required, at most 1024 bytes, without control characters.

## Isolation and permissions

Every operation revalidates the opaque scope and then requires the exact permission: `policy.write` for `ApplyAttempt`, `ObserveSchedule` and `Correct` (the journal worker and the observer are real project-scoped service principals), `telemetry.read` for `Health`. A project outside the scope, another organization's job and a job that does not exist all return the same `not_found`. State is keyed by organization, project and job.

## Bounded state

A job state keeps the newest `MaxRetainedRuns` (512) runs. Older runs leave the state with an explicit `compaction` record (count and frontier); the data-group journal remains the complete history. Evidence for a run older than the frontier is ignored with outcome `ignored`. Per run: at most 256 attempts, 16 events and 16 corrections per attempt; at most 64 definition revisions and 256 incomplete intervals per job; exceeding them is `quota`.

## What is wired to real data today

Implemented and tested: the pure reducer (`Reduce`, `ReduceEvent`, `Observe`, `ApplyCorrection`, `Evaluate`, `ExpectedOccurrences`) and the service (`ApplyAttempt`, `ObserveSchedule`, `Correct`, `Health`) against real `auth.Scope` authority, with a control-backed store (`jobs.NewControlStore`, constructed in `internal/appcore/app.go`; the `UpdateJob` handler is `Store.BindJobUpdate`, `internal/control/job_update.go`; per-job state is `ControlState.JobBooks`, `internal/model/control.go`).

Read side: `POST /api/v1/jobs/list` and `POST /api/v1/jobs/view` (`internal/httpapi/jobs_view.go`) return job state with `jobs.Health`.

Still not wired:

- The served node's background runner (`App.JobProducer`, `internal/appcore/producers_jobs.go`) reads the data-group job-attempt journal and calls `ApplyAttempt` under the in-process `system:runner` principal (see `docs/operations/background-workers.md`). No scheduler observer exists to call `ObserveSchedule`: there is no committed source of schedule definitions, so scheduled jobs read `unknown / no_schedule_observer`.
- No HTTP route exposes `Correct`; the SDK sends `manual.<run id>` schedule occurrences.
