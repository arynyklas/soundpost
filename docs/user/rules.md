<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Alert rules and conditions

An alert rule is evaluated by Soundpost on a fixed schedule against your own
stored telemetry. Each series the rule's expression returns becomes an *alert
condition*: a record of whether that series is a problem right now and how far
that answer can be trusted. A condition is deliberately separate from the error
issue and the human incident it may be linked to (see `incidents.md`).

## What a rule says

| Field | Meaning |
| --- | --- |
| Expression | a full PromQL or LogQL instant vector under a pinned profile; any other result kind is refused when the rule is saved |
| Interval | the evaluation grid step; evaluations happen at multiples of it, never at the wall clock |
| `for` | how long a series must be continuously present before it fires |
| Recovery hold | how long it must be continuously absent before it recovers; **zero unless you set it** |
| Missing data | `unknown` (default) or `error`: which health is reported when input could not be read completely |
| Severity | carried on every event of the rule |

A series is *present* when it appears in the instant vector, whatever its
numeric value. Presence moves a condition through `pending` (present, `for` not
yet elapsed), `firing`, `recovering` (absent, recovery hold not yet elapsed) and
`recovered`. With the default zero hold a firing condition goes straight to
`recovered` the first time its series is absent in a complete evaluation.

## Missing data is never a recovery

Rule queries never accept partial results. An evaluation is one of:

- **complete**: every input was read to the committed cursors, and the producer,
  loss and evidence-gap checks passed;
- **unknown** or **error**: a timeout, an unavailable or missing shard, stale
  input, a budget stop, or a query error. Nothing was learned.
- **complete but blocked**: the answer is complete, but the input evidence
  behind it is not (stale producer, reported loss, a declared evidence gap).

An unknown, error or blocked evaluation never moves a condition from `firing`
toward `recovered`, never counts as an absent series and never produces a
recovery. What it does produce is explicit freshness on the affected conditions:

| Freshness | Because |
| --- | --- |
| `fresh` | the newest evidence is a healthy, complete evaluation or a definite source event |
| `stale` | `stale_input`, `stale_producer` or reported `loss` |
| `unknown` | `timeout`, `unavailable`, `budget`, `query_error`, `incomplete_result`, `evidence_gap`, an `unknown` event from the source, and the other closed reason codes |

The reason is always one of a closed list of codes: never a query, a label value
or any telemetry text. A condition that is `firing` and `unknown` is still
firing, still counts as active, and is still shown that way. Only later healthy
evidence returns it to `fresh`, and a recovery is only a recovery
when the condition is `recovered` **and** `fresh`.

Missing data changes nothing on an incident: it cannot acknowledge, resolve or
clear an acknowledgment, and it cannot suppress or create a notification.

## Source order

Condition events from a source carry an epoch and a sequence. Soundpost applies
them in that order and not in arrival order:

- an old event cannot overwrite newer state, and a duplicate does nothing, however
  often it is retried;
- the same epoch and sequence with a different payload is a conflict and is
  rejected, never merged;
- a new epoch (a restarted producer or a new rule version) supersedes the
  previous one only if its event time is newer, so an old epoch cannot return;
- an adapter that has no sequence is ordered by event time with a deterministic
  tie rule that never prefers a recovery over a firing, and it can never
  overwrite a newer trusted sequence.

Both the event time and the arrival time of what was accepted are kept.

## Late evaluations and notifications

A rule evaluated on time is *live*. An evaluation computed one interval or more
after its scheduled time is a *backfill*: it updates the lifecycle but never
carries permission to notify, so a late catch-up cannot send a retroactive
notification. An operator can declare a replay window, which is audited, to let
a window of late evaluations notify.

## Only one writer, only the leader

Evaluations and condition changes are written to the control group under the
scheduler leader's lease. A leader that has been deposed is refused, both before
it writes and again by the control state machine if a newer leader has already
written the same condition. A privacy deletion or source closing that covers an
evaluation's data suppresses its pending output before it can change a
condition.

The records Soundpost keeps for rule outputs and condition changes are internal.
They are not notifications and are not delivered anywhere.

## Limits

- At most 4096 conditions per project. Past that, new conditions are refused
  with a quota error rather than evicting the history of settled ones.
- The most recent 16 accepted events per condition are kept for duplicate and
  conflict detection. A replay of an older sequence is treated as old.
