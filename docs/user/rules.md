<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Alert rules and conditions

An alert rule is evaluated by Soundpost on a fixed schedule against your own stored
telemetry. **Status:** `soundpost serve` starts the background runner
(`docs/operations/background-workers.md`), which evaluates every rule an organization
administrator has saved in the project's rule catalogue (see "Authoring rules" below), opens
conditions and notifies the organization's destinations. Each series the rule's expression
returns becomes an *alert condition*: a record of whether that series is a problem right now
and how far that answer can be trusted. A condition is deliberately separate from the error
issue and the human incident it may be linked to (see `incidents.md`).

## Authoring rules

Rules live in control state, one catalogue per project, and are written over
`POST /api/v1/rules` (the **Rules** section of the project's settings page in the console).
The request is closed: `operation` is one of `list`, `save`, `retire` or `replay`.

| Operation | Who | What it does |
| --- | --- | --- |
| `list` | a reader of the project, or an organization administrator | the project's rules (retired ones included) with each rule's `revision` and `version`, the pinned profiles and feature sets a rule may name, and whether the caller may author |
| `save` | an organization administrator | commits the next version of a rule (`command_id`, `rule_id`, `expected_revision`, `reason`, `rule`) |
| `retire` | an organization administrator | takes a rule out of evaluation; its record and history stay (`command_id`, `rule_id`, `expected_revision`, `reason`) |
| `replay` | an organization administrator | the operator's replay declaration (`rule_id`, `reason`, `replay.from_ns`, `replay.to_ns`); see "Late evaluations and notifications" |

A save is an audited command. The `command_id` is replayed idempotently (repeating it answers
the first result). `expected_revision` is the catalogue revision the author read, `0` for a
rule that does not exist yet: a stale author loses with a `409` instead of overwriting, and a
save made before a retirement cannot silently bring the rule back. The server assigns the
pinned **version** (one more than the previous), so a changed rule is always a new version and
its evaluations are committed under that version. `rules.write` is reserved and authorizes
nothing here: authoring needs organization administration, as destinations do.

Saving is the one moment a rule is judged. The expression is parsed and type-checked under the
pinned profile and feature set, and it must be an instant vector; a rule whose expression does
not parse, gives a scalar, a range or log streams, names an unknown profile or feature set,
carries a severity outside `info`, `warning`, `error` and `critical`, or sets an interval
outside 1 s to 24 h is refused with `400` and nothing is committed. A **recording rule**
(`kind: recording`, with `record_name` and optional `labels`) is also checked against the node's
recording source (see the operations page): the node must have one for the rule's project, and every
configured label must be a value that source's policy enumerates, so a rule that saves is not
one whose output is refused for its labels (`recording_source_unavailable`,
`recording_label_not_allowed`).

A saved rule takes effect at the next background pass and a retired one stops at it. The
commit is audited with the reason (`rules.define`, `rules.retire`, `rules.operator_replay`),
never with the expression, and moves neither the organization's policy epoch nor any
authority. The rules of a project are dropped when the project is retired.

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
notification. An operator can declare a replay window (`operation: replay`, an
organization administrator, audited, committed once however often it is repeated), to let
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
