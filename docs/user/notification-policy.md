<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Notification policy

One policy decides, for every issue, alert condition and incident, whether
someone is told now, whether it only goes into the shared queue, and whether it
waits for the daily digest. It is the only place that decides. Exactly one
entity owns the notifications of a problem at any moment, so an issue that is
promoted to an incident cannot be announced twice, and an old sender cannot run
beside the new one.

This page describes the decisions. Delivery (the durable outbox, retries,
SMTP, Telegram and signed webhooks) is separate; the policy only produces
decisions called intents. An intent says what should be sent, to whom and why or
why not. It is never a claim that something was delivered.

## When a problem is urgent

Evidence is grouped in 5-minute windows. The default policy treats a window as
urgent when any one of these holds:

| Rule | Default |
| --- | --- |
| An approved critical operation code occurred | one occurrence is enough, no denominator needed |
| Error rate | at least 20 observed operations **and** at least 5 distinct failures **and** a rate of at least 5% |
| Qualifying regression | at least 5 qualifying occurrences |

Everything below that is `queue`: it still appears in the shared queue at once.

- **Distinct failures.** Counts use deduplicated occurrence IDs. Sending the
  same occurrence again never raises a count.
- **A rate needs a named, complete denominator.** The denominator must be a
  complete operation count for exactly the same window, from fresh data. If it
  is missing, incomplete, for another window, stale, in conflict with another
  denominator for the same window, or smaller than the failures, the rate is
  **unknown**. No percentage is shown, and the critical-code, regression and
  count evidence still reaches the queue and can still be urgent.
- **Exact boundaries.** 100 operations with 5 failures is exactly 5% and urgent.
  101 operations with 5 failures is queue. 19 operations with 5 failures is
  queue. 5 qualifying regression occurrences are urgent, 4 are queue.
- **Counting limit.** A window remembers at most 1024 distinct occurrence IDs
  (the smallest, so the result does not depend on arrival order). A window that
  reaches this is flagged as saturated and its failure count is a lower bound.
- **Late history.** Evidence for a window that closed more than 10 minutes
  before it was processed, and every backfill, is recorded as late history and
  never interrupts anyone. An explicit operator replay is processed as live
  evidence. Evidence for a resolved issue is recorded and only reopens it when
  the issue workflow reports a qualifying reopen.

The thresholds, the approved critical codes and the reminder timings are
editable per project. The values above are the defaults.

## What people are told

| Intent | When | ACK | Snooze | Maintenance |
| --- | --- | --- | --- | --- |
| `open` | once per episode, when it first becomes urgent | sent | sent | suppressed |
| `reminder` | 15 minutes after the opening, then every 60 minutes | paused | paused | paused |
| `worse_impact` | severity rises above the episode peak, or a new critical service is affected | sent | sent | suppressed |
| `recovery` | the source recovered, from fresh data | sent | suppressed | suppressed |
| `resolution` | a person resolved it | sent | suppressed | suppressed |
| `current_state` | a suppression ended and something was held back | sent | n/a | n/a |
| `queue` | any change visible in the shared queue | immediate | immediate | immediate |
| `digest` | daily, see below | sent | held | held |

- **ACK pauses reminders only.** An ACK covers one impact revision. A worse
  impact has a new revision, so it is announced even right after an ACK, and the
  reminders for the new revision start again 15 minutes later.
- **One opening per episode.** Routine repeats stay grouped. A reminder catching
  up after downtime sends one reminder for the latest due slot, then returns to
  the 60-minute grid.
- **Recovery and resolution are different things.** A source recovery says the
  source recovered and leaves the human state open. A resolution says a person
  resolved it and also states whether the source is still firing. Neither is
  ever sent as the other. Unknown or stale data never produces a recovery.
- **The queue is never delayed.** A queue intent is produced at the moment the
  queue-visible state changes, in the same decision, not at digest time. Counts
  that grow inside the same queue state do not repeat it.

## Snooze and maintenance

Both need a reason, an actor, a scope (this entity, the project, or one
service) and an expiry. The default maximum is 7 days. They suppress delivery,
never ingestion, evaluation, the queue or the display of failures.

- A suppressed intent is still recorded, with `disposition: suppressed` and the
  code `snoozed`, `maintenance` or `shadow`. The impact revision still advances,
  so nothing worse is hidden.
- When the last suppression ends (at its exact expiry, or when someone ends
  it), the policy looks at the current state once and sends at most one
  `current_state` update if anything was held back. Replaying the timer, or a
  restart, sends nothing more.
- A scoped window that does not apply to a problem (another service) is ignored.
  A window scoped to one entity applies only to the entity that owns the
  notifications.

## Missing destinations

If nobody is configured to receive a notification, the policy records the
intent as `disposition: failed` with the code `no_destination`. That is a
visible failed delivery, never a success. Disabled and removed recipients are
not destinations.

## Daily digest

Each recipient gets one digest a day at 09:00 in their own time zone (an IANA
name such as `Asia/Kolkata`). A recipient without a zone uses the installation
default, and an installation without one uses UTC. An unknown or malformed zone
is refused with a typed error and is never guessed or silently replaced.

Only non-urgent items that changed since the last digest are included; urgent
items were already announced. Digest identity is one per recipient, local date
and policy revision, so a restart or a replayed timer does not send it twice,
and a new policy revision starts a new identity.

A digest that falls inside maintenance or a snooze is skipped without
consuming its content: the items appear in the first digest afterwards.

Daylight saving time follows the zone rules shipped with the product (a pinned
copy of the IANA data, never the host's). The digest is always 09:00 local:

- A local time that occurs twice (clocks go back) uses its first occurrence, so
  a recipient never gets two digests for one date.
- A local time that does not exist (clocks go forward) is the instant of the
  change, the first moment after the gap, if that is still the same date.
- A date that does not exist at all (for example 30 December 2011 in
  Pacific/Apia) has no digest.
- Times beyond the range of the 64-bit nanosecond clock are refused with a typed
  error instead of wrapping.

## One owner

Every entity of one problem (the issue, the condition, the incident) is linked
to one policy state, and exactly one of them is the canonical owner. Only the
owner's evidence decides urgency, reminders and resolution. Evidence from a
linked non-owner is recorded but sends nothing; evidence from an entity that is
not linked is refused.

Ownership moves only by an explicit cutover that names the owner revision it
expects. A stale revision fails closed, so two writers cannot both win. The
first incident snapshot after a promotion adopts the episode that the issue
already opened; there is no second opening. A cutover can also switch to
`shadow` delivery, which computes every decision (marked `shadow`) without
sending anything, and back to `active`, which reevaluates once.

Every event also carries the policy revision it was produced under. An older
revision is refused, a newer one must bring its configuration.

## What an intent contains

Identifiers, enums, counts and times only: the entity, tier, severity, source
and human state, freshness, the count/rate/regression explanation, the affected
service, the reminder number or the digest identity. Telemetry text, error
messages, occurrence contents and the free-text reasons people give for a
snooze never appear in an intent.

The stable key of an intent is `(org, policy, entity, impact revision, kind,
recipient)` plus an ordinal for kinds that repeat inside one revision (reminder
number, queue revision, digest local date). The same decision always produces
the same key, so replays are idempotent.

## Limits

State per problem is bounded: 3 windows of at most 1024 occurrence IDs, 32
recipients, 8 linked entities, 8 critical services, 16 source cursors and a
ledger of the last 64 decisions. Going beyond a bound is a typed refusal.

The `Late` and `Backfilled` counters are best-effort provenance: a replayed late
event counts again.
