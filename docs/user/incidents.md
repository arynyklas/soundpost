<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Incident response

An incident is the human side of an alert. It is deliberately separate from the
alert condition that raised it and from any error issue it links to, so what a
person decided never hides what the source is doing, and the other way round.

## What an incident keeps apart

| Part | Who changes it | Meaning |
| --- | --- | --- |
| Status `open` / `resolved` | people only | the human workflow |
| Owner | people only | who is working on it |
| ACK (actor, time, impact revision) | people only | pauses reminders only |
| Snooze (reason, actor, expiry) | people only | pauses reminders for a while |
| Maintenance (reason, actor, expiry) | people only | suppresses new notifications for a while |
| Condition state and freshness | the system | `firing`, `recovered` or `unknown`; `fresh`, `stale` or `unknown` |
| Impact episode, severity, revision | the system | how bad it is; the revision rises on every worse impact |

- ACK keeps the condition firing and the incident open. It pauses reminders for
  the impact revision it covers; a later, worse impact has a new revision and
  its own notification intent, ACKed or not.
- When the source recovers, the incident stays acknowledged and open until a
  person resolves it. Missing, stale or partial data is `unknown`, never
  `recovered`: a recovery report from stale data is rejected.
- Resolving needs an explicit reason and does not touch the alert. If the
  source keeps firing after a resolve, the incident keeps showing that, and a
  new episode or a worse impact proposes a new incident linked to the resolved
  one. A resolved timeline is never reopened or rewritten.
- System condition events can never assign an owner, acknowledge or resolve.

## Snooze and maintenance

They are different scopes with different history. Both need a reason, record
who set them and expire on their own; the default maximum is 7 days. Both are
ended explicitly with `unsnooze` / `maintenance_end` (a reason is required), and
neither stops ingestion, evaluation or the display of failures. Maintenance
suppresses new notification intents: they are still recorded, with the code
`maintenance`, so nothing disappears silently.

## Actions

`open`, `ack`, `resolve`, `assign`, `impact`, `snooze`, `unsnooze`,
`maintenance`, `maintenance_end`, `link`. Every action carries a command ID and
the incident version it expects. The actor is the signed-in session, never a
request field.

- The same command ID returns the original result, however often it is retried.
- Two actions that expect the same version cannot both win: the second gets a
  conflict carrying the current version and is never retried automatically as a
  different human decision. Read the incident and decide again.
- Scope and grants are checked before the incident is looked up; an incident
  outside your scope and one that does not exist look the same.
- The audit holds identifiers (who, which action, which incident), never the
  reason text, evidence or raw error messages.

## Correlation

Incidents that share a linked service, release or error issue are *proposed* as
related. Nothing is merged, and text similarity is never used.

## Effects are intent only

An action records safe audit and outbox intent (for example `notify_open`,
`notify_impact`, `reminders_pause`). Delivering notifications is a separate
step; an incident action never sends anything itself.
