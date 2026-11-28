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
- A project keeps at most 1024 incidents with their state. Only when a new
  incident would exceed that, resolved incidents whose resolution is at least 90
  days old are pruned, oldest first, to make room. Open incidents and recently
  resolved ones are never pruned; if nothing is old enough the new incident is
  refused (`quota`) rather than anything being trimmed silently. A pruned
  incident keeps its identity and version as a stub that holds none of its state
  and reads as erased: the identity is what stops a still-firing episode from
  opening, and notifying for, a second incident. The project keeps the newest
  4096 stubs; a stub older than those is dropped, and only an episode that is
  still current after that many further prunings would open a new incident.
  While the members of a replicated installation are being upgraded, a pruned
  incident is removed instead (the previous rule) until every member declared the
  protocol: `docs/operations/upgrade.md`, "Bounded-state rules across an upgrade".

## Snooze and maintenance

They are different scopes with different history. Both need a reason, record
who set them and expire on their own; the default maximum is 7 days. Both are
ended explicitly with `unsnooze` / `maintenance_end` (a reason is required), and
neither stops ingestion, evaluation or the display of failures. Maintenance
suppresses new notification intents: they are still recorded, with the code
`maintenance`, so nothing disappears silently.

## Actions

`open`, `ack`, `resolve`, `assign`, `impact`, `snooze`, `unsnooze`,
`maintenance`, `maintenance_end`, `link`, `title`, `note`. Every action carries a command ID and
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

## Title, notes, copy and GitLab (console API, decision D92)

- **Title.** An incident may carry a title (1 to 160 bytes after trimming, valid UTF-8, no control character): the `title` action, needs `incidents.write`, version-checked like every action, allowed on open and resolved incidents (it names the incident; it does not change the workflow). The same title again is `409 incident_title_unchanged`. Without a title the console names an incident `Incident <8 hex>`. The audit records that a title was set, never its text.
- **Notes.** The `note` action appends a plain-text note (1 to 2000 bytes, control characters other than a line break refused) to the timeline, on open **and resolved** incidents (post-incident notes). Notes are append-only: there is no edit and no delete. At most 120 of the 128 timeline entries and 64 KiB of note text per incident are used, so a note can never prevent an acknowledge or a resolve (`429 incident_notes_full` / `incident_timeline_full`). Note text lives only in the incident state: a deletion that covers the incident erases it, and it is never copied into an audit record, a notification, an event webhook or a GitLab issue; the Markdown timeline export includes it because the caller can already read it. The console renders note text as text.
- **Copy.** The Copy menu puts a Markdown text built by the server on the clipboard: the console **link**, a **task description** (identifiers, severity, status, linked entity IDs and the link; no title and no note) or, for an incident, the **timeline** in order. All user text in it is escaped, and GitLab's triggers (mentions, references, quick actions, autolinks, commit SHAs) are defused with U+200B so pasting never pings or cross-links. Without the node's public address the link is `not available` (`public_origin_not_configured`).
- **GitLab.** **Create GitLab issue** creates one issue in the GitLab project mapped to the Soundpost project and stores only its link (`docs/operations/gitlab.md`). A second create returns the stored link, an answer that may have been lost is shown as **unknown** and is looked up by its marker before anything is created again, and nothing is read back from GitLab. Connection and project mappings are set by an organization administrator on the GitLab settings page; any member reads them but only an administrator can change them.
- **Event webhooks.** An administrator may subscribe an endpoint to incident and issue events (`incident.opened`, `incident.acknowledged`, `incident.resolved`, `issue.new`, `issue.regressed`, `issue.resolved`, `issue.reopened`, `release.registered`); requests are signed, carry identifiers and links only and are retried through the notification outbox (`docs/operations/event-webhooks.md`).
- **Contracted installations.** Title, notes and the GitLab link are refused with `501 needs_contracted_installation` until the installation is contracted; fresh installations are contracted from the start. After the first such record a rollback to the previous release loses them silently, which is why this is a one-way step (`docs/operations/upgrade.md`).

## Correlation

Incidents that share a linked service, release or error issue are *proposed* as
related. Nothing is merged, and text similarity is never used.

## Effects are intent only

An action records safe audit and outbox intent (for example `notify_open`,
`notify_impact`, `reminders_pause`). Delivering notifications is a separate
step; an incident action never sends anything itself.
