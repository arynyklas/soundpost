<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Event webhooks

An event webhook tells another system that something changed in Soundpost: an incident opened, was acknowledged or
resolved; an error issue is new, regressed or was resolved; a release was registered. The request carries **identifiers and a
console link only**: no title, message, log, stack, note or user text. API: `docs/operations/console-api.md` section 9.

## Events

| Event | When | Entity member | Extra members |
|---|---|---|---|
| `incident.opened` / `incident.acknowledged` / `incident.resolved` | the incident timeline gets an open, ack or resolve entry | `incident` | `severity`, `service`, `release_id` (first linked), `revision` (timeline entry number) |
| `issue.new` | the issue is seen for the first time | `issue` | `revision` |
| `issue.regressed` | the lifecycle reopened a resolved issue (one event per reopening) | `issue` | `release_id` (release of the regressing occurrence), `revision` |
| `issue.resolved` | a human resolved the issue (from the audit entry) | `issue` | `revision` |
| `issue.reopened` | a human reopened the issue (not a regression) | `issue` | `revision` |
| `release.registered` | a release is registered | `release` | |
| `test.ping` | the console's test button; sent to that endpoint only | `endpoint` | |

Body (version 1): `{"version":1,"delivery_id","event","occurred_at":"<ns>","org","project",<entity member>,"severity"?,"release_id"?,"service"?,"revision"?,"url"}`.
`severity` is `minor|major|critical`. `url` is the console hash link built from the configured public origin. Request headers:
`Soundpost-Event`, `Soundpost-Delivery-ID`, `Soundpost-Timestamp` (unix seconds of this attempt), `Soundpost-Signature`.

`occurred_at` is the incident timeline entry's time for incident events; for issue, release and test events it is the time this node
detected the change.

## Signature and rotation

`Soundpost-Signature: v1=<hex HMAC-SHA256(secret, "<timestamp>.<delivery-id>.<exact body>")>[,v1=<same with the previous secret>]`.
Verify over the exact bytes received, accept a timestamp within 5 minutes, and **deduplicate by `Soundpost-Delivery-ID`**: a retry sends the same
bytes and the same ID with a fresh timestamp and signature, and an uncertain outcome (the receiver may have accepted it) is retried too.
`providers.Receiver` is the reference verifier; `contrib/gitlab-bridge/` is a reference receiver.

Saving an endpoint with a new secret **rotates**: the old sealed secret moves to a previous slot and the request carries two `v1=` values for 24 hours
(judged at the attempt's own time), so a receiver may switch to the new secret at any moment. After that only the new secret signs and the previous one is
removed at the endpoint's next save. A second rotation inside the window replaces the previous slot. Secrets are write-only (16..256 bytes), sealed in control
state, and never in a response, audit entry, outbox body or log.

## Delivery

Events use the notification outbox: the same claim, lease, fence and complete protocol; 12 attempts or 24 hours; accepted only with a receipt; an
unknown outcome stays visible (`uncertain`). The sender follows the egress rules of every webhook (https only, no credentials or query in the URL, no loopback,
private, link-local or metadata addresses, no redirects, bounded responses, `--notify-egress-allow` for private prefixes), with the outcomes table of
`notification-channels.md`. A closing deletion that covers an event's time pauses its delivery and a completed one cancels it, as for notifications. While a
project's notification ownership cutover is not `new_active`, event deliveries are recorded as suppressed (`shadow`) and not sent.

An event endpoint is a destination of type `event_webhook` and is **never** a notification route: normal incident and condition notifications go to
smtp, telegram and webhook destinations only, and an event goes only to the event endpoints that subscribe to it (enforced at routing, at the dispatcher and at
every provider). Event endpoints do not appear in `/api/v1/destinations` or the policy view; each organization has at most 32.

## How events are produced

The leader's worker runs an event producer for every project (after the issue and incident producers). It compares committed incidents, issues and releases
with a durable per-project feed (`event:feed`, a policy state of the outbox) and commits the new feed and one delivery per (event, subscribed endpoint) in one
fenced transaction; delivery IDs are deterministic (event identity and endpoint), so a replayed pass, a second leader or a crash between commit and next pass
creates nothing twice and loses nothing.

* The **first pass of a project is a baseline**: what exists is recorded silently, so enabling the feature never floods history. Events that happen before
  the producer first sees a project are not announced.
* Events are produced whether or not an endpoint subscribes (the feed always advances), so an endpoint added later receives only later events.
* **Events come from committed history, not snapshots:** incident events from the timeline entries, `issue.resolved` / `issue.reopened` from the append-only audit log
  (the feed keeps an audit cursor; the baseline starts at its current length), `issue.regressed` from the lifecycle's reopening records, `issue.new` and
  `release.registered` from first sight. A resolve and a regression (or a reopen) inside one pass interval are all announced, each once, under distinct delivery IDs.
  Only `issue.new` and `release.registered` are detected by presence, so an entity created and gone inside one interval is never seen.
* One commit carries at most 64 deliveries; a larger burst drains over the next commits and passes, in order.
* **Bounds:** the feed state is at most 240 KiB: marks for at most 1100 incidents, 300 issues, 1536 releases and 64 test requests, pruned to the live entities
  (control itself bounds incidents to 1024 and issues to 256 per project). Past the incident or issue bound an entity is not announced until room exists and the
  pass reports `quota` (`event_feed_full`). The release set evicts its oldest build time and never announces a release at or below the evicted build time
  (the "floor"); a project with more than 1536 releases at the first pass announces none of the surplus.
* A test request (`event_test` setting) is handled once per request by the producer of its project; a request pending before the first pass is not replayed.

## Operating

* `POST /api/v1/events/webhooks` `list` shows per endpoint one state word: `working` (newest attempted delivery accepted), `retrying`, `failing` (failed or
  uncertain), `pending` (nothing attempted yet) or `no_deliveries`. `deliveries` lists the recent deliveries with phase, attempts, `uncertain` and the closed code.
* Rolling back to a release without this feature: a stored `destination:` setting with the new members is read by the old release (unknown members ignored on read)
  but an old release's save of such a destination is refused (strict decode); the `event:feed` policy state is skipped only by releases that know the subject, so
  roll back only after disabling or deleting the event endpoints.
* Not exercised: no real third-party receiver was used; tests use local TLS receivers and the reference Receiver.
