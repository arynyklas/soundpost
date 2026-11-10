<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Investigation reads and what each state means

The investigation console reads Soundpost's own scoped API (`POST /api/v1/investigate`, `GET /api/v1/capabilities`). Every read is authorized by the server for your own account. Choosing an organization, projects, time zone and window in the console is navigation, not access.

## Scope

- The bar at the top of the investigation area always shows the organization, projects, environment, time zone and window the current view was computed for.
- The scope is kept in the address bar as organization/project IDs, nanosecond timestamps, the time zone name and the section. Back and forward restore it. Query text, credentials and telemetry values are never placed in the address.
- Windows are half open: the start is included, the end is not. Timestamps stay exact decimal strings.
- No environment filter exists on the server yet, so every view covers all environments and the bar says so.
- A project or organization that does not exist, that you may not read, or that was revoked is shown as **Not found**. The console cannot and does not tell these apart. Changing scope discards what was loaded for the old scope; a slow answer for an earlier scope is dropped and never drawn.

## States

Every view shows exactly one of these, spelled in words (never colour alone):

| State | Meaning |
| --- | --- |
| Loading | The read for the current scope has not answered. Nothing from any other scope is shown. |
| Ready | The requested data is complete for the window. |
| Empty | The read completed with nothing missing and found nothing. It is not a health signal. |
| Partial | The answer is real but incomplete: some data did not answer, or some parts of the view are not available. Missing data is not zero and not healthy. |
| Stale | The newest data is older than expected. Treat figures as possibly out of date. |
| Not available | The service behind this view (or a separate grant it needs) is not available in this installation. This is never presented as empty or successful. |
| Not found | The selection does not exist or is not available to your account. |
| Signed out | Your session ended. Sign in again. |
| Rate limited | Too many requests; wait and retry. Nothing was changed. |
| Error | The request failed. The request ID shown can be given to your administrator. |

## What is available today

- **Services**: the readable evidence sources of the selected projects, the metric names observed in the window (with freshness and watermarks), and separate sections for health, dependencies and releases. Those three are **Not available**; a service identity cannot be confirmed because services are not registered yet.
- **Trace**: a link is shown only when your scope can resolve the trace; the trace content is **Not available**.
- **Queue and incidents**: every row is a real committed incident, visible as soon as it is committed (not held for a digest). The alert condition (what the source reports), the issue workflow and the incident response (what people decided) are separate badges and timelines. **Issue workflow, delivery attempts, the digest, urgency and unread changes** are **Not available** until their services exist. A missing denominator is shown as **Rate unknown** with the observed count and freshness, never as 0%. Issues, jobs and releases are **Not available**. **Replays and profiles** also need separate grants that do not exist yet, so they are **Not available** without probing for the target.
- **Explore**: **Not available**.
- **Project settings**: the source capabilities your account may read, per project (a project without a readable source is Empty), and the progress of a restriction, revocation or deletion operation you look up by ID. Notification destinations, retention, source policy, SSO and organization/team administration are **Not available**; no destination secret is ever shown.

A restricted raw source appears only to its named readers; other readers of the same project never see it, its counts or its discovery results.

Values from telemetry are shown as plain text; they are never interpreted as HTML.

## Acting on an incident

Assign, acknowledge, resolve, link evidence, report impact, snooze, end a snooze, start maintenance and end maintenance need organization administration of the incident's organization. The actor is always your signed-in account; no field of the request can name another actor, origin or organization.

- Every action names the revision you were looking at. If someone else committed first, the server applies nothing, tells you the current revision and does not retry. Your typed reason stays in the form until you reload the incident and submit again. Nothing is shown as committed before the server acknowledges it.
- If the connection fails after an action was sent, the outcome is **unknown**. **Resend the same request** is safe: the server returns the original result instead of applying the action twice.
- Acknowledging pauses reminders only; the source stays firing and is still shown as firing. A worse impact is still eligible to notify unless an active maintenance window suppresses it.
- Resolving while the source is firing needs a reason and leaves a persistent banner: the incident was resolved by a person, the source was not recovered.
- Snooze and maintenance are separate, expiring, reasoned windows. Neither hides the source, the timeline or ingestion problems.
- Operation progress: **fencing** is pending (reads are denied but the fence is not complete) and is never success; **held** and **failed** are not success; a logically complete deletion is not physical erasure, and the physical and backup deadlines are the real ones the server holds.
