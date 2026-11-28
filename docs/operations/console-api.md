<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Console API contract (owner decision D92)

Backend contract for the redesigned console. Status per endpoint: **planned** (contract only), **landed** (in this tree, tests green).
The API lane keeps this file current; the web lane builds against it. Until an endpoint is **landed** the console must show the screen
state honestly (never fake data).

## Conventions (all new routes)

* `POST` with a JSON body, same credential rules as `/api/v1/actions`: browser session + CSRF (`artifactCredential`) or a bearer server
  token. The body never names a scope: `org` and `project(s)` are selectors that the caller's own credential confirms; anything the
  caller may not see answers the same `404 not_found` as a missing thing.
* Identifiers are hex IDs. Nanosecond times and 64-bit counters/versions are **decimal strings** (`"1763719198418220004"`).
* Error body (existing): `{"code":"invalid|forbidden|not_found|conflict|quota|unavailable|...","detail":"<closed token>","request_id":"..."}`.
  `409` on a lost version race carries `current_version` (incident/issue actions, as today).
* List answers share one envelope: `{"org","projects":[ids],"state":"ready|empty|incomplete|stale|not_available","reason":"<closed token>",
  "items":[...],"more":bool,"next_cursor":"<opaque>","sections":[{"name","state","reason"}]}`. `limit` 1..200 (default 50), `projects` 1..16
  (`MAX_PROJECTS`). A cursor is bound to the caller's visibility and the request; a cursor from another request is `400 cursor_invalid`.
  **Unknown or unsupported is never 0**: a number that cannot be stated is `null` with a `*_state` (or section) saying why.
* `window` is `{"start":"<ns>","end":"<ns>"}` (end exclusive), at most 31 days.

## 1. Incident title (landed)

* `IncidentView.title` and `IncidentSummary.title` (queue and investigate): string, `""` when none was ever set (the console shows its own fallback).
* Action `POST /api/v1/actions` with `entity_kind:"incident"`, `kind:"title"`, `payload:{"title":"<text>"}`. 1..160 bytes after trimming,
  valid UTF-8, no control characters (`400 incident_title_invalid`; `incident_reason_invalid` when a `reason` is sent). Needs `incidents.write`
  (or org admin). Version compare-and-set like every incident action (`expected_version`, `409` with `current_version`). Setting the title the
  incident already has is `409 incident_title_unchanged`. Allowed on open and resolved incidents (it names the incident, it does not change its
  workflow). Audited as `incidents.title` (the audit never carries the text). Timeline entry `{"type":"title","title":"<text>"}`.
* `IncidentView.external` and the timeline entries of the link transitions (`external_begin|external_end|external_adopt`, with
  `external:{"provider","kind":"begin|end|adopt","result"?,"project"?,"iid"?,"url"?,"code"?}`) belong to the GitLab group: these actions are
  internal (`incidents.Service`), not on `/api/v1/actions`.
* **Needs a contracted installation (D93):** until the installation is contracted (`docs/operations/upgrade.md`) this write is refused with `501 unsupported` / `needs_contracted_installation` and nothing is written; fresh installations are contracted from the start. Reads are unaffected. **One-way (D94):** the first such record on an installation raises the control-state format marker to 2 before it is committed (a write whose marker cannot be written fails with a retryable `503` and stores nothing); from then on the previous release refuses to start on the data (`schema_newer`), so going back needs a backup taken before the first record.

## 2. Incident timeline notes (landed)

* Action `kind:"note"`, `payload:{"note":"<text>"}`; 1..2000 bytes, valid UTF-8, control characters other than `\n` refused, a blank note refused
  (`400 incident_note_invalid`; `incident_reason_invalid` when a `reason` is sent). Append-only: there is no edit or delete. Allowed on open
  **and resolved** incidents (post-incident notes). Timeline entry `{"version","type":"note","note":"<text>","actor":"<user id>","at":"<ns>"}`.
  Notes (and title and external link entries) may fill at most the timeline minus a reserve of 8 entries (so at most 120 of 128), and the
  notes of one incident hold at most 64 KiB of JSON-encoded text in total (the control group refuses an incident state above 256 KiB; this
  keeps ack/resolve possible in the worst case): a note past either limit is `429 quota` `incident_notes_full`, a title or link past the reserve
  `429 incident_timeline_full`. A note can therefore never prevent ack/resolve. Audited as `incidents.note` (no text in the audit).
* **Privacy:** note text lives only in the incident state. A deletion that covers the incident erases it with the state (the entry carries
  `at`, which is what the deletion window reads; verified with a real range deletion in `TestIncidentTitleAndNotesAreErasedWithTheStateByARangeDeletion`).
  Text is never copied into audits, intents, notifications, event webhooks or the GitLab issue
  description; the Markdown timeline export (below) includes notes because the caller is already allowed to read them.
* Readers of the incident (`POST /api/v1/incidents/get`) see notes. The incident (including its notes) is pruned with the rest of a resolved
  incident's state when the control group prunes resolved incidents (90 days).
* **Needs a contracted installation (D93):** until the installation is contracted (`docs/operations/upgrade.md`) this write is refused with `501 unsupported` / `needs_contracted_installation` and nothing is written; fresh installations are contracted from the start. Reads are unaffected. **One-way (D94):** same as section 1: the first record raises the format marker first, and the previous release then refuses to start.

## 3. Directory: project and user display names for members (landed)

`POST /api/v1/directory` `{"org","projects"?:[ids]}` → `{"org","org_name"?,"projects":[{"id","name"}],"members":[{"id","display_name"?,"email"?,"admin"?,"enabled"?}],"can_set_names":bool}`
(`org_name` is the organization's own name, so the console names the organization for readers that cannot list organizations.)

* Caller must be a member (membership enabled) or admin of `org`; a stranger, another organization's user and a retired organization are the
  same `404`. A server token is refused (`403`). An org admin sees every project and member; anyone else sees only the projects they hold
  any grant on (directly or through an enabled team), and only the members who hold a grant on one of those projects plus the org admins
  (so owners and actors resolve) and themselves. A member whose membership is disabled is not listed for anyone but an admin. `projects`
  (at most 200) only narrows the project list; it never widens it and does not narrow `members`.
* Never returns grants or credentials. **E-mail addresses only to an org admin:** an org admin's `members[]` items also carry `email`,
  `admin:bool` and `enabled:bool` (`enabled` is false for a disabled membership; an org admin is enabled); a plain member's items never
  carry `email`, `admin` or `enabled`. Only users of the organization (members or admins) are ever listed. `display_name` is absent when
  none is set (the console falls back to the short ID).
* `POST /api/v1/directory/names` `{"org","command_id","user","display_name"}` sets (1..80 bytes of UTF-8, no control character, no
  leading/trailing space) or clears (`""`) a display name (`400 display_name_invalid`) → `{"user","state":"set|cleared"}` (the text is never echoed). An org
  admin sets any member's or admin's, a member only their own (`403` for another's, `404` for a user the org does not know, a stranger or a
  disabled member). Idempotent by `command_id` (same id, other content: `409`; another principal's replay: `404`). Audited as `member_name`
  (the audit never carries the text); stored as the organization setting `member_name:<user>`.

## 4. Error-issue owner and reader access (landed)

* Action `entity_kind:"issue"`, `kind:"assign"`, `payload:{"owner":"<user id>"}`; an absent/`null` owner unassigns. The owner must be a member
  or admin of the organization (`400 issue_owner_unknown`; the incident `assign` keeps `400 incident_owner_unknown`). Needs `issues.write` (or
  org admin). `reason` is optional: without one the audit says `owner assigned` / `owner cleared`. Conflict-safe exactly like the other issue
  actions (`expected_version` = issue revision, `409` `issue_version_conflict` with `current_version`, command ID retry returns the original
  result); setting the owner an issue already has, or clearing an unassigned one, is `409 issue_state_conflict`. Audited as `issues.assign`
  (targets: the issue and, when set, the owner ID). A grant on another project, read-only, `incidents.write` and another organization are the
  one `404` a missing issue gets. Assigning works in every workflow (open, resolved, ignored); evidence, resolve, reopen and a regression keep
  the owner.
* `IssueSummary.owner`, `IssueActionView.owner` and `GroupingView.owner` (id, omitted when none). `IssueSummary.external`,
  `IssueActionView.external`, `GroupingView.external` and `IncidentView.external` are the links to an external tracker issue (GitLab group):
  `[{"provider","state":"creating|linked|unknown|refused","project"?,"iid"?,"url"?,"code"?,"at"}]` (never the marker). The external link
  operations are internal (no `kind` for them on `/api/v1/actions`: `400 action_kind_unknown`).
* **Project readers (`telemetry.read`) and `issues.write` holders can read error issues**: `POST /api/v1/investigate` kind `issue`,
  `POST /api/v1/evidence/issue` and `POST /api/v1/evidence/occurrence` read through the issue lifecycle under the caller's own scope (they no
  longer answer `issue_evidence_needs_org_admin` to a reader). A scope that is none of administration, `telemetry.read` and `issues.write`
  (an `incidents.write`-only person) still gets that typed `not_available` answer. An installation that has not bound the issue lifecycle
  answers `issue_evidence_view_not_built` to a reader. Release records stay org-admin as today, except the new release list.
  Cross-organization and cross-project reads are the same `404`; a reader never sees an issue of a project outside their grants. The stored
  occurrence record (stack, message) needs `telemetry.read`: an `issues.write`-only person gets the grouping facts and the occurrence IDs with
  `occurrence_needs_telemetry_read` for the detail (unchanged).
* **Needs a contracted installation (D93):** until the installation is contracted (`docs/operations/upgrade.md`) this write is refused with `501 unsupported` / `needs_contracted_installation` and nothing is written; fresh installations are contracted from the start. Reads are unaffected. **One-way (D94):** same as section 1: the first owner or link record raises the format marker first, and the previous release then refuses to start.

## 5. Lists and search (landed)

Common request: `{"org","projects":[ids],"window"?,"limit"?,"cursor"?,"query"?:"<text>","sort"?:"<kind specific>"}`.

* `POST /api/v1/issues/list` (**landed**) — filters: `workflow:["open","resolved","ignored"]`, `owner:"<id>"|"none"`, `release:"<id>"`,
  `regressed:bool` (an issue counts as regressed when a stored regression evaluation reopened it; the filter is `not_available`
  `regression_not_available` when the lifecycle is not wired), `last_seen_after`/`last_seen_before` (ns, exclusive), optional `window` (on `last_seen`).
  Reader scope: `telemetry.read` on every named project, or `issues.write`, or org admin. `query` matches a hex ID prefix or a case-insensitive
  substring of the title. Item: `{"project_id","issue_id","workflow","revision","owner"?,"title":string|null,"title_state":"ready|not_available",
  "first_seen":"<ns>"|null,"last_seen":"<ns>"|null,"occurrences":"<n>","compacted":bool,"releases":[ids],"releases_truncated"?:true,
  "external"?:[{"provider","state","project"?,"iid"?,"url"?,"code"?,"at"}]}` (`external` replaces the planned `gitlab` member: the
  link summary, never the marker; the first/last seen are `null` only for an issue with no stored evidence). Counts and times are
  `issues.Summarize`, exact across compaction. **The title** is the exception type of the newest retained occurrence (the stored occurrence carries
  no message and the list never carries frames or user data), no control characters, at most 160 bytes cut on a character boundary, read through the storage scan
  under the caller's own `telemetry.read` for that project; without the grant, with the record gone or the reader not wired it is `null` with
  `title_state:"not_available"` and the `titles` section is `incomplete` `titles_not_available`. A request reads at most 256 stored occurrences
  (the titles of its page and the candidates of a title search); when a search reaches the cap the answer is `incomplete` `search_scan_capped` with `more:true` and a
  cursor that resumes after the last examined issue; a candidate whose title cannot be read cannot match and makes a search `incomplete`
  `search_title_unreadable`. Sort: `last_seen` (default), `first_seen`, `occurrences`, all descending, ties by project then issue ID.
  Paging by an authenticated cursor bound to the caller and to the request (everything but `cursor` and `limit`): a cursor of another request, caller or
  scope, a forged or an expired one is `400 cursor_invalid`. Sections: `issues`, `titles`, `regressions` (only with `regressed`).
* `POST /api/v1/releases/list` (**landed**) — filters: `environment:"<id>"`, `deployed_after:"<ns>"` (some marker, in `environment` when given, with
  `last_deployed_at` later than it), `has_regressions:bool` (`regressed_issues` > 0 / = 0; a release whose counts are unknown matches neither),
  `window` (on `build_time`). `query` matches a hex ID prefix of the release or a case-insensitive label substring. Sort: `build_time`
  (default, newest first) or `deployed_at` (latest recorded deploy first; releases without a marker last), ties by project then release ID.
  Paging by an authenticated cursor (cursor of another request or caller: `400 cursor_invalid`). Item:
  `{"project_id","release_id","build_id","label","build_time","parents":[ids],"deploys":[{"environment","deployed_at"}],
  "deploy_state":"known|unknown","new_issues","regressed_issues","resolved_issues","counts_state":"ready|incomplete|not_available"}`.
  `deploys[].deployed_at` is the last recorded time per environment; `deploys` is `[]` with `deploy_state:"unknown"` when nothing was recorded.
  Readable by project readers (`telemetry.read` on every named project, or org admin); the release records are read, never the debug
  artifacts. Counts come from the project's issue evidence the caller may read: `new_issues` = issues whose earliest evidence names this
  release (an issue whose earliest evidence names no release is counted nowhere); `regressed_issues` = issues with a stored regression
  evaluation (eligible or reopened) on evidence of this release; `resolved_issues` = resolved issues listing this release among their
  fixed descendants or resolution frontier. A release touched by issues with folded (compacted) evidence has `counts_state:"incomplete"`
  (the counts are lower bounds). When the issue evidence cannot be read the three counts are `null` and `counts_state:"not_available"`.
  Sections: `releases` (`incomplete` reason `release_scan_capped` past 20000 releases per project), `deploys`, `issue_counts`
  (`incomplete` `issue_evidence_compacted`, `not_available` `issue_counts_not_available`); the envelope `state` is `incomplete` when any
  section is.
* `POST /api/v1/replays/list` (**landed**) — `window` required. Needs `telemetry.read` **and** `replay.read` on every project, else `200` with
  `state:"not_available"` reason `separate_grant_required` and nothing is scanned or probed (the same answer whether or not replays exist); `replay.read`
  without `telemetry.read` is the `404`. Item: `{"project_id","replay_id","session_id":id|null,"first_at","last_at","chunks":"<n>",
  "recording":"complete|partial|gap","gaps":"<n>"}`, newest `last_at` first (`sort`: `last_at` default, `first_at`; ties by project, replay ID), `query` a hex
  prefix of the replay or session ID. Summarised from the stored chunks of the window: `chunks` counts distinct stored sequences, `gaps` counts holes
  between stored sequences plus chunks that report a gap or loss themselves, `recording` is `gap` when `gaps` > 0, `partial` when the first stored
  sequence inside the window is not 1 (the beginning lies outside the window), else `complete` (nothing is missing in what is stored). Times are the chunks'
  wall clock inside the window. `session_id` is `null` when the stored chunks of one replay disagree. Bounded scan (100000 chunks, 5000 replays, 256 MiB):
  past it the answer is `incomplete` `scan_capped`; a shard that did not answer makes it `incomplete` `shards_missing`. Chunk content (nodes, events) is never
  returned here (the stream route stays the only reader).
* `POST /api/v1/profiles/list` (**landed**) — `window` required. Needs `telemetry.read` and `profiles.read` on every project (same typed
  `not_available` `separate_grant_required` / `404` rule as replays). Item: `{"project_id","profile_id","source_id":id|null,"method"?,
  "unit":"samples|nanoseconds|events|unknown","first_at","last_at","coverage":"complete|partial|unknown","unsupported_reason"?}`, newest `last_at` first
  (`sort` `last_at`|`first_at`), `query` a hex prefix of the profile or source ID. **Contract change:** the unit vocabulary is the stored one
  (`samples`, `nanoseconds`, `events`), not `milliseconds`; chunks of one profile that disagree are `unit:"unknown"`. Every profile keeps its own unit.
  `coverage` mirrors the profile view: `partial` when a native chunk sequence is missing or does not start at 1 inside the window, the last native chunk
  is not complete, or any chunk reports loss or truncation; otherwise `complete`. `unknown` (with `unsupported_reason`, never a number) when the profile's
  capability record is not `supported` (its own safe reason code, else `capability_<status>`), is not stored (`capability_not_found`), could not be
  read (`shards_missing`), or the unit/source of its chunks disagree (`unit_unknown`, `unit_mismatch`, `source_mismatch`). Frames, stacks and samples
  are never returned. Same scan bounds and `incomplete` reasons as replays.

## 6. Service RED metrics (landed)

`POST /api/v1/services/red` `{"org","projects","service":"<id>","environment"?:"<id>","window","step_seconds"?}` →
`{"org","service","state","reason"?,"window","step_seconds","rate":{"state","reason"?,"per_second":number|null,"points":[{"t","v":number|null}]},
"errors":{"state","reason"?,"ratio":number|null,"count":"<n>"|null,"points":[{"t","v":number|null}]},
"duration":{"state","reason"?,"p50_ms","p95_ms","p99_ms":number|null,"points":[{"t","p50_ms","p95_ms","p99_ms":number|null}]},
"requests":"<n>"|null,"freshness":{"completeness","watermarks","cached"},"gaps":[{"start","end"}]}`

* Visibility first: the service must be admitted by an active source policy of one of the named projects the caller can read (and, when `environment`
  is named, that policy must list the environment); anything else is the same `404 not_found` as a missing project. Computed under the caller's
  `telemetry.read` from the stored spans of the service in the window (`projects` 1..16, window at most 31 days, `step_seconds` a whole number).
* The samples are the **entry spans** of the service: span kind `server` or `consumer` (a server span usually has a remote parent, so "root" would
  miss the service's own requests). `requests` counts them all. `errors.count` is the spans with status `error`; `errors.ratio` is errors over the
  spans with a finished outcome (`ok` or `error`; `cancelled` and `incomplete` count as requests only). Duration is exact (nearest-rank quantiles) over
  the finished spans scanned, from the monotonic clock when both ends share the clock domain, else the wall clock; an unfinished span has no duration.
* Buckets are `[window.start + i*step, +step)` by span start time. `step_seconds` defaults to window/60 rounded up to whole seconds, at least 10 s;
  more than 120 points is `400 step_invalid`. `t` and gap bounds are decimal-string nanoseconds. A bucket with no sample is a gap: its point is
  `null` (never 0) and consecutive empty buckets are listed in `gaps`. The last bucket may be shorter than the step (its rate uses its real length).
* A window without a sample is `empty` with reason `no_samples` (every number `null`, the whole window one gap). A section with samples but no
  finished span is `empty` `no_finished_spans` for duration only. `incomplete` reasons, in precedence: `scan_capped` (more than 200000 entry spans
  or a read bound), `shards_missing` (a shard did not answer; `freshness.completeness:"partial"`), `spans_sampled` (a stored span carries a sample
  probability below 1, so the counts are those of the stored spans, not request counts). All three sections carry the reason.
* Not wired storage: `not_available` `list_source_not_wired`.

## 7. Deploy timestamps per release x environment (landed)

`POST /api/v1/releases/deploys`:

* `{"op":"record","org","project","release","environment","deployed_at"?:"<ns>","command_id"}` — org admin of the org (the rule of
  `POST /api/v1/releases/register`: `Authorize(OrgAdmin)`), **or a server token that holds `release.write` on the project** (below). The release must exist in the project;
  `environment` is an ID that an **active** source policy of the project lists (`400 deploy_environment_unknown`). `deployed_at` defaults to
  the server clock; it must be > 0 and not later than now + 5 min (`400 deploy_time_invalid`). Recording the same (release, environment)
  again keeps the earliest time (`first_deployed_at`), moves `last_deployed_at` to the latest and counts every recording (`count`, decimal
  string). Answer: the marker `{"project_id","release_id","environment","first_deployed_at","last_deployed_at","count"}`. Idempotent by
  `command_id` (a retry returns the marker, same id with other content is `409`, another principal's replay is `404`). A project keeps at
  most 4096 markers: a new (release, environment) past that is `429 quota` detail `deploy_markers_full`; nothing is dropped and an
  existing marker still counts redeploys. Audited `releases.deploy` (identifiers only); stored as organization setting
  `deploy:<project>:<release>:<environment>`. Recording a marker does **not** move the organization's policy epoch.
* `{"op":"list","org","projects","release"?}` (1..16 projects) → `{"org","projects":[ids],"items":[{"project_id","release_id","environment","first_deployed_at","last_deployed_at","count"}]}`
  for readers (the credential must cover every named project, else `404`). A release with no marker has **no** item: the console says
  "deploy time unknown" (the build time is never presented as a deploy).

**Release pipelines (`release.write`, D93).** A server token never holds `org.admin`. For CI there is one narrow server-token permission,
`release.write`, project-scoped like every token (the token's project list) and issued by an org admin through
`POST /api/v1/admin/tokens/issue` (`"permissions":["release.write"]`; it is not a grant of a person). It allows exactly three things on the
token's projects: `POST /api/v1/releases/register`, `POST /api/v1/releases/deploys` op `record`, and a **public** source-map upload
`POST /api/v1/artifacts` (multipart) under the unchanged artifact policy (size ceiling, type checks, holds, source policy, project confinement;
a manifest with source content is refused, and the principal must hold `artifacts.write` on the project or administer the org). The token's
principal must be an org administrator, exactly as for the human path. A token with `release.write` can do nothing else (no reads, incident or issue
actions, policies, destinations, administration); a token without it (`telemetry.ingest`, `artifacts.write` only, ...) is refused `404` on register and
record; another project or organization is the same `404`; revoked and expired tokens are refused. Issuance is audited as `issue_server_token` (the
reason carries `[permissions: ...]`); every use is audited by the existing `releases.register` / `releases.deploy` rows (principal = the token's
principal). Revoke with `POST /api/v1/admin/tokens/revoke`. `POST /api/v1/admin/tokens/list` `{"org_id"}` (org admin, fresh session) lists the
organization's tokens `{"tokens":[{"id","principal","projects":[ids],"permissions":[...],"expires":"<unix s>","state":"active|expired|revoked"}]}`; never the secret.
**Token registrations are idempotent appends (no control revision needed).** A `release.write` token cannot read the control revision, so for a token
`POST /api/v1/releases/register` ignores `expected_revision` (optional) and the server supplies the revision itself, retrying when only a revision race was lost.
The natural key is the immutable identity `{id, build_id, parents, build_time_ns, debug_artifacts}` plus the `command_id`: a release already registered with
the identical identity (and the label it was first registered with) answers its original receipt and commits nothing; the same `command_id` for another
release, the same release id with other identity fields, or any label change is `409 conflict` (detail `release_conflict`). A rename stays an
administrator action with the entity revision and `expected_revision` (human sessions keep today's strict semantics). `POST /api/v1/releases/deploys` op `record`
never needed a revision: a replay of the same `command_id` returns the same marker without counting again, the same `command_id` with other content is `409`, a new
`command_id` is another recording (`count`+1).

## 8. Related-incident proposals (landed, read-only)

`POST /api/v1/incidents/related` `{"org","project_id","incident_id"}` → `{"proposals":[{"project_id","incident_id","status","severity","shared":[{"kind":"service|release|issue","id"}]}],"more"?:true}`.
Only structured shared links (`incidents.Correlate`), never time or text similarity. No accept/dismiss.

* The scope is the caller's own on the named project (`telemetry.read`, `incidents.write` or org admin, as `POST /api/v1/incidents/get`), derived
  from the credential before any record is read. **Proposals are within the project of the target**: the links an incident carries
  (issue, release and service IDs) are project-local and `Correlate` correlates one project, so an incident of another project (readable
  or not) is never read, named or counted. A missing target, an erased one, another project or organization and a revoked grant are the same
  `404 not_found`.
* Only open incidents are correlated: a resolved target answers `{"proposals":[]}`. `proposals` is never `null`; it is ordered by incident ID
  and holds at most 64 entries (`more:true` when there were further ones). Each entry names the other incident's status and severity and
  the links they share, nothing else (no title, owner or text).
* The body is closed (`org`, `project_id`, `incident_id`); a scope field or an unknown member is `400`.

## 9. Event webhooks (landed)

Events: `incident.opened`, `incident.acknowledged`, `incident.resolved`, `issue.new`, `issue.regressed`, `issue.resolved`, `issue.reopened` (human reopen, not a regression),
`release.registered` (and `test.ping` from the console test button). Delivered through the existing durable fenced notification outbox
(the same claim/lease/complete protocol, retry budget 12 attempts / 24 h, uncertain outcomes kept visible).

Endpoint management `POST /api/v1/events/webhooks` (org admin; same authority as destinations):

* `{"op":"list","org"}` → `{"endpoints":[{"id","name","host","events":[...],"enabled","has_secret","version","secret_rotated_at"?,
  "previous_secret_until"?,"state":"working|retrying|failing|no_deliveries","last_delivery"?:{...}}],"events":[all event names]}`
* `{"op":"save","org","command_id","expected_version","reason","endpoint":{"id","name","url","events":[...],"enabled","secret"?}}` — `url` is https
  without credentials, query or fragment and passes the egress rules of every webhook (no loopback, private, link-local or metadata
  addresses, no redirects). `secret` is write-only, 16..256 bytes; sending a new secret on an existing endpoint **rotates**: the endpoint signs
  with both the new and the previous secret for 24 h (two `v1=` values), then the previous one is dropped.
  `409` on a stale `expected_version`.
* `{"op":"test","org","endpoint","command_id","project"?}` records one test request (admin command `event_test`, audited, idempotent by `command_id`) for
  that enabled endpoint; the leader's next worker pass (default 5 s) creates one `test.ping` delivery to **that endpoint only**, in the feed of `project`
  (the first project of the organization by ID when absent) → `{"state":"requested","endpoint","project"}`. Several requests inside one pass collapse into one ping.
* `{"op":"deliveries","org","endpoint","limit"?}` (1..200, default 50) → `{"org","endpoint","state":"ready|empty|incomplete","reason"?,"deliveries":[{"id","event",
  "entity_kind","entity_id","project","phase","status","code"?,"attempts","uncertain"?,"possible_duplicate"?,"last_outcome"?,"last_code"?,"last_at"?,"next_at"?,"eligible_at"}]}`,
  newest first, read from the outbox of the organization's projects (at most 64; more is `incomplete` reason `projects_capped`).

**Contract changes made when this section landed:** `state` has a fifth word, `pending` (deliveries exist, none attempted yet: neither "working" nor
"no_deliveries" would be true); `events` lists the eight subscribable events (`issue.reopened` added) (`test.ping` is not subscribable); `url` may be left out when saving an existing
endpoint (the console never receives the URL path); `test` takes an optional `project`; list/deliveries answers carry `state`; an endpoint may not reuse the ID of
a notification destination (`event_endpoint_id_taken`) and an organization has at most 32 endpoints (`quota`). Save/test need a fresh human session (like every
administration command); list and deliveries also answer a server token holding `org.admin`. Operator guide: `docs/operations/event-webhooks.md`.

Request to the receiver (`providers` webhook version 1 headers):

```
POST <url>
Content-Type: application/json
Soundpost-Event: issue.regressed
Soundpost-Delivery-ID: <stable hex delivery id>
Soundpost-Timestamp: <unix seconds of this attempt>
Soundpost-Signature: v1=<hex HMAC-SHA256(secret, "<ts>.<delivery-id>.<exact body>")>[,v1=<signature with the previous secret>]
{"version":1,"delivery_id":"..","event":"issue.regressed","occurred_at":"<ns>","org":"<id>","project":"<id>",
 "incident"|"issue"|"release":"<id>","severity"?:"minor|major|critical","release_id"?:"<id>","service"?:"<id>","revision"?:"<n>","url":"<console link>"}
```

**Identifiers and links only**: no title, message, log, stack, note or user text. A retry sends the same bytes and the same delivery ID;
the receiver must deduplicate by delivery ID. `contrib/gitlab-bridge/` is the reference receiver.

## 10. GitLab (landed)

Operator guide: `docs/operations/gitlab.md`.

* **(a) Copy** `POST /api/v1/incidents/markdown` and `POST /api/v1/issues/markdown`: `{"org","project_id","id","format":"link|description|timeline"}`
  → `{"state":"ready|not_available","reason"?,"markdown"?:"..."}`. Reader scope (the same not-found rules as the incident / issue reads; an issue
  is read under `telemetry.read`, `issues.write` or org admin). `link` is the console URL in the hash form of the notifications
  (`<origin>/#view=incidents&org=<org>&projects=<project>&incident=<project>:<id>`, issues `view=issues` and `target=`); without the node's public
  origin the answer is `state:"not_available"`, reason `public_origin_not_configured`. `description` is the task text: identifiers, severity,
  status, linked entity IDs and the link (no title, note or telemetry text). `timeline` (incident only; `400` for an issue) is the timeline in
  chronological order: time (UTC RFC 3339), type, origin, the actor's ID (no directory lookup), reason, title, owner, impact, link, the external
  link operation (provider, kind, result: never a URL or marker) and notes (block-quoted). All user text is Markdown-escaped
  (`\ ` * _ { } [ ] ( ) < > # + - . ! | ~ &`, newlines in single-line fields become spaces), so a copied note cannot inject HTML, links, tables or headings. GitLab triggers are defused too: U+200B is inserted after `@ # ! & % ~ $` (mentions, `#`/`!`/`&` references, `%milestone`, `~label`, `$snippet`, `group/project#1`), after `://` and `www.` (autolinks, e-mails), between `[[` (wiki), inside 7..40 hex runs (commit SHAs) and before a leading `/` (quick actions), so pasting never pings or cross-links (see `docs/operations/gitlab.md`).
* **(b)** `contrib/gitlab-bridge/` consuming section 9 (see its README): verifies the signature (5 minute window, current and previous secret),
  deduplicates by delivery ID (25 h, persisted), `issue.new` and `incident.opened` create a GitLab issue found by a deterministic marker before
  any create, `issue.regressed` adds a note (creating the issue first when absent), every other event is acknowledged and ignored. 2xx only after the
  action succeeded, 5xx on a GitLab failure. No contract change to section 9.
* **(c) Native one-way create** `POST /api/v1/gitlab/issues` (session + CSRF or bearer; the body names no scope):
  * `{"op":"preview","org","project_id","entity":{"kind":"incident|issue","id"}}` (reader scope) → `{"state":"ready|not_available","reason"?,
    "gitlab_project"?,"title","description","labels":[...],"existing":null|{"state","url"?,"gitlab_project"?,"iid"?,"code"?,"from"?:{"kind","id"}}}`.
    `not_available` reasons: `gitlab_not_connected`, `gitlab_mapping_missing`, `gitlab_mapping_kind` (the kind is not in the mapping's `create_from`).
    `existing` is the link stored on this entity, else (incident) the link of a linked error issue the caller can read (`from`).
  * `{"op":"create","org","project_id","entity","command_id","title"?,"description"?,"labels"?:[...]}` — needs `incidents.write` / `issues.write` on
    the project (or org admin); a caller without it, another organization's or project's entity and a missing one are the same `404`. One GitLab issue
    per entity, ever: a second create returns the stored link (`state:"linked"`, `created:false`). `title` 1..255 bytes, no control characters (default
    `Soundpost incident <8 hex>` / `Soundpost issue <8 hex>`); `description` (default: the preview text) at most 8000 bytes and never a
    `soundpost-ref-` marker; `labels` at most 10, replacing the mapping's labels. The marker (`model.ExternalMarker`) is always appended by the
    server. The command ID makes a retry return the first result.
    Answer `{"state":"linked|unknown|refused","created":bool,"url"?,"gitlab_project"?,"iid"?:"<n>","code"?}` (HTTP 200):
    `linked`; `unknown` (the request may have reached GitLab: nothing is retried automatically; the next `create` or `recheck` looks the issue up by
    its marker **before** creating; codes `gitlab_timeout`, `gitlab_canceled`, `gitlab_transport_error`, `gitlab_server_error`, `gitlab_bad_response`,
    `gitlab_link_not_recorded`); `refused` (definite: `gitlab_unauthorized`, `gitlab_forbidden`, `gitlab_not_found`, `gitlab_invalid`,
    `gitlab_unprocessable`, `gitlab_rate_limited`, `gitlab_redirect_refused`, `gitlab_egress_blocked`, `gitlab_tls_failed`, `gitlab_unreachable`
    (nothing was written), and before GitLab is called `gitlab_not_connected`, `gitlab_mapping_missing`, `gitlab_mapping_kind`). `409` with
    `detail:"in_progress"`: another create holds the entity (a durable 2 minute lease; two concurrent creates make exactly one request).
  * `{"op":"recheck","org","project_id","entity"}` (write scope) looks up by marker only and links if found; never creates. Answer as create, with
    `state:"not_linked"` or the stored `unknown` / `refused` state and `code:"gitlab_no_match"` when GitLab has no issue with the marker.
  * `{"op":"link_from","org","project_id","entity","from":{"kind","id","project_id"?}}` (write scope on both entities, same organization;
    `project_id` defaults to the request's) links the entity to the GitLab issue already stored on `from`; `refused` / `gitlab_source_not_linked`
    when `from` has none.
  * The link is stored on the entity (incident timeline entries `external_begin`, `external_end` / `external_adopt`; issue record) and audited
    (`incidents.external_*`, `issues.external_*`). GitLab state, comments and assignees are **never** read back and nothing is synced or auto-resolved.
  * **Needs a contracted installation, and is one-way (D93, D94):** `create` (before the lease, so before GitLab is called) and a `recheck` or `link_from` that would record a link
    answer `501 unsupported` / `needs_contracted_installation` on a non-contracted installation (nothing is stored); the first
    stored link raises the control-state format marker to 2 before it is committed, and the previous release then refuses to start on the data (`docs/operations/upgrade.md`).
  * The description sent to GitLab holds identifiers, severity, status, linked entity IDs and the console link only: never a note, a title of an
    incident or error, or any telemetry text.
* **Settings** `POST /api/v1/gitlab/settings`:
  * `{"op":"read","org"}` (any org member; a non-member is `404`) → `{"connected":bool,"base_host":"host[:port]","mappings":[{"project_id","gitlab_project",
    "create_from":["incident","issue"],"labels":[...]}],"token":{"has_token":bool,"expires_at"?,"scopes"?},"epoch":"<n>","can_edit":bool}` — the
    mappings of the projects the caller can see (an admin sees all), never the token, the URL path or the marker. `epoch` is the value a save
    sends back as `expected_epoch`; `expires_at` (`YYYY-MM-DD`) and `scopes` are what the last `test` recorded.
  * `{"op":"save","org","command_id","expected_epoch","reason","connection":{"base_url","token"?,"mappings":[...]}}` and
    `{"op":"disconnect","org","command_id","expected_epoch","reason"}` (org admin, fresh session). The answer is the read view with
    `state:"committed"`. The token is write-only (sealed in the organization secrets), omitted = keep (a changed `base_url` or a new token clears the
    recorded scopes and expiry). `409` when the connection changed after `expected_epoch` (other organization changes do not conflict). `base_url` is
    https, no credentials, query or fragment (a path prefix is allowed); a loopback, private, link-local or metadata literal is `400 gitlab_egress_blocked`
    unless an administrator allowed the private prefix (`--notify-egress-allow`); names are resolved and checked again at every call; redirects are never
    followed, TLS 1.2 minimum, no proxy. A mapping is `{"project_id" (a project of the organization),"gitlab_project" (path or numeric ID),"create_from":
    ["incident","issue"],"labels":[≤10]}`, at most 64 mappings. Audited as `gitlab.connection` (never the token or the URL).
  * `{"op":"test","org"}` (org admin) → calls GitLab `GET /personal_access_tokens/self` and answers `{"ok","scopes"?,"expires_at"?,"code"?}`
    (`gitlab_token_inactive` for a revoked or expired token); a usable answer is recorded for the settings page (audited `gitlab.token_check`).
* Real GitLab: tests use a local stub server; **no real GitLab instance was exercised**.

## 11. Configuration surfaces (existing endpoints; web builds on these)

| Console page | Endpoint | Who |
|---|---|---|
| Notification destinations | `POST /api/v1/destinations` (`list`/`save`) | org admin |
| Notification (urgency) policy, retention | `POST /api/v1/policies` (`read`/`write`) | `policy.write` / org admin |
| Alert rules | `POST /api/v1/rules` | list: `telemetry.read`; write: org admin |
| Members, grants, teams, SSO, source policies, audit | `POST /api/v1/admin/read`, `POST /api/v1/admin/commands` | org admin |
| Names for members/projects | section 3 | member / admin |

## Status

| Section | Status |
|---|---|
| 1 title | landed |
| 2 notes | landed |
| 3 directory | landed |
| 4 issue owner, reader access | landed |
| 5 lists | landed |
| 6 RED | landed |
| 7 deploys | landed |
| 8 related | landed |
| 9 event webhooks | landed |
| 10 GitLab | landed |
| 11 configuration | existing |
