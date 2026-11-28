<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# GitLab integration

Soundpost can hand an incident or an error issue over to GitLab in three ways. All of them are **one way**: Soundpost writes to
GitLab and never reads GitLab's state, comments or assignees back, and nothing is synced or resolved automatically. What leaves
Soundpost is identifiers, a severity and status word, linked entity IDs and a console link. Never a title, note, message, log, stack
or any telemetry text. The API contract is `docs/operations/console-api.md` section 10.

| Way | What it is | Needs |
|---|---|---|
| Copy | The console copies a link, a task description or the incident timeline as Markdown to paste anywhere. | `--public-origin` for the link |
| Bridge | `contrib/gitlab-bridge/`, a small receiver of the signed event webhook that creates and updates GitLab issues. | an event webhook endpoint, a GitLab project token |
| Native create | A button in the console creates the GitLab issue directly from the node. | the organization's GitLab connection |

## Copy (Markdown)

`POST /api/v1/incidents/markdown` and `/api/v1/issues/markdown`, readable by anyone who can read the incident or issue.

* `link`: `<public origin>/#view=incidents&org=<org>&projects=<project>&incident=<project>:<id>` (issues: `view=issues`, `target=`).
  Without a public origin (`--public-origin`, or the origin derived from `--listen`) the answer says `public_origin_not_configured`.
* `description`: identifiers, severity, status, linked entity IDs and the link.
* `timeline` (incident only): every timeline entry in order, with the time in UTC, the type, the actor's ID, the reason, titles, owners,
  links and notes. This is the one copy that contains free text (titles, reasons, notes) because the caller may already read it.
  Every piece of user text is Markdown-escaped and notes are block-quoted, so pasted text cannot inject HTML, links, tables or headings.
  **Pasting never pings or cross-links.** In addition to the Markdown backslash escapes, every GitLab trigger in user text is defused by
  inserting a zero-width space (U+200B), which GitLab does not parse as part of a reference, and which a reader does not see: after
  `@ # ! & % ~ $` (mentions, `#1` issues, `!1` merge requests, `&1` epics, `%milestone`, `~label` and `~"label"`, `$snippet`, and the
  `group/project#1` / `!1` forms), after the colon of `://` and after `www.` (no autolinks; `user@example.com` is cut at the `@`), between
  `[` `[` (wiki links), after the fourth character of a 7 to 40 character hex run (commit SHAs) and before a `/` that starts a text
  (quick actions). `<!-- -->` is escaped by the `<` escape and notes are block-quoted, so no line of a note starts a quick action. The
  zero-width space stays in the pasted text; it is invisible but is part of the text if someone searches for it. Identifiers in code spans
  are not touched (GitLab does not link inside code). The description sent by native create and by the bridge has no field for user text
  at all (identifiers, severity word, status, release ID and a link); the tests assert it.

## Native create

### Connect (organization administrator)

Settings page or `POST /api/v1/gitlab/settings`:

* `base_url`: the https URL of your GitLab (a path prefix such as `https://host/gitlab` is allowed). No credentials, query or fragment.
* `token`: a GitLab project or personal access token with the `api` scope (write-only: it is sealed in the node's control state, never
  shown again, never in an audit entry, a log, an error or an answer; an omitted token keeps the stored one).
* `mappings`: per Soundpost project, the GitLab project (`group/name` or the numeric ID), which entity kinds may be created (`incident`,
  `issue`) and the labels to set.

`test` calls `GET /api/v4/personal_access_tokens/self` and shows whether the token is active, its scopes and its expiry. `disconnect`
removes the connection and the sealed token. Saving and disconnecting need a fresh session (re-authenticated in the last five
minutes), the organization epoch the page read (`expected_epoch`; a concurrent change to the connection is a `409`) and a reason; they
are audited as `gitlab.connection` (the audit never carries the token or the URL), a test result as `gitlab.token_check`.

### Network rules (same as every webhook)

The node refuses to call loopback, private, link-local, unique-local, multicast, CGNAT, reserved and cloud-metadata addresses. A GitLab on a
private network needs an administrator to allow its prefix with `--notify-egress-allow` (loopback, link-local and metadata can never be
allowed). The address is checked when the URL is saved (literals), when the name is resolved and again on the connected socket, on
every call. Redirects are never followed, no proxy is used, TLS 1.2 is the minimum and certificate verification cannot be disabled (extra
trust roots come from `--notify-ca-file`). Calls time out after 10 seconds and answers are cut at 256 KiB.

### Create, exactly once

A GitLab issue is created for an incident or error issue by someone who may write it (`incidents.write` / `issues.write` on the
project, or organization administration). There is at most one GitLab issue per entity, ever:

1. The entity is read; if it already has a link, that link is returned (`created:false`).
2. A durable two-minute **lease** is taken on the entity (`external_begin`, a version compare-and-set on the incident or issue).
   A second create while the lease stands is `409 in_progress`; two concurrent creates make exactly one request.
3. GitLab is asked for an issue whose description holds the entity's marker (`soundpost-ref-<hex>`, derived from the organization,
   kind and ID). The match is made on the description itself, never on the search result alone. **A lookup always comes before a
   create.** If it finds the issue the entity is linked and nothing is created.
4. Otherwise the issue is created with the marker in its description, and the entity is linked (`external_end`).

Outcomes, kept on the entity as a closed code:

* **linked**: the link (GitLab project, issue number, URL) is stored.
* **refused**: GitLab said no (`gitlab_unauthorized` 401, `gitlab_forbidden` 403, `gitlab_not_found` 404, `gitlab_invalid`,
  `gitlab_unprocessable` 422, `gitlab_rate_limited`), or nothing was sent (`gitlab_unreachable`, `gitlab_egress_blocked`,
  `gitlab_tls_failed`, `gitlab_redirect_refused`). Fix the cause and create again.
* **unknown**: the request may have reached GitLab (timeout or a dropped connection after it was written, a 5xx, an answer that is not a
  usable issue, or a crash before the outcome was recorded). Nothing is retried automatically. Press **Recheck** (a lookup by marker that
  links the issue if GitLab has it and never creates) or create again (which looks up first). If you search GitLab yourself and the issue
  is there, either button finds it. If the lease of a crashed attempt is still standing, it expires after two minutes.

`link_from` links an entity to the GitLab issue already stored on another entity of the same organization (for example an incident to the
issue its error issue already has); both entities must be ones you may write.

### What GitLab receives

The title (`Soundpost incident <8 hex>` / `Soundpost issue <8 hex>`, or the one you typed) and a description of identifiers, severity,
status, linked entity IDs and the console link, ending in the marker line. The preview shows exactly this before you create. Text you
type into the description is yours; the server refuses a description that contains a Soundpost marker.

## Bridge

`contrib/gitlab-bridge/README.md`. It consumes the signed event webhook (`docs/operations/console-api.md` section 9, endpoint management
in the console under event webhooks) and needs no connection in Soundpost.

## Operating notes

* Rollback: the connection is an organization setting (`gitlab:connection`) plus a secret of the same name; an older release ignores the
  unknown keys. The link on an incident (`external` member of the incident state) and on an error issue record is a new optional member
  the older release does not read: it starts and ignores it, but it drops the link (and the title and notes) when it stores the record
  again, an error issue's link within seconds of its start. Do not roll back after the first link (`docs/operations/upgrade.md`, "D92 records"
  has the measured behaviour and the recovery by `recheck`). Disconnecting does not remove links already stored.
* Tests use a local stub GitLab. No real GitLab instance has been exercised; run the connection `test` and one create against your own
  instance before relying on it.
