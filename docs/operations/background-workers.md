<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Background workers

The leader-only background work of a node lives in `internal/appcore/workers.go`
(`App.NewWorkers`, `App.RunWorkers`, `Workers.Run`, `Workers.Tick`). It drives,
per project, the modules that are otherwise only libraries: the rules scheduler,
evaluator and committer (`internal/rules`), the recording output worker, the
condition consumer (`internal/conditions`) and the notification outbox and
delivery worker (`internal/notify`). For the delivery semantics see
[delivery semantics](delivery-semantics.md); for who owns notifications during
an adoption see [notification cutover](notification-cutover.md).

## What one pass does

A pass takes the control group's leadership lease once (`Fence`). A node that is
not the leader returns immediately and does nothing. As the leader, for each
organization it serves it derives the system scopes afresh (see below), then for
each project (at most `MaxProjects` per pass, in rotation):

1. **Rules.** Lists the project's rules (`RuleSource`), takes the next `MaxRules`
   in rotation and runs the scheduler under the lease with the project-scoped
   read scope and the project's organization-administrator scope. The grid is
   fixed by the committed state, so a second pass at the same time commits
   nothing.
2. **Recording outputs.** If an `OutputAdmission` is configured, flushes up to
   `OutputLimit` pending recording outputs.
3. **Producers.** Runs each configured `Producer` (issues and incidents from
   ingested errors, job books from ingested job attempts) under the lease, each
   bounded and idempotent.
4. **Conditions.** Consumes up to `ConsumeLimit` condition outputs into
   condition state.
5. **Notification decisions.** If a `NotificationRouting` is configured, decides
   the conditions and the incidents that may notify (at most `NotifyLimit` per
   pass, each kind) into the delivery outbox.
6. **Ownership mode.** If the project has a notification cutover record, brings
   its delivery states to the mode its phase requires (`SyncModes`).
7. **Delivery.** If a `Sender` is configured, runs one delivery pass (a batch of
   at most `DeliveryBatch` claims).

The lease is re-proved against a fresh quorum observation at the start of each
project, and by each stage's constructor before every effect (the delivery worker
again immediately before each send). A lease that is lost ends the pass
(`PassReport.Deposed`); nothing after that point is written. Stage failures are
recorded in the report by closed stage and fault code, never as text, and do not
stop the other stages or projects. A lease that cannot be proved either way
(the quorum is unreachable) is reported as a `fence` error and the project is
skipped.

## Bounds and backoff

`Run` waits `Interval` (default 5 s, at least 10 ms) between passes. Passes that
report errors double the wait up to `MaxBackoff` (default 1 min); a clean pass or
a non-leader node returns to `Interval`. A pass is bounded by `PassTimeout`
(default 2 min). `Run` starts no goroutine of its own and returns after the pass
in flight observes cancellation.

## The worker principal

`soundpost serve` runs the runner under an in-process **system principal per
organization** (owner decision D1). `auth.Service.AuthorizeSystem` derives its
scope; the audit actor is `system:runner` (the principal ID of an organization is
the ASCII bytes of that name followed by three bytes of the organization's
digest, so every audit row, command owner and timeline entry says who acted).

* **Never a credential.** There is no token, session or user record. No route,
  header, cookie or body field selects it: `Authenticate` never returns a system
  credential, a scope cannot be decoded from JSON, and `create_user` refuses a
  user ID that carries the system tag. A test hits every registered route with
  every spelling of the principal and proves nothing is accepted or committed.
* **Exactly the roles the runner needs.** Project read (the rule evaluator), the
  organization-administrator scope of the control commits (rule evaluations,
  conditions, delivery records, system-origin incident open/impact),
  `issues.write` (issue producer) and `policy.write` (job producer). Raw reads,
  artifacts, replay, profiles, source credentials, instance administration,
  release registration, deletion, retention, legal holds and ownership cutover are
  outside it; a system incident action other than a system-origin open or impact
  is refused.
* **Re-derived every pass.** Every pass derives its scopes afresh for each
  project. An organization that is unknown or retired, or a project that is
  retired, yields no scope at the next pass (the pass reports `auth`/`not_found`
  and commits nothing); a scope already in hand ends at its next validation, and
  so does one whose organization policy epoch moved.
* **Audited as that actor.** Everything the runner commits (condition changes,
  delivery transitions, incidents, issues, job books) carries
  `auth.SystemPrincipal(org)` as its principal.

With no `Orgs` configured the runner serves every organization in control state
that is not retired, listed again at every pass. A project the scope cannot be
derived for is reported as an `auth` stage error and skipped.

## What the served process wires

`soundpost serve` starts the runner next to the fences (leader only; a follower
returns from each pass at once) with:

* **Producers** (`App.Producers`): turn ingested evidence into control state before
  conditions are consumed (issues and incidents from ingested errors, job books from
  ingested job attempts).
* **Routing** (`App.OrgRouting`): the conditions and incidents of every project
  notify every enabled destination of the project's organization, under the
  approved default notification policy. The destinations are what the
  `destination` admin command configures (type, https endpoint or address,
  enabled, sealed secret); a destination enabled later is picked up at the next
  pass.
* **Sender** (`App.NotificationSender`): the signed webhook, Telegram Bot API and
  SMTP providers behind the organization-scoped destination registry over committed
  control state and the control store's sealed secrets. A destination whose channel
  the node has not configured (SMTP without `--notify-smtp-host`) fails visibly with
  `channel_unconfigured`, never silently.

The node's own delivery environment is flags, validated before storage opens:
`--public-origin`, `--notify-egress-allow` (private CIDRs only; loopback, link-local
and metadata ranges can never be allowed), `--notify-ca-file`, `--notify-smtp-*`,
`--notify-telegram-api`, `--notify-send-timeout` and `--worker-interval`. Webhook
attempt timestamps are recorded once per attempt under `<data-dir>/notify`
(node-local, 0700, removed after two days).

## What is still not wired

Each seam below is a nil interface in `WorkerConfig`, which switches that stage
off. None is replaced by a stand-in that reports success.

* `RuleSource`: control state has no rule catalogue and no authoring route, so
  nothing lists rules and no condition is evaluated by a served node.
* `OutputAdmission`: admitting recording batches needs a recording-source
  credential; recording outputs stay pending until one is wired.
* `Producer` (the resolver of the registered recording producer identity).

## Bounded retention of login and elevation state

`POST /api/v1/oidc/start` needs no credential, and each elevated read leaves
elevation bookkeeping, so both are bounded:

* Live (unexpired) pending OIDC logins are capped at 1024. At the cap the start
  route returns a retryable `unavailable` (HTTP 503, `Retry-After: 60`) before
  any provider discovery fetch or state write.
* `auth.Service.SweepExpired` (run on the fence cadence, about once a minute)
  deletes pending OIDC records (5-minute life) and elevation records (15-minute
  life) once expired; a start also collects expired pending records. The expiry
  instant is read by the proposing node and the result is replicated as state, so
  replicas hold identical bytes.
* Retained on purpose: every audit row (`elevate`, `elevated_read` and the
  per-response release audit, about 300 bytes each). They are the evidence that
  an elevated read was audited before release and are not collected by this
  sweep. Sessions and other control state are not touched by it.
