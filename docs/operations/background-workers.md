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

* **Rules** (`App.RuleCatalogue`): the rule catalogue in control state. An organization
  administrator saves rules over `POST /api/v1/rules` (see `docs/user/rules.md`); the runner
  lists each project's active rules from the committed state at every pass, so a saved rule is
  evaluated at the next pass and a retired one stops at it. There is no rule file and no
  reload: control state is the one source.
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

## The recording source

Alert rules need no credential: they read through the worker principal's project-scoped read
scope and write only control state. A **recording rule** writes its result back as metric
samples, which is a data-plane write, and the data plane is open only to a registered
source: the node needs the credential of one. The operator onboards a source for the project
(`POST /api/v1/sources`, a source policy that allows `metric`, a registered resource and the
label values the rule's configured labels may take; the credential is returned once), writes the
credential to a file readable only by the service user, and starts the node with
`--recording-source-credential-file <file>`. The node authenticates it at start (a credential
that is unknown, revoked or expired fails startup with a static reason that does not echo it),
never stores it, and reads the source's project, resource registry and policy revision from
control state at every evaluation, so a revoked, expired or re-versioned source applies at the
next pass. With it the runner wires `OutputAdmission` (admission through the ordinary ingest
path under that credential, receipt lookup after an ambiguous answer) and the producer resolver
(one stable producer per source), and the rule route accepts recording rules for that source's
project. Without it recording rules cannot be saved and `OutputAdmission` stays nil, so a
recording output would stay pending: nothing is admitted on a node that was not given the
credential. One node has one recording source, so recording rules are possible for exactly its
project.

## What is still not wired

Each seam below is a nil interface in `WorkerConfig`, which switches that stage off. None is
replaced by a stand-in that reports success.

* `OutputAdmission` and `Producer` on a node started without
  `--recording-source-credential-file` (see above).

## Bounded retention of login and elevation state

`POST /api/v1/oidc/start` needs no credential, and each elevated read leaves
elevation bookkeeping, so both are bounded:

* Live (unexpired) pending OIDC logins are capped at 1024. At the cap the start
  route returns a retryable `unavailable` (HTTP 503, `Retry-After: 60`) before
  any provider discovery fetch or state write.
* `auth.Service.SweepExpired` (run on the 5-second reconcile tick of the fence
  cadence) deletes pending OIDC records (5-minute life), elevation records
  (15-minute life) and sessions (12-hour life) once expired; a start also
  collects expired pending records. A session goes at the instant `Authenticate`
  refuses it. The expiry instant is read by the proposing node and the result is
  replicated as state, so replicas hold identical bytes. A tick with nothing
  expired commits nothing. The commit that removes expired records goes through
  `control.Store.UpdateSweepExpired` and does not move the control
  `AuthorityRevision`: every use already refuses such a record at the same
  instant, so removing it widens and narrows no access. The writer is guarded:
  a sweep that removed a live record, added or altered one, or changed anything
  else bumps the revision like an unclassified writer.
* Which login and elevation writes move `AuthorityRevision` (10.29, each decided
  from what the commit writes). Not moved, through guarded writers that bump on
  any other difference: the pending OIDC record a start adds and its callback
  consumes (`UpdatePendingLogin`; it authenticates nobody, the session is a
  separate write); the `elevated_read` audit row of an elevated read
  (`UpdateAuditAppend`; audit rows are never read back by an access decision);
  and a login that consumes a TOTP step or a recovery code
  (`UpdateSessionCreate`; only `User.LastTOTP`, raised, and `User.Recovery`,
  losing a hash, change, and no decision reads either field). Moved, on
  purpose: `Elevate` itself (the elevation record is the access grant that
  `ResolveElevation` rebuilds a cross-organization read scope from), logout,
  and every other write to a user, membership or grant.
* Audit rows (`elevate`, `elevated_read` and the per-response release audit, about
  300 bytes each) are not collected by this sweep. Decision proposed by lane 1
  wave 7, recommendation: accept: elevation audits have no retention of their own;
  they follow the one audit-log retention of the control state, which the
  retention worker's hourly `ExpireControlLog` pass already applies (365 days by
  default; an organization's own `audit` retention setting can only lengthen it;
  the erasing and scrubbing audits are never expired). An elevation lives 15
  minutes, so after the audit row is dropped nothing references it. Raising or
  shortening the 365-day default is an owner decision on audit retention and a
  one-line change to `retention.Defaults().AuditDays`.
