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
configured organization it authenticates the worker principal's token afresh,
then for each project (at most `MaxProjects` per pass, in rotation):

1. **Rules.** Lists the project's rules (`RuleSource`), takes the next `MaxRules`
   in rotation and runs the scheduler under the lease with the project-scoped
   read scope and the project's organization-administrator scope. The grid is
   fixed by the committed state, so a second pass at the same time commits
   nothing.
2. **Recording outputs.** If an `OutputAdmission` is configured, flushes up to
   `OutputLimit` pending recording outputs.
3. **Conditions.** Consumes up to `ConsumeLimit` condition outputs into
   condition state.
4. **Notification decisions.** If a `NotificationRouting` is configured, decides
   the conditions that may notify (at most `NotifyLimit` per pass) into the
   delivery outbox.
5. **Ownership mode.** If the project has a notification cutover record, brings
   its delivery states to the mode its phase requires (`SyncModes`).
6. **Delivery.** If a `Sender` is configured, runs one delivery pass (a batch of
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

There is no internal, privilege-minting scope in the auth package, and the
workers do not invent one. Committing control state (rule evaluations, condition
state, delivery records) needs an organization-administrator scope, and the only
credential that can obtain one is an organization administrator's own: a server
token cannot carry `org.admin` (it is not a grantable permission). A pass
therefore acts as an administrator's session named in `WorkerConfig.Principals`:
the organization and a function returning the bearer token. The function is
called on every pass, which is where the process renews the session (sessions
last 12 hours), and the token is authenticated afresh each time, so revoking it
stops the workers at once. The principal must also be an organization member
holding a `telemetry.read` grant on the projects served (the rule evaluator
reads with the project-scoped read scope).

A project for which the principal cannot be authorized is reported as an `auth`
stage error and skipped. A non-interactive worker identity that may mint an
`org.admin` scope for its own organization only would remove the session
renewal; it needs an owner decision and an audited constructor in the auth
package, and does not exist.

## What is not wired by default

Each seam below is a nil interface in `WorkerConfig`, which switches that stage
off. None is replaced by a stand-in that reports success.

* `RuleSource`: control state has no rule catalogue yet, so nothing lists rules.
* `OutputAdmission`: admitting recording batches needs a recording-source
  credential; recording outputs stay pending until one is wired.
* `NotificationRouting`: there is no committed notification-policy catalogue; the
  routing says which policy, revision and destinations a project's conditions
  notify. Severity text other than `critical` and `major` is decided as minor.
* `Sender`: the provider senders (`internal/notify/providers`) need operator
  configuration (SMTP host, Telegram client, webhook egress policy, origin and an
  attempt stamper) and a `notify.SecretReader` over the sealed destination
  secrets. Neither exists in a deployed node, so no notification leaves it.
* `Producer`: the recording producer identity resolver.

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
