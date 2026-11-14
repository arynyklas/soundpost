# Notification ownership cutover

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

This page is the operator's contract for making Soundpost the *normal*
notification owner of a project, handing it back, and what the product itself
verifies along the way. The code is `internal/notify/cutover.go` (the facade,
`AdvanceCutover`, the shadow evaluator and parity comparison) and, in the control
group, `internal/control/cutover.go` and `internal/control/delivery_outbox.go`
(the state machine and the fences). What a delivery is and how it can end
ambiguously is in [delivery semantics](delivery-semantics.md); the independent
outage detector is in [external deadman](external-deadman.md).

## What this product does, and what it never claims

The *old owner* is an external system that sends the normal notifications today.
Soundpost cannot observe it, stop it or start it. The authorized adoption flow
(an operator with the customer's authorization) disables it and hands this
product audited evidence. This product

* **records** the ownership state, the evidence and who authorized each step, in
  committed control state (replicated, snapshotted, restored like the rest of
  the control state);
* **verifies** what it can verify about itself: that the evidence is bound to this
  cutover, this revision and this frontier, that it is fresh, that the
  authorization is the calling administrator's own, that its own committed
  deliveries are exactly the ones the operator accounted for, and that its own
  source checkpoints have reached the frontier;
* **fences** every send by that committed state, atomically with the delivery
  records it protects.

It never pretends that a cross-product atomic transaction exists. Between "the
old sender is disabled" and "the new owner is active" there is a window in which
no one is the owner; the design makes that window explicit (`barrier_verified`)
and one-sided: **a missed notification is preferred to two normal owners.**

Legacy history stays **read-only**. There is no importer and nothing in this
feature deletes, rewrites or exports legacy data: the cutover touches only its
own record (`ControlState.CutoverBooks`), the delivery books and the audit
trail. Legacy retention and export obligations are met by the legacy system, not
here.

## The phases

One record per project. Exactly one normal owner is active in `shadow`,
`quiescing_old`, `new_active` and `old_active`; **none** is active in
`barrier_verified` and `rollback_quiescing`. No phase has two.

| Phase | Active owner | What Soundpost does |
| --- | --- | --- |
| `shadow` | old | decides everything, records every would-be delivery as `suppressed` with code `shadow`, sends nothing |
| `quiescing_old` | old | same; the old sender is being disabled |
| `barrier_verified` | none | same; the old owner's disablement is evidenced and verified; nothing is active |
| `new_active` | new | claims and sends |
| `rollback_quiescing` | none | claims stop at once; the new owner drains; nothing is active |
| `old_active` | old | sends nothing; the old owner is authorized again |

Transitions (every other pair is refused with `cutover_transition_invalid`):

```
(none) -> shadow -> quiescing_old -> barrier_verified -> new_active -> rollback_quiescing -> old_active -> quiescing_old
                          \-> shadow (abort)        \-> shadow (abort)         \
                                                                               new_active -> new_active   (only to acknowledge a disaster restore)
```

Each command carries: a command ID (a retry of the same command is a replay),
the **expected cutover revision** (zero before the first command), the
source/version frontier manifest, the old and the new owner IDs (fixed by the
first command), the requested phase, an **explicit operator reason** (1 to 512
printable bytes) and, for `barrier_verified`, `new_active` and `old_active`, the
barrier evidence below.

## The barrier checklist

The evidence is data the operator flow supplies. A transition into
`barrier_verified`, `new_active` (and a rollback into `old_active`) is verified
**inside the transaction that commits it**; a failed barrier commits nothing and
returns every failed check by its closed code.

| Item | Supplied as | Verified by the product | Check codes |
| --- | --- | --- | --- |
| **Verified source checkpoints** | the frontier manifest: per source, the source policy version and the data-journal cursor the old owner had processed through | each source exists in the project, is enabled and is at exactly that version; the project's committed issue checkpoint for the cursor's group has reached the cursor | `source_unknown`, `source_version`, `checkpoint_behind` |
| **Pending/unknown delivery accounting** | counts of the product's pending, claimed and unknown deliveries and a digest of the unknown set, with a review flag | the counts and the digest equal the committed deliveries; no claim is live; unknown sends are reviewed | `accounting_pending`, `accounting_claimed`, `accounting_unknown`, `claims_live`, `unknown_unreviewed` |
| **Old-owner disable evidence** | the owner, a method, when it was observed, a digest of the audited artifact, the old owner's own pending/unknown counts | recorded; checked for shape, for being about the old owner, for being fresh (at most one hour old) and observed *after* the quiescing began; the old owner reports no pending sends | `owner_evidence`, `owner_stale`, `owner_pending` |
| **Explicit authorization** | the principal, a digest of the authorization record, its validity window | the principal is the calling administrator's own; the window covers now and is at most 24 hours | `authorization` |
| **Rollback route** | the owner the route returns to and a digest of the runbook step | recorded; the route returns to the old owner | `route` |
| **Independent observer proof** | the observer, the failure domain asserted for it and for this product, when it last proved itself armed | recorded; present and fresh (at most 15 minutes); the two asserted domains differ and the observer is neither owner. An absent or stale proof is an **unknown observer state** and refuses the barrier | `observer`, `observer_stale`, `observer_domain` |
| *Binding* | the cutover ID, the revision the evidence was prepared for, the digest of the manifest | equal to the committed values, so evidence cannot be replayed into another cutover, an older revision or another frontier | `evidence_missing`, `evidence_binding`, `manifest_digest` |

What the product **cannot** verify, and therefore only records: that the old
sender is really disabled, that the observer really runs somewhere else, that the
asserted failure domains are true, and that the authorization record exists. The
digests tie each claim to an artifact the adoption flow retains; the audit trail
says who asserted it and when.

The unknown set is the product's own outstanding ambiguous sends: claims whose lease
lapsed with no completion, retries pending after an unknown attempt, and deliveries
that settled `uncertain`. A delivery that settled `uncertain` (by a rollback, an
exhausted budget or an unknown terminal) stays in the set until it is pruned from the
bounded delivery history, so every later barrier shows and reviews it again.

`CutoverService.Facts` returns what the product's own side of the accounting is at
this instant (pending, claimed, unknown, the unknown digest, the committed
checkpoints and any unacknowledged restore) so the operator flow builds its
evidence from the product's view, not from memory.

## What the fences do

* **No send outside `new_active`.** Inside the same transaction as the delivery
  records they protect, control (a) records every external delivery decided
  while the project is not in `new_active` as `suppressed`/`shadow` (never
  `pending`), (b) refuses to lease any delivery while it is not in `new_active`,
  and (c) lets the worker's pre-send check report `revoked` for a delivery it had
  leased before the phase changed, so a rollback that begins between a claim and
  its send stops that send.
* **No retroactive backlog.** Entering `new_active` or `old_active` revokes every
  delivery that is still open: an unsent one is `cancelled` with the code
  `revoked`; one that may already have reached the provider settles as
  `uncertain`. Nothing the old owner may already have handled is sent late by the
  new one.
* **Claims carry the owner revision.** A claim names the cutover revision its
  worker observed and records it on the attempt. A claim decided under another
  revision than the committed one is refused (`delivery_owner_stale`) and opens
  no attempt.
* **Expected revision.** Two operators racing on one revision: one wins, the
  others get a typed conflict carrying the current revision. A policy edit races a
  mode change the same way, through the canonical-owner revision of the policy
  state (`owner_revision_mismatch`) and the policy-state version.
* **Command reuse.** The same command ID with the same content returns the
  original result (marked as a replay) however much later; the same ID with other
  content is a conflict. A late retry of an old owner's flow therefore never moves
  the state.

## Shadow and parity

While the project is not `new_active`, `SyncModes` brings every policy state to
shadow mode (`ModeFor`), so the policy reducer still decides everything but
records nothing as deliverable. Run it after every transition and on every worker
pass. A subject whose policy state is created while the project is not `new_active`
starts in active mode until the next sync; control already records its deliveries
as suppressed, so the gap is safe but the state's own mode lags.

When the product becomes the active owner, the policy's own rule for the end of a
shadow applies: what a subject had suppressed while the product only watched is
reevaluated **once**, as at most one `current_state` update per subject. The old
owner's opening is never re-announced.

`ShadowEvaluator` replays the same policy events on an in-memory twin held in
*active* mode. It never stores, claims or sends. Its decisions say what the
product would do as the owner (including a suppression by a maintenance window,
which the stored shadow code would hide). `CompareParity` compares them with a
legacy decision stream supplied by the adoption flow in the same vocabulary, **per
decision, not by totals**: the source version, the dedup identity (a legacy replay
that shares one dedup ID collapses), the impact revision and ordinal, the
suppression and the intended recipients. A decision only one side took, a recipient
set that differs, or a different suppression is a named mismatch. The legacy
stream is *data*; this product never imports legacy history.

## Rollback

1. `rollback_quiescing`: committed at once, from `new_active`, with only a reason.
   From this commit nothing is claimed and in-flight sends are stopped before the
   request is made.
2. `old_active`: refused until **no claim is live** (the new owner has quiesced),
   the unknown sends (including claims whose lease lapsed with no completion) are
   counted, reviewed and digest-matched, and the route and the authorization are
   evidenced. The product then settles the lapsed claims as `uncertain`
   (never retried, never turned into success) and revokes the pending ones.
3. The operator flow then re-enables the old sender. The product records
   `old_active` *before* that, never after: the other order would be two owners.

## After a disaster restore

A restore quarantines every credential, sender and grant of the restored state in
a new authentication generation (see [backup and restore](backup-restore.md)).
The cutover record comes back from the backup, so it can claim `new_active` for a
world that no longer exists. Therefore, while a restore generation is committed
and the cutover has not acknowledged it:

* no claim leases anything (`restore_pending`); a delivery is neither sent nor
  settled as a missing destination while the senders are inactive;
* new decisions are recorded as `suppressed`/`restore_pending`.

The activation is explicit and audited: `new_active -> new_active` (or the normal
`barrier_verified -> new_active` if the record is in another phase) with full
barrier evidence in which the **previous incarnation** of the new owner is the one
shown disabled (observed after the restore), and the restore generation named in
`restore_generation`. It revokes the restored backlog and starts a new epoch. A
project that never had a cutover has no record to acknowledge the restore: it
needs one (a nominal old owner, then the same flow) before it sends. This is
deliberately conservative.

## Erasure

When a project or organization is retired, the cutover record keeps its
identities (cutover, owners, frontier), revision, phase, epoch and, per step, the
command, principal, transition, time and the digests of the command and of the
evidence. The operator's free-text reasons and the evidence payloads are
dropped. Control audit entries carry closed codes only, never operator text.

## Bounds

At most 16 frontier entries per command; 64 steps kept per record (the oldest are
evicted; the control command table still answers a replay of an evicted command with
its original acknowledgment, the cutover state being the current one); a reason of at
most 512 bytes. Everything over a bound except the step history is refused, never
truncated.

## Application wiring

The cutover arm is part of the delivery handler, so `Store.BindDeliveryOutbox()`
(already bound by `appcore.Open`) is all control needs. The composition builds
`notify.NewCutoverService(app.Control, clock)` for the operator flow and the C11 views,
and every worker pass calls `Outbox.SyncModes` with the committed cutover state before
`RunOnce`. The deletion hook adds one line to `eraseControlBooks`:
`func() (int, error) { return eraseCutoverBooks(st, p, at) },`.

## Not covered here

The product has no HTTP routes or C11 views for the cutover yet: the read API is
`CutoverService.Cutover`/`Facts`, and the view wiring belongs to the application
composition. The adoption flow that produces the evidence, disables the old
sender and re-enables it on rollback is the adoption plan's, with the customer's
authorization. No real customer, sender or provider is contacted by anything in
this repository's qualification of this feature.
