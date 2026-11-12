# Notification delivery semantics

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

This page says exactly what the durable notification outbox guarantees, what it
does not, and how a delivery that did not end cleanly looks to an operator. The
policy that decides *what* is sent is described in
[notification policy](../user/notification-policy.md); the provider adapters (SMTP,
Telegram, signed webhooks) exist as a tested package (`internal/notify/providers`,
see [notification channels](notification-channels.md)), but `soundpost serve` does not
wire them or start the runner that sends, so a served node sends nothing. The code is
`internal/notify/{outbox,worker}.go` and, in the control group,
`internal/control/delivery_outbox.go`.

## What is promised and what is not

* **At-least-once attempts with a stable identity, never exactly-once.** A
  delivery has one stable idempotency ID, the hash of its C08 key
  (organization, policy, entity, impact revision, kind, recipient and, for kinds
  that repeat inside one revision, an ordinal). The same ID is used for every
  attempt and is the provider's deduplication key where the provider has one.
  Nothing here claims a recipient received a message exactly once, and nothing
  promises a provider will ever accept one.
* **Accepted means the provider said so.** A delivery is `accepted` only when the
  provider returned an acceptance with a provider message identity. An outcome
  without that evidence is recorded as `unknown`, never as accepted.
  Acceptance is also not human receipt.
* **Uncertainty stays visible.** An attempt that may have reached the provider is
  `unknown`. It is never turned into success or into a plain failure, it is kept
  in the immutable attempt history, and the delivery is flagged `uncertain`. If
  such a delivery is later accepted it is flagged `possible_duplicate`.
* **Missing channels and exhausted retries are visible failures.** A delivery that
  has no destination, or ran out of budget, is `failed` or `uncertain` with a
  closed reason. It is never silent and never success.

## Where the state lives

Everything durable is in the control group (C05), in `ControlState.DeliveryBooks`,
and is carried by control snapshots and restores like the rest of the state:

| Key | Holds |
| --- | --- |
| `delivery:<id>` | one delivery: stable ID, typed body, phase, immutable attempts |
| `policy:<org>:<project>:<policy>:<subject>` | the opaque policy state of one notification subject and its version |
| `fence:<org>:<project>` | the highest leader lease the project's outbox accepted |

No destination secret, endpoint, provider message text, raw log or error message
is ever stored. A delivery body has typed fields only (identifiers, enums, counts
and closed codes). Secrets are resolved by the sender at every attempt from the
destination's sealed secret and are never copied into the outbox or its audit.

## How a decision becomes a delivery

1. Evidence or a human action is mapped to a `PolicyEvent` and decided by the pure
   reducer (`notify.Decide`) **outside** control apply, with an injected time.
2. `Outbox.Submit` commits, in **one** C05 transaction (`ClaimDelivery`, operation
   `enqueue`), the new policy state and every intent the decision produced, under
   a compare-and-set of the policy state version. That transaction is also the
   evidence checkpoint: the state carries the highest applied source cursors.
3. A decision that was already applied decides nothing and commits nothing. A
   crash after the incident committed and before the worker ran, a lost response,
   a second worker or a restart therefore produce **exactly one** delivery ID. A
   lost race for the same policy state recomputes the decision from the winner; two
   decisions are never merged.

The C05 command vocabulary has no `enqueue` kind, so enqueue is an operation of
`ClaimDelivery` (the producing half of the claim queue); `claim` is the other,
and `complete` and `cancel` are the operations of `CompleteDelivery`. Adding a
dedicated kind is a one-line change to the parent-owned command list and needs no
change to the handler.

Intents that are not external sends are recorded too, so nothing is hidden: the
shared queue entry is `queued` (never sent, never `accepted`), a suppressed intent
is `suppressed` with its code, and a missing destination is `failed` with
`no_destination`.

## Claim, send, complete

```
claim (atomic: lease + attempt)  ->  revalidate  ->  re-fence  ->  send  ->  complete
```

* **Claim** (`Outbox.Claim`) leases due deliveries under the caller's leader
  lease and opens attempt *n* for each, in one transaction. The lease is first
  validated against a fresh quorum observation; control then compares it with the
  highest lease the project's outbox has accepted.
* **Revalidation** happens before every send, from committed control state: the
  destination still exists and is enabled; a deletion covering the delivery's
  origin is closing (the send is **paused**) or complete (the delivery is
  **cancelled** as `deleted`); the project is not retired; the worker's own scope
  still validates. The same checks run atomically inside the claim.
* **Re-fence**: the worker validates its lease again immediately before the
  external effect, so leadership lost between the claim and the send stops the run.
* **Send** goes through the narrow `notify.Sender` interface, only here and
  outside every transaction, with a timeout shorter than the lease.
* **Complete** (`Outbox.Complete`) closes exactly the claimed attempt. C08's
  signature carries no lease, so the lease is the stored claim's: it is validated
  against a fresh quorum observation, and control rejects a completion whose
  attempt number or fence is not the stored claim's, or whose lease is older than
  the highest the outbox accepted.

### Outcomes

| Kind | Meaning | Effect |
| --- | --- | --- |
| `accepted` | the provider accepted and returned a message identity | delivery `accepted` (`possible_duplicate` if an earlier attempt was unknown) |
| `retry` | a definite non-acceptance; nothing reached the recipient | delivery stays `pending`, same ID, scheduled |
| `unknown` | the provider may have accepted (timeout after the request, sender error, crash, a lapsed lease) | delivery stays `pending` and `uncertain`, same ID, scheduled |
| `terminal` | a definite refusal | `failed`, or `uncertain` if an earlier attempt was unknown |

A sender error, a timeout and an `accepted` outcome without a valid provider
identity are all `unknown`. Only closed codes are stored; whatever a provider or a
transport printed is discarded.

## Leader change, crash and duplicates

* **Accepted before a crash.** The provider accepts, the process dies before
  `Complete`. Nothing durable says so; the claim is still open. After its lease
  lapses the next claim closes that attempt **`unknown`, by the system, with the
  code `claim_expired`**, and retries the **same delivery ID** as the next attempt.
  A provider that deduplicates by ID returns the same message; one that does not
  may deliver twice. The record then says `accepted`, `uncertain` and
  `possible_duplicate`: the possibility of a duplicate is documented in the
  record itself.
* **An unexpired claim is not taken over**, even by a newer leader, so an old
  worker's in-flight send has finished or timed out before a second one starts.
  Failover therefore delays a retry by at most the lease (default two minutes).
  Claims a deposed worker made but did not reach are recorded `unknown` when they
  lapse (the worker cannot prove it did not send), which can make a delivery that
  was never sent look uncertain: a deliberate conservative choice.
* **A stale worker never completes a newer attempt.** The old attempt is closed
  and immutable; a completion naming it is a conflict (or a stale-fence
  rejection); a completion under an older lease than the highest accepted is a
  stale-fence rejection at control apply, whichever delivery it names. A closed
  attempt is never edited: repeating its exact outcome is a no-op, anything else
  is a conflict.
* **A minority partition cannot claim or complete.** Every claim and completion is
  a control quorum transaction; a partitioned leader's reads and proposals fail.
* **Late completion of a lapsed attempt is rejected.** If a worker records an
  outcome after its attempt was already closed `unknown`, the attempt stays
  `unknown`; the evidence is not appended to a closed attempt.

## Retry budget

12 attempts or 24 hours from first eligibility, whichever comes first, with a
capped, jittered delay (half of the capped exponential base `min(15 min, 1 s·2^(n-1))`
plus a jittered other half, so never above the cap), and the provider's
`Retry-After` (a delay) honored when it is longer, never beyond the budget. These
limits are enforced by control and cannot be loosened by a worker; a worker may
only be tighter in delay. Jitter is injected and, by default, derived from the
delivery ID and attempt, so a restart does not change the schedule.

Exhaustion is a terminal reason that preserves uncertainty: `failed` /
`retry_exhausted` if every attempt was a definite retry, `uncertain` /
`retry_exhausted` if any attempt was unknown. A delivery that was never attempted
for 24 hours is `cancelled` / `expired`. The attempt history and a control audit
entry for the settlement are kept.

## Deletion, revocation and destination changes (C12)

* While a deletion that covers a delivery's origin is **closing**, matching derived
  sends are **paused**: they are neither claimed nor cancelled, and resume if the
  deletion fails. Completing the deletion cancels them as `deleted`. A delivery
  records the evidence interval it was derived from; an unknown interval is
  treated as covered, and a historical-range deletion covers a delivery for any
  signal of its predicate because a delivery does not record which signal it came
  from.
* A request already **in flight** when a deletion begins cannot be recalled. Its
  outcome is still recorded (`accepted` or `unknown`), and the record holds only
  typed fields: nothing derived from the deleted content is released.
* A **removed** destination is a visible `failed` delivery (`no_destination`); a
  **disabled** one is `cancelled` (`destination_disabled`). A destination secret
  rotation takes effect at the next attempt (the sender resolves the secret fresh);
  the delivery ID does not change.
* A **retired** organization or project is unreachable: every command for it is
  refused as absent, and its deliveries remain as typed audit.
* Any administrative change (including a destination edit) ends every scope minted
  before it. A worker that is running when that happens fails closed: it stops, the
  attempt stays open and lapses to `unknown`. Run the worker with a freshly minted
  scope each pass.

## Bounds

Settled history per project is bounded to 1024 deliveries, oldest first, benign
ones (`queued`, `suppressed`, `accepted`) before failures and cancellations; open
deliveries are never pruned and are bounded to 4096 per project (a visible quota
error, not a silent drop). Every terminal reason is also a control audit entry that
outlives its record. Policy states are bounded to 1024 per project and 256 KiB each.

## What is verified, and what is not here

The behavior above is exercised in `internal/control/delivery_outbox_test.go` (the
closed handler against a real single-voter control group: fences, attempts, the
budget, C12 gating, bounds, determinism under reordered retries, restart and
snapshot import) and `internal/notify/{outbox,worker}_test.go` (the adapter and
worker over a real control group with restarts, driven by a **fake** `Sender`).
`TestOutboxThreeNode*` run a real three-voter control group in one process (three
stores, three Raft groups, an in-process transport) and kill or cut off the
leader at each boundary of the pipeline. They do **not** cross separate OS
processes, the mTLS transport, a wall clock or the data groups, and no real
provider has been called.

Not built at the time of this task's commit and since added elsewhere: the provider adapters (`internal/notify/providers/{smtp,telegram,webhook}`, see `notification-channels.md`). Still not part of this document's scope: the application wiring of the worker (the control handler is bound with `Store.BindDeliveryOutbox()`; `soundpost serve` does not start the worker, see `background-workers.md`) and a scheduler that mints a fresh scope and lease per pass.
