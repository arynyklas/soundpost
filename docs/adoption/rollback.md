<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Tested rollback

`tools/adoption rollback` (`runRollback`, library entry `Rollback`) hands the one normal-notification owner back to the old owner after a [cutover](cutover.md), or abandons a cutover that never reached the new owner. It consumes the same plan 06 engine and the same interfaces; read [cutover](cutover.md) for the runtime, the adapters and the trust boundaries. Nothing here touches a customer system or is customer acceptance, and the isolated staged rollback with a real provider ledger is **not done** (see the end).

## The order is the point

Quiesce the new owner **first**, record the old owner, and only then re-enable exactly one old normal route. At no instant between the phases are both senders enabled:

| # | Phase | What happens | Engine | Senders |
| --- | --- | --- | --- | --- |
| 1 | `new_owner_quiesced` | the engine stops the new owner (claims stop at once); the tool waits until no claim is live; unknown provider outcomes are **recorded** and, if any, must be reviewed | `rollback_quiescing` (nobody active) | none |
| 2 | `old_owner_recorded` | the old owner is recorded as the active owner **before** it is re-enabled (the other order would be two owners) | `old_active` | none (the legacy route is still disabled) |
| 3 | `old_route_restored` | the legacy operator re-enables ITS NORMAL ROUTE, once; the old route is observed enabled; the deadman is still armed | unchanged | the old owner only |

The restore is refused unless the engine's own `ActiveOwners` reports exactly the old owner, so it can never run while the new owner is active or quiescing, or before the old owner is recorded. If the legacy route is already observed enabled (a crash after the effect), no second restore is issued.

A cutover that never reached the new owner (`incomplete`, or `reconciliation_blocked` is not this case: there the new owner is active) is rolled back by the engine's **abort**: from `quiescing_old` or `barrier_verified` the engine goes back to `shadow` (phases 1 and 2 are then trivially satisfied) and the old route is restored. A cutover that stopped before the engine moved restores nothing it did not disable.

## Inputs, refusals and authorization

`Rollback(ctx, CutoverReceipt, Reason, Authorization)`:

* **The receipt** locates the run: it must match the state file's run, plan digest, scope and state path, and the state file must pass the same integrity checks as a cutover resume (checksum, plan digest, command-ID set). It is a locator, not authority: the engine and the state file are.
* **`Reason`**: `code` from the closed set `operator_requested`, `delivery_gap`, `duplicate_delivery`, `destination_failure`, `incomplete_cutover`, `other`; `text`, 1 to 512 bytes of valid UTF-8 without control characters (carried to the engine's audit trail, private); `unknown_reviewed`, the attestation below.
* **The authorization**: the same `Authorization` type, not read-only, current, at most 24 hours long, exactly one scope naming the run's scope, `Collectors` drawn from `cutover`/`rollback` and including `rollback`. A cutover-only grant cannot roll back and vice versa. It is re-verified before **every** phase; a grant that lapses mid-way leaves the rollback `incomplete` with nobody sending and a fresh grant resumes it.
* **No ready gate.** An expired or missing gate never blocks a rollback.

Everything is verified before the first side effect; a refusal changes nothing and returns no receipt.

## Unknown and unresolved provider outcomes

Before the old owner is recorded the rollback records, in the state file and the receipt, the engine's unknown delivery count (`RollbackUnknown.Engine`: claims whose lease lapsed with no completion, retries after an unknown attempt, deliveries that settled `uncertain`) and the new route's delivery IDs whose provider outcome is `unknown`. If any exist and `Reason.unknown_reviewed` is false, the rollback stops `incomplete` with `unknown_outcomes_unreviewed`: the new owner stays quiesced, nobody sends, and the old route is **not** restored until the operator has reviewed the recorded outcomes and repeats the call with the attestation. The unknown outcomes are never turned into success or retried by this tool.

## Crash, timeout and resume

Each phase is persisted atomically after it completes (the state file's `rollback` section; see the cutover page). The receipt phase is `incomplete` with a closed code until the third phase completes, then `done`. A resume repeats the call with the **same reason** (code and text; only the unknown-outcome attestation may change), reads which engine commands committed and repeats only what did not, with the same derived command IDs:

| Stopped after | Engine | Senders | Resume |
| --- | --- | --- | --- |
| the engine entered `rollback_quiescing` | `rollback_quiescing` | none | drains, records, records the old owner, restores |
| waiting for claims (deadline) | `rollback_quiescing` | none | waits again |
| the old owner was recorded | `old_active` | none | restores |
| the restore took effect, response lost | `old_active` | old only | observes enabled, issues nothing, finishes |
| the engine answers another phase or owner | as the engine says | as observed | refuses to restore (`engine_conflict`) |

A finished rollback refuses a second one (`already done`), and a rolled-back run is finished for good: `Cutover` on its state refuses (start a new run with the next `policy_generation` and a new state path).

## Deadman

The independent deadman is never counted, quiesced or switched by a rollback: its interface is read-only. Its proof must still be armed after the restore; a rollback whose restore disarms it is `incomplete` with `deadman_not_armed` (the old route is already enabled; the operator fixes the deadman and repeats the call).

## No automatic deletion

No code path of the rollback or the cutover deletes or reconfigures a legacy system, the new product, retained history or an old schedule beyond quiescing and restoring the **normal route**: the legacy operator interface has no such method, and the tests assert the interface surface.

## Receipt, public projection and CLI

`RollbackReceipt` (private) carries the run, state version, phase, completed phases, stop code, reason class, engine phase and active owners, whether the old route was last observed enabled, whether the deadman was armed, the recorded unknown outcomes (including delivery IDs) and blockers. The public `RollbackPublicSummary` is closed: `schema_version`, `phase`, `phases_required`, `phases_completed`, `incomplete_code`, `reason_code`, `active_owners` (a count), `new_owner_quiesced`, `old_route_restored`, `unknown_outcomes` (a count), `unknown_reviewed`, `deadman_armed`, `blocker_counts`, `customer_acceptance` (always `false`).

```
adoption rollback --receipt FILE --authorization FILE --reason-code CODE --reason-text TEXT \
  --private-directory DIRECTORY --public-summary NEWFILE \
  [--unknown-reviewed] [--private-directory-acl-confirmed] [--timeout 10m]
```

`--receipt` is a cutover receipt JSON; its state file must be in `--private-directory`. Each invocation writes `DIRECTORY/rollback-RUNID.receipt-vN.json` and the new public summary and exits non-zero unless the rollback is `done`. The same `--timeout` and exclusive-output rules as the cutover apply; the wait for the new owner to drain ends with the deadline.

## NOT done (authorization-blocked)

* The isolated staging cutover/rollback run with an **actual provider delivery ledger** and the authorized customer cutover and observation window have not been run.
* No real legacy-operator adapter exists in this repository; the restore, the observation and the delivery listing are interfaces that the owning environment implements under its authorization.
