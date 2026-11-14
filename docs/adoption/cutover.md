<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# One-owner cutover

`tools/adoption cutover` (`runCutover`, library entry `Cutover`) coordinates the one moment the adoption plan must get right: the normal-notification owner changes from the legacy system to Soundpost, with **exactly one** normal sender at every instant and an explicit, resumable record of how far it got. Its counterpart is [rollback](rollback.md).

Product approval is not customer authorization. This tool, its tests and this page contain no customer system, hostname, path, credential or inventory, and nothing here is customer acceptance. The test suite runs against the real plan 06 engine in a temporary directory with in-process fakes for everything outside it. The authorized staged run and the authorized customer cutover are **not done** (see the end of this page).

## What it consumes and what it never copies

The ownership state machine, the barrier checks and the one-active-owner invariant belong to the plan 06 engine: `internal/notify` (`CutoverService`, `ActiveOwners`, `ModeFor`) over `internal/control`. See [notification cutover](../operations/notification-cutover.md). This tool **drives** that engine; it does not reimplement a phase, a barrier check or an incident/outbox reducer. It asks the engine's own `ActiveOwners` who may send in a phase, hands it the evidence the engine verifies (accounting read from the engine's own `Facts`, the old owner's disable evidence, the explicit authorization, the rollback route, the independent observer proof) and lets the engine refuse.

Everything outside the engine is an interface the owning environment implements (tests implement synthetic fakes):

| Interface | Surface | Notes |
| --- | --- | --- |
| `CutoverEngine` | `AdvanceCutover`, `Cutover`, `Facts` | `*notify.CutoverService` satisfies it |
| `CutoverLegacyOperator` | `Observe`, `QuiesceNormal`, `RestoreNormal`, `Delivered` | closed: nothing deletes, disables or reconfigures anything but the old **normal route** |
| `CutoverNewRoute` | `TestDelivery`, `Due`, `Delivered` | the new route's delivery observer |
| `CutoverDeadman` | `Proof` | **read-only**: the independent deadman is excluded from the barrier |

The runtime (`CutoverRuntime`: gate public key, caller clock, the four interfaces, the engine scope) travels in the context (`CutoverWithRuntime`) because `Cutover(ctx, ReadyGate, OwnershipPlan, Authorization)` and `Rollback(ctx, CutoverReceipt, Reason, Authorization)` have fixed signatures. **No real legacy-operator, route, deadman or engine-transport adapter exists in this repository**: the shipped CLI refuses with `no legacy-operator ... adapter is compiled into this build`. Customer-specific adapters are discovered under authorization and belong to the owning environment; a build that carries them replaces `cutoverConnect`.

## The five durable phases

Each phase is persisted atomically (see "State file") before the next one starts. The engine phases are the plan 06 phases.

| # | Phase | What happens | Engine |
| --- | --- | --- | --- |
| 1 | `preflight` | gate, authorization and plan are verified; engine at a start state with the expected epoch; source checkpoints reached the frontier; legacy normal route observed **enabled**; independent deadman armed; destination test delivery confirmed | read only |
| 2 | `old_route_quiescence_acknowledged` | the engine enters `quiescing_old` (old owner still the active owner), then the legacy operator disables its **normal route** and acknowledges with the plan's method, the command ID, a digest, nothing pending | `shadow` (if no record), `quiescing_old` |
| 3 | `source_version_handover` | fresh disable observation, deadman proof and engine `Facts` become the barrier evidence; the engine verifies source versions, checkpoints, accounting, observer, authorization and route | `barrier_verified` (nobody active) |
| 4 | `new_route_activated` | the old route is re-observed disabled; the engine's `ActiveOwners` must allow the new owner next to it; the engine activates; the reply must be exactly the new owner as the one active owner of the planned generation; the old route is observed once more | `new_active` |
| 5 | `delivery_reconciliation` | both sides' delivery IDs against what was due; the deadman must still be armed | none |

The receipt phase is `done` only after phase 5 found no blocker. A crash, a timeout, a cancelled context, an adapter error, a refused barrier or a lapsed gate or authorization between any two phases leaves the state file and the receipt at **`incomplete`** with a closed code (`timeout`, `cancelled`, `adapter_error`, `barrier_refused`, `engine_conflict`, `guard_refused`, `legacy_sender_enabled`, `legacy_state_unexpected`, `quiescence_not_acknowledged`, `deadman_not_armed`, `both_senders`, `destination_test_failed`). A reconciliation with blockers is `reconciliation_blocked`; the new owner stays active and nothing is rolled back or deleted automatically.

## Preconditions: records that gate action are verified first

`Cutover` verifies, with the caller-supplied clock (`CutoverRuntime.Now`), before any change and again before **every** phase:

* **The ready gate**: `VerifyReadyGate(gate, publicKey, now)` from [the readiness gate](readiness-gate.md): signature, shape, ten criteria, not future-dated, not expired. An unsigned, tampered, expired or wrongly signed gate refuses. The gate's scope must equal the plan's scope, and a `production` plan needs a gate whose evidence is production-proven. A gate that lapses mid-run stops the run (`guard_refused`); a fresh gate resumes it.
* **The authorization** (the existing `Authorization` type): explicit, **not** read-only, `GrantID` and `Authority` present, `NotBefore`/`ExpiresAt` current and at most 24 hours apart (the engine's own bound), `MaxEvidenceAgeSeconds` in 1–86400, exactly one scope whose `ID` equals the plan's scope and whose `Collectors` are drawn from `cutover` and `rollback` without repeats and include `cutover`. Scopes naming other IDs are ignored. A grant is an operator assertion, not cryptographic identity.
* **Freshness**: the old owner's observations and the deadman proof must be no older than `MaxEvidenceAgeSeconds` **and** no older than the engine accepts as barrier evidence (one hour for the old owner, 15 minutes for the observer), so a lax grant cannot move a refusal to the barrier, after the old route is quiesced.

## OwnershipPlan (private, immutable for the run)

| Field | Meaning |
| --- | --- |
| `run_id` | lowercase `[a-z0-9-]`, 1–63, first character alphanumeric; every command ID derives from it |
| `scope`, `environment` | the gate's scope; `staging` or `production` |
| `state_path` | absolute path of the operator-private state file (the CLI derives it; see below) |
| `project`, `old_owner`, `new_owner` | engine identities; the project must be the engine scope's single project |
| `policy_generation` | the canonical-owner **epoch** the new owner will run under: the engine's epoch plus one. A plan for an earlier generation cannot start again |
| `frontier` | pre-cutover source cursor/version: per source, the policy version and journal cursor the old owner processed through. The engine verifies versions and that its checkpoints reached the cursor; the tool pre-checks the checkpoints so a lagging frontier refuses **before** the old route is touched |
| `old_quiescence.method` | the closed method code (`[a-z0-9_.:-]`, at most 64) the legacy operator must attest |
| `destination_test` | `destination` label and `probe_id` of the test delivery the new route must confirm before the old route is touched |
| `deadman` | the independent deadman's identity and failure domains (see below) |
| `rollback_runbook_ref` | reference of the audited rollback step, bound into the evidence as a digest |
| `unknown_reviewed` | attests that unknown provider outcomes on either side were reviewed |
| `provider_uncertainty` | the declared number of notifications whose provider outcome may stay unknown |

A resume with **any** different field is refused (`resume refused`): the declared uncertainty cannot be raised after the observation. Roll back and start a new run instead.

## Resume, command IDs and one owner

Every engine command ID and legacy command ID derives from `sha256(run_id, name)`; the state file records the set and a resume refuses any difference. A resume asks the engine which of its commands already committed (its timeline) and repeats **only** what did not, so a lost response, a crash after a commit or a timeout never issues a command twice, never activates a second owner and never re-quiesces with another ID. The legacy operator must be idempotent on the command ID. It repeats the original acknowledgement for a repeated ID, and **must not cache a failed or ineffective result as the command's outcome**.

The one-sender invariant is asserted at the moments it could break:

* activation is attempted only when the old route is freshly observed disabled **and** `ActiveOwners(new_active)` plus the observed old route would not be two senders (`both_senders` otherwise);
* after activation the old route is observed again; an enabled old route next to the active new owner is `both_senders`, the run stops incomplete and a [rollback](rollback.md) resolves it;
* the engine itself never reports more than one active owner and records `barrier_verified` with nobody active between the two.

Urgent work that arrives while the old route is disabled and the new owner is not yet active is never touched by this tool (it has no way to). It is the product's shadow-suppressed decision, reevaluated once by the engine at activation. The reconciliation checks that every due notification, urgent ones included, was delivered exactly once.

## Independent deadman

The deadman is excluded from the ownership barrier. The plan names its identity and the failure domains asserted for it and for the product. The plan is refused when the deadman is the old or the new owner, has no identity or domain, or shares the product's domain. The tool never counts it as an owner, never passes it to any operation, and has **no method** to quiesce, switch or reconfigure it: `CutoverDeadman` is read-only (`Proof`). The proof must come from exactly the named deadman, be armed and fresh at the preflight, after the quiescence, before the barrier, before the activation and after the reconciliation. The proof is the engine's independent-observer evidence; the engine checks the domains differ and that the observer is neither owner. A quiescence that disarms the deadman stops the run before the new owner is active.

## Delivery reconciliation

Inputs: the notifications due since the pre-cutover cursor (`CutoverNewRoute.Due`, with `urgent`), the new route's observed deliveries and the legacy route's, each with an outcome `delivered` or `unknown`. Per due ID: one confirmed delivery is fine; two or more (on either or both sides) is a **duplicate**; none and no unknown is a **gap** (and an **urgent gap** when flagged); only unknown outcomes are **provider uncertainty**, accepted up to `provider_uncertainty` IDs. Also blockers: a delivery nobody decided (`unexpected_delivery`), a legacy delivery after the quiescence acknowledgement (`old_sender_after_quiesce`), and malformed observations (empty, over-long or space-containing IDs, duplicate due IDs, unknown outcome values). Blocker codes: `delivery_gap`, `urgent_delivery_gap`, `duplicate_delivery`, `unexpected_delivery`, `old_sender_after_quiesce`, `uncertainty_exceeded`, `malformed_observation`.

Re-running `Cutover` on a `reconciliation_blocked` run repeats the reconciliation alone (the observation window is the operator's: run it again after the agreed window).

## State file

`StatePath` holds the run's private durable record: schema, a **monotonic version** (+1 per persisted change), the plan and its digest, the command-ID set, the completed phases, the receipt phase (`incomplete` from the first write until `done`), the stop code, the quiescence attestation, the reconciliation and blockers, and any rollback progress. It is written atomically (temporary file in the same directory, fsync, rename; mode 0600) with a compare-and-swap on the version, so a second writer cannot silently overwrite the first; the swap **detects** a concurrent writer, it does not exclude one: one run, one process. A checksum detects corruption and accidental edits; it is not authentication. A state file restored from an old copy cannot move the engine: the engine's committed timeline decides what is repeated, and a stale copy meeting an engine that moved on stops with `engine_conflict` without issuing a command. A lost state file cannot be resumed or rolled back by this tool (a hand-written receipt is refused); recover from the engine's own audit trail and the legacy operator.

## Receipt and public projection

`CutoverReceipt` (private): run, scope, plan digest, state path and version, phase, completed phases, stop code, engine phase/revision/epoch, active owners, the reconciliation (including gap IDs) and blockers. The **public** projection (`CutoverPublicSummary`) is closed: `schema_version`, `phase`, `phases_required`, `phases_completed`, `incomplete_code`, `active_owners` (a count), `old_route_quiesced`, `new_route_active`, the reconciliation counts, `blocker_counts` and `customer_acceptance`, which is always `false`. No identifier, path, time, digest, scope or free text.

## CLI

```
adoption cutover --gate FILE --gate-public-key FILE --plan FILE --authorization FILE \
  --private-directory DIRECTORY --public-summary NEWFILE \
  [--private-directory-acl-confirmed] [--timeout 10m]
```

`--gate` is the signed `ReadyGate` JSON; `--gate-public-key` a file with the hex 32-byte ed25519 public key; `--plan` the plan JSON with **no** `state_path` and a valid `run_id`; `--authorization` the grant JSON; `--private-directory` an existing operator-private directory outside every repository (the same containment, mode and Windows ACL rules as [intake](authorization.md)). The state file is `DIRECTORY/cutover-RUNID.state.json`; each invocation writes the private receipt `DIRECTORY/cutover-RUNID.receipt-vN.json` (N is the state version) and the new public summary, then exits non-zero unless the run is `done`. A repeated `--public-summary` path is never overwritten. `--timeout` is positive and at most one hour and bounds the whole call (a deadline mid-run is `incomplete`, not `done`). A second invocation of a finished run refuses (`already done`) and writes nothing.

## What the tests prove (synthetic, in-process)

The named suite is `go test ./tools/adoption -run 'TestCutover|TestRollback|TestDeadman' -count=1`: crash and timeout between every pair of phases recover to one owner with the same command IDs and urgent work delivered once; gate, authorization, plan, resume, double-activation, preflight, freshness, barrier, both-sender, reconciliation, unknown-outcome and accounting boundaries (including real pending and unknown deliveries in the engine's outbox); state-file atomicity; closed projections; the CLI. They do not prove any behaviour of a real legacy system or provider.

## NOT done (authorization-blocked)

* The isolated staging run with an **actual provider delivery ledger** and the authorized **customer cutover and observation window** have not been run. The reconciliation here compares synthetic observers.
* No real legacy-operator, route-observer or deadman adapter exists; actual legacy adapters are discovered under authorization (Task 1) and are not available to this repository.
* Real clocks across systems are not simulated: the engine requires the old owner's and the deadman's observation times to be after the quiescing began and not after the engine's command time, so adapters' clocks must be disciplined.
