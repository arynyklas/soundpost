<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Notification policy parity (no-send shadow comparison)

`ComparePolicy` (`tools/adoption/policy_compare.go`, `notification_ledger.go`) compares what a customer's old notification owner did with what the canonical Soundpost owner **would** have done, and classifies every difference. It is a comparison tool, not a policy engine: the canonical reducer stays in `internal/notify`, `internal/incidents` and `internal/conditions`. The tool replays event streams through `notify.ShadowEvaluator`, compares decisions with `notify.CompareParity`, and validates the approved configuration with the reducer's own validation. Nothing is stored, claimed or sent.

**Parity is not cloning.** A legacy page that the canonical owner does not reproduce is only acceptable when something explains it, and the explanation is approved by the owner. Reproducing every noisy legacy page would defeat the point of adoption.

## Trust boundaries and what is synthetic

- Every input and the full `PolicyReport` are **private**. They name entities, keyed recipient pseudonyms and approvals. They belong in the operator-controlled private directory used by intake (outside every checkout, restrictive permissions; on Windows add `--private-directory-acl-confirmed` only after verifying the NTFS ACL).
- Only `PolicyPublicSummary` may be published: integers, a `by_reason` map from a closed reason enum to a count, and a verdict enum. It has no entity, recipient key, approver, reason text or identifier. `customer_acceptance` is always `false`.
- Recipients appear **only as keyed pseudonyms**. `LedgerRecipientKey(key, rawHandle)` is HMAC-SHA-256 (domain-separated, truncated to a `model.ID`); the key (at least 32 bytes) and the raw handles never leave the operator. The ledger has no field that can hold an address and a raw address fails JSON decoding of a recipient key. Register canonical destinations with the same pseudonym as their destination ID, so both sides name a recipient identically. The tool cannot verify that an ID was derived with the operator's key.
- Human reason text (approvals, control supersessions, maintenance reasons) is private input. It is validated and bounded but never copied into the report or summary.
- The tests use synthetic fixtures only: in-process engines, generated IDs and times, local temporary directories. **No customer system, address, credential or inventory is read, assumed or contacted, and no result here is customer acceptance.** A real signed no-send shadow window and the private acceptance ledger remain separate, separately authorized work.

## Inputs

| Input | Contents |
| --- | --- |
| `LegacyEvidence.Ledger` | One `LedgerEntry` per legacy delivery attempt: entity, kind, impact revision, ordinal, recipient pseudonym, `AttemptID` (the delivery idempotency ID), `Attempt` (from 1), `EventTime`, `DeliveredAt`, `SourceVersion`, outcome (`delivered`, `suppressed`, `failed`, `unknown`), suppression code and the legacy `Trigger` the operator normalized the rule into (`per_occurrence`, `count`, `rate`, `rate_unknown_denominator`, `impact`, `regression`, `critical_code`, `reminder_timer`, `source_recovery`, `incident_resolve`, `manual`, `other`). |
| `LegacyEvidence.Acks / Lifecycle / Windows` | Human ACKs (impact revision covered, time); source recoveries and incident resolutions as separate facts; recorded snooze/maintenance windows with reason, start and expiry. |
| `LegacyEvidence.Ownership` | Exactly one owner per notification class (`urgent`, `reminder`, `recovery`, `queue`, `digest`): `soundpost` or `customer_retained`. |
| `LegacyEvidence.Controls` | Policy threshold controls the customer tools hold today (`min_operations`, `min_failures`, `rate_basis_points`, `regression_min`, `critical_codes`, `first_reminder`, `reminder_every`, `max_suppression`, `digest_zone`, `other`). |
| `CanonicalShadowEvidence` | `Replays` (event streams per subject, replayed through `notify.ShadowEvaluator`) and/or recorded `Decisions` with the decision time and optionally the template `Basis`/`Rate`. A refused replayed event decides nothing and is a blocker finding. |
| `ApprovedPolicy` | The policy `Revision` and `Config` under comparison, `Approvals` and `Controls` dispositions. |

Malformed closed enums, identifiers or ledger fields are refused with an error. Replayed events under another policy revision or configuration than the approved one are blocker findings.

## Ledger comparison: attempt, event time, source version

`ledgerReduce` collapses the legacy ledger to one record per logical decision and recipient, independent of input order:

- Entries sharing an `AttemptID` are **retries** of one delivery. An attempt that reached the provider wins, otherwise the last attempt.
- An identical entry again is a **duplicate record**, not a second delivery.
- A delivered notice of **older source evidence** than one already delivered for the same entity is **late**: it is excluded from comparison and is never the current state (it is reported as noise).
- Two separate attempts of one decision keep the delivered one with the newest source version; a further delivered copy is a **duplicate delivery** the recipient actually received (noise).
- One attempt ID for two decisions, two outcomes for one attempt, or a delivery before its event are blocker findings; they are never silently repaired.

## Classification

Every difference is one of four classes, each with a closed reason:

| Class | Meaning | Reasons |
| --- | --- | --- |
| `missing_urgency` (**blocker**) | Legacy interrupted a person and nothing explains why the canonical owner did not. Never waivable by an approval. | `urgent_not_delivered`, `reminder_not_delivered`, `recipient_dropped`, `silenced_without_window` |
| `noise` | No urgency lost, but unapproved. Reported separately. | `repeat_occurrence_page`, `legacy_fake_rate`, `reminder_after_ack`, `reminder_cadence`, `legacy_ignored_window`, `legacy_duplicate_delivery`, `legacy_late_delivery`, `canonical_extra_interrupt`, `worse_impact_after_ack`, `recipient_added`, `queue_cadence`, `digest_cadence`, `source_version_skew`, `suppression_reason`, `dedup_inconsistent` |
| `intentional` | A noise difference covered by a complete approval within its expected impact. | same as noise |
| `inert` | Neither side would have interrupted anyone, or a class stays with a customer tool. | `legacy_suppressed_only`, `canonical_suppressed_only`, `customer_retained_class` |

Key rules: repeated exception occurrences are one group, so legacy per-occurrence pages beyond a canonical opening that already covers that impact are noise; a rate legacy computed without a known denominator is never reproduced (`legacy_fake_rate`); an ACK covers reminders for the impact it saw, so later legacy reminders are noise, while a worsened impact must still interrupt (`worse_impact_after_ack` when only canonical does, a blocker when only legacy did); a canonical silence by maintenance or snooze is excused only by a recorded window with a reason and an expiry covering the decision time (the window is half-open); a source recovery and an incident resolution are separate kinds and separate facts.

## Intentional differences

A difference is intentional only with **all three** of: an owner-approved reason (`OwnerReason` and `ApprovedBy`), the policy revision (`PolicyRevision` equal to the approved revision) and an observable expected impact (`Expected.Effect`, which must be the effect the reason implies, and `MaxDecisions` > 0). Missing, mismatching or exceeded approvals leave the difference as noise and add a blocker finding (`approval_incomplete`, `approval_revision_mismatch`, `approval_effect_mismatch`, `approval_unknown_difference`, `approval_blocker_class`, `approval_ambiguous`, `approval_impact_exceeded`). An approval that matches nothing is reported (`approval_unused`). The report records the observed impact per approval.

## Policy threshold controls

Every control recorded from the customer tools needs a disposition: `preserved` (the canonical configuration holds the same value; critical codes compare as sets), `superseded` or `retained_external` (each needs a reason, an approving owner and the policy revision). A control with no disposition is `control_silently_discarded`, a preserved control that differs or cannot be held by the configuration is `control_preserved_mismatch`, an incomplete supersession is `control_supersession_incomplete`; all are blockers. Dispositions for unknown controls are reported (`control_disposition_orphan`).

## Ownership

Each class that either side delivered needs a declared owner. A class declared `customer_retained` while the canonical owner would deliver it is `dual_normal_sender`; a class with no declaration is `ownership_unspecified`; contradictory declarations are `ownership_ambiguous`. All are blockers: after cutover exactly one normal sender owns each class.

## Semantic checks and the verdict

Checks report `pass`, `fail`, `unverified` or `not_exercised`: `occurrence_grouping`, `impact_rate_regression_interrupt`, `unknown_denominator_no_rate` (canonical decisions recorded with `Basis`/`Rate` are verified; a replayed decision has no recorded basis and is `unverified`), `ack_semantics`, `recovery_resolve_separate`, `late_event_ordering`, `duplicate_event_handling`, `job_retry_handling` (including that the canonical owner is not behind the newest legacy source version), `queue_digest_cadence`, `window_reason_expiry`, `ownership_boundary`, `control_preservation`.

Verdicts, in precedence order: `blocked` (any missing urgency, blocker finding or failed check), `insufficient_evidence` (either side has no decisions: empty is never parity), `unresolved` (unapproved noise or an unverified check), `incomplete_coverage` (a check was never exercised) and `reconciled`. `reconciled` is a statement about the supplied evidence only, never customer acceptance.

## Command

The parent wires `policy-compare` to `runPolicyCompare(ctx, args)` with the arguments after the subcommand:

```
go run ./tools/adoption policy-compare --legacy <legacy.json> --canonical <canonical.json> --approved-policy <approved.json> --private-output <external-private-directory> --public-summary <new-summary-file> [--private-directory-acl-confirmed] [--timeout 2m]
```

It writes `policy-report.json` (private, exclusive, mode 0600) into the private directory and the closed public summary to a new file, then exits non-zero unless the verdict is `reconciled`; the evidence is written in either case. Existing files are never overwritten. The private directory checks are the intake tool's and need a valid local Git context.

## Not covered here

The signed no-send shadow window over a real system (firing, repeat, ACK, worse impact, snooze expiry, recovery, late and duplicate events, job retry) and the resolution of every real urgent and noise difference in the private acceptance ledger are outside this tool and this repository. They need the owning environment's separate authorization.
