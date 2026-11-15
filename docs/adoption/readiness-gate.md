<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Cutover readiness gate

`tools/adoption readiness` (`runReadiness`) decides whether a cutover gate may be issued. It consumes typed evidence references produced by committed tools; it never re-implements a drill, query, journey or durability check.

## Required criteria (all ten, no partial approval)

`journey_gateway_model`, `journey_frontend_api_db`, `journey_background_retry`, `source_policy`, `query_profile`, `isolation_matrix` (cross-org/project/artifact/tail/replay/profile denial), `delivery_policy`, `deletion_restore`, `external_deadman`, `legacy_retention_export`.

Each criterion needs at least one reference that is fully valid. Missing evidence is a `missing_evidence` blocker whose detail names the exact kind (for example `missing evidence: external_deadman`). These kind names belong to this gate (`tools/adoption/readiness.go`); the closure ledger uses a different vocabulary for the same subjects (for example `tenant_isolation_matrix`, `retention_export_record`, `external_deadman_failure_domain`; see `closure.md`), and a gate signed by one tool is not accepted by the other without an explicit mapping.

## Evidence reference

`EvidenceRef`: kind, producer (allowlisted per kind: adoption-journeys, adoption-shadow, adoption-policy-compare, adoption-retention, drills, qualify, smoke), sha256 digest of the producer's report, observed-at, authorization id, scope, environment (`synthetic|staging|production`), result (`pass|fail|not_run`), `disruptive`, and for the deadman a `failure_domain`.

A reference is refused with a named blocker when: producer unknown, digest malformed, observation stale (older than `max_age_seconds`) or future-dated against the ledger clock, scope differs from the ledger's, result `not_run` or `fail`, environment synthetic, environment staging while `require_production` is set (`production_proof_outstanding`, never substituted), no live matching authorization (same id, scope, environment, kind, inside its not-before/expiry window), a disruptive drill without an authorization that explicitly sets `disruptive`, or a deadman whose failure domain is empty or equals `product_failure_domain`.

With `require_production` false, staging evidence may pass, but the result and the signed gate record `production_proven: false` / production proof outstanding.

## Producer reports (08.05-W1)

A digest is not accepted as a bare reference. `ReadyForCutover(ctx, ledger, authorizations, reports)` takes the producers' report bodies (`NewReadinessReports`; the CLI reads them from `--reports DIR`, one regular file per report, at most 256 files of 16 MiB, nothing else in the directory). A body is found only by the SHA-256 of its own bytes, so a reference cannot name one digest and be satisfied by other bytes. For every reference that is not already refused for a malformed digest or a result other than `pass`, the body named by the digest is decoded strictly (unknown fields and trailing data are refused) and judged by the adapter of the reference's producer. Every allowlisted producer has one; the gate itself checks the 10 kinds below and no producer stays a bare digest.

| Producer | Report that the digest names | Kinds | Passes only when |
|---|---|---|---|
| `adoption-journeys` (08.03) | `journeys.json` (`JourneyReport`) | the three `journey_*` | schema version known, `scope` and `verified_at` present, the section of the kind exists exactly once, has at least one check and every check passed; `verified_at` equals the reference's `observed_at`; `scope` equals the ledger's (`journeys --scope LABEL`) |
| `adoption-shadow` (08.02) | private shadow report (`ShadowReport`) | `source_policy` | `scope` and `observed_at` present, reconciled, no policy violation, no external send, no normal delivery, parity equal over at least one comparison, at least one record received; `observed_at` (the instant the run began) equals the reference's; `scope` (the shadow policy file's `scope`) equals the ledger's |
| `adoption-policy-compare` (08.04) | policy comparison report (`PolicyReport`) | `source_policy`, `delivery_policy` | `scope` and `observed_at` present, verdict `reconciled`, at least one comparison, no missing urgency; `observed_at` (the instant the command ran) equals the reference's; `scope` (the approved policy file's `scope`) equals the ledger's |
| `adoption-retention` (08.07) | legacy-history status (`HistoryReport`) | `legacy_retention_export` | `scope` and `evaluated_at` present, clear, no blocker, at least one recorded obligation, none overdue, no active writer on the legacy history; `evaluated_at` equals the reference's `observed_at`; `scope` (the history snapshot file's `scope`) equals the ledger's |
| `qualify` (07.05) | `campaign-report.json` (`soundpost-query-campaign/1`) | `query_profile` | `observed_at` present, verified, nothing missing, no failure, every row verified, a release row and a smoke row for every required layout; `observed_at` (when the campaign verified its rows) equals the reference's |
| `smoke` (07.04) | `isolation.json` of `smoke isolation` | `isolation_matrix` | version 1, `ObservedAt` present, at least one denial row (error status, outcome `indistinguishable_from_guess`) and one own-read row (status 200, outcome `only_own_scope`), no other row, every row names actor, target and surface; `ObservedAt` equals the reference's |
| `drills` (07.07) | the `<scenario>.json` of one `drills` scenario, target `isolated` | `delivery_policy` (`provider-failure-outage`, `owner-cutover-rollback`), `deletion_restore` (`stale-policy-delete-barrier`, `backup-predates-deletion`, `restore-authority-unavailable`), `external_deadman` (`external-deadman`) | status `passed` and at least one check, every check ok; `started_at` (RFC 3339, the one instant the report records) equals the reference's `observed_at` |

Each failure is a blocker that names the kind (`code:kind` in the CLI error):

- `report_body_missing`: no supplied body has the digest. A body altered after its digest was recorded has another digest, so it is reported this way too: the gate cannot tell a missing report from a changed one.
- `report_invalid`: the body is not a report of that producer that can speak for that kind: not JSON, unknown field, trailing data, another schema or version, another producer's report, another kind's report (for example a deletion drill for the deadman) or a drill of a target other than `isolated`.
- `report_not_passing`: the body is of the right kind and its own verdict, checks or counts do not pass (table above).
- `wrong_scope`: besides the reference naming a scope other than the ledger's, the report itself names (adoption-journeys, adoption-shadow, adoption-policy-compare, adoption-retention) a scope other than the ledger's. A report that names no scope is `report_invalid`.
- `report_time_mismatch`: every producer's report carries the instant it was observed at and the reference's `observed_at` must be exactly that instant: a months-old report cannot be cited as fresh. A report with no usable time is `report_invalid`.
- `report_unverifiable`: only with `require_verified_reports`, for a producer with no adapter (none is allowlisted today).

A satisfied criterion carries `body_verified: true` in the signed gate; `criteria_body_verified` in the public summary counts them.

What the body checks do not establish:

- A `drills` body that passes may record parts of itself as `not_run_items` (the deadman drill always records `independent failure domain` and `real alert destination` as not run on the isolated host). They are the drill's own statement and are not interpreted here; independence of the deadman remains the ledger's `failure_domain` claim, checked against `product_failure_domain` only.
- The `drills` and `smoke` bodies are decoded with a mirror of the JSON those `package main` tools write (`readinessDrillReport`, `readinessIsolationReport`); a change of their shape must change the mirror. The `qualify` body is decoded with its own exported `CampaignReport`.
- `qualify`, `smoke` and `drills` reports name no scope: they describe the product build under test or an isolated harness (`drills` runs only against target `isolated`), not a customer scope. Their `scope` in the ledger remains the operator's claim; a report of one of them can satisfy ledgers of different scopes. The adoption reports (journeys, shadow, policy comparison, history) are scope-bound as the table says; the scope label is supplied by the operator who runs the producer, so the binding stops an honest report being reused for another scope, not an operator who labels a run falsely.
- The `smoke isolation` matrix covers capabilities and exports, not every denial surface named by the criterion (artifact, tail, replay, profile).
- Which scenario of a kind the operator references is the operator's choice: one valid reference satisfies a kind.
- Reports of the closure (08.07 `closure.go`), cutover (08.06) and readiness (08.05) tools are not producers of evidence references.

## Signed gate

`ReadyForCutover(ctx, AcceptanceLedger, Authorizations) (CutoverReadiness, error)` returns blockers, or an unsigned gate when complete. `SignReadyGate` (ed25519, standard library) signs only complete results; the signature covers the ledger digest, criteria, authorizations, scope, issue instant (the ledger clock), expiry and production flag. Expiry is the earliest of each used evidence's observed-at plus the freshness window and each used authorization's expiry.

`VerifyReadyGate(gate, publicKey, now)` is the consumer entry point (task 08.06). It refuses a bad key, missing/garbled/invalid signature (tamper, wrong key), a malformed shape, a missing or duplicated criterion, future dating, and expiry (`now >= expires_at`), using the caller's clock.

## CLI

```
adoption readiness --ledger L.json --authorizations A.json --reports REPORTS_DIR --signing-key KEYFILE \
  --private-output NEW_PRIVATE.json --public-summary NEW_PUBLIC.json [--now RFC3339] [--timeout 1m]
```

`--reports` is required: a digest is never accepted without its report. `KEYFILE` holds a hex 32-byte ed25519 seed. `--now` overrides the ledger clock. Exit 0 and a signed gate in the private output only when complete; otherwise a non-zero exit listing `code:kind` blockers. Output files are created exclusively (never overwritten).

## Public projection

Closed shape: `ready`, `criteria_required`, `criteria_satisfied`, `criteria_body_verified`, `blocker_counts` (blocker code → count), `production_proof_outstanding`, `customer_acceptance` (always `false`). No scope, ids, digests, domains or times.

## Trust boundaries and what is synthetic-only

- The ledger, authorizations, report bodies and gate are private; only the public summary may leave. Evidence digests are verified against the producers' report bodies (see above); the gate trusts those bodies as far as the producers' own verdicts go and does not re-run any producer.
- Authorizations are caller-supplied data; this tool does not prove who issued them.
- The test suite runs only against synthetic fixtures in memory and temporary directories. No customer system was contacted. The gate is never customer acceptance, and no drill is run by this tool; the authorized drills against a real or staged topology are not done here.
