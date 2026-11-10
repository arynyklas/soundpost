<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Cutover readiness gate

`tools/adoption readiness` (`runReadiness`) decides whether a cutover gate may be issued. It consumes typed evidence references produced by committed tools; it never re-implements a drill, query, journey or durability check.

## Required criteria (all ten, no partial approval)

`journey_gateway_model`, `journey_frontend_api_db`, `journey_background_retry`, `source_policy`, `query_profile`, `isolation_matrix` (cross-org/project/artifact/tail/replay/profile denial), `delivery_policy`, `deletion_restore`, `external_deadman`, `legacy_retention_export`.

Each criterion needs at least one reference that is fully valid. Missing evidence is a `missing_evidence` blocker whose detail names the exact kind (for example `missing evidence: external_deadman`).

## Evidence reference

`EvidenceRef`: kind, producer (allowlisted per kind: adoption-journeys, adoption-shadow, adoption-policy-compare, adoption-retention, drills, qualify, smoke), sha256 digest of the producer's report, observed-at, authorization id, scope, environment (`synthetic|staging|production`), result (`pass|fail|not_run`), `disruptive`, and for the deadman a `failure_domain`.

A reference is refused with a named blocker when: producer unknown, digest malformed, observation stale (older than `max_age_seconds`) or future-dated against the ledger clock, scope differs from the ledger's, result `not_run` or `fail`, environment synthetic, environment staging while `require_production` is set (`production_proof_outstanding`, never substituted), no live matching authorization (same id, scope, environment, kind, inside its not-before/expiry window), a disruptive drill without an authorization that explicitly sets `disruptive`, or a deadman whose failure domain is empty or equals `product_failure_domain`.

With `require_production` false, staging evidence may pass, but the result and the signed gate record `production_proven: false` / production proof outstanding.

## Signed gate

`ReadyForCutover(ctx, AcceptanceLedger, Authorizations) (CutoverReadiness, error)` returns blockers, or an unsigned gate when complete. `SignReadyGate` (ed25519, standard library) signs only complete results; the signature covers the ledger digest, criteria, authorizations, scope, issue instant (the ledger clock), expiry and production flag. Expiry is the earliest of each used evidence's observed-at plus the freshness window and each used authorization's expiry.

`VerifyReadyGate(gate, publicKey, now)` is the consumer entry point (task 08.06). It refuses a bad key, missing/garbled/invalid signature (tamper, wrong key), a malformed shape, a missing or duplicated criterion, future dating, and expiry (`now >= expires_at`), using the caller's clock.

## CLI

```
adoption readiness --ledger L.json --authorizations A.json --signing-key KEYFILE \
  --private-output NEW_PRIVATE.json --public-summary NEW_PUBLIC.json [--now RFC3339] [--timeout 1m]
```

`KEYFILE` holds a hex 32-byte ed25519 seed. `--now` overrides the ledger clock. Exit 0 and a signed gate in the private output only when complete; otherwise a non-zero exit listing `code:kind` blockers. Output files are created exclusively (never overwritten).

## Public projection

Closed shape: `ready`, `criteria_required`, `criteria_satisfied`, `blocker_counts` (blocker code → count), `production_proof_outstanding`, `customer_acceptance` (always `false`). No scope, ids, digests, domains or times.

## Trust boundaries and what is synthetic-only

- The ledger, authorizations and gate are private; only the public summary may leave. Evidence digests are trusted as references to the producers' reports: this tool checks structure, freshness, scope, authorization and independence claims, not the report contents. Verifying that a digest matches a real report is the producer pipeline's job.
- Authorizations are caller-supplied data; this tool does not prove who issued them.
- The test suite runs only against synthetic fixtures in memory and temporary directories. No customer system was contacted. The gate is never customer acceptance, and no drill is run by this tool; the authorized drills against a real or staged topology are not done here.
