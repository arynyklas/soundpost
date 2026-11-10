<!--
Copyright 2026 Aryn Yklas
SPDX-License-Identifier: Apache-2.0
-->

# Query language profiles and the qualification campaign

Soundpost implements three query-language profiles with its own engine. They are language
profiles only: no upstream HTTP, API, Sentry or OTLP surface is a Soundpost product contract, and
no production path reaches an oracle.

## Exact pins

Pins live in `profiles/query/*.json` and are checked, not restated, by the campaign.

| Profile id | Upstream | Commit | FeatureSets |
| --- | --- | --- | --- |
| `promql-prometheus-3.1.0` | Prometheus 3.1.0 | `7086161a93b262aa0949dbf2aba15a5a7b13e0a3` | 4 |
| `promql-prometheus-3.13.5` | Prometheus 3.13.5 | `f497435984d1ca1d84cda5ed309387ac2eb1f8f6` | 128 |
| `logql-loki-3.5.2` | Loki 3.5.2 | `257d2f62bf8a81b44dea6fe88968d1d28c8e01e7` | 64 |

A FeatureSet is one registered combination of the profile's version gates (for example
`promql-binop-fill-modifiers`, `promql-extended-range-selectors`, `type-and-unit-labels`). The
oracle configuration digests are `7164c79e...8679` (both PromQL profiles share one configuration) and
`797fff58...d6c2` (LogQL). Every profile is a separate row; no row inherits an upstream version from
a suite default.

## The campaign

`qualification/query-matrix.yaml` lists the required evidence: every profile x seed release row
(profile commit, oracle configuration digest, the id of every registered FeatureSet, the
input-normalization identity) and one smoke row per persisted layout (`single`, `distributed`).
`tools/qualify` (`RunQueryConformance`) runs the locked tooling:

```
soundpost-querycheck smoke   --storage real --control real --own-http --restart --compact --modes <layout> --cases <five case files>
soundpost-querycheck release --policy conformance/query/release-policy.json --all-profiles --all-feature-sets \
    --require-locked --require-zero-unbound --require-zero-skips --require-zero-mismatches --seed <seed> --smoke-report <single smoke report>
```

and verifies the written reports. Run it with
`go run ./tools/qualify/cmd/query-campaign --matrix qualification/query-matrix.yaml --artifact-dir <dir>`;
the exit status is nonzero unless every required row is verified. `campaign-report.json` in the
artifact directory maps each row to its report, report sha256, profile commit, oracle configuration
digest, FeatureSet count, input-normalization identity and build identity, and carries the
aggregate counts.

A row is verified only when the report it names exists, parses, matches its pinned digests and
reports: zero unbound obligations, zero unrun cases (matched equals required), zero skips, zero
mismatches, zero normalization loss, oracle runs observed and none unavailable or unverified, zero
unobserved Go tests, zero rejected provenance, all interactions covered, zero scenario failures,
and a zero exit code from the tool. Smoke rows additionally require real storage and control, the
layout actually run, every required case file run, no failing step, every persistence and isolation
scenario of the policy present and passing, and an empty NOT-satisfied list. A missing row, FeatureSet,
profile or layout, a duplicate, a row bound to a report of another profile, kind, seed or layout, an
absent or unparsable report, or a digest mismatch fails with the exact evidence named.

## What it proves, and what it does not

It proves that the locked release gate and smoke runner were executed for all three pinned
profiles, every registered FeatureSet, the matrix seeds and both layouts, and that their own
verdicts were zero-defect. Semantic comparison, normalization, loading and coverage inventory
remain the sole property of `internal/conformance/query`; the campaign adds no second policy.

It does not prove:

- Equivalence beyond the finite authored corpora, the declared generator axes (pairwise plus the
  declared higher-order tuples) and the listed seeds. A seed is a command-line input of the
  release tool; the report does not record it, so a seed is bound only by the campaign's own
  invocation.
- Tolerances other than those in the locked comparator and release policy; the campaign has none.
- Behaviour of upstream HTTP/API surfaces, Sentry, or OTLP.
- Oracle observation unless the release command is given `--runtime` (matrix `runtime`); without
  it the gate records zero oracle runs and the campaign fails.

## State on this tree

The campaign fails, and must. The locked release gate rejects with `3141 unresolved (unbound 785,
unrun 2355, 1 rejected provenance audit)` with the single-layout smoke report supplied (`3152` without it): none of the 785 obligations is bound to an implementation, case set and observed test,
and none of the 2355 required cases ran against the owned engine and an oracle. Distributed smoke is
not run (no multi-node harness for the owned query paths) and single-layout smoke records its
unsatisfied requirements. The workflow `.github/workflows/conformance.yml` runs the campaign in CI
and is verification-only; it has not been executed.
