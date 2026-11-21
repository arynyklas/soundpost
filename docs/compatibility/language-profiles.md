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

The input normalization the gate checks is evidence the smoke run produced, never a claim: every stage of the
persisted path compares the float samples it sent with the ones storage returned, and, for each native histogram
feed (direct ingest, remote write v1 and v2), the histograms it sent with the ones storage returned, record for
record and field for field (`query.HistogramInput`: counts above 2^53 as decimals, floats as their bits, spans,
bucket deltas, custom bounds, reset hint). The gate fails when the authored inputs hold no stale marker, no
integer native histogram or no float native histogram, because the loss check of that kind would then never have
been exercised. The identity over this evidence is pinned in `qualification/query-matrix.yaml`.

The smoke layouts are real installations, not stand-ins. `single` is one node. `distributed` is three
in-process voters (`internal/smokecluster`, `appcore.OpenDistributed`) on three private directories,
joined over mTLS peer listeners from one authenticated cluster seed, with the owned ingest, query and
live routes served on every voter. The five case files run unchanged on it (the persisted path
restarts the whole cluster), and `internal/conformance/query/smoke.RunDistributed` adds the cross-node
scenario: a write acknowledged through any voter is readable on all of them, the owned PromQL, LogQL,
discovery and live routes answer on followers, isolation and revocation hold on every voter, losing
the leader leaves the survivors answering completely and acknowledging (an election window yields
errors without values, never an apparently complete empty answer), a voter without quorum
acknowledges nothing and fails reads closed, and restarted voters converge on identical data with every
original receipt unchanged. The voters share one host and one process, so this is a software
failure-domain check, not the three-independent-hardware qualification (`docs/operations/distributed.md`).

## Numeric determinism and platforms (10.33)

The release platform is linux/amd64 only (decision D10); arm64, Windows and macOS rows are reported as
`out_of_release_scope`, never as passed. Within that scope the engines are bit-compared with the pinned
references, with two declared limits:

- `^` (power with a non-integer exponent) and `exp()` use the platform `math.Pow`/`math.Exp`, as the pinned
  references do. On amd64 `math.Exp` is assembly that uses fused multiply-add when the CPU has it, so the last
  bits of such results differ between a CPU with and without FMA (measured with `GODEBUG=cpu.fma=off`: 17,904
  of 900,676 `Pow` and 49,598 `Exp` probe results change) and between architectures. There is no deterministic
  amd64 reference to port, and a pure-Go port would move the owned results away from the references on the
  release platform. They are therefore declared non-portable: conformance holds on hosts with the CPU features
  of the oracle host (FMA), and on no other platform. `Pow` with an integer exponent is identical everywhere.
  `Log`, `Log2`, `Log10` and `Exp2` are portable pure-Go ports (`third_party/portablemath`).
- Invalid-operation NaN payloads are canonicalised at the arithmetic sites listed in
  `internal/query/value` (`Add`/`Sub`/`Mul`/`Div`, quantile, Kahan sum, variance, histogram average and
  quantile interpolation). Other NaN-creating arithmetic (the remaining aggregations, `rate`/`deriv`,
  `holt_winters`, LogQL metric math, histogram bucket math) is not wrapped: its NaN payload bits are only
  guaranteed on linux/amd64. Wrapping them and running the suites under qemu arm64 (10.33-W2) is an arm64
  item and so out of the release scope.

## PromQL selector regexes that are not UTF-8 (02.12-W3)

Observed against both pinned references (`conformance/query/cases/promql-wave6-regex-utf8*.json`, same
behaviour on 3.1.0 and 3.13.5):

- A label-matcher regex (`=~`, `!~`, including `__name__`) whose `|`-separated alternatives contain no
  regexp metacharacter (`\ . + * ? ( ) | [ ] { } ^ $`) is matched by byte equality against the
  alternatives and is never compiled, so it is accepted even when it is not valid UTF-8 (the PromQL
  string escape `\xff` yields one such byte). The owned engine does the same for both PromQL profiles.
- Any metacharacter in any alternative sends the pattern through the compiler, which rejects the
  invalid UTF-8 (`m{v=~"\xff.*"}`, `(\xff)`, `[\xff]`, `(?i)\xff`, `\xff|a.*`).
- `label_replace` always compiles its regex, so `label_replace(m,"d","x","v","\xff")` is an evaluation
  error on both references and on the owned engine (the comparator cannot compare that error text, so it
  is covered by the syntax rows only as an accepted query).
- A quoted or raw string holding the character U+FFFD itself is a lexical error on both references
  (`m{v="<U+FFFD>"}`); the escape `"\ufffd"` is accepted. The owned lexer and formatter follow this.
- Not probed: label values that are invalid UTF-8 (the case format carries JSON strings only), and Loki
  stream-selector regexes.

## Shard strings and replica merges (02.12-W2, 07.05#10)

The OCI oracle feeds the engine one iterator below every merge and never shards, so no release row can
observe the `shard_aggregations` string switch, what a sharded evaluation does with an entry that two
shard inputs both deliver, or what the querier-side merge iterators collapse. `conformance/query/author/logql-shard-probe`
drives the pinned Loki 3.5.2 sources directly (a native build of the sha256-verified source archive, as
`native-oracle.sh build-loki-shard-probe`; the recorded file says so) over inputs authored in
`conformance/query/cases/logql-shard-replica-probe.json`. Its observations
(`conformance/query/evidence/native-logql-shard-replica-observations.json`, content-locked) are replayed
without a container runtime by Go tests bound to `shard-capability-domain`, `iterator-entry-merge` and
`iterator-sample-merge`; a bound test that is removed, renamed or unlisted fails
`TestShardReplicaProbeIsBoundToItsObligations` and, once the evidence is regenerated, the release gate
(an unobserved bound test is an unresolved obligation). What the pinned sources do:

- The shard mapper recognizes exactly `first_over_time`, `last_over_time`, `quantile_over_time` and
  `approx_topk`. Each enables its own capability and no other; a name listed twice enables it once;
  every other string (another case or spelling, surrounding space or newline, a `shard-` prefix, two names
  joined by a comma, the empty string, an unrelated name) enables nothing and does not affect its
  neighbours. `approx_topk` is refused with `approx_topk is not enabled. See -limits.shard_aggregations`
  unless its own name is listed, whatever else is. `internal/query/logql.ShardAggregationGates` gives the
  same answer on all 200 observed (string list, query) rows.
- The sharded evaluation (shard mapper plus downstream engine) keeps every copy of an entry that several
  shard inputs deliver; the owned query path over the same entries as stored rows gives the same answer
  group by group, ties between streams included (label text order on both sides, not the original stream
  hash that the iterators below use).
- The querier-side merge iterators do collapse: `NewMergeEntryIterator` returns one entry per distinct
  (timestamp, stream, line) of its inputs, whether the copies come from several inputs or from one;
  `NewMergeSampleIterator` suppresses a sample whose non-zero hash equals another's at one timestamp and
  stream (zero hashes and equal values never collapse). The owned engine has no such layer: equal text
  never identifies a record, a row of multiplicity n is n entries, and a replica is a further row (the
  locked rule text of `iterator-entry-merge`: normalization must distinguish owned multiplicity from
  upstream replica merging and cannot globally deduplicate input). This is a declared divergence, not a
  silent one: the per-fixture counts of both sides are pinned in
  `internal/conformance/query/logql_native_shard_replica_test.go`, so a fixture that stops diverging, a
  new divergence or a changed collapse rule fails a test.

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

All 785 obligations are bound to an implementation, their case sets and an observed Go test, and the
campaign was last run to completion against the real pinned oracle images (lane 2 wave 7, WSL Docker,
1266 s): all 8 required rows verified, every row exit 0. The images are local, digest-locked artifacts
(`source-lock.json` `artifact.path`); a host that does not hold them records zero oracle runs and the
campaign fails by design. The Docker-free replays (recorded native observations, content locks,
bindings) run in `go test` on every host.

The workflow `.github/workflows/conformance.yml` runs on every pull request and on `workflow_dispatch`.
Its earlier runs failed in the `Campaign tests (race)` step: first the default 10 minute `go test`
limit (`-timeout 100m` now), then `TestDistributedClusterScenarioHoldsAcrossNodesAndNodeLoss` with a
504 on a two-vCPU runner. Cause (measured on a 2-CPU-pinned host with a competing load): the Raft
transport queued every heartbeat of a group (one per 20 ms tick) behind a slow delivery, up to 128 per
lane, so a read-index round, which rides the same lane, waited seconds and a read ran into the 30 s
query deadline; a lane now keeps only the newest heartbeat and heartbeat response
(`internal/replica/transport.go`, `TestLaneKeepsOnlyTheNewestHeartbeatBehindASlowReceiver`). A hosted
runner does not hold the lab daemon's locked oracle images, so the workflow builds them
(`conformance/query/oracles/build-images.sh`) and the harness runs one only after proving its files
against `content_identity` in `source-lock.json` (see `conformance/query/README.md`). Observed run of
the campaign on a hosted runner: not yet.
