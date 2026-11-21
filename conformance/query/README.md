<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Query conformance corpora

Development-only comparison of the owned PromQL/LogQL engines against pinned
upstream reference builds. The references run only inside isolated oracle
images; they are never a production fallback.

## Locked files are byte-exact and LF-only

`source-lock.json` pins every case file (`cases/`), every audit result file
(`audits/*.json`) and every profile file (the repository's `profiles/query/*.json`) by the
SHA-256 of its raw bytes. It does **not** pin: the two audit generator scripts
`audits/promql-author.py` and `audits/promql-details.py` (they are inputs to the
accepted audits; the audit files they produced are what is locked),
`acceptance.json`, `obligations.json`, `fixtures/adapters/*`, `primitives/*` and
`oracles/*`. Git normalises line endings (`core.autocrlf=input`),
so a file that is CRLF in a Windows working tree hashes differently from the
blob a clean checkout receives. Every locked file MUST be written with LF line
endings before its hash is recorded. After editing any locked file:

1. recompute its entry under `inventory_files` (key `cases/<name>`) or
   `profile_files`;
2. run `go run ./cmd/soundpost-querycheck inventory --check`.

A mutated or unlocked case file hard-fails; `compared: 0` is a failure, never a
pass.

## Inputs are authored, expected values are native observations

The inputs of every case file are authored by this project (the files carry
`"schema":"soundpost-authored-logql-cases-v1"` and an Apache-2.0 header). In
`cases/logql-pipeline-differential.json` and `cases/logql-json-path-syntax.json`,
and in `internal/query/logql/testdata/native-syntax-errors.json`, the expected
outcomes are not authored: they record what the pinned Loki 3.5.2 reference
returned for those inputs, and each row's `binding_scope` says so. They are not
authored predictions. Rows
whose reference output is nondeterministic are excluded (below), and rows whose
native error text has no projected semantic family are excluded until the
oracle driver (`oracles/logql-native/classify.go`) classifies them.

Pipeline rows compare the exact label set. Syntax rows compare acceptance, the
semantic family and, when the native text exposes one, the start byte.

## Native nondeterminism

When two requests of one `logfmt` expression stage name the same line key
(for example `|logfmt a="c", b="c", c="a"`), the pinned reference assigns the
key to one of the labels in Go map-iteration order. Repeated native runs return
both assignments. Soundpost resolves this deterministically: the first
requesting label in request order owns the key. Such rows are not in the corpus.

An instant `count_values` result with two or more groups has no order in the pinned
PromQL references either: `aggregationCountValues` collects the groups in a Go map and
emits them in iteration order (`promql/engine.go` in Prometheus 3.1.0 lines 3365-3402 and
3.13.5 lines 4183-4220; the instant path keeps that order, `rangeEval` "shortcut so as not
to change sort order", 3.1.0:1265 / 3.13.5:1537). Such rows stay in the corpus and carry
`"unordered_vector": true`: the evaluation phase compares the instant vector as a multiset
of exact series, so a wrong label text, count, value or number of series still fails, and
only the order is free. The marker is comparison-only and is stripped before the case is
sent to a reference; it is rejected on range rows (range results are sorted by labels,
`sortMatrixResult`, and stay compared in order). Every other row compares order exactly.

## Rebuilding the oracles

The oracle images embed the driver and the `soundpost-querycheck` adapter and
are referenced from the lock by local image id, so a source change to either
requires a rebuild and a repin of `profiles[].artifact.path` and `.sha256`:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
  -o conformance/query/oracles/querycheck-linux-amd64 ./cmd/soundpost-querycheck
docker build --build-arg LOGQL_GO_IMAGE=<digest-pinned golang 1.24.5> \
  -f conformance/query/oracles/logql-loki-3.5.2.Dockerfile \
  -t soundpost-oracle-logql-loki-3.5.2:current conformance/query/oracles
```

The PromQL images take `--build-arg EVALUATION_GO_IMAGE=<digest-pinned golang>`
(1.23.4 for Prometheus 3.1.0, 1.26.10 for 3.13.5). Re-inspect the image id
before every run; a stale id fails with a Docker "No such image" error.

The image ids in `source-lock.json` are the ids of the daemon that built them. A rebuild
on another daemon yields other ids (layer timestamps; the pinned upstream images and
Dockerfiles are unchanged), so it is followed by a repin: the three evaluation ids
(`profiles[].artifact.path` and `.sha256`), the configuration variants (below), the
`image_sha256` values of `internal/conformance/query/testdata/native-configuration-observations.json`
and the `acceptance.json` `configuration_phase` block, then `author/relock.py` for
`provenance.json` and `acceptance.json` and `go run ./cmd/soundpost-querycheck inventory --check`.
The last repin is the Debian 13 / Docker 26.1.5 build of 2026-11-18 on a lab Docker host
(`.superpowers/sdd/approved-product/l2oci-evidence/`): every recorded reference observation
(181 configuration scenarios) came out identical on the new images.

## Oracle images without the locked ids (hosted CI runner, fresh host)

A daemon that does not hold the locked image ids cannot be given them: an id is the hash of the
image configuration, which carries layer timestamps. `oracles/build-images.sh` builds the five local
images on such a daemon from the pinned inputs with the Dockerfiles as locked (upstream release
images by linux/amd64 digest, the Go builder images by digest under
`profiles[].reference_compiler.builder_image`, source archives by `ADD --checksum`, the adapter from
the tree under test) and tags them `soundpost-oracle-<profile>:current` (the configuration variants
under `profiles[].configuration_oracle.image`). The workflow `.github/workflows/conformance.yml` runs it
before the campaign.

`RunOracle` and the configuration phase (`oracle_image.go`) use the locked id whenever the daemon
holds it, exactly as before. Only when the daemon positively answers "No such image" for the locked id,
and the lock carries `content_identity` (under `artifact` and `configuration_oracle`), is the tagged
image used, and only after the harness has proven, for the image id it will run: platform, entrypoint,
and the SHA-256 of every listed file as `docker cp` delivers it (the upstream release binary, the
reference driver compiled from the pinned source, the time zone dataset, the configuration file). One
differing byte, a missing file or another entrypoint refuses the image; a missing image fails with the
way to build it. The adapter (`/adapter`) is not listed: it is the harness's own code, rebuilt from
the tree under test. Observations made this way carry `oracle.resolved_image_id` and
`oracle.identity_basis: "content-identity"` next to the locked `image_sha256`.

After a change of the reference driver sources (`oracles/evaluation`, `oracles/logql-native`), of a
pinned upstream image or of a configuration file, rebuild with the script on a clean daemon and
recompute the `content_identity` file digests (`docker create`, `docker cp -L <id>:<path> - | tar -xO |
sha256sum`) together with the image ids; both are repinned in `source-lock.json`.

Measured (2026-11-21, Docker 26.1.5, a private daemon behind a CONNECT proxy): the rebuilt
`/evaluation-reference` of both Prometheus pins is byte-identical to the native build of
`author/native-oracle.sh` (sha256 `c4bc8a87...` for 3.1.0, `0915e4e1...` for 3.13.5) and the
rebuilt Loki `/usr/bin/loki` and `/oracle-zoneinfo.zip` equal `reference_compiler` / the dataset
recorded for the lock; only the image ids differ.

## Running the phases

Run each phase separately; a mixed-phase file silently skips rows of the other
phase when only one is requested.

```sh
go run ./cmd/soundpost-querycheck compare --phase syntax   --profiles logql-loki-3.5.2 \
  --cases conformance/query/cases/logql-syntax-pipeline.json --require-locked --runtime docker
go run ./cmd/soundpost-querycheck compare --phase pipeline --profiles logql-loki-3.5.2 \
  --cases conformance/query/cases/logql-syntax-pipeline.json --require-locked --runtime docker
```

The other phases are `evaluation` (PromQL), `logql-template` and `logql-metric`.

### The configuration phase (Prometheus configuration obligations)

`--phase configuration` (PromQL profiles only) observes the
`configuration/protocols` and `configuration/scrape-inheritance` obligations of both
Prometheus pins. Those obligations describe how the unmodified Prometheus release
loads a scrape configuration, which the evaluation oracle's `/adapter` cannot
express, so each pin has a separately pinned configuration-phase oracle image
(decision D29): `soundpost-oracle-promql-prometheus-<v>-configuration:current`,
built `FROM` the locked evaluation-oracle image id plus one added file
(`oracles/promql-prometheus-<v>-configuration.Dockerfile`, `.yaml`); no source
is copied and no layer below it changes. The harness starts the upstream
`/bin/prometheus` through `--entrypoint /bin/sh` with the observation script
`internal/conformance/query/configuration_observe.sh` and reads only whether it
became ready, the error it logged, and `/api/v1/status/config`.

```sh
docker build --pull=false --provenance=false --sbom=false \
  -f conformance/query/oracles/promql-prometheus-3.1.0-configuration.Dockerfile \
  -t soundpost-oracle-promql-prometheus-3.1.0-configuration:current conformance/query/oracles
python3 conformance/query/author/lock-configuration-oracle.py   # records ids and hashes
python3 conformance/query/author/release-author.py --only configuration
go run ./cmd/soundpost-querycheck compare --phase configuration \
  --cases conformance/query/cases/release-configuration.json --require-locked --runtime docker
python3 conformance/query/author/record-configuration-observations.py report.json
```

A daemon with the classic (overlay2) image store cannot resolve the configuration
Dockerfiles' `FROM <name>@sha256:<image id>` (a local image id is not a registry digest).
Map the base to the local image with a named build context; the Dockerfile stays as locked:

```sh
B=$(docker image inspect soundpost-oracle-promql-prometheus-3.1.0:current --format '{{.Id}}')
docker build --pull=false --provenance=false --sbom=false \
  --build-context "soundpost-oracle-promql-prometheus-3.1.0@$B=docker-image://soundpost-oracle-promql-prometheus-3.1.0:current" \
  -f conformance/query/oracles/promql-prometheus-3.1.0-configuration.Dockerfile \
  -t soundpost-oracle-promql-prometheus-3.1.0-configuration:current conformance/query/oracles
```

The owned side is `internal/sources/prometheus_config.go`; its scope (the modelled
keys and text forms) is stated in that file. `ConfigurationScenario` rows carry the
authored acceptance, refusal family and the effective values the rule text fixes;
the recorded reference observations are replayed Docker-free by
`TestReleaseConfiguration*`, and `author/configuration-mutants.py` (throwaway
copies only) shows twelve deliberate resolver defects are caught.

## Sample timestamps in comparison rows must be whole milliseconds

The pinned Prometheus oracle stores and returns milliseconds, while Soundpost keeps
nanosecond storage. Rows are only valid comparison inputs when every sample
timestamp is a whole number of milliseconds; otherwise the oracle sees floored
copies and the comparison measures that input difference, not an engine defect
(the design forbids rounding nanosecond storage into evaluator input without a
declared normalization). Evaluation times, steps and lookbacks are floored to the
millisecond domain by the engines themselves.

## Docker-free replay of recorded observations

The comparator needs the oracle images, which not every environment has. Native
results for the metric (LogQL) and evaluation (PromQL) phases are therefore also
recorded as offline testdata, and ordinary `go test` replays them through the same
production comparator:

- `internal/conformance/query/testdata/native-metric-observations.json`
  (`TestOwnedMatchesRecordedNativeMetricObservations`);
- `internal/conformance/query/testdata/native-promql-observations.json`
  (`TestOwnedMatchesRecordedNativeEvaluationObservations`).

Each row names the exact profile and enabled features it was observed under. Where
a native error text had no semantic family when it was recorded, `error.id` was
projected with the same rules as the oracle driver source. Both tests carry a row
floor so recorded evidence cannot silently shrink. They complement, and never
replace, the live `--require-locked` runs above.

## Native tie order is nondeterministic

`topk`/`bottomk` over tied values return different series on repeated native runs
(Go map order). Soundpost orders ties deterministically by label order, and rows
whose native result varied across repeated runs are excluded from every corpus.

## Build network

The PromQL oracle builds fetch Go modules. When the build container cannot reach
the module proxy ("connection refused"), the build fails although the host can;
retry, because the failure has been intermittent. The pinned Dockerfiles are not
edited to work around it.

## Release cases bind obligations to oracle-run rows

The release gate needs every ledger obligation bound to its positive, negative
and interaction case IDs, and every one of those cases run against the pinned
oracle and the owned engine. `release-cases.json` lists the content-locked case
files whose rows carry those ledger IDs; `soundpost-querycheck release --runtime
<docker>` runs each file through the differential runner that qualified it
(`syntax`, `evaluation`, `logql-metric`, `logql-template`) and the gate counts a
case matched only if the oracle identity verifies and the runner found no
disagreement. `--detail <file>` writes every outcome with its mismatch text.

`cases/release-*.json`, `release-cases.json` and the `production_bindings` and
`test_observations` of `acceptance.json` are generated by
`python3 conformance/query/author/release-author.py` (the script also rewrites
the content locks it owns). Rows are authored from obligation signatures and the
committed fixtures; no expectation is copied from an upstream run. An obligation
is bound only if all three of its case IDs exist; the others stay unbound.
`author/observe-go-tests.sh` records the `go test -json` evidence the bound Go
tests are observed from.

Negative rows must fail with an error family the oracle driver already
classifies (`oracles/evaluation/errors.go`); a native error with no projected
family is an unclassified hard mismatch, and the pinned images are never rebuilt
to add one.

The driver loads every `author/ext_<name>.py` (`build(ctx)` declares its case
files, puts rows and records `ctx.bind(obligation, package, go_tests)`); the
modules are `grammar` (PromQL grammar, lexical, precedence, duration and fill
syntax), `numeric` (function domains and numeric facts), `histogram` (native
histogram layouts, annotations, start timestamps), `semantics` (selector, time
modifier, matching, errors, regex primitives, engine options, sample budget) and
`logql` (parsers, filters, mutation, ordering, binary, template primitives).
`release-author.py --only <name>` writes and content-locks just that module's
files; `author/run-phase.sh` runs one locked file against the pinned oracles.
The Go tests a binding cites are listed per module in
`author/observed-tests.d/*.txt` (`<package> <TestName>`). Their expectations come
from the obligation text and IEEE/Go arithmetic, never from an oracle run, and
they cover what one differential query cannot observe (cancellation, deadline,
storage failure, budget exhaustion, engine option switches).

The four configuration obligations, `configuration/protocols` and
`configuration/scrape-inheritance` of both PromQL profiles, are bound like every
other obligation. Their rule states that they "change materialized input
acquisition, not fixed-input language evaluation", so the evaluation oracle's
`/adapter` cannot observe them; the configuration phase below observes them
against a separately pinned configuration-phase oracle image (D29).

## Evaluation phase without an OCI runtime (native references)

`author/native-oracle.sh build` and `setup <repo>` build the two pinned Prometheus evaluation
references natively from the sha256-verified upstream archives (the recipe of
`oracles/promql-prometheus-<v>.Dockerfile`) and write a fake runtime that runs the evaluation
adapter against them; pass it as `--runtime`. Only the evaluation phase is served. An observation
made this way is a native build of the pinned source, not the digest-locked image: `record` takes
`native` or `oci` and writes it into the recorded file. `author/ext-histogram-probe.py` authors the
extended-selector native-histogram probe (`cases/promql-extended-histograms.json`, 2,860 comparisons)
and records the reference observations to `evidence/native-promql-extended-histogram-observations.json`
(content-locked in `source-lock.json`), replayed by
`TestOwnedMatchesRecordedNativeExtendedHistogramObservations` from the locked bytes. The probe's first
run (two mismatching rows, the smoothed mixed-schema divergence fixed in `promql/select.go`) is kept in
the wave-17 evidence (`l2w17-evidence/lane2/probe-first-run-mismatches.json`).

`author/native-oracle.sh build-loki` builds the pinned Loki 3.5.2 driver (`oracles/logql-native`, go1.24.5,
`-mod=vendor`, the recipe of `oracles/logql-loki-3.5.2.Dockerfile`; the time zone dataset is the zoneinfo.zip of that
toolchain) from the sha256-verified source archive; `setup <repo>` points the LogQL adapter and the fake runtime at it
and `run-logql <cases.json> <report.json>` runs the `logql-metric` phase. The driver serves the logql-metric, pipeline
and template phases (the syntax phase needs the stock `/usr/bin/loki` of the image). `author/logql-interval-probe.py`
authors the raw-log interval probe (`cases/logql-interval-multiplicity.json`, 970 comparisons: eight fixture families,
stored rows of multiplicity > 1, both directions, limits, ties across streams, a line filter, the interval boundary,
pre-epoch timestamps, a label_format that reorders the visible labels) and records the observations to
`evidence/native-logql-interval-observations.json` (content-locked in `source-lock.json`), replayed by
`TestOwnedMatchesRecordedNativeLogQLIntervalObservations` from the locked bytes. The probe's first two runs (152 and 156
mismatching rows: the tied-entry choice by original stream hash, and the pinned `lastEntry.Unix() < 0` rule after a pre-epoch entry) are
kept in the wave-18 evidence (`l2w18-evidence/lane2/loki-interval-run*-report.json`).

`author/native-oracle.sh build-loki-shard-probe` builds `author/logql-shard-probe` inside the same verified Loki tree
(a nested module, build tag `soundpost_logql_shard_probe`, so it is outside the product module). The oracle driver feeds
the engine one iterator below every merge and never shards; the probe drives what that cannot reach: the shard mapper's
`shard_aggregations` string switch (`NewShardMapper`), the real sharded evaluation (shard mapper plus downstream engine)
over two or three shard inputs that deliver the same entries, and the querier-side merge iterators
(`NewMergeEntryIterator`, `NewMergeSampleIterator`, the sort iterators). `author/logql-shard-probe.py generate` authors
`cases/logql-shard-replica-probe.json` (40 string lists x 5 queries, 10 log fixtures, 7 sample fixtures); the probe reads it
on stdin; `author/logql-shard-probe.py record <observed.json>` writes `evidence/native-logql-shard-replica-observations.json`
(content-locked). `TestOwnedMatchesRecordedNativeShardAggregationSwitch`, `TestOwnedMatchesRecordedNativeShardedReplicaInputs`,
`TestRecordedNativeEntryMergeCollapseIsDeclaredAgainstOwned` and `TestRecordedNativeSampleMergeCollapseIsDeclaredAgainstOwned`
replay them from the locked bytes and are the bound Go tests of `shard-capability-domain`, `iterator-entry-merge` and
`iterator-sample-merge` (the `=` prefix of a name in `author/ext_logql.py` marks a full test name outside the
implementation package). Regenerating `evidence/release-go-tests.jsonl` while its own lock entry is present fails the
two bound tests that read the inventory (the file is being rewritten): remove the entry from `source-lock.json`, run
`observe-go-tests.sh` and `release-author.py --observe`, then relock `acceptance.json` and the evidence file.
