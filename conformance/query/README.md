<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Query conformance corpora

Development-only comparison of the owned PromQL/LogQL engines against pinned
upstream reference builds. The references run only inside isolated oracle
images; they are never a production fallback.

## Locked files are byte-exact and LF-only

`source-lock.json` pins every case file, audit file and profile file by the
SHA-256 of its raw bytes. Git normalises line endings (`core.autocrlf=input`),
so a file that is CRLF in a Windows working tree hashes differently from the
blob a clean checkout receives. Every locked file MUST be written with LF line
endings before its hash is recorded. After editing any locked file:

1. recompute its entry under `inventory_files` (key `cases/<name>`) or
   `profile_files`;
2. run `go run ./cmd/soundpost-querycheck inventory --check`.

A mutated or unlocked case file hard-fails; `compared: 0` is a failure, never a
pass.

## Expected values are native observations

Rows in `cases/logql-pipeline-differential.json` and
`cases/logql-json-path-syntax.json`, and rows in
`internal/query/logql/testdata/native-syntax-errors.json`, record what the
pinned Loki 3.5.2 reference returned. They are not authored predictions. Rows
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

Four obligations stay unbound: `configuration/protocols` and
`configuration/scrape-inheritance` of both PromQL profiles. Their rule states
that they "change materialized input acquisition, not fixed-input language
evaluation": the owned product has no scrape-configuration implementation and the
pinned oracle wrapper has no configuration-parsing phase (it is never rebuilt),
so no differential row can observe them and none was fabricated.
