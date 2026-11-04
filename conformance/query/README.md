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
