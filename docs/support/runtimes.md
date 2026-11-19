<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# SDK runtime support and qualification status

Status: **no runtime row is qualified for release.** `go run ./tools/qualify/cmd/qualify --suite runtime --matrix qualification/matrix.yaml --report <dir>` judges each row only against the build it names (object header, version output and platform are checked; a different version, OS or architecture never stands in) and exits non-zero until every required row is exercised and passing. Each row is exactly one of `exercised` (with raw safe series), `not_exercised`, `unsupported` or `denied`. An unavailable capability carries no number: zero is never reported for it.

| Runtime | Linux amd64 | Linux arm64 |
|---|---|---|
| CPython 3.12 (GIL) | exercised, **FAILED** on 3.12.3: `fixtures/sdk/profiles/python.py` exits 1 (`sys.monitoring.use_tool_id(PROFILER_ID)` raises "tool 2 is already in use" in the coexistence case; the same fixture passed on a Windows 3.14.2 build) | not exercised (no build) |
| CPython 3.13 / 3.14 (GIL) | not exercised (no build) | not exercised |
| Node 22 | exercised, profile fixture passed on 22.23.4 | not exercised |
| Node 24 | not exercised | not exercised |
| Bun 1.3.14 | exercised, profile fixture passed | not exercised |

What "passed" means: only the committed runtime-profile supplement fixture (03.09). HTTP/DB/job critical-path journeys need a private fixture environment and are not part of this suite. Windows-hosted runs (Python 3.14.2, Node 22.23.4, Bun 1.3.14) are recorded as non-required rows and qualify nothing on Linux. The frozen manifest patch levels (`fixtures/sdk/qualification.json`) differ from the builds installed here and stay `not_run`.

`fixtures/sdk/qualification.json` (`measured_evidence`) is written only by `node fixtures/sdk/qualify.mjs`, from sealed runs. One run observes one Node on one host (`--run-out run.json --run-only`); `--merge run.node22.json,run.node24.json` builds the manifest from several. A run carries the source digest of the tree (`go run ./build source-digest`), its host and a digest over both; every merged row is bound to `{run digest, runtime, host id, source stamp}`. A run built against another source refuses the whole merge, a rerun replaces exactly the rows it produced (rows are keyed by id, the newest `recorded_at` wins), overhead is replaced only by a run that supplies it, and rows recorded without a binding or against an older source move to `retired_evidence` and are never claimed. The frozen `runtime_targets` keep `not_run`; `target_coverage` lists which frozen target has an observed engine-sample row of exactly its version (a different patch level never counts). Rules and reasons: `fixtures/sdk/qualify-merge.mjs`; tests: `bun test fixtures/sdk/qualify-merge.test.ts`.

Evidence rows of `fixtures/sdk/critical` name their PostgreSQL by the pinned image digest in every mode (`postgres_image`) plus `postgres_server`: `container_started_by_tool`, or `dsn` with `postgres_image_attestation: operator` when the server was reached by `--pg-dsn`. A DSN server needs `--pg-dsn-image <the pinned digest reference>`, the operator's statement of the image it was started from; a tag, an id prefix or another digest is refused.

Overhead budgets for these runtimes are in [budgets.md](budgets.md); core server capture currently misses them.
