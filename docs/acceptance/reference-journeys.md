<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Reference application journeys (acceptance 07.04)

`go run ./tools/smoke journeys --artifact-dir <dir>` provisions an isolated product and the generic
reference estate in `examples/reference/`, drives it, reads the admitted evidence back and evaluates
fourteen rows. It exits **nonzero while any required row is unsatisfied**. A row is never marked
passed because its prerequisite is missing; the closed reason is printed instead.

## What it starts (all on loopback, nothing from the network)

| Part | How |
| --- | --- |
| Soundpost node | the static binary from `go run ./build release` (`--binary` or `--release DIR`), `serve --mode single` over HTTPS with a private CA; later restarted on the same data directory to read |
| PostgreSQL | a container of the LOCAL image `92620daddcd9` (16.14) with `log_statement=all`, tmpfs data, random password; removed (with its volume) when the run ends. The shared `soundpost-sdk-pg16-local` container is not touched |
| Dependency | `examples/reference/dependency/server.py` (Python stdlib HTTPS, uninstrumented) |
| API | `examples/reference/api/serve.py` (Python WSGI, SDK WSGI/psycopg/httpx integrations) |
| Gateway | `examples/reference/gateway/server.ts` under Bun (`packages/bun` serve/fetch) |
| Web | `examples/reference/web/` built by Vite 7 with `packages/build` (the real source map is uploaded to `POST /api/v1/artifacts`), served by the gateway, driven by headless Linux Chrome 156 through Playwright against the real HTTPS origin |
| Jobs | `examples/reference/jobs/run.py` (scheduler + worker, SDK job attempts) |

Compose is used only for the two backing services (`examples/reference/compose.yaml`); the SDK-bearing
apps are host processes because they use the committed SDK source trees. Compose was validated with
`docker compose config` only, it was not started by the smoke.

Platform notes recorded by the run: the host is Windows with WSL2 (kernel in the artifact). Vite's native
binaries exist only for win32 in the pinned `node_modules`, so the web build runs with the Windows Node 22.23.4
from WSL (it reaches the WSL loopback node); everything else is Linux. Python is the system 3.12.3 with
cryptography 41.0.7 (the SDK pins 50.0.0) and the pure-Python psycopg 3.2.10/httpx 0.28.1 copied by
`examples/reference/pysite.sh`; this is a version mismatch, not a qualification of the pinned set.

## Rows

| Row | Required | Meaning |
| --- | --- | --- |
| `gateway_dependency_child_span` | yes | one gateway request is a single-rooted trace: gateway server -> `http.call`/`api` -> API server -> `db.execute`/`postgres` and `http.call`/`dependency`, read through `POST /api/v1/traces/view` |
| `frontend_request_api_db_chain` | yes | the real browser action `ui.action` -> `http.call`/`gateway` -> gateway -> API -> database and dependency, one trace whose id is the id the page reported |
| `error_admitted_with_known_build` | yes | the stored browser error carries the known web build id |
| `error_linked_to_request_trace` | yes | that error carries the action's trace id and a span id |
| `build_source_map_uploaded` | yes | the build's upload returned a receipt for that build; no `sourceMappingURL` is shipped |
| `mapped_frame_at_known_location` | yes | the generated position Chrome reported for the thrown error, mapped by the real symbolication service in the OCI sandbox using the uploaded map, is `src/receipt.ts:24:10` (`throw new UnpricedOrderError()`, 0-based column) under the known build |
| `job_failed_attempt_retained_then_success` | yes | stored attempts of the deterministic run: attempt 1 started+failed, attempt 2 started+succeeded, distinct attempt ids, ordered |
| `same_trace_in_wrong_org_denied` | yes | with both traces readable by the owning reader, a reader of another organization gets 403/404 with no trace data, with its own org id and with the owner's |
| `canaries_absent_everywhere` | yes | three canaries (browser body, prompt, SQL literal) are shown to have reached the dependency, the database row and PostgreSQL's statement log, and are absent from the node data dir (decoded through nested base64, the decoder used by the storage tests), every process output and every read answer |
| `db_span_safe_operation_only` | yes | every database span has only `db.execute`/`postgres`; no SQL text appears in any stored record or trace view |
| `replay_masked_interaction_real_recorder` | yes | the real recorder's chunks are stored |
| `profile_linkage_with_capability_truth` | yes | a runtime profile is stored and linked, with the real capability status |
| `actual_ids_equal_expected` | yes | admitted build, job and run ids equal the deterministic expected ones; both traces are admitted |
| `actual_versions_recorded` | yes | actual versions of every runtime and image |

IDs are deterministic (`journeyID`, SHA-256 of fixed names): org, project, sources, builds, job
`reference.catalog.refresh` and run `1`. Trace ids come from the SDKs; the smoke compares the id the page
reported with the admitted one and finds the direct request's trace as the only parentless gateway span.

## Observed result and what is NOT satisfied

Two consecutive runs of the committed smoke ended with the same outcome (exit status 1): twelve rows
passed and two did not. Run output: `.superpowers/sdd/approved-product/07.04-evidence/`.

* `replay_masked_interaction_real_recorder`: **NOT satisfied**, reason `sdk_recorder_chunks_not_enqueued`. In
  real Chrome the recorder emitted 1 chunk to the application's `emit` callback; `packages/browser` has no
  client method that turns an emitted chunk into a queued record (`bufferedRecords` stayed 0, 0 receipts, 0
  stored). The documented Go-validator mismatch (node fields `rect`/`pres`, wider tag enum) is therefore not
  even reached, and is still open as described in `packages/browser/README.md`.
* `profile_linkage_with_capability_truth`: **NOT satisfied**, reason `sdk_profile_not_delivered`. Chrome 156
  with `Document-Policy: js-profiling` really profiled (status `supported`, 32 samples), but
  `startProfile` returns a local report and nothing in `packages/browser`/`packages/core` enqueues it: 0
  profile rows stored. No runtime/native profile linkage exists to inspect.
* Known and visible, not a row: the stored browser error has no frames (`safe_original_stack_unavailable`,
  documented SDK behaviour). The mapped-frame row therefore maps the position Chrome reported for the real
  thrown error (taken from Playwright's `pageerror`), not a frame the SDK captured. Python job errors do
  carry frames.
* `mapped_frame_at_known_location` depends on the symbolication sandbox's fixed 5 s / 100 ms budgets. On this
  shared, heavily loaded host the first attempts returned `deadline` in some runs (all of 3 in two earlier
  runs; 7 of 8 in one later run) and `resolved` in the others; the smoke retries up to 8 times one second apart and records every
  attempt in `details.json`. A run whose attempts are all `deadline` (or `sandbox_unavailable`) leaves the
  row unsatisfied with that reason. No timeout was changed.
* The deployed node has no symbolication route (`httpapi.NewEvidence(nil, ...)` in `appcore`) and no job read
  route at this commit, so frames are resolved by `app.NewSymbolicator` over the stopped node's data
  directory, and job attempts and error records are read with `Storage.Scan` after stopping the node.
  Trace reads go through the real HTTP route after restarting the node on the same data.
* Job attempts, the error and spans DO reach the backend and are admitted; the 03.06/03.09 doubt about job
  attempts was checked and did not hold for the Python SDK here. Profiles, capability records and replay
  chunks do not reach it (rows above). Capability records were not attempted.
* Not covered: a browser other than Chrome 156 headless; Linux arm64; the pinned cryptography 50.0.0; running
  the apps as containers; the `soundpost-sdk-pg16-local` container (a separate local PostgreSQL 16 container of the same image was used).
