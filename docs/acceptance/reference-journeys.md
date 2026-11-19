<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Reference application journeys (acceptance 07.04)

`go run ./tools/smoke journeys --artifact-dir <dir>` provisions an isolated product and the generic
reference estate in `examples/reference/`, drives it, reads the admitted evidence back and evaluates
eighteen rows. It exits **nonzero while any required row is unsatisfied**. A row is never marked
passed because its prerequisite is missing; the closed reason is printed instead.

## What it starts (all on loopback, nothing from the network)

| Part | How |
| --- | --- |
| Soundpost node | the static binary from `go run ./build release` (`--binary` or `--release DIR`), `serve --mode single` over HTTPS with a private CA; later restarted on the same data directory to read |
| PostgreSQL | a real PostgreSQL 16 server with `log_statement=all` and a random password, removed when the run ends. Default: a container of the LOCAL image `92620daddcd9` (16.14, tmpfs data; the shared `soundpost-sdk-pg16-local` container is not touched). With `--pg-local DIR` (a PostgreSQL installation holding `bin/{initdb,pg_ctl,postgres}` and `lib/`) an unprivileged server is started from that directory on loopback instead, for a host without a container runtime; the applications reach either through the same psycopg driver, and the canary proof reads the server's own statement log in both cases |
| Dependency | `examples/reference/dependency/server.py` (Python stdlib HTTPS, uninstrumented) |
| API | `examples/reference/api/serve.py` (Python WSGI, SDK WSGI/psycopg/httpx integrations) |
| Gateway | `examples/reference/gateway/server.ts` under Bun (`packages/bun` serve/fetch) |
| Web | `examples/reference/web/` built by Vite 7 with `packages/build` (the real source map is uploaded to `POST /api/v1/artifacts`), served by the gateway, driven by headless Linux Chrome 156 through Playwright against the real HTTPS origin |
| Jobs | `examples/reference/jobs/run.py` (scheduler + worker, SDK job attempts) |

Compose is used only for the two backing services (`examples/reference/compose.yaml`); the SDK-bearing
apps are host processes because they use the committed SDK source trees and the per-source configuration the
smoke provisions. Every compose image is a required `REFERENCE_*_IMAGE` environment reference (a local image id; `pull_policy: never`),
pinned by `TestReferenceComposeRunsOnlyNamedLocalImages`. Compose was validated with `docker compose config` only,
it was not started by the smoke.

Platform notes: everything runs on Linux, including the web build (Linux Node 22 with the Vite from the pnpm workspace:
`examples/reference/web` is a workspace member, so `pnpm install --frozen-lockfile` installs its pinned dependencies).
Python is the system interpreter with the hash-locked packages of `examples/reference/requirements.lock` (the pins of
`sdk/python/requirements-*.lock`, including cryptography 50.0.0) installed by `examples/reference/pysite.sh` with
`pip --require-hashes`; `tools/smoke` `TestReferenceLockMatchesSDKLocks` keeps that file equal to the SDK locks.
The headless browser trusts the run's private CA through an NSS database when `certutil` exists; on a host without it the
smoke passes the run's own leaf by its public-key pin (`--ignore-certificate-errors-spki-list`, nothing else is ignored).
The server-side symbolication sandbox is the node's own native sandbox: run the smoke where the node has a delegated cgroup v2
subtree (a systemd service with `Delegate=memory pids` and `DelegateSubgroup=main`) and pass its parent with
`--symbolicate-cgroup-root`; no container runtime is needed anywhere.

## Rows

| Row | Required | Meaning |
| --- | --- | --- |
| `gateway_dependency_child_span` | yes | one gateway request is a single-rooted trace: gateway server -> `http.call`/`api` -> API server -> `db.execute`/`postgres` and `http.call`/`dependency`, read through `POST /api/v1/traces/view` |
| `frontend_request_api_db_chain` | yes | the real browser action `ui.action` -> `http.call`/`gateway` -> gateway -> API -> database and dependency, one trace whose id is the id the page reported |
| `error_admitted_with_known_build` | yes | the stored browser error, read through the product (the UI trace view names the occurrence and its issue; `POST /api/v1/evidence/occurrence` answers for it), carries the known web build id |
| `error_linked_to_request_trace` | yes | that stored error carries the action's trace id and a span id |
| `build_source_map_uploaded` | yes | the build's upload returned a receipt for that build; no `sourceMappingURL` is shipped |
| `mapped_frame_at_known_location` | yes | the STORED error carries the frames of the shipped bundle, each naming the uploaded artifact (the page's build receipt gives the browser SDK the artifact id); `POST /api/v1/evidence/frames`, asked about exactly those stored frames, maps the innermost one through the uploaded source map to `src/receipt.ts:24:10` (`throw new UnpricedOrderError()`, 0-based column) under the known build, and the stored frame is at the generated position the real browser reported. Nothing is mapped by the harness |
| `job_failed_attempt_retained_then_success` | yes | the job view (`POST /api/v1/jobs/view`) of the deterministic run: attempt 1 started and failed (effective state included), attempt 2 started and succeeded, distinct attempt ids, ordered, the retry is the final attempt and the run is recovered |
| `same_trace_in_wrong_org_denied` | yes | with both traces readable by the owning reader, a reader of another organization gets 403/404 with no trace data, with its own org id and with the owner's |
| `canaries_absent_everywhere` | yes | three canaries (browser body, prompt, SQL literal) are shown to have reached the dependency, the database row and PostgreSQL's statement log, and are absent from the node data dir (decoded through nested base64, the decoder used by the storage tests), every process output and every read answer |
| `db_span_safe_operation_only` | yes | every database span has only `db.execute`/`postgres`; no SQL text appears in any stored record or trace view |
| `replay_masked_interaction_real_recorder` | yes | the real recorder's chunks are stored |
| `profile_linkage_with_capability_truth` | yes | a browser profile is stored and linked, with the real capability status |
| `browser_profile_read_through_profile_view` | yes | the stored browser profile is read back through `POST /api/v1/profiles/view`: ready (or incomplete with declared loss), the same sample count as storage, frames that are the shipped bundle's origin-relative script paths, a supported `browser_js_self_profile` capability record the chunks name |
| `browser_profile_refusals_stored_capability_only` | yes | the same page SDK in the same real Chrome, once served without the `js-profiling` Document-Policy (`/?document-policy=off`, denied / `document_policy_missing`) and once with the Profiler API absent (unsupported / `js_self_profiling_unavailable`), delivers the capability record alone: acknowledged, stored with the status and reason the page reported, named by no chunk. The profile route, asked about that record's id, answers 404 (a refused run has no profile id; the route reads chunks) |
| `browser_profile_scenarios_console_errors_explained` | yes | the profile scenarios log no console error, except the browser's own `Document policy violation: js-profiling is not allowed in this document.` in the denied run. The one 404 console error of every page was the browser's `/favicon.ico` request, which the reference gateway now answers with 204 |
| `runtime_profile_delivered_stored_linked` | yes | the CPython SDK in the job process samples the run (`python_wall_samples`), delivers the profile, the product stores it, and `POST /api/v1/profiles/view` reads it back: samples present, the sampled function `summarise_catalog` shown, a supported capability record of that method linked. A profiler that could not see every thread or tick declares loss, so the view is `incomplete` with the closed reason `coverage_incomplete` and a non-zero loss; that is accepted, an incomplete view that declares no loss or any other state or reason is not |
| `actual_ids_equal_expected` | yes | admitted build, job and run ids equal the deterministic expected ones; both traces are admitted |
| `actual_versions_recorded` | yes | actual versions of every runtime and image |

IDs are deterministic (`journeyID`, SHA-256 of fixed names): org, project, sources, builds, job
`reference.catalog.refresh` and run `1`. Trace ids come from the SDKs; the smoke compares the id the page
reported with the admitted one and finds the direct request's trace as the only parentless gateway span.

## Observed result

Errors, frames, jobs and the runtime profile are observed as the product's own route answers after the node is stopped and
started again on the same data (`readsAfterRestart`, `journeys_served.go`); the harness maps nothing and scans no storage for
them. Storage is scanned only for what has no read route (replay chunk counts, profile and capability record counts) and for canaries.

The recorded observation under `tools/smoke/testdata/journeys/observed.json` (`TestReferenceJourneyAssertions/recorded` re-assesses it) is the
eighteen-row run of the `node-loss-journeys` drill against a recovered three-member cluster on a Linux x86-64 worker (2026-11-19, all
eighteen rows required and satisfied, exit status 0); the run output is `.superpowers/sdd/approved-product/l1m-evidence/run1/`. An earlier
fifteen-row single-node run (Debian 13, kernel 6.12, PostgreSQL 16.9 from `--pg-local`, Node 22.23.4, Bun 1.3.14, CPython 3.13.5, Chrome
156.0.8078.80, a transient systemd user service with a delegated cgroup) is `.superpowers/sdd/approved-product/l5w21-evidence/journeys/`.
(That directory is part of the private development ledger, gitignored: **private-ledger evidence, not shipped with the repository.** The smoke itself is committed and repeats the run.)

Notes on that run:

* `replay_masked_interaction_real_recorder`: satisfied after task 11.02 (it was NOT satisfied, `sdk_recorder_chunks_not_enqueued`).
  The recorder now emits the server's closed schema (decision D2) and `startReplay(client, ...)` (`@soundpost/browser/replay`) enqueues every chunk itself. The reference
  page records while the driver types the canary note into the textarea, clicks it and writes the same text into a text node;
  the run on Linux Chrome 156 stored 3 replay chunks with no canary anywhere. Contract: `packages/browser/README.md`.
* `profile_linkage_with_capability_truth`: satisfied after task 10.17 (it was NOT satisfied, `sdk_profile_not_delivered`, because
  `startProfile` returned a local report and nothing enqueued it). The reference page now starts the run with `startClientProfile(client, ...)`
  (`deploymentProfiles: true`) and the SDK queues one `capability` record and the `profile_chunk`(s) through its ordinary queue. Two
  consecutive runs on Linux Chrome 156 with `Document-Policy: js-profiling` stored 1 profile row (33 and 32 samples, equal to the
  report's `sample_count`) and 1 linked capability record; the smoke now also requires every stored chunk to name a stored capability
  of signal `profile_chunk` in the same clock domain before it counts the delivery. The `web` source policy lists `capability`
  next to `profile_chunk` (the server admits only listed kinds). Evidence: `.superpowers/sdd/approved-product/10.17-report.md`.
* The stored browser error carries frames now: the page's build receipt (`artifact_ids` in the gateway's `/config.json`) tells the browser
  SDK the artifact id of each shipped asset, which is how the server can resolve a frame. A bundle deployed without that receipt
  keeps path-only frames and the mapped-frame row fails with `frame_artifact_unbound`.
* `mapped_frame_at_known_location` depends on the symbolication sandbox's fixed 5 s / 100 ms budgets. On a loaded host the first
  attempts can answer `deadline`; the smoke asks the frame route up to 8 times one second apart and records every attempt in
  `details.json` (`frame_route_attempts`). A run whose attempts are all `deadline` (or `sandbox_unavailable`) leaves the
  row unsatisfied with that reason. No timeout was changed.
* The runtime profile of a Python process is `incomplete` with `coverage_incomplete` and declared loss (135 lost of 326 samples in
  the recorded run): the sampling profiler cannot see a thread that does not run. The row accepts exactly that product truth.
* Not covered: a browser other than Chrome 156 headless; Linux arm64; running the apps as containers; a native (perf helper)
  profile row, which needs root, an OCI runtime and a kernel the helper supports.
* Job attempts, the error and spans DO reach the backend and are admitted; the 03.06/03.09 doubt about job
  attempts was checked and did not hold for the Python SDK here.

## Against a recovered cluster (`--cluster-attach`, 07.07#16)

`go run ./tools/smoke journeys --cluster-attach FILE ...` runs the same applications, the same drive and the same eighteen rows against a
three-member distributed cluster that somebody else bootstrapped and put through a node loss, instead of starting a single node. The
cluster's owner is `tools/drills --scenario node-loss-journeys` (`docs/operations/drills.md`, "After recovery: the reference journeys"),
which writes the attach document (`tools/smoke/testdata/journeys/attach.json` is a committed sample; the parser, `journeys_cluster.go`,
is strict) and runs the smoke as its child. What differs from the single node, and nothing else does:

* Nothing is started or bootstrapped: the installation's owner logs in and provisions the journeys' organizations, users and sources
  through a member; control writes and reads retry the answers a recovering cluster documents as retryable (HTTP 400/409 `stale` or
  `conflict`, the typed 503); every other answer is the row's evidence.
* Every application ingests through the member its role in the document names, and the document must name members that were
  killed and restored; every member must answer `/readyz` ready before anything is provisioned (a leg pointed at a member that does not
  serve fails the run there). The members serve one TLS leaf, so the browser pins one key as before; the page's `connect-src` names the
  gateway's ingest origin, so the page's member is the gateway's.
* The collect step's in-process storage scan needs a data directory to itself: through the control channel (JSON lines on stdin/stdout)
  the cluster's owner shuts the `scan` member down, the smoke opens that member's directory as that member (`appcore.OpenDistributed`
  on its node file; it joins the two running members), scans, and asks the owner to start the member again. **Every login and every read of the
  rows afterwards, the traces, errors, frames, job and profile, is served by that restored member.** The leak scan covers all three members' directories
  while two of them run (a file that vanishes between listing and reading is skipped and counted).
* `details.json` carries a `cluster` object (members, roles, recovered members, the member the reads went through) and the order page's flush report
  (`order_driver_flush`); `observed.json` has the same shape as the single-node document.

## The same estate under the UI end-to-end suite (acceptance 05.06 and 05.09)

`web/e2e/support/estate.ts` (`seedEstate`) starts the same programs as host processes for the investigation UI specs: the Bun gateway (twice: one in
front of the instrumented API, one in front of the same API code started without `--config`, an unavailable producer), the Python API over a PostgreSQL 16
database that the run creates and drops, the uninstrumented dependency, and the order page built by Vite with `packages/build` (its source map uploaded
through `POST /api/v1/artifacts`). Sources, the builder's artifact token and the investigator are made through the public admin and source routes. The
page runs in the browser under test (Chromium, Firefox or WebKit project) and places three orders: priced, unpriced (the page throws `UnpricedOrderError`
in its real minified bundle) and priced through the second gateway. Each program is stopped with SIGTERM and must report nothing pending or lost.
Nothing is composed by the suite: every span, error and mapped frame the UI shows was delivered by an SDK to the real ingest route.

| Spec | What it reads |
| --- | --- |
| `web/e2e/estate-traces.spec.ts` (pointer and keyboard) | the priced trace (eight spans in one tree: page action, page-to-gateway call, gateway request, gateway-to-API call, API request, two database calls, the dependency call; three dependency boundaries; the path's self times add up to the root's observed duration), the dark trace (four spans, the call to the API is the boundary, none of the API's spans exist), the span-to-Explore link carrying the span's own recorded window, the page's failure as an error occurrence on the action span linked to its issue |
| `web/e2e/investigation-journeys.spec.ts`, organization C (keyboard only) | the same traces, and trace -> failure -> issue -> frame mapped by the real source map of the real build (`src/receipt.ts:24:`), with the map's source text never shown |

Host requirements, none substituted: `E2E_ESTATE_DATABASE_URL` (an admin DSN of a PostgreSQL 16 server, for example a container on a Docker host:
`postgresql://postgres:PASSWORD@HOST:PORT/postgres`), `E2E_PYTHON` (3.12 to 3.14 with the locked psycopg, httpx and cryptography), Bun 1.3.14
(`E2E_BUN`, default `bun`), the harness's `E2E_PKI`, and `h.sh prep` (which now also installs `@soundpost/reference-web` and `@soundpost/build`).
The symbolication sandbox (`E2E_SANDBOX=1`) maps the frame. Durations differ on every run; the specs assert structure and the page's own arithmetic.
